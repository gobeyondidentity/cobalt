#!/bin/bash
# Deploy and run the DPU agent on bluefield3
#
# Usage: ./scripts/deploy-agent.sh [start|stop|restart|status|logs]
#
# Environment variables:
#   DPU_HOST    - DPU hostname/IP (default: 192.168.1.204)
#   DPU_USER    - SSH user (default: ubuntu)
#   BMC_ADDR    - BMC address (default: 192.168.1.203:443)
#   BMC_USER    - BMC username (default: root)
#   BMC_PASS    - BMC password (required for start)
#   AGENT_PORT  - Agent listen port (default: 50052)

set -e

DPU_HOST="${DPU_HOST:-192.168.1.204}"
DPU_USER="${DPU_USER:-ubuntu}"
BMC_ADDR="${BMC_ADDR:-192.168.1.203:443}"
BMC_USER="${BMC_USER:-root}"
AGENT_PORT="${AGENT_PORT:-50052}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

ssh_cmd() {
    ssh -o ConnectTimeout=5 "${DPU_USER}@${DPU_HOST}" "$@"
}

build_agent() {
    echo "Building agent for ARM64..."
    cd "$PROJECT_ROOT"
    GOOS=linux GOARCH=arm64 go build -o /tmp/agent-arm64 ./cmd/agent
    echo "Build complete: /tmp/agent-arm64"
}

deploy_agent() {
    echo "Deploying agent to ${DPU_USER}@${DPU_HOST}..."
    scp /tmp/agent-arm64 "${DPU_USER}@${DPU_HOST}:~/agent"
    ssh_cmd "chmod +x ~/agent"
    echo "Deploy complete"
}

start_agent() {
    if [ -z "$BMC_PASS" ]; then
        echo "Error: BMC_PASS environment variable required"
        echo "Usage: BMC_PASS=xxx ./scripts/deploy-agent.sh start"
        exit 1
    fi

    echo "Starting agent on ${DPU_HOST}:${AGENT_PORT}..."
    ssh_cmd "pkill -f './agent' 2>/dev/null || true"
    sleep 1

    # Start agent with nohup, redirect output to log file
    ssh_cmd "FC_BMC_PASSWORD='${BMC_PASS}' nohup ./agent \
        --listen=:${AGENT_PORT} \
        --bmc-addr=${BMC_ADDR} \
        --bmc-user=${BMC_USER} \
        > agent.log 2>&1 &"

    sleep 2

    # Verify it's running
    if ssh_cmd "pgrep -f './agent'" > /dev/null; then
        echo "Agent started successfully"
        echo "  Listen: ${DPU_HOST}:${AGENT_PORT}"
        echo "  BMC: ${BMC_ADDR}"
        echo "  Logs: ssh ${DPU_USER}@${DPU_HOST} tail -f agent.log"
    else
        echo "Error: Agent failed to start. Check logs:"
        ssh_cmd "cat agent.log"
        exit 1
    fi
}

stop_agent() {
    echo "Stopping agent on ${DPU_HOST}..."
    ssh_cmd "pkill -f './agent' 2>/dev/null || true"
    echo "Agent stopped"
}

status_agent() {
    echo "Agent status on ${DPU_HOST}:"
    if ssh_cmd "pgrep -f './agent'" > /dev/null 2>&1; then
        echo "  Status: RUNNING"
        ssh_cmd "pgrep -af './agent'"
    else
        echo "  Status: STOPPED"
    fi
}

logs_agent() {
    echo "Agent logs from ${DPU_HOST}:"
    ssh_cmd "tail -50 agent.log 2>/dev/null || echo 'No logs found'"
}

case "${1:-}" in
    build)
        build_agent
        ;;
    deploy)
        build_agent
        deploy_agent
        ;;
    start)
        start_agent
        ;;
    stop)
        stop_agent
        ;;
    restart)
        stop_agent
        sleep 1
        start_agent
        ;;
    status)
        status_agent
        ;;
    logs)
        logs_agent
        ;;
    ""|help)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  build    - Build agent binary for ARM64"
        echo "  deploy   - Build and copy agent to DPU"
        echo "  start    - Start agent on DPU (requires BMC_PASS)"
        echo "  stop     - Stop agent on DPU"
        echo "  restart  - Restart agent on DPU (requires BMC_PASS)"
        echo "  status   - Check if agent is running"
        echo "  logs     - Show agent logs"
        echo ""
        echo "Example:"
        echo "  ./scripts/deploy-agent.sh deploy"
        echo "  BMC_PASS=BluefieldBMC1 ./scripts/deploy-agent.sh start"
        ;;
    *)
        echo "Unknown command: $1"
        exit 1
        ;;
esac
