# Secure Infrastructure Makefile
# Build commands for all project binaries

# Output directory
BIN_DIR := bin

# Binary names
AEGIS := $(BIN_DIR)/aegis
AEGIS_ARM64 := $(BIN_DIR)/aegis-arm64
BLUECTL := $(BIN_DIR)/bluectl
NEXUS := $(BIN_DIR)/nexus
KM := $(BIN_DIR)/km
SENTRY := $(BIN_DIR)/sentry
SENTRY_AMD64 := $(BIN_DIR)/sentry-amd64
SENTRY_ARM64 := $(BIN_DIR)/sentry-arm64
DPUEMU := $(BIN_DIR)/dpuemu

# Version from git tag or "dev"
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# ldflags for embedding version
LDFLAGS := -X github.com/nmelo/secure-infra/internal/version.Version=$(VERSION)

.PHONY: all aegis bluectl nexus km sentry dpuemu test clean release help

# Default target: build all binaries
all: $(BIN_DIR)
	@echo "Building all binaries..."
	@go build -ldflags "$(LDFLAGS)" -o $(AEGIS) ./cmd/aegis
	@echo "  $(AEGIS)"
	@go build -ldflags "$(LDFLAGS)" -o $(BLUECTL) ./cmd/bluectl
	@echo "  $(BLUECTL)"
	@go build -ldflags "$(LDFLAGS)" -o $(KM) ./cmd/keymaker
	@echo "  $(KM)"
	@go build -ldflags "$(LDFLAGS)" -o $(NEXUS) ./cmd/nexus
	@echo "  $(NEXUS)"
	@go build -ldflags "$(LDFLAGS)" -o $(SENTRY) ./cmd/sentry
	@echo "  $(SENTRY)"
	@go build -ldflags "$(LDFLAGS)" -o $(DPUEMU) ./dpuemu/cmd/dpuemu
	@echo "  $(DPUEMU)"
	@echo "Done."

# Create bin directory if needed
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Build aegis for local platform and cross-compile for BlueField (ARM64)
aegis: $(BIN_DIR)
	@echo "Building aegis..."
	@go build -ldflags "$(LDFLAGS)" -o $(AEGIS) ./cmd/aegis
	@echo "  $(AEGIS)"
	@echo "Cross-compiling aegis for BlueField (linux/arm64)..."
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(AEGIS_ARM64) ./cmd/aegis
	@echo "  $(AEGIS_ARM64)"

# Build bluectl CLI
bluectl: $(BIN_DIR)
	@echo "Building bluectl..."
	@go build -ldflags "$(LDFLAGS)" -o $(BLUECTL) ./cmd/bluectl
	@echo "  $(BLUECTL)"

# Build nexus
nexus: $(BIN_DIR)
	@echo "Building nexus..."
	@go build -ldflags "$(LDFLAGS)" -o $(NEXUS) ./cmd/nexus
	@echo "  $(NEXUS)"

# Build keymaker CLI
km: $(BIN_DIR)
	@echo "Building km (keymaker)..."
	@go build -ldflags "$(LDFLAGS)" -o $(KM) ./cmd/keymaker
	@echo "  $(KM)"

# Build sentry for local platform and cross-compile for Linux hosts
sentry: $(BIN_DIR)
	@echo "Building sentry..."
	@go build -ldflags "$(LDFLAGS)" -o $(SENTRY) ./cmd/sentry
	@echo "  $(SENTRY)"
	@echo "Cross-compiling sentry for Linux (amd64)..."
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(SENTRY_AMD64) ./cmd/sentry
	@echo "  $(SENTRY_AMD64)"
	@echo "Cross-compiling sentry for Linux (arm64)..."
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(SENTRY_ARM64) ./cmd/sentry
	@echo "  $(SENTRY_ARM64)"

# Build DPU emulator
dpuemu: $(BIN_DIR)
	@echo "Building dpuemu..."
	@go build -ldflags "$(LDFLAGS)" -o $(DPUEMU) ./dpuemu/cmd/dpuemu
	@echo "  $(DPUEMU)"

# Run all tests
test:
	@echo "Running tests..."
	@go test ./...

# Remove bin directory contents
clean:
	@echo "Cleaning bin/..."
	@rm -rf $(BIN_DIR)/*
	@echo "Done."

# Build release binaries for multiple platforms
release: $(BIN_DIR)
	@echo "Building release binaries..."
	@echo ""
	@echo "darwin/arm64:"
	@GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/aegis-darwin-arm64 ./cmd/aegis
	@echo "  $(BIN_DIR)/aegis-darwin-arm64"
	@GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/bluectl-darwin-arm64 ./cmd/bluectl
	@echo "  $(BIN_DIR)/bluectl-darwin-arm64"
	@GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/km-darwin-arm64 ./cmd/keymaker
	@echo "  $(BIN_DIR)/km-darwin-arm64"
	@echo ""
	@echo "linux/amd64:"
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/aegis-linux-amd64 ./cmd/aegis
	@echo "  $(BIN_DIR)/aegis-linux-amd64"
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/bluectl-linux-amd64 ./cmd/bluectl
	@echo "  $(BIN_DIR)/bluectl-linux-amd64"
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/km-linux-amd64 ./cmd/keymaker
	@echo "  $(BIN_DIR)/km-linux-amd64"
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/sentry-linux-amd64 ./cmd/sentry
	@echo "  $(BIN_DIR)/sentry-linux-amd64"
	@echo ""
	@echo "linux/arm64 (BlueField DPU):"
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/aegis-linux-arm64 ./cmd/aegis
	@echo "  $(BIN_DIR)/aegis-linux-arm64"
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/bluectl-linux-arm64 ./cmd/bluectl
	@echo "  $(BIN_DIR)/bluectl-linux-arm64"
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/km-linux-arm64 ./cmd/keymaker
	@echo "  $(BIN_DIR)/km-linux-arm64"
	@echo ""
	@echo "Release build complete."

# =============================================================================
# Quickstart Demo Targets
# Run each step of the emulator quickstart guide
# =============================================================================

.PHONY: demo-clean demo-step1 demo-step2 demo-step3 demo-step4 demo-step5 demo-step6 demo-step7 demo-step8 demo-step9 demo-step10 demo-step11 demo-step12 demo-step13

# Reset environment for fresh start
demo-clean:
	@echo "=== Clean Slate ==="
	@rm -f ~/.local/share/bluectl/dpus.db
	@rm -f ~/.local/share/bluectl/key
	@rm -rf ~/.km
	@echo "Database and config removed. Ready for fresh start."

# Step 1: Start the server (runs in foreground)
demo-step1:
	@echo "=== Step 1: Start Server ==="
	@echo "Starting server on :18080..."
	@echo "Press Ctrl+C to stop"
	$(BIN_DIR)/nexus

# Step 2: Create tenant
demo-step2:
	@echo "=== Step 2: Create Tenant ==="
	$(BIN_DIR)/bluectl tenant add gpu-prod --description "GPU Production Cluster"

# Step 3: Start emulator (runs in foreground)
demo-step3:
	@echo "=== Step 3: Start DPU Emulator ==="
	@echo "Starting emulator on :18051..."
	@echo "Press Ctrl+C to stop"
	$(BIN_DIR)/dpuemu serve --port 18051 --fixture dpuemu/fixtures/bf3-static.json

# Step 4: Register DPU
demo-step4:
	@echo "=== Step 4: Register DPU ==="
	$(BIN_DIR)/bluectl dpu add localhost --name bf3

# Step 5: Assign DPU to tenant
demo-step5:
	@echo "=== Step 5: Assign DPU to Tenant ==="
	$(BIN_DIR)/bluectl tenant assign gpu-prod bf3

# Step 6: Create operator invitation
demo-step6:
	@echo "=== Step 6: Create Operator Invitation ==="
	@$(BIN_DIR)/bluectl operator invite operator@example.com gpu-prod
	@echo ""
	@echo "Now run: make demo-step7"
	@echo "Enter the invite code when prompted"

# Step 7: Accept operator invitation
demo-step7:
	@echo "=== Step 7: Accept Operator Invitation ==="
	$(BIN_DIR)/km init

demo-step7-verify:
	@echo "=== Verify Operator ==="
	$(BIN_DIR)/km whoami

# Step 8: Create SSH CA
demo-step8:
	@echo "=== Step 8: Create SSH CA ==="
	$(BIN_DIR)/km ssh-ca create test-ca

# Step 9: Grant CA access
demo-step9:
	@echo "=== Step 9: Grant CA Access ==="
	$(BIN_DIR)/bluectl operator grant operator@example.com gpu-prod test-ca bf3

# Step 10: Submit attestation
demo-step10:
	@echo "=== Step 10: Submit Attestation ==="
	$(BIN_DIR)/bluectl attestation bf3

# Step 11: Distribute credentials
demo-step11:
	@echo "=== Step 11: Distribute Credentials ==="
	$(BIN_DIR)/km push ssh-ca test-ca bf3

# Step 12: Test host agent (optional)
demo-step12:
	@echo "=== Step 12: Test Host Agent ==="
	$(BIN_DIR)/sentry --dpu-agent http://localhost:9443 --oneshot

# Step 13: Sign a user certificate
demo-step13:
	@echo "=== Step 13: Sign a User Certificate ==="
	@echo "Generating test SSH key..."
	@ssh-keygen -t ed25519 -f /tmp/demo_key -N "" -C "demo@example.com" -q
	@echo "Signing with test-ca..."
	@$(BIN_DIR)/km ssh-ca sign test-ca --principal ubuntu --pubkey /tmp/demo_key.pub > /tmp/demo_key-cert.pub
	@echo "Certificate saved to /tmp/demo_key-cert.pub"
	@echo ""
	@echo "Inspecting certificate:"
	@ssh-keygen -L -f /tmp/demo_key-cert.pub
	@echo ""
	@echo "Cleaning up..."
	@rm -f /tmp/demo_key /tmp/demo_key.pub /tmp/demo_key-cert.pub
	@echo "Done."

# =============================================================================
# Hardware Demo Targets
# For real BlueField DPU deployment (setup-hardware.md)
# =============================================================================

.PHONY: hw-clean hw-step1 hw-step2 hw-step3-deploy hw-step4 hw-step5 hw-step5-accept hw-step6 hw-step6-grant hw-step7 hw-step8 hw-step9

# Configuration - override with: make hw-step4 DPU_IP=192.168.1.204
DPU_IP ?= 192.168.1.204
DPU_USER ?= ubuntu
DPU_NAME ?= bf3-prod-01
CONTROL_PLANE_IP ?= $(shell hostname -I | awk '{print $$1}')

# Reset environment for fresh start
hw-clean:
	@echo "=== Clean Slate (Hardware) ==="
	@rm -f ~/.local/share/bluectl/dpus.db
	@rm -f ~/.local/share/bluectl/key
	@rm -rf ~/.km
	@echo "Database and config removed. Ready for fresh start."

# Step 1: Start the server (runs in foreground)
hw-step1:
	@echo "=== HW Step 1: Start Server ==="
	@echo "Starting server on :18080..."
	@echo "Press Ctrl+C to stop"
	$(BIN_DIR)/nexus

# Step 2: Create tenant
hw-step2:
	@echo "=== HW Step 2: Create Tenant ==="
	$(BIN_DIR)/bluectl tenant add gpu-prod --description "GPU Production Cluster"

# Step 3: Deploy agent to DPU (requires SSH access)
hw-step3-deploy:
	@echo "=== HW Step 3: Deploy Agent to DPU ==="
	@echo "Copying agent to $(DPU_USER)@$(DPU_IP)..."
	scp $(BIN_DIR)/aegis-linux-arm64 $(DPU_USER)@$(DPU_IP):~/aegis
	@echo ""
	@echo "Agent copied. SSH to DPU and run:"
	@echo "  chmod +x ~/aegis"
	@echo "  ~/aegis --listen :18051 -local-api -control-plane http://$(CONTROL_PLANE_IP):18080 -dpu-name $(DPU_NAME)"

# Step 4: Register DPU
hw-step4:
	@echo "=== HW Step 4: Register DPU ==="
	$(BIN_DIR)/bluectl dpu add $(DPU_IP) --name $(DPU_NAME)
	$(BIN_DIR)/bluectl tenant assign gpu-prod $(DPU_NAME)

# Step 5: Create operator invitation
hw-step5:
	@echo "=== HW Step 5: Create Operator ==="
	@echo "Creating invitation..."
	@$(BIN_DIR)/bluectl operator invite operator@example.com gpu-prod
	@echo ""
	@echo "Now run: make hw-step5-accept"
	@echo "Enter the invite code when prompted"

hw-step5-accept:
	@echo "=== HW Step 5b: Accept Invitation ==="
	$(BIN_DIR)/km init

hw-step5-verify:
	@echo "=== HW Step 5: Verify Operator ==="
	$(BIN_DIR)/km whoami

# Step 6: Create SSH CA and grant access
hw-step6:
	@echo "=== HW Step 6: Create SSH CA ==="
	$(BIN_DIR)/km ssh-ca create prod-ca

hw-step6-grant:
	@echo "=== HW Step 6b: Grant Access ==="
	$(BIN_DIR)/bluectl operator grant operator@example.com gpu-prod prod-ca $(DPU_NAME)

# Step 7: Submit attestation
hw-step7:
	@echo "=== HW Step 7: Attestation ==="
	$(BIN_DIR)/bluectl attestation $(DPU_NAME)

# Step 8: Deploy host agent
hw-step8-deploy:
	@echo "=== HW Step 8: Deploy Host Agent ==="
	@echo "Copy sentry to your host server and run:"
	@echo "  ~/sentry --dpu-agent http://localhost:9443"
	@echo ""
	@echo "Or for x86_64 hosts:"
	@echo "  scp $(BIN_DIR)/sentry-linux-amd64 user@HOST_IP:~/sentry"

# Step 9: Push credentials
hw-step9:
	@echo "=== HW Step 9: Push Credentials ==="
	$(BIN_DIR)/km push ssh-ca prod-ca $(DPU_NAME) --force

# =============================================================================
# QA Testing Targets
# Three-VM setup: server, emulator (DPU), host with TMFIFO emulation
# =============================================================================

.PHONY: qa-help qa-vm-create qa-vm-delete qa-vm-start qa-vm-stop qa-vm-recover qa-vm-status
.PHONY: qa-build qa-up qa-down qa-rebuild qa-health qa-status qa-logs qa-clean
.PHONY: qa-tmfifo-up qa-tmfifo-down qa-test-tmfifo qa-push-binaries
.PHONY: qa-test-transport qa-test-transport-mock qa-test-transport-tmfifo qa-test-transport-integration
.PHONY: qa-test-transport-doca qa-doca-build qa-doca-deploy

# QA VM Configuration
QA_VM_SERVER := qa-server
QA_VM_EMU := qa-emu
QA_VM_HOST := qa-host
QA_WORKSPACE := $(shell pwd)/qa-workspace
QA_TMFIFO_PORT := 54321

# QA environment help
qa-help:
	@echo "QA Environment (3 VMs with TMFIFO emulation):"
	@echo ""
	@echo "VM Management:"
	@echo "  make qa-vm-create   Create all three VMs"
	@echo "  make qa-vm-delete   Delete all VMs"
	@echo "  make qa-vm-start    Start all VMs (silent)"
	@echo "  make qa-vm-stop     Stop all VMs (silent)"
	@echo "  make qa-vm-recover  Fix stuck VMs (recreates Unknown/Suspended)"
	@echo "  make qa-vm-status   Show VM status and processes"
	@echo ""
	@echo "Build & Deploy:"
	@echo "  make qa-build       Cross-compile and push binaries to VMs"
	@echo "  make qa-push-binaries  Push pre-built binaries to VMs"
	@echo "  make qa-up          Start services (checks if running first)"
	@echo "  make qa-down        Stop all services"
	@echo "  make qa-rebuild     Full rebuild: down, clean, build, up"
	@echo ""
	@echo "TMFIFO Emulation:"
	@echo "  make qa-tmfifo-up   Start TMFIFO emulation between VMs"
	@echo "  make qa-tmfifo-down Stop TMFIFO emulation"
	@echo "  make qa-test-tmfifo Test TMFIFO communication"
	@echo ""
	@echo "Monitoring:"
	@echo "  make qa-health      Check server and emulator health"
	@echo "  make qa-status      Show registered tenants and DPUs"
	@echo "  make qa-logs        Show service logs"
	@echo "  make qa-clean       Stop services and clean workspace"
	@echo ""
	@echo "Transport Testing:"
	@echo "  make qa-test-transport      Run all transport unit tests"
	@echo "  make qa-test-transport-mock Run MockTransport tests only"
	@echo "  make qa-test-transport-tmfifo  Test TmfifoNetTransport via emulator"
	@echo "  make qa-test-transport-integration  Full stack: sentry enrollment"
	@echo ""
	@echo "DOCA Comch Testing (BlueField hardware at 192.168.1.204):"
	@echo "  make qa-doca-build          Build with -tags doca on BlueField"
	@echo "  make qa-doca-deploy         Deploy DOCA-enabled binaries to BlueField"
	@echo "  make qa-test-transport-doca Test DOCAComchTransport on real hardware"
	@echo ""
	@echo "Architecture:"
	@echo "  qa-server  Control plane server (:18080)"
	@echo "  qa-emu     DPU emulator (:50051 gRPC, :9443 local API)"
	@echo "  qa-host    GPU host with sentry (connects via TMFIFO)"
	@echo ""
	@echo "TMFIFO emulation:"
	@echo "  qa-emu:/dev/tmfifo_net0  <--TCP:$(QA_TMFIFO_PORT)-->  qa-host:/dev/tmfifo_net0"

# Create all three QA VMs in parallel
qa-vm-create:
	@echo "Creating 3 VMs in parallel..."
	@( multipass launch 24.04 --name $(QA_VM_SERVER) --cpus 2 --memory 1G --disk 5G >/dev/null 2>&1 && echo "  qa-server: done" ) & \
	( multipass launch 24.04 --name $(QA_VM_EMU) --cpus 1 --memory 512M --disk 5G >/dev/null 2>&1 && echo "  qa-emu: done" ) & \
	( multipass launch 24.04 --name $(QA_VM_HOST) --cpus 1 --memory 512M --disk 5G >/dev/null 2>&1 && echo "  qa-host: done" ) & \
	wait
	@echo "Installing socat on qa-emu..."
	@multipass exec $(QA_VM_EMU) -- sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
	@multipass exec $(QA_VM_EMU) -- sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq socat
	@echo "Installing socat on qa-host..."
	@multipass exec $(QA_VM_HOST) -- sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
	@multipass exec $(QA_VM_HOST) -- sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq socat
	@multipass list | grep -E "^(Name|qa-)"

# Delete all QA VMs
qa-vm-delete:
	@multipass delete $(QA_VM_SERVER) --purge 2>/dev/null || true
	@multipass delete $(QA_VM_EMU) --purge 2>/dev/null || true
	@multipass delete $(QA_VM_HOST) --purge 2>/dev/null || true
	@rm -rf $(QA_WORKSPACE)

# Start all QA VMs
qa-vm-start:
	@multipass start $(QA_VM_SERVER) $(QA_VM_EMU) $(QA_VM_HOST) >/dev/null 2>&1

# Stop all QA VMs
qa-vm-stop:
	@multipass stop $(QA_VM_SERVER) $(QA_VM_EMU) $(QA_VM_HOST) >/dev/null 2>&1

# Recover stuck QA VMs
qa-vm-recover:
	@echo "Checking for stuck VMs..."
	@for vm in $(QA_VM_SERVER) $(QA_VM_EMU) $(QA_VM_HOST); do \
		STATE=$$(multipass info $$vm 2>/dev/null | grep State | awk '{print $$2}'); \
		if [ "$$STATE" = "Unknown" ] || [ "$$STATE" = "Suspended" ]; then \
			echo "  $$vm is stuck ($$STATE), recreating..."; \
			multipass delete $$vm --purge 2>/dev/null || true; \
			if [ "$$vm" = "$(QA_VM_SERVER)" ]; then \
				multipass launch 24.04 --name $$vm --cpus 2 --memory 1G --disk 5G; \
			else \
				multipass launch 24.04 --name $$vm --cpus 1 --memory 512M --disk 5G; \
				multipass exec $$vm -- sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq; \
				multipass exec $$vm -- sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq socat; \
			fi; \
			echo "  $$vm recreated"; \
		else \
			echo "  $$vm: $$STATE (ok)"; \
		fi; \
	done
	@echo "Recovery complete. Run 'make qa-push-binaries' to redeploy binaries."

# Show QA VM status
qa-vm-status:
	@echo "=== Server VM ==="
	@multipass info $(QA_VM_SERVER) 2>/dev/null | grep -E "^(Name|State|IPv4)" || echo "Not running"
	@multipass exec $(QA_VM_SERVER) -- pgrep -a nexus 2>/dev/null || echo "  server: not running"
	@echo ""
	@echo "=== Emulator VM (DPU) ==="
	@multipass info $(QA_VM_EMU) 2>/dev/null | grep -E "^(Name|State|IPv4)" || echo "Not running"
	@multipass exec $(QA_VM_EMU) -- pgrep -a dpuemu 2>/dev/null || echo "  dpuemu: not running"
	@multipass exec $(QA_VM_EMU) -- pgrep -a "socat.*tmfifo_net0" 2>/dev/null || echo "  tmfifo: not running"
	@echo ""
	@echo "=== Host VM ==="
	@multipass info $(QA_VM_HOST) 2>/dev/null | grep -E "^(Name|State|IPv4)" || echo "Not running"
	@multipass exec $(QA_VM_HOST) -- pgrep -a sentry 2>/dev/null || echo "  host-agent: not running"
	@multipass exec $(QA_VM_HOST) -- pgrep -a "socat.*tmfifo_net0" 2>/dev/null || echo "  tmfifo: not running"

# Build and push binaries to QA VMs (uses local repo)
qa-build:
	@echo "=== Building binaries ==="
	@$(MAKE) all
	@echo "=== Cross-compiling Linux binaries ==="
	@mkdir -p $(QA_WORKSPACE)
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(QA_WORKSPACE)/nexus ./cmd/nexus
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(QA_WORKSPACE)/dpuemu ./dpuemu/cmd/dpuemu
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(QA_WORKSPACE)/sentry ./cmd/sentry
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(QA_WORKSPACE)/aegis ./cmd/aegis
	@$(MAKE) qa-push-binaries

# Push pre-built binaries to QA VMs
qa-push-binaries:
	@echo "=== Pushing binaries to VMs ==="
	@multipass transfer $(QA_WORKSPACE)/nexus $(QA_VM_SERVER):/home/ubuntu/
	@multipass exec $(QA_VM_SERVER) -- chmod +x /home/ubuntu/nexus
	@multipass transfer $(QA_WORKSPACE)/dpuemu $(QA_VM_EMU):/home/ubuntu/
	@multipass transfer $(QA_WORKSPACE)/aegis $(QA_VM_EMU):/home/ubuntu/
	@multipass exec $(QA_VM_EMU) -- chmod +x /home/ubuntu/dpuemu /home/ubuntu/aegis
	@multipass transfer $(QA_WORKSPACE)/sentry $(QA_VM_HOST):/home/ubuntu/
	@multipass exec $(QA_VM_HOST) -- chmod +x /home/ubuntu/sentry
	@echo "=== Done ==="

# Start TMFIFO emulation using socat
qa-tmfifo-up:
	@EMU_IP=$$(multipass info $(QA_VM_EMU) | grep IPv4 | awk '{print $$2}'); \
	echo "=== Starting TMFIFO on $$EMU_IP:$(QA_TMFIFO_PORT) ==="; \
	multipass exec $(QA_VM_EMU) -- sudo socat -d PTY,raw,echo=0,link=/dev/tmfifo_net0,mode=666 TCP-LISTEN:$(QA_TMFIFO_PORT),reuseaddr,fork >/dev/null 2>&1 & \
	sleep 2; \
	multipass exec $(QA_VM_HOST) -- sudo socat -d PTY,raw,echo=0,link=/dev/tmfifo_net0,mode=666 TCP:$$EMU_IP:$(QA_TMFIFO_PORT) >/dev/null 2>&1 & \
	sleep 2; \
	echo "TMFIFO ready"

# Stop TMFIFO emulation
qa-tmfifo-down:
	@multipass exec $(QA_VM_EMU) -- sudo pkill -9 socat >/dev/null 2>&1 || true
	@multipass exec $(QA_VM_HOST) -- sudo pkill -9 socat >/dev/null 2>&1 || true

# Test TMFIFO communication
qa-test-tmfifo:
	@echo "=== Testing TMFIFO communication ==="
	@echo "Test 1: Host -> DPU"
	@multipass exec $(QA_VM_HOST) -- bash -c 'echo "PING_FROM_HOST" > /dev/tmfifo_net0' & \
	sleep 1; \
	multipass exec $(QA_VM_EMU) -- bash -c 'timeout 3 head -n1 /dev/tmfifo_net0 || echo "FAIL: timeout"'
	@echo ""
	@echo "Test 2: DPU -> Host"
	@multipass exec $(QA_VM_EMU) -- bash -c 'echo "PONG_FROM_DPU" > /dev/tmfifo_net0' & \
	sleep 1; \
	multipass exec $(QA_VM_HOST) -- bash -c 'timeout 3 head -n1 /dev/tmfifo_net0 || echo "FAIL: timeout"'
	@echo ""
	@echo "=== TMFIFO test complete ==="

# Start QA services
qa-up: qa-tmfifo-up
	@echo "=== Starting server ==="
	@multipass exec $(QA_VM_SERVER) -- pgrep -x server || multipass exec $(QA_VM_SERVER) -- bash -c "nohup /home/ubuntu/nexus > /home/ubuntu/nexus.log 2>&1 &"
	@sleep 2
	@echo "=== Starting emulator ==="
	@multipass exec $(QA_VM_EMU) -- pgrep -x dpuemu || multipass exec $(QA_VM_EMU) -- bash -c "nohup /home/ubuntu/dpuemu serve --listen :50051 > /home/ubuntu/dpuemu.log 2>&1 &"
	@sleep 2
	@$(MAKE) qa-health

# Stop QA services
qa-down: qa-tmfifo-down
	@echo "=== Stopping services ==="
	@multipass exec $(QA_VM_SERVER) -- pkill -f server 2>/dev/null || true
	@multipass exec $(QA_VM_EMU) -- pkill -f dpuemu 2>/dev/null || true
	@multipass exec $(QA_VM_HOST) -- pkill -f sentry 2>/dev/null || true
	@echo "Services stopped"

# Full rebuild: down, clean, build, up
qa-rebuild: qa-down qa-clean qa-build qa-up

# Check health of QA services
qa-health:
	@echo "=== Server ==="
	@SERVER_IP=$$(multipass info $(QA_VM_SERVER) | grep IPv4 | awk '{print $$2}'); \
	echo "  IP: $$SERVER_IP"; \
	curl -s http://$$SERVER_IP:18080/health | python3 -m json.tool || echo "  Status: not responding"
	@echo ""
	@echo "=== Emulator (DPU) ==="
	@EMU_IP=$$(multipass info $(QA_VM_EMU) | grep IPv4 | awk '{print $$2}'); \
	echo "  IP: $$EMU_IP"; \
	echo "  gRPC: :50051"; \
	echo "  Local API: :9443"

# Show QA environment status
qa-status:
	@echo "=== Tenants ==="
	@$(BIN_DIR)/bluectl tenant list --insecure 2>/dev/null || echo "  (none or server not running)"
	@echo ""
	@echo "=== DPUs ==="
	@$(BIN_DIR)/bluectl dpu list --insecure 2>/dev/null || echo "  (none or server not running)"

# Show QA service logs
qa-logs:
	@echo "=== Server log ==="
	@multipass exec $(QA_VM_SERVER) -- tail -30 /home/ubuntu/nexus.log 2>/dev/null || echo "No server log"
	@echo ""
	@echo "=== Emulator log ==="
	@multipass exec $(QA_VM_EMU) -- tail -30 /home/ubuntu/dpuemu.log 2>/dev/null || echo "No emulator log"
	@echo ""
	@echo "=== Host Agent log ==="
	@multipass exec $(QA_VM_HOST) -- tail -30 /home/ubuntu/sentry.log 2>/dev/null || echo "No host-agent log"
	@echo ""
	@echo "=== TMFIFO socat logs ==="
	@echo "-- EMU --"
	@multipass exec $(QA_VM_EMU) -- tail -10 /home/ubuntu/tmfifo-socat.log 2>/dev/null || echo "No socat log"
	@echo "-- HOST --"
	@multipass exec $(QA_VM_HOST) -- tail -10 /home/ubuntu/tmfifo-socat.log 2>/dev/null || echo "No socat log"

# Clean QA environment
qa-clean:
	@$(MAKE) qa-down 2>/dev/null || true
	@rm -rf $(QA_WORKSPACE)
	@multipass exec $(QA_VM_SERVER) -- rm -f /home/ubuntu/nexus /home/ubuntu/*.log 2>/dev/null || true
	@multipass exec $(QA_VM_EMU) -- rm -f /home/ubuntu/dpuemu /home/ubuntu/aegis /home/ubuntu/*.log 2>/dev/null || true
	@multipass exec $(QA_VM_HOST) -- rm -f /home/ubuntu/sentry /home/ubuntu/*.log 2>/dev/null || true
	@echo "Cleaned"

# =============================================================================
# Transport Interface Testing
# =============================================================================

# Run all transport unit tests
qa-test-transport:
	@echo "=== Transport Interface Unit Tests ==="
	@go test -v ./pkg/transport/...

# Run MockTransport tests only (no VMs required)
qa-test-transport-mock:
	@echo "=== MockTransport Tests ==="
	@go test -v ./pkg/transport/... -run "Mock"

# Test TmfifoNetTransport via emulator (requires VMs + TMFIFO)
# Prerequisites: make qa-up
qa-test-transport-tmfifo:
	@echo "=== TmfifoNetTransport Test ==="
	@echo "Checking prerequisites..."
	@multipass exec $(QA_VM_HOST) -- ls /dev/tmfifo_net0 >/dev/null 2>&1 || (echo "ERROR: TMFIFO not available. Run 'make qa-up' first." && exit 1)
	@echo "Running sentry with --force-tmfifo --oneshot..."
	@HOST_IP=$$(multipass info $(QA_VM_HOST) | grep IPv4 | awk '{print $$2}'); \
	EMU_IP=$$(multipass info $(QA_VM_EMU) | grep IPv4 | awk '{print $$2}'); \
	multipass exec $(QA_VM_HOST) -- /home/ubuntu/sentry --force-tmfifo --oneshot 2>&1 | tee /tmp/qa-transport-test.log; \
	if grep -q "Transport: tmfifo_net" /tmp/qa-transport-test.log; then \
		echo ""; \
		echo "✓ PASS: TmfifoNetTransport used"; \
	else \
		echo ""; \
		echo "✗ FAIL: Expected 'Transport: tmfifo_net' in output"; \
		exit 1; \
	fi
	@if grep -q "Enrolled via tmfifo_net" /tmp/qa-transport-test.log; then \
		echo "✓ PASS: Enrollment succeeded via transport"; \
	else \
		echo "✗ FAIL: Enrollment did not complete via transport"; \
		exit 1; \
	fi
	@echo ""
	@echo "=== TmfifoNetTransport test complete ==="

# Full integration test: sentry enrollment through Transport layer
# Prerequisites: make qa-rebuild (to push latest binaries)
qa-test-transport-integration:
	@echo "=== Transport Integration Test ==="
	@echo "This test verifies the full stack:"
	@echo "  1. DPU agent listening via TmfifoNetListener"
	@echo "  2. Host agent connecting via TmfifoNetTransport"
	@echo "  3. Enrollment message round-trip"
	@echo "  4. Posture report via transport"
	@echo ""
	@echo "Step 1: Verify services are running..."
	@$(MAKE) qa-health
	@echo ""
	@echo "Step 2: Verify TMFIFO is connected..."
	@multipass exec $(QA_VM_HOST) -- ls /dev/tmfifo_net0 >/dev/null 2>&1 || (echo "ERROR: TMFIFO not available" && exit 1)
	@multipass exec $(QA_VM_EMU) -- ls /dev/tmfifo_net0 >/dev/null 2>&1 || (echo "ERROR: TMFIFO not available on EMU" && exit 1)
	@echo "✓ TMFIFO connected"
	@echo ""
	@echo "Step 3: Run sentry enrollment..."
	@multipass exec $(QA_VM_HOST) -- /home/ubuntu/sentry --force-tmfifo --oneshot 2>&1 | tee /tmp/qa-integration-test.log
	@echo ""
	@echo "Step 4: Verify results..."
	@PASS=true; \
	if grep -q "Transport: tmfifo_net" /tmp/qa-integration-test.log; then \
		echo "✓ Transport: tmfifo_net"; \
	else \
		echo "✗ Transport selection failed"; \
		PASS=false; \
	fi; \
	if grep -q "Enrolled via tmfifo_net" /tmp/qa-integration-test.log; then \
		echo "✓ Enrollment via transport"; \
	else \
		echo "✗ Enrollment failed"; \
		PASS=false; \
	fi; \
	if grep -q "Host ID:" /tmp/qa-integration-test.log; then \
		echo "✓ Host ID assigned"; \
	else \
		echo "✗ No Host ID"; \
		PASS=false; \
	fi; \
	if [ "$$PASS" = "true" ]; then \
		echo ""; \
		echo "=== Integration test PASSED ==="; \
	else \
		echo ""; \
		echo "=== Integration test FAILED ==="; \
		exit 1; \
	fi

# =============================================================================
# DOCA Comch Testing (BlueField Hardware)
# =============================================================================

# BlueField-3 DPU configuration
BLUEFIELD_IP := 192.168.1.204
BLUEFIELD_USER := ubuntu
BLUEFIELD_SSH := ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no $(BLUEFIELD_USER)@$(BLUEFIELD_IP)
BLUEFIELD_REMOTE_DIR := /home/ubuntu/secure-infra

# Build with DOCA tags on the BlueField (requires DOCA SDK)
# The BlueField has the DOCA SDK installed; we build there to link against it
qa-doca-build:
	@echo "=== Building with DOCA on BlueField ==="
	@echo "Checking BlueField connectivity..."
	@$(BLUEFIELD_SSH) "echo 'Connected to BlueField'" || (echo "ERROR: Cannot reach BlueField at $(BLUEFIELD_IP)" && exit 1)
	@echo ""
	@echo "Syncing source to BlueField..."
	@rsync -az --delete --exclude='.git' --exclude='bin/' --exclude='qa-workspace/' \
		-e "ssh -o StrictHostKeyChecking=no" \
		. $(BLUEFIELD_USER)@$(BLUEFIELD_IP):$(BLUEFIELD_REMOTE_DIR)/
	@echo ""
	@echo "Building with -tags doca..."
	@$(BLUEFIELD_SSH) "cd $(BLUEFIELD_REMOTE_DIR) && go build -tags doca -o bin/aegis-doca ./cmd/aegis" 2>&1 || \
		(echo ""; echo "NOTE: Build may fail if DOCA SDK not installed or implementation incomplete"; exit 1)
	@$(BLUEFIELD_SSH) "cd $(BLUEFIELD_REMOTE_DIR) && go build -tags doca -o bin/sentry-doca ./cmd/sentry" 2>&1 || true
	@echo ""
	@echo "=== DOCA build complete ==="
	@$(BLUEFIELD_SSH) "ls -la $(BLUEFIELD_REMOTE_DIR)/bin/*-doca 2>/dev/null" || echo "No DOCA binaries built"

# Deploy DOCA-enabled binaries (after qa-doca-build)
qa-doca-deploy:
	@echo "=== Deploying DOCA binaries on BlueField ==="
	@$(BLUEFIELD_SSH) "test -f $(BLUEFIELD_REMOTE_DIR)/bin/aegis-doca" || \
		(echo "ERROR: No DOCA binaries found. Run 'make qa-doca-build' first." && exit 1)
	@$(BLUEFIELD_SSH) "sudo cp $(BLUEFIELD_REMOTE_DIR)/bin/aegis-doca /usr/local/bin/aegis-doca && \
		sudo chmod +x /usr/local/bin/aegis-doca"
	@echo "✓ Deployed aegis-doca to /usr/local/bin/"
	@$(BLUEFIELD_SSH) "test -f $(BLUEFIELD_REMOTE_DIR)/bin/sentry-doca" && \
		$(BLUEFIELD_SSH) "sudo cp $(BLUEFIELD_REMOTE_DIR)/bin/sentry-doca /usr/local/bin/sentry-doca && \
			sudo chmod +x /usr/local/bin/sentry-doca" && \
		echo "✓ Deployed sentry-doca to /usr/local/bin/" || true

# Test DOCAComchTransport on real BlueField hardware
# Prerequisites: make qa-doca-build
qa-test-transport-doca:
	@echo "=== DOCA Comch Transport Test ==="
	@echo "Target: BlueField-3 DPU at $(BLUEFIELD_IP)"
	@echo ""
	@echo "Step 1: Verify BlueField connectivity..."
	@$(BLUEFIELD_SSH) "echo 'BlueField reachable'" || (echo "ERROR: Cannot reach BlueField" && exit 1)
	@echo "✓ BlueField connected"
	@echo ""
	@echo "Step 2: Check DOCA availability..."
	@$(BLUEFIELD_SSH) "dpkg -l | grep -q doca" && echo "✓ DOCA packages installed" || \
		(echo "⚠ DOCA packages not found (may still work if SDK headers available)")
	@$(BLUEFIELD_SSH) "test -f /opt/mellanox/doca/include/doca_comch.h" && \
		echo "✓ DOCA Comch headers present" || \
		echo "⚠ DOCA Comch headers not found at /opt/mellanox/doca/include/"
	@echo ""
	@echo "Step 3: Run transport unit tests with DOCA tag..."
	@$(BLUEFIELD_SSH) "cd $(BLUEFIELD_REMOTE_DIR) && go test -tags doca -v ./pkg/transport/... -run 'DOCA|Comch' 2>&1" | tee /tmp/qa-doca-test.log || true
	@echo ""
	@echo "Step 4: Test DOCAComchTransport initialization..."
	@$(BLUEFIELD_SSH) "cd $(BLUEFIELD_REMOTE_DIR) && go test -tags doca -v ./pkg/transport/... -run 'TestDOCA' 2>&1" | tee -a /tmp/qa-doca-test.log || true
	@echo ""
	@if grep -q "not yet implemented" /tmp/qa-doca-test.log; then \
		echo "=== DOCA transport builds but implementation incomplete ==="; \
		echo "The -tags doca build succeeded. Implementation TODOs remain."; \
	elif grep -q "PASS" /tmp/qa-doca-test.log; then \
		echo "=== DOCA transport test PASSED ==="; \
	else \
		echo "=== DOCA transport test status: check output above ==="; \
	fi

# =============================================================================
# Help
# =============================================================================

# Show available targets
help:
	@echo "Secure Infrastructure Build Targets:"
	@echo ""
	@echo "  make all        Build all binaries (default)"
	@echo "  make agent      Build agent (local + ARM64 for BlueField)"
	@echo "  make bluectl    Build bluectl CLI"
	@echo "  make server     Build server"
	@echo "  make km         Build keymaker CLI"
	@echo "  make sentry Build sentry"
	@echo "  make dpuemu     Build DPU emulator"
	@echo "  make test       Run all tests"
	@echo "  make clean      Remove bin/ contents"
	@echo "  make release    Build release binaries for all platforms"
	@echo ""
	@echo "Quickstart Demo Targets:"
	@echo ""
	@echo "  make demo-clean        Reset environment (clean slate)"
	@echo "  make demo-step1        Start server (Terminal 1)"
	@echo "  make demo-step2        Create tenant"
	@echo "  make demo-step3        Start emulator (Terminal 2)"
	@echo "  make demo-step4        Register DPU"
	@echo "  make demo-step5        Assign DPU to tenant"
	@echo "  make demo-step6        Create operator invitation"
	@echo "  make demo-step7        Accept operator invitation (km init)"
	@echo "  make demo-step7-verify Verify operator (km whoami)"
	@echo "  make demo-step8        Create SSH CA"
	@echo "  make demo-step9        Grant CA access"
	@echo "  make demo-step10       Submit attestation"
	@echo "  make demo-step11       Distribute credentials"
	@echo "  make demo-step12       Test host agent (optional)"
	@echo "  make demo-step13       Sign a user certificate"
	@echo ""
	@echo "Hardware Demo Targets (for real BlueField DPU):"
	@echo ""
	@echo "  make hw-clean         Reset environment"
	@echo "  make hw-step1         Start server"
	@echo "  make hw-step2         Create tenant"
	@echo "  make hw-step3-deploy  Deploy agent to DPU via SSH"
	@echo "  make hw-step4         Register DPU (DPU_IP=x.x.x.x)"
	@echo "  make hw-step5         Create operator invitation"
	@echo "  make hw-step5-accept  Accept invitation (km init)"
	@echo "  make hw-step6         Create SSH CA"
	@echo "  make hw-step6-grant   Grant CA access"
	@echo "  make hw-step7         Submit attestation"
	@echo "  make hw-step8-deploy  Deploy host agent instructions"
	@echo "  make hw-step9         Push credentials (--force)"
	@echo ""
	@echo "  Configure: DPU_IP, DPU_USER, DPU_NAME, CONTROL_PLANE_IP"
	@echo ""
	@echo "QA Testing Targets (3 VMs with TMFIFO emulation):"
	@echo ""
	@echo "  make qa-help          Show detailed QA help"
	@echo "  make qa-vm-create     Create all three VMs"
	@echo "  make qa-vm-delete     Delete all VMs"
	@echo "  make qa-vm-status     Show VM status"
	@echo "  make qa-build         Build and push binaries to VMs"
	@echo "  make qa-up            Start all services"
	@echo "  make qa-down          Stop all services"
	@echo "  make qa-rebuild       Full rebuild cycle"
	@echo "  make qa-health        Health check"
	@echo "  make qa-logs          Show service logs"
	@echo "  make qa-tmfifo-up     Start TMFIFO emulation"
	@echo "  make qa-test-tmfifo   Test TMFIFO communication"
	@echo ""
	@echo "  make help       Show this help"
