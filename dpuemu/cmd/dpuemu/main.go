// dpuemu is a DPU emulator that implements the same gRPC interface as the real agent.
// It enables development, testing, and demos without physical hardware.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nmelo/secure-infra/dpuemu/internal/fixture"
	"github.com/nmelo/secure-infra/dpuemu/internal/portutil"
	"github.com/nmelo/secure-infra/dpuemu/internal/server"
	"github.com/spf13/cobra"
)

var (
	// Flags
	listenAddr      string
	port            int
	fixturePath     string
	instanceID      string
	localAPIPort    int
	controlPlaneURL string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "dpuemu",
	Short: "DPU emulator for development and testing",
	Long: `dpuemu emulates a BlueField DPU agent, enabling development and testing
without physical hardware. It implements the same gRPC interface as the real agent.

Quick start:
  dpuemu serve --port 50052

Commands:
  serve    Start the emulator server

Examples:
  dpuemu serve                                      # Uses default fixture, port 50051
  dpuemu serve --port 50052                         # Custom port with default fixture
  dpuemu serve --fixture=fixtures/bf3-static.json  # Custom fixture file
  dpuemu serve --listen=:50051                      # Alternative port syntax
  dpuemu serve --fixture=fixtures/bf3-blueman.json --instance-id=001`,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the DPU emulator server",
	Long: `Start the gRPC server that emulates a DPU agent.

If no fixture is specified, a default fixture is used with:
  Hostname: dpuemu-local
  Model:    Emulated BlueField-3
  Serial:   EMU-00000001
  Status:   healthy

Port can be specified as:
  --port 50052       # Port number only
  --listen :50052    # Address format (alternative)
  --listen 0.0.0.0:50052  # Bind to specific interface

If both --port and --listen are provided, --port takes precedence.

With --instance-id, template variables in the fixture are replaced:
  {{.InstanceID}}   -> the instance ID
  {{.Hostname}}     -> bf3-emu-{instanceID}
  {{.SerialNumber}} -> MT0000000{instanceID}

Local API:
  --local-api-port 9443    # Enable HTTP API for host-agent communication

The local API exposes endpoints for host-agent registration and posture:
  POST /local/v1/register  - Host registration
  POST /local/v1/posture   - Posture reports
  POST /local/v1/cert      - Host certificate requests

Control Plane Integration:
  --control-plane http://localhost:8080  # Forward registrations to control plane`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVarP(&listenAddr, "listen", "l", "", "Address to listen on (e.g., :50051 or 0.0.0.0:50051)")
	serveCmd.Flags().IntVarP(&port, "port", "p", 0, "Port to listen on (takes precedence over --listen)")
	serveCmd.Flags().StringVarP(&fixturePath, "fixture", "f", "", "Path to fixture JSON file (optional, uses defaults if not set)")
	serveCmd.Flags().StringVarP(&instanceID, "instance-id", "i", "", "Instance ID for templating")
	serveCmd.Flags().IntVar(&localAPIPort, "local-api-port", 9443, "HTTP port for local API (host-agent communication)")
	serveCmd.Flags().StringVar(&controlPlaneURL, "control-plane", "", "Control plane URL to forward host registrations (e.g., http://localhost:8080)")

	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	// Resolve listen address from --port and --listen flags
	addr, err := portutil.ResolvePort(port, listenAddr)
	if err != nil {
		return fmt.Errorf("invalid port configuration: %w", err)
	}

	// Build template variables
	var vars *fixture.TemplateVars
	if instanceID != "" {
		vars = &fixture.TemplateVars{
			InstanceID:   instanceID,
			Hostname:     fmt.Sprintf("bf3-emu-%s", instanceID),
			SerialNumber: fmt.Sprintf("MT0000000%s", instanceID),
		}
	}

	// Load fixture or use default
	var fix *fixture.Fixture
	if fixturePath != "" {
		fmt.Printf("Loading fixture from %s\n", fixturePath)
		fix, err = fixture.Load(fixturePath, vars)
		if err != nil {
			return fmt.Errorf("loading fixture: %w", err)
		}
	} else {
		fmt.Println("Using default fixture (no --fixture specified)")
		fix = fixture.DefaultFixture()
	}

	// Create server
	srv := server.New(server.Config{
		ListenAddr:      addr,
		InstanceID:      instanceID,
		Fixture:         fix,
		LocalAPIPort:    localAPIPort,
		ControlPlaneURL: controlPlaneURL,
	})

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		srv.Stop()
	}()

	// Start server
	return srv.Start(addr)
}
