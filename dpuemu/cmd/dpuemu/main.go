// dpuemu is a DPU emulator that implements the same gRPC interface as the real agent.
// It enables development, testing, and demos without physical hardware.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/beyondidentity/fabric-console/dpuemu/internal/fixture"
	"github.com/beyondidentity/fabric-console/dpuemu/internal/server"
	"github.com/spf13/cobra"
)

var (
	// Flags
	listenAddr   string
	fixturePath  string
	instanceID   string
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

Modes:
  serve    Start the emulator server with fixture data

Examples:
  dpuemu serve --fixture=fixtures/bf3-static.json --listen=:50051
  dpuemu serve --fixture=fixtures/bf3-blueman.json --instance-id=001`,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the DPU emulator server",
	Long: `Start the gRPC server that emulates a DPU agent.
The server loads fixture data and responds to gRPC requests with that data.

With --instance-id, template variables in the fixture are replaced:
  {{.InstanceID}}   -> the instance ID
  {{.Hostname}}     -> bf3-emu-{instanceID}
  {{.SerialNumber}} -> MT0000000{instanceID}`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVarP(&listenAddr, "listen", "l", ":50051", "Address to listen on")
	serveCmd.Flags().StringVarP(&fixturePath, "fixture", "f", "", "Path to fixture JSON file")
	serveCmd.Flags().StringVarP(&instanceID, "instance-id", "i", "", "Instance ID for templating")
	serveCmd.MarkFlagRequired("fixture")

	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	// Build template variables
	var vars *fixture.TemplateVars
	if instanceID != "" {
		vars = &fixture.TemplateVars{
			InstanceID:   instanceID,
			Hostname:     fmt.Sprintf("bf3-emu-%s", instanceID),
			SerialNumber: fmt.Sprintf("MT0000000%s", instanceID),
		}
	}

	// Load fixture
	fmt.Printf("Loading fixture from %s\n", fixturePath)
	fix, err := fixture.Load(fixturePath, vars)
	if err != nil {
		return fmt.Errorf("loading fixture: %w", err)
	}

	// Create server
	srv := server.New(server.Config{
		ListenAddr: listenAddr,
		InstanceID: instanceID,
		Fixture:    fix,
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
	return srv.Start(listenAddr)
}
