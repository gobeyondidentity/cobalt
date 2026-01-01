// Fabric Console DPU Agent
// Runs on BlueField DPU ARM cores, exposes system info, OVS, and attestation APIs

package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	agentv1 "github.com/beyondidentity/fabric-console/gen/go/agent/v1"
	"github.com/beyondidentity/fabric-console/internal/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	version = "0.1.0"

	listenAddr = flag.String("listen", ":50051", "gRPC listen address")
	bmcAddr    = flag.String("bmc-addr", "", "BMC address for Redfish API (optional)")
	bmcUser    = flag.String("bmc-user", "root", "BMC username")
)

func main() {
	flag.Parse()

	log.Printf("Fabric Console Agent v%s starting...", version)

	// Build configuration
	cfg := agent.DefaultConfig()
	cfg.ListenAddr = *listenAddr
	cfg.BMCAddr = *bmcAddr
	cfg.BMCUser = *bmcUser

	// Load sensitive config from environment
	if err := cfg.LoadFromEnv(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()
	agentServer := agent.NewServer(cfg)
	agentv1.RegisterDPUAgentServiceServer(grpcServer, agentServer)

	// Enable reflection for grpcurl
	reflection.Register(grpcServer)

	// Start listening
	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
	}

	log.Printf("gRPC server listening on %s", cfg.ListenAddr)

	// Handle shutdown gracefully
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		grpcServer.GracefulStop()
		cancel()
	}()

	// Serve
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("gRPC server error: %v", err)
	}

	<-ctx.Done()
	log.Println("Agent stopped")
}
