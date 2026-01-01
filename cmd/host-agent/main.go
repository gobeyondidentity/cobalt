// Fabric Console Host Agent
// Runs on host machines with DPUs, exposes host system info and GPU status

package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	hostv1 "github.com/beyondidentity/fabric-console/gen/go/host/v1"
	"github.com/beyondidentity/fabric-console/internal/hostagent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	version = "0.1.0"

	listenAddr = flag.String("listen", ":50052", "gRPC listen address")
)

func main() {
	flag.Parse()

	log.Printf("Fabric Console Host Agent v%s starting...", version)

	// Build configuration
	cfg := hostagent.DefaultConfig()
	cfg.ListenAddr = *listenAddr

	// Load config from environment
	if err := cfg.LoadFromEnv(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()
	agentServer := hostagent.NewServer(cfg)
	hostv1.RegisterHostAgentServiceServer(grpcServer, agentServer)

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
	log.Println("Host Agent stopped")
}
