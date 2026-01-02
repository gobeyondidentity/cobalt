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
	"time"

	agentv1 "github.com/nmelo/secure-infra/gen/go/agent/v1"
	"github.com/nmelo/secure-infra/internal/agent"
	"github.com/nmelo/secure-infra/internal/agent/localapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

var (
	version = "0.1.0"

	listenAddr      = flag.String("listen", ":50051", "gRPC listen address")
	bmcAddr         = flag.String("bmc-addr", "", "BMC address for Redfish API (optional)")
	bmcUser         = flag.String("bmc-user", "root", "BMC username")
	localAPIEnabled = flag.Bool("local-api", false, "Enable local HTTP API for Host Agent")
	localListen     = flag.String("local-listen", "localhost:9443", "Local API listen address")
	controlPlane    = flag.String("control-plane", "", "Control Plane URL (required if local API enabled)")
	dpuName         = flag.String("dpu-name", "", "DPU name for registration (required if local API enabled)")
)

func main() {
	flag.Parse()

	log.Printf("Fabric Console Agent v%s starting...", version)

	// Build configuration
	cfg := agent.DefaultConfig()
	cfg.ListenAddr = *listenAddr
	cfg.BMCAddr = *bmcAddr
	cfg.BMCUser = *bmcUser
	cfg.LocalAPIEnabled = *localAPIEnabled
	cfg.LocalAPIAddr = *localListen
	cfg.ControlPlaneURL = *controlPlane
	cfg.DPUName = *dpuName

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

	// Register standard gRPC health service for grpc-health-probe and Kubernetes health checks
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

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

	// Start local API server if enabled
	var localServer *localapi.Server
	if cfg.LocalAPIEnabled {
		localServer, err = startLocalAPI(ctx, cfg, agentServer)
		if err != nil {
			log.Fatalf("Failed to start local API: %v", err)
		}
	}

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)

		// Shutdown local API server first
		if localServer != nil {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := localServer.Stop(shutdownCtx); err != nil {
				log.Printf("Local API shutdown error: %v", err)
			}
		}

		grpcServer.GracefulStop()
		cancel()
	}()

	// Serve gRPC
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("gRPC server error: %v", err)
	}

	<-ctx.Done()
	log.Println("Agent stopped")
}

// startLocalAPI initializes and starts the local HTTP API server.
func startLocalAPI(ctx context.Context, cfg *agent.Config, agentServer *agent.Server) (*localapi.Server, error) {
	log.Printf("Starting local API for Host Agent communication...")

	localCfg := &localapi.Config{
		ListenAddr:       cfg.LocalAPIAddr,
		ControlPlaneURL:  cfg.ControlPlaneURL,
		DPUName:          cfg.DPUName,
		DPUID:            cfg.DPUID,
		DPUSerial:        cfg.DPUSerial,
		AllowedHostnames: cfg.AllowedHostnames,
		AttestationFetcher: func(ctx context.Context) (*localapi.AttestationInfo, error) {
			return fetchAttestation(ctx, agentServer)
		},
	}

	server, err := localapi.NewServer(localCfg)
	if err != nil {
		return nil, err
	}

	if err := server.Start(); err != nil {
		return nil, err
	}

	log.Printf("Local API enabled: %s", cfg.LocalAPIAddr)
	log.Printf("Control Plane: %s", cfg.ControlPlaneURL)
	log.Printf("DPU Name: %s", cfg.DPUName)

	return server, nil
}

// fetchAttestation retrieves the current DPU attestation status.
func fetchAttestation(ctx context.Context, agentServer *agent.Server) (*localapi.AttestationInfo, error) {
	resp, err := agentServer.GetAttestation(ctx, &agentv1.GetAttestationRequest{
		Target: "irot", // Use internal Root of Trust
	})
	if err != nil {
		return &localapi.AttestationInfo{
			Status:      "unavailable",
			LastChecked: time.Now(),
		}, nil
	}

	var status string
	switch resp.Status {
	case agentv1.AttestationStatus_ATTESTATION_STATUS_VALID:
		status = "valid"
	case agentv1.AttestationStatus_ATTESTATION_STATUS_INVALID:
		status = "invalid"
	default:
		status = "unavailable"
	}

	var measurements []string
	for _, cert := range resp.Certificates {
		if cert.FingerprintSha256 != "" {
			measurements = append(measurements, cert.FingerprintSha256)
		}
	}

	return &localapi.AttestationInfo{
		Status:       status,
		Measurements: measurements,
		LastChecked:  time.Now(),
	}, nil
}
