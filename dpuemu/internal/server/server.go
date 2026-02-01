// Package server provides a gRPC server that emulates a DPU agent.
package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"

	agentv1 "github.com/gobeyondidentity/secure-infra/gen/go/agent/v1"
	"github.com/gobeyondidentity/secure-infra/dpuemu/internal/fixture"
	"github.com/gobeyondidentity/secure-infra/dpuemu/internal/localapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server is a gRPC server that emulates a DPU agent using fixture data.
type Server struct {
	agentv1.UnimplementedDPUAgentServiceServer
	fixture      *fixture.Fixture
	instanceID   string
	listener     net.Listener
	grpcServer   *grpc.Server
	httpServer   *http.Server
	localAPI     *localapi.Server
	localAPIPort int
}

// Config holds server configuration.
type Config struct {
	ListenAddr      string
	InstanceID      string
	Fixture         *fixture.Fixture
	LocalAPIPort    int    // HTTP port for local API (0 to disable)
	ControlPlaneURL string // URL to forward host registrations (empty to disable)
}

// New creates a new emulator server.
func New(cfg Config) *Server {
	s := &Server{
		fixture:      cfg.Fixture,
		instanceID:   cfg.InstanceID,
		localAPIPort: cfg.LocalAPIPort,
	}
	if cfg.LocalAPIPort > 0 {
		s.localAPI = localapi.New(cfg.Fixture, cfg.ControlPlaneURL)
	}
	return s
}

// Start starts the gRPC server and optionally the local HTTP API.
func (s *Server) Start(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = lis

	s.grpcServer = grpc.NewServer()
	agentv1.RegisterDPUAgentServiceServer(s.grpcServer, s)
	reflection.Register(s.grpcServer)

	log.Printf("dpuemu gRPC server listening on %s", addr)
	if s.instanceID != "" {
		log.Printf("instance ID: %s", s.instanceID)
	}
	if s.fixture != nil && s.fixture.SystemInfo != nil {
		log.Printf("emulating: %s (serial: %s)", s.fixture.SystemInfo.Hostname, s.fixture.SystemInfo.SerialNumber)
	}

	// Start local API HTTP server if configured
	if s.localAPI != nil && s.localAPIPort > 0 {
		httpAddr := fmt.Sprintf(":%d", s.localAPIPort)
		s.httpServer = &http.Server{
			Addr:    httpAddr,
			Handler: s.localAPI,
		}
		go func() {
			log.Printf("dpuemu local API listening on %s", httpAddr)
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("local API server error: %v", err)
			}
		}()
	}

	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}

// GetSystemInfo returns hardware and software information about the emulated DPU.
func (s *Server) GetSystemInfo(ctx context.Context, req *agentv1.GetSystemInfoRequest) (*agentv1.GetSystemInfoResponse, error) {
	log.Printf("GetSystemInfo called")
	if s.fixture == nil {
		return &agentv1.GetSystemInfoResponse{
			Hostname: "dpuemu",
			Model:    "Emulated DPU",
		}, nil
	}
	return s.fixture.ToSystemInfoResponse(), nil
}

// ListBridges returns all OVS bridges configured on the emulated DPU.
func (s *Server) ListBridges(ctx context.Context, req *agentv1.ListBridgesRequest) (*agentv1.ListBridgesResponse, error) {
	log.Printf("ListBridges called")
	if s.fixture == nil {
		return &agentv1.ListBridgesResponse{}, nil
	}
	return s.fixture.ToListBridgesResponse(), nil
}

// GetFlows returns OpenFlow rules for a specific bridge.
func (s *Server) GetFlows(ctx context.Context, req *agentv1.GetFlowsRequest) (*agentv1.GetFlowsResponse, error) {
	log.Printf("GetFlows called for bridge: %s", req.Bridge)
	if s.fixture == nil {
		return &agentv1.GetFlowsResponse{}, nil
	}
	return s.fixture.ToGetFlowsResponse(req.Bridge), nil
}

// GetAttestation returns DICE/SPDM certificates and measurements.
func (s *Server) GetAttestation(ctx context.Context, req *agentv1.GetAttestationRequest) (*agentv1.GetAttestationResponse, error) {
	log.Printf("GetAttestation called")
	if s.fixture == nil {
		return &agentv1.GetAttestationResponse{
			Status: agentv1.AttestationStatus_ATTESTATION_STATUS_UNAVAILABLE,
		}, nil
	}
	return s.fixture.ToGetAttestationResponse(), nil
}

// HealthCheck verifies the emulator is running and responsive.
func (s *Server) HealthCheck(ctx context.Context, req *agentv1.HealthCheckRequest) (*agentv1.HealthCheckResponse, error) {
	var resp *agentv1.HealthCheckResponse
	if s.fixture == nil {
		resp = &agentv1.HealthCheckResponse{
			Healthy: true,
			Version: "dpuemu-0.2.0",
		}
	} else {
		resp = s.fixture.ToHealthCheckResponse()
	}

	// Log health status
	status := "SERVING"
	if !resp.Healthy {
		status = "NOT_SERVING"
	}
	log.Printf("HealthCheck: status=%s", status)

	// Log component health if verbose (components exist)
	if len(resp.Components) > 0 {
		for name, comp := range resp.Components {
			compStatus := "healthy"
			if !comp.Healthy {
				compStatus = "unhealthy"
			}
			log.Printf("  component %s: %s", name, compStatus)
		}
	}

	return resp, nil
}

// DistributeCredential simulates deploying a credential to the host via the DPU.
func (s *Server) DistributeCredential(ctx context.Context, req *agentv1.DistributeCredentialRequest) (*agentv1.DistributeCredentialResponse, error) {
	log.Printf("DistributeCredential called: type=%s, name=%s, key_len=%d",
		req.GetCredentialType(), req.GetCredentialName(), len(req.GetPublicKey()))

	// Emulator always succeeds
	return &agentv1.DistributeCredentialResponse{
		Success:       true,
		Message:       fmt.Sprintf("Emulated distribution of %s", req.GetCredentialName()),
		InstalledPath: fmt.Sprintf("/etc/ssh/trusted-user-ca-keys.d/%s.pub", req.GetCredentialName()),
		SshdReloaded:  true,
	}, nil
}
