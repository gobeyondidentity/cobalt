// Package server provides a gRPC server that emulates a DPU agent.
package server

import (
	"context"
	"fmt"
	"log"
	"net"

	agentv1 "github.com/beyondidentity/fabric-console/gen/go/agent/v1"
	"github.com/beyondidentity/fabric-console/dpuemu/internal/fixture"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server is a gRPC server that emulates a DPU agent using fixture data.
type Server struct {
	agentv1.UnimplementedDPUAgentServiceServer
	fixture    *fixture.Fixture
	instanceID string
	listener   net.Listener
	grpcServer *grpc.Server
}

// Config holds server configuration.
type Config struct {
	ListenAddr string
	InstanceID string
	Fixture    *fixture.Fixture
}

// New creates a new emulator server.
func New(cfg Config) *Server {
	return &Server{
		fixture:    cfg.Fixture,
		instanceID: cfg.InstanceID,
	}
}

// Start starts the gRPC server.
func (s *Server) Start(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = lis

	s.grpcServer = grpc.NewServer()
	agentv1.RegisterDPUAgentServiceServer(s.grpcServer, s)
	reflection.Register(s.grpcServer)

	log.Printf("dpuemu server listening on %s", addr)
	if s.instanceID != "" {
		log.Printf("instance ID: %s", s.instanceID)
	}
	if s.fixture != nil && s.fixture.SystemInfo != nil {
		log.Printf("emulating: %s (serial: %s)", s.fixture.SystemInfo.Hostname, s.fixture.SystemInfo.SerialNumber)
	}

	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
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
	log.Printf("HealthCheck called")
	if s.fixture == nil {
		return &agentv1.HealthCheckResponse{
			Healthy: true,
			Version: "dpuemu-0.1.0",
		}, nil
	}
	return s.fixture.ToHealthCheckResponse(), nil
}
