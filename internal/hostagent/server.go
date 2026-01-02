// Package hostagent implements the Host Agent gRPC server.
package hostagent

import (
	"context"
	"log"
	"time"

	hostv1 "github.com/nmelo/secure-infra/gen/go/host/v1"
	"github.com/nmelo/secure-infra/pkg/host"
)

// Server implements the HostAgentService gRPC interface.
type Server struct {
	hostv1.UnimplementedHostAgentServiceServer

	config    *Config
	collector *host.Collector
	startTime int64
	version   string
}

// NewServer creates a new host agent server.
func NewServer(cfg *Config) *Server {
	return &Server{
		config:    cfg,
		collector: host.NewCollector(),
		startTime: time.Now().Unix(),
		version:   "0.1.0",
	}
}

// GetHostInfo returns basic information about the host machine.
func (s *Server) GetHostInfo(ctx context.Context, req *hostv1.GetHostInfoRequest) (*hostv1.GetHostInfoResponse, error) {
	log.Printf("GetHostInfo called")
	info, err := s.collector.CollectHostInfo(ctx)
	if err != nil {
		return nil, err
	}

	return &hostv1.GetHostInfoResponse{
		Hostname:      info.Hostname,
		OsName:        info.OSName,
		OsVersion:     info.OSVersion,
		KernelVersion: info.KernelVersion,
		Architecture:  info.Architecture,
		CpuCores:      int32(info.CPUCores),
		MemoryGb:      info.MemoryGB,
		UptimeSeconds: info.UptimeSeconds,
	}, nil
}

// GetGPUInfo returns information about GPUs installed on the host.
func (s *Server) GetGPUInfo(ctx context.Context, req *hostv1.GetGPUInfoRequest) (*hostv1.GetGPUInfoResponse, error) {
	log.Printf("GetGPUInfo called")
	gpus, err := s.collector.CollectGPUInfo(ctx)
	if err != nil {
		return nil, err
	}

	var result []*hostv1.GPU
	for _, g := range gpus {
		result = append(result, &hostv1.GPU{
			Index:          int32(g.Index),
			Name:           g.Name,
			Uuid:           g.UUID,
			DriverVersion:  g.DriverVersion,
			CudaVersion:    g.CUDAVersion,
			MemoryMb:       g.MemoryMB,
			TemperatureC:   int32(g.TemperatureC),
			PowerUsageW:    int32(g.PowerUsageW),
			UtilizationPct: int32(g.UtilizationPct),
		})
	}

	return &hostv1.GetGPUInfoResponse{Gpus: result}, nil
}

// GetSecurityInfo returns security posture of the host.
func (s *Server) GetSecurityInfo(ctx context.Context, req *hostv1.GetSecurityInfoRequest) (*hostv1.GetSecurityInfoResponse, error) {
	log.Printf("GetSecurityInfo called")
	info, err := s.collector.CollectSecurityInfo(ctx)
	if err != nil {
		return nil, err
	}

	return &hostv1.GetSecurityInfoResponse{
		SecureBootEnabled: info.SecureBootEnabled,
		TpmPresent:        info.TPMPresent,
		TpmVersion:        info.TPMVersion,
		UefiMode:          info.UEFIMode,
		FirewallStatus:    info.FirewallStatus,
		SelinuxStatus:     info.SELinuxStatus,
	}, nil
}

// GetDPUConnections returns info about DPUs connected to this host.
func (s *Server) GetDPUConnections(ctx context.Context, req *hostv1.GetDPUConnectionsRequest) (*hostv1.GetDPUConnectionsResponse, error) {
	log.Printf("GetDPUConnections called")
	connections, err := s.collector.CollectDPUConnections(ctx)
	if err != nil {
		return nil, err
	}

	var result []*hostv1.DPUConnection
	for _, c := range connections {
		result = append(result, &hostv1.DPUConnection{
			Name:        c.Name,
			PciAddress:  c.PCIAddress,
			RshimDevice: c.RShimDevice,
			MacAddress:  c.MACAddress,
			Connected:   c.Connected,
		})
	}

	return &hostv1.GetDPUConnectionsResponse{Dpus: result}, nil
}

// HealthCheck verifies the host agent is running and responsive.
func (s *Server) HealthCheck(ctx context.Context, req *hostv1.HealthCheckRequest) (*hostv1.HealthCheckResponse, error) {
	log.Printf("HealthCheck called")
	uptime := time.Now().Unix() - s.startTime

	components := make(map[string]*hostv1.ComponentHealth)

	// Check GPU availability
	gpus, _ := s.collector.CollectGPUInfo(ctx)
	if len(gpus) > 0 {
		components["nvidia-smi"] = &hostv1.ComponentHealth{
			Healthy: true,
			Message: "NVIDIA driver available",
		}
	} else {
		components["nvidia-smi"] = &hostv1.ComponentHealth{
			Healthy: true,
			Message: "No NVIDIA GPUs detected",
		}
	}

	// Check host info collection
	if _, err := s.collector.CollectHostInfo(ctx); err == nil {
		components["host-info"] = &hostv1.ComponentHealth{
			Healthy: true,
			Message: "Host info collection working",
		}
	} else {
		components["host-info"] = &hostv1.ComponentHealth{
			Healthy: false,
			Message: err.Error(),
		}
	}

	return &hostv1.HealthCheckResponse{
		Healthy:       true,
		Version:       s.version,
		UptimeSeconds: uptime,
		Components:    components,
	}, nil
}
