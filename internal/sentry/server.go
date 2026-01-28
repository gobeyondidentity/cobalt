// Package sentry implements the Host Agent gRPC server.
package sentry

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	hostv1 "github.com/nmelo/secure-infra/gen/go/host/v1"
	"github.com/nmelo/secure-infra/internal/version"
	"github.com/nmelo/secure-infra/pkg/host"
	"github.com/nmelo/secure-infra/pkg/sshscan"
)

// Default paths for SSH key scanning.
const (
	defaultRootSSHPath     = "/root/.ssh/authorized_keys"
	defaultHomeGlobPattern = "/home/*/.ssh/authorized_keys"
)

// Server implements the HostAgentService gRPC interface.
type Server struct {
	hostv1.UnimplementedHostAgentServiceServer

	config    *Config
	collector *host.Collector
	startTime int64
	version   string

	// SSH key scanning paths (configurable for testing)
	rootSSHPath     string
	homeGlobPattern string
}

// NewServer creates a new host agent server.
func NewServer(cfg *Config) *Server {
	return &Server{
		config:          cfg,
		collector:       host.NewCollector(),
		startTime:       time.Now().Unix(),
		version:         version.Version,
		rootSSHPath:     defaultRootSSHPath,
		homeGlobPattern: defaultHomeGlobPattern,
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

// ScanSSHKeys scans authorized_keys files and returns all SSH public keys.
func (s *Server) ScanSSHKeys(ctx context.Context, req *hostv1.ScanSSHKeysRequest) (*hostv1.ScanSSHKeysResponse, error) {
	log.Printf("ScanSSHKeys called")

	var allKeys []*hostv1.SSHKey

	// 1. Scan /root/.ssh/authorized_keys
	keys, err := s.scanAuthorizedKeysFile(s.rootSSHPath)
	if err == nil {
		allKeys = append(allKeys, keys...)
	}

	// 2. Scan /home/*/.ssh/authorized_keys
	matches, err := filepath.Glob(s.homeGlobPattern)
	if err == nil {
		for _, path := range matches {
			keys, err := s.scanAuthorizedKeysFile(path)
			if err == nil {
				allKeys = append(allKeys, keys...)
			}
		}
	}

	return &hostv1.ScanSSHKeysResponse{
		Keys:      allKeys,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// scanAuthorizedKeysFile reads and parses a single authorized_keys file.
func (s *Server) scanAuthorizedKeysFile(filePath string) ([]*hostv1.SSHKey, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	user := sshscan.ExtractUsername(filePath)
	keys, err := sshscan.ParseAuthorizedKeys(string(content), user, filePath)
	if err != nil {
		return nil, err
	}

	// Convert sshscan.SSHKey to hostv1.SSHKey
	var result []*hostv1.SSHKey
	for _, k := range keys {
		result = append(result, &hostv1.SSHKey{
			User:        k.User,
			KeyType:     k.KeyType,
			KeyBits:     int32(k.KeyBits),
			Fingerprint: k.Fingerprint,
			Comment:     k.Comment,
			FilePath:    k.FilePath,
		})
	}

	return result, nil
}
