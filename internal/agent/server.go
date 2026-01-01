// Package agent implements the DPU agent gRPC server.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	agentv1 "github.com/beyondidentity/fabric-console/gen/go/agent/v1"
	"github.com/beyondidentity/fabric-console/pkg/attestation"
	"github.com/beyondidentity/fabric-console/pkg/doca"
	"github.com/beyondidentity/fabric-console/pkg/ovs"
)

var errBMCNotConfigured = errors.New("BMC not configured")

// Server implements the DPUAgentService gRPC interface.
type Server struct {
	agentv1.UnimplementedDPUAgentServiceServer

	config     *Config
	sysCollect *doca.Collector
	invCollect *doca.InventoryCollector
	ovsClient  *ovs.Client
	redfishCli *attestation.RedfishClient

	startTime int64 // Unix timestamp when server started
	version   string
}

// NewServer creates a new agent server.
func NewServer(cfg *Config) *Server {
	var redfishCli *attestation.RedfishClient
	if cfg.BMCAddr != "" {
		redfishCli = attestation.NewRedfishClient(cfg.BMCAddr, cfg.BMCUser, cfg.BMCPassword)
	}

	return &Server{
		config:     cfg,
		sysCollect: doca.NewCollector(),
		invCollect: doca.NewInventoryCollector(),
		ovsClient:  ovs.NewClient(),
		redfishCli: redfishCli,
		startTime:  currentUnixTime(),
		version:    "0.1.0",
	}
}

// GetSystemInfo returns DPU hardware and software information.
func (s *Server) GetSystemInfo(ctx context.Context, req *agentv1.GetSystemInfoRequest) (*agentv1.GetSystemInfoResponse, error) {
	info, err := s.sysCollect.Collect(ctx)
	if err != nil {
		return nil, err
	}

	return &agentv1.GetSystemInfoResponse{
		Hostname:        info.Hostname,
		Model:           info.Model,
		SerialNumber:    info.SerialNumber,
		FirmwareVersion: info.FirmwareVersion,
		DocaVersion:     info.DOCAVersion,
		ArmCores:        int32(info.ARMCores),
		MemoryGb:        int32(info.MemoryGB),
		UptimeSeconds:   info.UptimeSeconds,
		OvsVersion:      info.OVSVersion,
		KernelVersion:   info.KernelVersion,
	}, nil
}

// GetDPUInventory returns detailed firmware and software inventory.
func (s *Server) GetDPUInventory(ctx context.Context, req *agentv1.GetDPUInventoryRequest) (*agentv1.GetDPUInventoryResponse, error) {
	inv, err := s.invCollect.Collect(ctx)
	if err != nil {
		return nil, err
	}

	// Convert firmwares
	var firmwares []*agentv1.FirmwareComponent
	for _, f := range inv.Firmwares {
		firmwares = append(firmwares, &agentv1.FirmwareComponent{
			Name:      f.Name,
			Version:   f.Version,
			BuildDate: f.BuildDate,
		})
	}

	// Add BMC firmware if available via Redfish
	if s.redfishCli != nil {
		if bmcFw, err := s.redfishCli.GetFirmwareInventory(ctx); err == nil {
			for _, f := range bmcFw {
				firmwares = append(firmwares, &agentv1.FirmwareComponent{
					Name:      f.Name,
					Version:   f.Version,
					BuildDate: f.BuildDate,
				})
			}
		}
	}

	// Convert packages
	var packages []*agentv1.InstalledPackage
	for _, p := range inv.Packages {
		packages = append(packages, &agentv1.InstalledPackage{
			Name:    p.Name,
			Version: p.Version,
		})
	}

	// Convert modules
	var modules []*agentv1.KernelModule
	for _, m := range inv.Modules {
		modules = append(modules, &agentv1.KernelModule{
			Name:   m.Name,
			Size:   m.Size,
			UsedBy: int32(m.UsedBy),
		})
	}

	return &agentv1.GetDPUInventoryResponse{
		Firmwares: firmwares,
		Packages:  packages,
		Modules:   modules,
		Boot: &agentv1.BootInfo{
			UefiMode:   inv.Boot.UEFIMode,
			SecureBoot: inv.Boot.SecureBoot,
			BootDevice: inv.Boot.BootDevice,
		},
		OperationMode: inv.OperationMode,
	}, nil
}

// ListBridges returns all OVS bridges configured on the DPU.
func (s *Server) ListBridges(ctx context.Context, req *agentv1.ListBridgesRequest) (*agentv1.ListBridgesResponse, error) {
	bridges, err := s.ovsClient.ListBridges(ctx)
	if err != nil {
		return nil, err
	}

	var result []*agentv1.Bridge
	for _, b := range bridges {
		result = append(result, &agentv1.Bridge{
			Name:  b.Name,
			Ports: b.Ports,
		})
	}

	return &agentv1.ListBridgesResponse{Bridges: result}, nil
}

// GetFlows returns OpenFlow rules for a specific bridge.
func (s *Server) GetFlows(ctx context.Context, req *agentv1.GetFlowsRequest) (*agentv1.GetFlowsResponse, error) {
	bridge := req.GetBridge()
	if bridge == "" {
		bridge = "ovsbr1" // default bridge
	}

	flows, err := s.ovsClient.GetFlows(ctx, bridge)
	if err != nil {
		return nil, err
	}

	var result []*agentv1.Flow
	for _, f := range flows {
		result = append(result, &agentv1.Flow{
			Cookie:   f.Cookie,
			Table:    int32(f.Table),
			Priority: int32(f.Priority),
			Match:    f.Match,
			Actions:  f.Actions,
			Packets:  f.Packets,
			Bytes:    f.Bytes,
			Age:      f.Age,
		})
	}

	return &agentv1.GetFlowsResponse{Flows: result}, nil
}

// GetAttestation returns DICE/SPDM certificates and measurements.
func (s *Server) GetAttestation(ctx context.Context, req *agentv1.GetAttestationRequest) (*agentv1.GetAttestationResponse, error) {
	if s.redfishCli == nil {
		return &agentv1.GetAttestationResponse{
			Status: agentv1.AttestationStatus_ATTESTATION_STATUS_UNAVAILABLE,
		}, nil
	}

	// Determine target (normalize user-friendly names to Redfish resource names)
	target := attestation.NormalizeTarget(req.GetTarget())

	result, err := s.redfishCli.GetCertificateChain(ctx, target)
	if err != nil {
		return &agentv1.GetAttestationResponse{
			Status: agentv1.AttestationStatus_ATTESTATION_STATUS_UNAVAILABLE,
		}, nil
	}

	var certs []*agentv1.Certificate
	for _, c := range result.CertificateChain {
		certs = append(certs, &agentv1.Certificate{
			Level:             int32(c.Level),
			Subject:           c.Subject,
			Issuer:            c.Issuer,
			NotBefore:         c.NotBefore,
			NotAfter:          c.NotAfter,
			Algorithm:         c.Algorithm,
			Pem:               c.PEM,
			FingerprintSha256: c.Fingerprint,
		})
	}

	return &agentv1.GetAttestationResponse{
		Certificates: certs,
		Measurements: result.Measurements,
		Status:       agentv1.AttestationStatus_ATTESTATION_STATUS_VALID,
	}, nil
}

// GetSignedMeasurements returns SPDM signed measurements from the DPU.
func (s *Server) GetSignedMeasurements(ctx context.Context, req *agentv1.GetSignedMeasurementsRequest) (*agentv1.GetSignedMeasurementsResponse, error) {
	if s.redfishCli == nil {
		return nil, errBMCNotConfigured
	}

	// Determine target (normalize user-friendly names to Redfish resource names)
	target := attestation.NormalizeTarget(req.GetTarget())
	if target == "" {
		target = attestation.TargetIRoT
	}

	// Convert indices
	var indices []int
	for _, idx := range req.GetIndices() {
		indices = append(indices, int(idx))
	}

	// Get signed measurements from BMC
	nonce := req.GetNonce()
	if nonce == "" {
		nonce = generateNonce()
	}

	resp, err := s.redfishCli.GetSignedMeasurements(ctx, target, nonce, indices)
	if err != nil {
		return nil, err
	}

	// Parse measurements
	measurements, err := attestation.ParseSPDMMeasurements(resp.SignedMeasurements, resp.HashingAlgorithm)
	if err != nil {
		return nil, err
	}

	var result []*agentv1.Measurement
	for _, m := range measurements {
		result = append(result, &agentv1.Measurement{
			Index:       int32(m.Index),
			Description: m.Description,
			Algorithm:   m.Algorithm,
			Digest:      m.Digest,
		})
	}

	return &agentv1.GetSignedMeasurementsResponse{
		Measurements:     result,
		HashingAlgorithm: resp.HashingAlgorithm,
		SigningAlgorithm: resp.SigningAlgorithm,
		SpdmVersion:      resp.Version,
	}, nil
}

// HealthCheck verifies the agent is running and responsive.
func (s *Server) HealthCheck(ctx context.Context, req *agentv1.HealthCheckRequest) (*agentv1.HealthCheckResponse, error) {
	components := make(map[string]*agentv1.ComponentHealth)

	// Check OVS
	_, ovsErr := s.ovsClient.GetVersion(ctx)
	components["ovs"] = &agentv1.ComponentHealth{
		Healthy: ovsErr == nil,
		Message: errMsg(ovsErr),
	}

	// Check system collector
	_, sysErr := s.sysCollect.Collect(ctx)
	components["system"] = &agentv1.ComponentHealth{
		Healthy: sysErr == nil,
		Message: errMsg(sysErr),
	}

	// Check BMC/Redfish if configured
	if s.redfishCli != nil {
		_, bmcErr := s.redfishCli.GetSPDMIdentity(ctx)
		components["bmc"] = &agentv1.ComponentHealth{
			Healthy: bmcErr == nil,
			Message: errMsg(bmcErr),
		}
	}

	uptime := currentUnixTime() - s.startTime

	return &agentv1.HealthCheckResponse{
		Healthy:       true,
		Version:       s.version,
		UptimeSeconds: uptime,
		Components:    components,
	}, nil
}

func errMsg(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func currentUnixTime() int64 {
	return time.Now().Unix()
}

// generateNonce creates a random 64-character hex string for SPDM freshness
func generateNonce() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
