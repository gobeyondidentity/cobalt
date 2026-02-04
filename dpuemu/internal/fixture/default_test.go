package fixture

import (
	"testing"

	agentv1 "github.com/gobeyondidentity/cobalt/gen/go/agent/v1"
)

func TestDefaultFixture(t *testing.T) {
	fix := DefaultFixture()

	t.Run("returns non-nil fixture", func(t *testing.T) {
		if fix == nil {
			t.Fatal("DefaultFixture() returned nil")
		}
	})

	t.Run("has expected hostname", func(t *testing.T) {
		if fix.SystemInfo == nil {
			t.Fatal("SystemInfo is nil")
		}
		if fix.SystemInfo.Hostname != "dpuemu-local" {
			t.Errorf("expected hostname 'dpuemu-local', got %q", fix.SystemInfo.Hostname)
		}
	})

	t.Run("has expected model", func(t *testing.T) {
		if fix.SystemInfo.Model != "Emulated BlueField-3" {
			t.Errorf("expected model 'Emulated BlueField-3', got %q", fix.SystemInfo.Model)
		}
	})

	t.Run("has expected serial", func(t *testing.T) {
		if fix.SystemInfo.SerialNumber != "EMU-00000001" {
			t.Errorf("expected serial 'EMU-00000001', got %q", fix.SystemInfo.SerialNumber)
		}
	})

	t.Run("health is healthy", func(t *testing.T) {
		if fix.Health == nil {
			t.Fatal("Health is nil")
		}
		if !fix.Health.Healthy {
			t.Error("expected Health.Healthy to be true")
		}
	})

	t.Run("health has emulator component", func(t *testing.T) {
		comp, ok := fix.Health.Components["emulator"]
		if !ok {
			t.Fatal("emulator component not found")
		}
		if !comp.Healthy {
			t.Error("expected emulator component to be healthy")
		}
	})

	t.Run("attestation is valid", func(t *testing.T) {
		if fix.Attestation == nil {
			t.Fatal("Attestation is nil")
		}
		if fix.Attestation.Status != "ATTESTATION_STATUS_VALID" {
			t.Errorf("expected attestation status VALID, got %q", fix.Attestation.Status)
		}
	})

	t.Run("attestation has DICE certificates", func(t *testing.T) {
		if len(fix.Attestation.Certificates) < 2 {
			t.Errorf("expected at least 2 DICE certificates, got %d", len(fix.Attestation.Certificates))
		}
		// Verify L0 Device Identity cert exists
		var hasL0, hasL1 bool
		for _, cert := range fix.Attestation.Certificates {
			if cert.Level == 0 {
				hasL0 = true
			}
			if cert.Level == 1 {
				hasL1 = true
			}
		}
		if !hasL0 {
			t.Error("expected L0 Device Identity certificate")
		}
		if !hasL1 {
			t.Error("expected L1 Alias certificate")
		}
	})

	t.Run("attestation has measurements", func(t *testing.T) {
		if len(fix.Attestation.Measurements) == 0 {
			t.Error("expected at least one measurement")
		}
		if _, ok := fix.Attestation.Measurements["boot_hash"]; !ok {
			t.Error("expected boot_hash measurement")
		}
	})

	t.Run("metadata indicates default source", func(t *testing.T) {
		if fix.Metadata == nil {
			t.Fatal("Metadata is nil")
		}
		if fix.Metadata["source"] != "default" {
			t.Errorf("expected metadata source 'default', got %q", fix.Metadata["source"])
		}
	})
}

func TestDefaultFixtureConversions(t *testing.T) {
	fix := DefaultFixture()

	t.Run("ToSystemInfoResponse returns valid response", func(t *testing.T) {
		resp := fix.ToSystemInfoResponse()
		if resp == nil {
			t.Fatal("ToSystemInfoResponse returned nil")
		}
		if resp.Hostname != "dpuemu-local" {
			t.Errorf("expected hostname 'dpuemu-local', got %q", resp.Hostname)
		}
	})

	t.Run("ToHealthCheckResponse returns healthy", func(t *testing.T) {
		resp := fix.ToHealthCheckResponse()
		if resp == nil {
			t.Fatal("ToHealthCheckResponse returned nil")
		}
		if !resp.Healthy {
			t.Error("expected healthy response")
		}
	})

	t.Run("ToGetAttestationResponse returns valid with certificates", func(t *testing.T) {
		resp := fix.ToGetAttestationResponse()
		if resp == nil {
			t.Fatal("ToGetAttestationResponse returned nil")
		}
		if resp.Status != agentv1.AttestationStatus_ATTESTATION_STATUS_VALID {
			t.Errorf("expected VALID status, got %v", resp.Status)
		}
		if len(resp.Certificates) < 2 {
			t.Errorf("expected at least 2 DICE certificates, got %d", len(resp.Certificates))
		}
		if len(resp.Measurements) == 0 {
			t.Error("expected at least one measurement")
		}
	})

	t.Run("ToListBridgesResponse returns empty list", func(t *testing.T) {
		resp := fix.ToListBridgesResponse()
		if resp == nil {
			t.Fatal("ToListBridgesResponse returned nil")
		}
		if len(resp.Bridges) != 0 {
			t.Errorf("expected 0 bridges, got %d", len(resp.Bridges))
		}
	})

	t.Run("ToGetFlowsResponse returns empty list", func(t *testing.T) {
		resp := fix.ToGetFlowsResponse("")
		if resp == nil {
			t.Fatal("ToGetFlowsResponse returned nil")
		}
		if len(resp.Flows) != 0 {
			t.Errorf("expected 0 flows, got %d", len(resp.Flows))
		}
	})
}
