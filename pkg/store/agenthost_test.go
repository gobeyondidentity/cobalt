package store

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestHostRegistration(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "agenthost_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	store, err := Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	t.Run("RegisterAgentHost_New", func(t *testing.T) {
		h := &AgentHost{
			DPUName:  "bf3-lab-01",
			DPUID:    "dpu_abc12345",
			Hostname: "workstation-01",
			TenantID: "tenant_xyz",
		}

		err := store.RegisterAgentHost(h)
		if err != nil {
			t.Fatalf("RegisterAgentHost failed: %v", err)
		}

		// Verify ID was generated
		if !strings.HasPrefix(h.ID, "host_") {
			t.Errorf("ID should start with 'host_', got %q", h.ID)
		}
		if len(h.ID) != 13 { // "host_" + 8 chars
			t.Errorf("ID length should be 13, got %d", len(h.ID))
		}

		// Verify timestamps were set
		if h.RegisteredAt.IsZero() {
			t.Error("RegisteredAt should be set")
		}
		if h.LastSeenAt.IsZero() {
			t.Error("LastSeenAt should be set")
		}
	})

	t.Run("RegisterAgentHost_DuplicateHostname", func(t *testing.T) {
		h := &AgentHost{
			DPUName:  "bf3-lab-02",
			DPUID:    "dpu_def67890",
			Hostname: "workstation-01", // Same hostname as above
			TenantID: "tenant_xyz",
		}

		err := store.RegisterAgentHost(h)
		if err == nil {
			t.Error("RegisterAgentHost should fail for duplicate hostname")
		}
	})

	t.Run("GetAgentHost", func(t *testing.T) {
		// First, register a host we can look up
		h := &AgentHost{
			DPUName:  "bf3-lab-03",
			DPUID:    "dpu_ghi11111",
			Hostname: "workstation-02",
			TenantID: "tenant_abc",
		}
		store.RegisterAgentHost(h)

		retrieved, err := store.GetAgentHost(h.ID)
		if err != nil {
			t.Fatalf("GetAgentHost failed: %v", err)
		}

		if retrieved.DPUName != "bf3-lab-03" {
			t.Errorf("DPUName = %q, want %q", retrieved.DPUName, "bf3-lab-03")
		}
		if retrieved.DPUID != "dpu_ghi11111" {
			t.Errorf("DPUID = %q, want %q", retrieved.DPUID, "dpu_ghi11111")
		}
		if retrieved.Hostname != "workstation-02" {
			t.Errorf("Hostname = %q, want %q", retrieved.Hostname, "workstation-02")
		}
		if retrieved.TenantID != "tenant_abc" {
			t.Errorf("TenantID = %q, want %q", retrieved.TenantID, "tenant_abc")
		}
	})

	t.Run("GetAgentHost_NotFound", func(t *testing.T) {
		_, err := store.GetAgentHost("host_nonexist")
		if err == nil {
			t.Error("GetAgentHost should fail for nonexistent host")
		}
	})

	t.Run("GetAgentHostByHostname", func(t *testing.T) {
		retrieved, err := store.GetAgentHostByHostname("workstation-02")
		if err != nil {
			t.Fatalf("GetAgentHostByHostname failed: %v", err)
		}

		if retrieved.DPUName != "bf3-lab-03" {
			t.Errorf("DPUName = %q, want %q", retrieved.DPUName, "bf3-lab-03")
		}
	})

	t.Run("UpdateAgentHostLastSeen", func(t *testing.T) {
		h, _ := store.GetAgentHostByHostname("workstation-02")

		err := store.UpdateAgentHostLastSeen(h.ID)
		if err != nil {
			t.Fatalf("UpdateAgentHostLastSeen failed: %v", err)
		}

		updated, _ := store.GetAgentHost(h.ID)
		// Verify the timestamp is recent (within last 5 seconds)
		if time.Since(updated.LastSeenAt) > 5*time.Second {
			t.Error("LastSeenAt should be within the last 5 seconds")
		}
		// Verify it's at least as recent as the original
		if updated.LastSeenAt.Before(h.LastSeenAt) {
			t.Error("LastSeenAt should not be before original time")
		}
	})

	t.Run("UpdateAgentHostLastSeen_NotFound", func(t *testing.T) {
		err := store.UpdateAgentHostLastSeen("host_nonexist")
		if err == nil {
			t.Error("UpdateAgentHostLastSeen should fail for nonexistent host")
		}
	})

	t.Run("DeleteAgentHost", func(t *testing.T) {
		h := &AgentHost{
			DPUName:  "bf3-delete-test",
			DPUID:    "dpu_del12345",
			Hostname: "workstation-delete",
		}
		store.RegisterAgentHost(h)

		err := store.DeleteAgentHost(h.ID)
		if err != nil {
			t.Fatalf("DeleteAgentHost failed: %v", err)
		}

		_, err = store.GetAgentHost(h.ID)
		if err == nil {
			t.Error("Host should not exist after deletion")
		}
	})

	t.Run("DeleteAgentHost_NotFound", func(t *testing.T) {
		err := store.DeleteAgentHost("host_nonexist")
		if err == nil {
			t.Error("DeleteAgentHost should fail for nonexistent host")
		}
	})
}

func TestHostByDPU(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "agenthost_dpu_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	store, err := Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Register a host
	h := &AgentHost{
		DPUName:  "bf3-unique-dpu",
		DPUID:    "dpu_unique123",
		Hostname: "host-linked-to-dpu",
		TenantID: "tenant_test",
	}
	store.RegisterAgentHost(h)

	t.Run("GetAgentHostByDPU_Found", func(t *testing.T) {
		retrieved, err := store.GetAgentHostByDPU("bf3-unique-dpu")
		if err != nil {
			t.Fatalf("GetAgentHostByDPU failed: %v", err)
		}

		if retrieved.ID != h.ID {
			t.Errorf("ID = %q, want %q", retrieved.ID, h.ID)
		}
		if retrieved.Hostname != "host-linked-to-dpu" {
			t.Errorf("Hostname = %q, want %q", retrieved.Hostname, "host-linked-to-dpu")
		}
	})

	t.Run("GetAgentHostByDPU_NotFound", func(t *testing.T) {
		_, err := store.GetAgentHostByDPU("nonexistent-dpu")
		if err == nil {
			t.Error("GetAgentHostByDPU should fail for nonexistent DPU")
		}
	})
}

func TestHostPostureUpdate(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "agenthost_posture_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	store, err := Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Register a host first
	h := &AgentHost{
		DPUName:  "bf3-posture-test",
		DPUID:    "dpu_posture123",
		Hostname: "posture-host",
		TenantID: "tenant_posture",
	}
	store.RegisterAgentHost(h)

	t.Run("UpdateAgentHostPosture_New", func(t *testing.T) {
		secureBoot := true
		tpmPresent := true

		p := &AgentHostPosture{
			HostID:         h.ID,
			SecureBoot:     &secureBoot,
			DiskEncryption: "luks",
			OSVersion:      "Ubuntu 24.04 LTS",
			KernelVersion:  "6.8.0-generic",
			TPMPresent:     &tpmPresent,
			PostureHash:    "sha256_abc123def456",
		}

		err := store.UpdateAgentHostPosture(p)
		if err != nil {
			t.Fatalf("UpdateAgentHostPosture failed: %v", err)
		}
	})

	t.Run("GetAgentHostPosture", func(t *testing.T) {
		p, err := store.GetAgentHostPosture(h.ID)
		if err != nil {
			t.Fatalf("GetAgentHostPosture failed: %v", err)
		}

		if p.SecureBoot == nil || !*p.SecureBoot {
			t.Error("SecureBoot should be true")
		}
		if p.DiskEncryption != "luks" {
			t.Errorf("DiskEncryption = %q, want %q", p.DiskEncryption, "luks")
		}
		if p.OSVersion != "Ubuntu 24.04 LTS" {
			t.Errorf("OSVersion = %q, want %q", p.OSVersion, "Ubuntu 24.04 LTS")
		}
		if p.KernelVersion != "6.8.0-generic" {
			t.Errorf("KernelVersion = %q, want %q", p.KernelVersion, "6.8.0-generic")
		}
		if p.TPMPresent == nil || !*p.TPMPresent {
			t.Error("TPMPresent should be true")
		}
		if p.PostureHash != "sha256_abc123def456" {
			t.Errorf("PostureHash = %q, want %q", p.PostureHash, "sha256_abc123def456")
		}
		if p.CollectedAt.IsZero() {
			t.Error("CollectedAt should be set")
		}
	})

	t.Run("UpdateAgentHostPosture_Update", func(t *testing.T) {
		secureBoot := false
		tpmPresent := false

		p := &AgentHostPosture{
			HostID:         h.ID,
			SecureBoot:     &secureBoot,
			DiskEncryption: "filevault",
			OSVersion:      "macOS 15.0",
			KernelVersion:  "24.0.0",
			TPMPresent:     &tpmPresent,
			PostureHash:    "sha256_newposturehash",
		}

		err := store.UpdateAgentHostPosture(p)
		if err != nil {
			t.Fatalf("UpdateAgentHostPosture update failed: %v", err)
		}

		// Verify the update
		retrieved, err := store.GetAgentHostPosture(h.ID)
		if err != nil {
			t.Fatalf("GetAgentHostPosture after update failed: %v", err)
		}

		if retrieved.SecureBoot == nil || *retrieved.SecureBoot {
			t.Error("SecureBoot should be false after update")
		}
		if retrieved.DiskEncryption != "filevault" {
			t.Errorf("DiskEncryption = %q, want %q", retrieved.DiskEncryption, "filevault")
		}
		if retrieved.PostureHash != "sha256_newposturehash" {
			t.Errorf("PostureHash = %q, want %q", retrieved.PostureHash, "sha256_newposturehash")
		}
	})

	t.Run("UpdateAgentHostPosture_NilBooleans", func(t *testing.T) {
		// Register another host for nil boolean test
		h2 := &AgentHost{
			DPUName:  "bf3-nil-test",
			DPUID:    "dpu_nil123",
			Hostname: "nil-bool-host",
		}
		store.RegisterAgentHost(h2)

		p := &AgentHostPosture{
			HostID:         h2.ID,
			SecureBoot:     nil, // Unknown
			DiskEncryption: "none",
			OSVersion:      "Windows 11",
			TPMPresent:     nil, // Unknown
		}

		err := store.UpdateAgentHostPosture(p)
		if err != nil {
			t.Fatalf("UpdateAgentHostPosture with nil booleans failed: %v", err)
		}

		retrieved, err := store.GetAgentHostPosture(h2.ID)
		if err != nil {
			t.Fatalf("GetAgentHostPosture failed: %v", err)
		}

		if retrieved.SecureBoot != nil {
			t.Error("SecureBoot should be nil (unknown)")
		}
		if retrieved.TPMPresent != nil {
			t.Error("TPMPresent should be nil (unknown)")
		}
	})

	t.Run("GetAgentHostPosture_NotFound", func(t *testing.T) {
		_, err := store.GetAgentHostPosture("host_nonexist")
		if err == nil {
			t.Error("GetAgentHostPosture should fail for nonexistent host")
		}
	})

	t.Run("DeleteHost_CascadesPosture", func(t *testing.T) {
		// Register a host with posture, then delete it
		hCascade := &AgentHost{
			DPUName:  "bf3-cascade-test",
			DPUID:    "dpu_cascade123",
			Hostname: "cascade-host",
		}
		store.RegisterAgentHost(hCascade)

		secureBoot := true
		p := &AgentHostPosture{
			HostID:     hCascade.ID,
			SecureBoot: &secureBoot,
		}
		store.UpdateAgentHostPosture(p)

		// Delete the host
		err := store.DeleteAgentHost(hCascade.ID)
		if err != nil {
			t.Fatalf("DeleteAgentHost failed: %v", err)
		}

		// Posture should also be gone
		_, err = store.GetAgentHostPosture(hCascade.ID)
		if err == nil {
			t.Error("Posture should be deleted when host is deleted (cascade)")
		}
	})
}

func TestListHostsByTenant(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "agenthost_tenant_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	store, err := Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// Register hosts in different tenants
	hosts := []AgentHost{
		{DPUName: "dpu-a1", DPUID: "id_a1", Hostname: "host-a1", TenantID: "tenant_a"},
		{DPUName: "dpu-a2", DPUID: "id_a2", Hostname: "host-a2", TenantID: "tenant_a"},
		{DPUName: "dpu-b1", DPUID: "id_b1", Hostname: "host-b1", TenantID: "tenant_b"},
		{DPUName: "dpu-c1", DPUID: "id_c1", Hostname: "host-c1", TenantID: ""},
	}

	for i := range hosts {
		if err := store.RegisterAgentHost(&hosts[i]); err != nil {
			t.Fatalf("RegisterAgentHost failed: %v", err)
		}
	}

	t.Run("ListAgentHosts_ByTenant", func(t *testing.T) {
		tenantAHosts, err := store.ListAgentHosts("tenant_a")
		if err != nil {
			t.Fatalf("ListAgentHosts failed: %v", err)
		}

		if len(tenantAHosts) != 2 {
			t.Errorf("Expected 2 hosts in tenant_a, got %d", len(tenantAHosts))
		}

		// Verify all returned hosts belong to tenant_a
		for _, h := range tenantAHosts {
			if h.TenantID != "tenant_a" {
				t.Errorf("Host %s should be in tenant_a, got %s", h.ID, h.TenantID)
			}
		}
	})

	t.Run("ListAgentHosts_AllHosts", func(t *testing.T) {
		allHosts, err := store.ListAgentHosts("")
		if err != nil {
			t.Fatalf("ListAgentHosts failed: %v", err)
		}

		if len(allHosts) != 4 {
			t.Errorf("Expected 4 hosts total, got %d", len(allHosts))
		}
	})

	t.Run("ListAgentHosts_EmptyTenant", func(t *testing.T) {
		noHosts, err := store.ListAgentHosts("tenant_nonexistent")
		if err != nil {
			t.Fatalf("ListAgentHosts failed: %v", err)
		}

		if len(noHosts) != 0 {
			t.Errorf("Expected 0 hosts in nonexistent tenant, got %d", len(noHosts))
		}
	})

	t.Run("ListAgentHosts_OrderByHostname", func(t *testing.T) {
		allHosts, _ := store.ListAgentHosts("")

		// Verify ordering
		for i := 1; i < len(allHosts); i++ {
			if allHosts[i].Hostname < allHosts[i-1].Hostname {
				t.Error("Hosts should be ordered by hostname")
			}
		}
	})
}
