package store

import (
	"strings"
	"testing"
)

// TestTrustRelationshipCRUD tests basic CRUD operations for trust relationships.
func TestTrustRelationshipCRUD(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Test CreateTrustRelationship
	t.Run("CreateTrustRelationship", func(t *testing.T) {
		tr := &TrustRelationship{
			SourceHost:    "host-01.example.com",
			TargetHost:    "host-02.example.com",
			SourceDPUID:   "dpu1",
			SourceDPUName: "bf3-01",
			TargetDPUID:   "dpu2",
			TargetDPUName: "bf3-02",
			TenantID:      "tenant1",
			TrustType:     TrustTypeSSHHost,
			Bidirectional: false,
		}
		err := store.CreateTrustRelationship(tr)
		if err != nil {
			t.Fatalf("CreateTrustRelationship failed: %v", err)
		}

		// Verify ID was generated
		if tr.ID == "" {
			t.Error("expected ID to be generated")
		}
		if !strings.HasPrefix(tr.ID, "tr_") {
			t.Errorf("expected ID to start with 'tr_', got '%s'", tr.ID)
		}
		if len(tr.ID) != 11 { // "tr_" + 8 chars
			t.Errorf("expected ID length 11, got %d", len(tr.ID))
		}
	})

	// Test GetTrustRelationship
	t.Run("GetTrustRelationship", func(t *testing.T) {
		tr := &TrustRelationship{
			ID:            "tr_testget1",
			SourceHost:    "server-a.example.com",
			TargetHost:    "server-b.example.com",
			SourceDPUID:   "dpu1",
			SourceDPUName: "bf3-01",
			TargetDPUID:   "dpu2",
			TargetDPUName: "bf3-02",
			TenantID:      "tenant1",
			TrustType:     TrustTypeMTLS,
			Bidirectional: true,
		}
		err := store.CreateTrustRelationship(tr)
		if err != nil {
			t.Fatalf("CreateTrustRelationship failed: %v", err)
		}

		retrieved, err := store.GetTrustRelationship("tr_testget1")
		if err != nil {
			t.Fatalf("GetTrustRelationship failed: %v", err)
		}

		if retrieved.ID != "tr_testget1" {
			t.Errorf("expected ID 'tr_testget1', got '%s'", retrieved.ID)
		}
		if retrieved.SourceHost != "server-a.example.com" {
			t.Errorf("expected SourceHost 'server-a.example.com', got '%s'", retrieved.SourceHost)
		}
		if retrieved.TargetHost != "server-b.example.com" {
			t.Errorf("expected TargetHost 'server-b.example.com', got '%s'", retrieved.TargetHost)
		}
		if retrieved.SourceDPUID != "dpu1" {
			t.Errorf("expected SourceDPUID 'dpu1', got '%s'", retrieved.SourceDPUID)
		}
		if retrieved.SourceDPUName != "bf3-01" {
			t.Errorf("expected SourceDPUName 'bf3-01', got '%s'", retrieved.SourceDPUName)
		}
		if retrieved.TargetDPUID != "dpu2" {
			t.Errorf("expected TargetDPUID 'dpu2', got '%s'", retrieved.TargetDPUID)
		}
		if retrieved.TargetDPUName != "bf3-02" {
			t.Errorf("expected TargetDPUName 'bf3-02', got '%s'", retrieved.TargetDPUName)
		}
		if retrieved.TenantID != "tenant1" {
			t.Errorf("expected TenantID 'tenant1', got '%s'", retrieved.TenantID)
		}
		if retrieved.TrustType != TrustTypeMTLS {
			t.Errorf("expected TrustType 'mtls', got '%s'", retrieved.TrustType)
		}
		if !retrieved.Bidirectional {
			t.Error("expected Bidirectional to be true")
		}
		if retrieved.Status != TrustStatusActive {
			t.Errorf("expected Status 'active', got '%s'", retrieved.Status)
		}
		if retrieved.SuspendReason != nil {
			t.Errorf("expected nil SuspendReason, got '%s'", *retrieved.SuspendReason)
		}
		if retrieved.TargetCertSerial != nil {
			t.Errorf("expected nil TargetCertSerial, got '%d'", *retrieved.TargetCertSerial)
		}
		if retrieved.CreatedAt.IsZero() {
			t.Error("expected non-zero CreatedAt")
		}
		if retrieved.UpdatedAt.IsZero() {
			t.Error("expected non-zero UpdatedAt")
		}
	})

	// Test GetTrustRelationship not found
	t.Run("GetTrustRelationship_NotFound", func(t *testing.T) {
		_, err := store.GetTrustRelationship("nonexistent")
		if err == nil {
			t.Error("expected error for nonexistent trust relationship, got nil")
		}
	})

	// Test DeleteTrustRelationship
	t.Run("DeleteTrustRelationship", func(t *testing.T) {
		tr := &TrustRelationship{
			ID:            "tr_delete01",
			SourceHost:    "delete-src.example.com",
			TargetHost:    "delete-tgt.example.com",
			SourceDPUID:   "dpu1",
			SourceDPUName: "bf3-01",
			TargetDPUID:   "dpu3",
			TargetDPUName: "bf3-03",
			TenantID:      "tenant1",
			TrustType:     TrustTypeSSHHost,
		}
		store.CreateTrustRelationship(tr)

		err := store.DeleteTrustRelationship("tr_delete01")
		if err != nil {
			t.Fatalf("DeleteTrustRelationship failed: %v", err)
		}

		_, err = store.GetTrustRelationship("tr_delete01")
		if err == nil {
			t.Error("expected error for deleted trust relationship, got nil")
		}
	})

	// Test DeleteTrustRelationship not found
	t.Run("DeleteTrustRelationship_NotFound", func(t *testing.T) {
		err := store.DeleteTrustRelationship("nonexistent")
		if err == nil {
			t.Error("expected error for deleting nonexistent trust relationship, got nil")
		}
	})
}

// TestTrustRelationshipWithCertSerial tests creating trust with certificate serial.
func TestTrustRelationshipWithCertSerial(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	serial := uint64(12345678)
	tr := &TrustRelationship{
		ID:               "tr_certser1",
		SourceHost:       "cert-src.example.com",
		TargetHost:       "cert-tgt.example.com",
		SourceDPUID:      "dpu1",
		SourceDPUName:    "bf3-01",
		TargetDPUID:      "dpu2",
		TargetDPUName:    "bf3-02",
		TenantID:         "tenant1",
		TrustType:        TrustTypeSSHHost,
		TargetCertSerial: &serial,
	}
	err := store.CreateTrustRelationship(tr)
	if err != nil {
		t.Fatalf("CreateTrustRelationship failed: %v", err)
	}

	retrieved, err := store.GetTrustRelationship("tr_certser1")
	if err != nil {
		t.Fatalf("GetTrustRelationship failed: %v", err)
	}

	if retrieved.TargetCertSerial == nil {
		t.Error("expected non-nil TargetCertSerial")
	} else if *retrieved.TargetCertSerial != serial {
		t.Errorf("expected TargetCertSerial %d, got %d", serial, *retrieved.TargetCertSerial)
	}
}

// TestUpdateTargetCertSerial tests updating the certificate serial.
func TestUpdateTargetCertSerial(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create trust without serial
	tr := &TrustRelationship{
		ID:            "tr_upserial",
		SourceHost:    "upserial-src.example.com",
		TargetHost:    "upserial-tgt.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	}
	store.CreateTrustRelationship(tr)

	// Verify no serial initially
	retrieved, _ := store.GetTrustRelationship("tr_upserial")
	if retrieved.TargetCertSerial != nil {
		t.Error("expected nil TargetCertSerial initially")
	}

	// Update serial
	newSerial := uint64(99887766)
	err := store.UpdateTargetCertSerial("tr_upserial", newSerial)
	if err != nil {
		t.Fatalf("UpdateTargetCertSerial failed: %v", err)
	}

	// Verify serial was updated
	retrieved, _ = store.GetTrustRelationship("tr_upserial")
	if retrieved.TargetCertSerial == nil {
		t.Error("expected non-nil TargetCertSerial after update")
	} else if *retrieved.TargetCertSerial != newSerial {
		t.Errorf("expected TargetCertSerial %d, got %d", newSerial, *retrieved.TargetCertSerial)
	}

	// Test UpdateTargetCertSerial not found
	err = store.UpdateTargetCertSerial("nonexistent", 123)
	if err == nil {
		t.Error("expected error for updating nonexistent trust relationship, got nil")
	}
}

// TestListTrustRelationshipsByTenant tests listing trust relationships by tenant.
func TestListTrustRelationshipsByTenant(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create trust relationships for tenant1
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_tenant1a",
		SourceHost:    "t1a-src.example.com",
		TargetHost:    "t1a-tgt.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_tenant1b",
		SourceHost:    "t1b-src.example.com",
		TargetHost:    "t1b-tgt.example.com",
		SourceDPUID:   "dpu2",
		SourceDPUName: "bf3-02",
		TargetDPUID:   "dpu3",
		TargetDPUName: "bf3-03",
		TenantID:      "tenant1",
		TrustType:     TrustTypeMTLS,
	})

	// Create trust relationship for tenant2
	store.AddTenant("tenant2", "Tenant Two", "", "", nil)
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_tenant2a",
		SourceHost:    "t2a-src.example.com",
		TargetHost:    "t2a-tgt.example.com",
		SourceDPUID:   "dpu4",
		SourceDPUName: "bf3-04",
		TargetDPUID:   "dpu5",
		TargetDPUName: "bf3-05",
		TenantID:      "tenant2",
		TrustType:     TrustTypeSSHHost,
	})

	// List for tenant1
	relationships, err := store.ListTrustRelationships("tenant1")
	if err != nil {
		t.Fatalf("ListTrustRelationships failed: %v", err)
	}

	if len(relationships) != 2 {
		t.Errorf("expected 2 trust relationships for tenant1, got %d", len(relationships))
	}

	for _, tr := range relationships {
		if tr.TenantID != "tenant1" {
			t.Errorf("expected TenantID 'tenant1', got '%s'", tr.TenantID)
		}
	}

	// List for tenant2
	relationships, err = store.ListTrustRelationships("tenant2")
	if err != nil {
		t.Fatalf("ListTrustRelationships failed: %v", err)
	}

	if len(relationships) != 1 {
		t.Errorf("expected 1 trust relationship for tenant2, got %d", len(relationships))
	}
}

// TestListAllTrustRelationships tests listing all trust relationships across all tenants.
func TestListAllTrustRelationships(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create trust relationships for tenant1
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_all_t1a",
		SourceHost:    "all-t1a-src.example.com",
		TargetHost:    "all-t1a-tgt.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_all_t1b",
		SourceHost:    "all-t1b-src.example.com",
		TargetHost:    "all-t1b-tgt.example.com",
		SourceDPUID:   "dpu2",
		SourceDPUName: "bf3-02",
		TargetDPUID:   "dpu3",
		TargetDPUName: "bf3-03",
		TenantID:      "tenant1",
		TrustType:     TrustTypeMTLS,
	})

	// Create trust relationship for tenant2
	store.AddTenant("tenant2", "Tenant Two", "", "", nil)
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_all_t2a",
		SourceHost:    "all-t2a-src.example.com",
		TargetHost:    "all-t2a-tgt.example.com",
		SourceDPUID:   "dpu4",
		SourceDPUName: "bf3-04",
		TargetDPUID:   "dpu5",
		TargetDPUName: "bf3-05",
		TenantID:      "tenant2",
		TrustType:     TrustTypeSSHHost,
	})

	// List all trust relationships
	relationships, err := store.ListAllTrustRelationships()
	if err != nil {
		t.Fatalf("ListAllTrustRelationships failed: %v", err)
	}

	if len(relationships) != 3 {
		t.Errorf("expected 3 trust relationships total, got %d", len(relationships))
	}

	// Verify we have relationships from both tenants
	tenantsSeen := make(map[string]bool)
	for _, tr := range relationships {
		tenantsSeen[tr.TenantID] = true
	}
	if !tenantsSeen["tenant1"] || !tenantsSeen["tenant2"] {
		t.Error("expected trust relationships from both tenant1 and tenant2")
	}
}

// TestListTrustRelationshipsByDPU tests listing trust relationships involving a specific DPU.
func TestListTrustRelationshipsByDPU(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create trust relationships where dpu1 is source
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_dpu1src",
		SourceHost:    "dpu1src-host.example.com",
		TargetHost:    "dpu1src-tgt.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})

	// Create trust relationships where dpu1 is target
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_dpu1tgt",
		SourceHost:    "dpu1tgt-src.example.com",
		TargetHost:    "dpu1tgt-host.example.com",
		SourceDPUID:   "dpu3",
		SourceDPUName: "bf3-03",
		TargetDPUID:   "dpu1",
		TargetDPUName: "bf3-01",
		TenantID:      "tenant1",
		TrustType:     TrustTypeMTLS,
	})

	// Create trust relationship not involving dpu1
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_nodpu1",
		SourceHost:    "nodpu1-src.example.com",
		TargetHost:    "nodpu1-tgt.example.com",
		SourceDPUID:   "dpu2",
		SourceDPUName: "bf3-02",
		TargetDPUID:   "dpu3",
		TargetDPUName: "bf3-03",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})

	// List for dpu1
	relationships, err := store.ListTrustRelationshipsByDPU("dpu1")
	if err != nil {
		t.Fatalf("ListTrustRelationshipsByDPU failed: %v", err)
	}

	if len(relationships) != 2 {
		t.Errorf("expected 2 trust relationships for dpu1, got %d", len(relationships))
	}

	for _, tr := range relationships {
		if tr.SourceDPUID != "dpu1" && tr.TargetDPUID != "dpu1" {
			t.Errorf("expected dpu1 to be source or target, got source=%s target=%s", tr.SourceDPUID, tr.TargetDPUID)
		}
	}

	// List for dpu2
	relationships, err = store.ListTrustRelationshipsByDPU("dpu2")
	if err != nil {
		t.Fatalf("ListTrustRelationshipsByDPU failed: %v", err)
	}

	if len(relationships) != 2 {
		t.Errorf("expected 2 trust relationships for dpu2, got %d", len(relationships))
	}

	// List for dpu with no relationships
	relationships, err = store.ListTrustRelationshipsByDPU("dpu-none")
	if err != nil {
		t.Fatalf("ListTrustRelationshipsByDPU failed: %v", err)
	}

	if len(relationships) != 0 {
		t.Errorf("expected 0 trust relationships for dpu-none, got %d", len(relationships))
	}
}

// TestListTrustRelationshipsByHost tests listing trust relationships involving a specific host.
func TestListTrustRelationshipsByHost(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create trust relationships where host-a is source
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_hostasrc",
		SourceHost:    "host-a.example.com",
		TargetHost:    "host-b.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})

	// Create trust relationships where host-a is target
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_hostatgt",
		SourceHost:    "host-c.example.com",
		TargetHost:    "host-a.example.com",
		SourceDPUID:   "dpu3",
		SourceDPUName: "bf3-03",
		TargetDPUID:   "dpu1",
		TargetDPUName: "bf3-01",
		TenantID:      "tenant1",
		TrustType:     TrustTypeMTLS,
	})

	// Create trust relationship not involving host-a
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_nohosta",
		SourceHost:    "host-b.example.com",
		TargetHost:    "host-c.example.com",
		SourceDPUID:   "dpu2",
		SourceDPUName: "bf3-02",
		TargetDPUID:   "dpu3",
		TargetDPUName: "bf3-03",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})

	// List for host-a
	relationships, err := store.ListTrustRelationshipsByHost("host-a.example.com")
	if err != nil {
		t.Fatalf("ListTrustRelationshipsByHost failed: %v", err)
	}

	if len(relationships) != 2 {
		t.Errorf("expected 2 trust relationships for host-a, got %d", len(relationships))
	}

	for _, tr := range relationships {
		if tr.SourceHost != "host-a.example.com" && tr.TargetHost != "host-a.example.com" {
			t.Errorf("expected host-a to be source or target, got source=%s target=%s", tr.SourceHost, tr.TargetHost)
		}
	}

	// List for host-b
	relationships, err = store.ListTrustRelationshipsByHost("host-b.example.com")
	if err != nil {
		t.Fatalf("ListTrustRelationshipsByHost failed: %v", err)
	}

	if len(relationships) != 2 {
		t.Errorf("expected 2 trust relationships for host-b, got %d", len(relationships))
	}

	// List for host with no relationships
	relationships, err = store.ListTrustRelationshipsByHost("host-none.example.com")
	if err != nil {
		t.Fatalf("ListTrustRelationshipsByHost failed: %v", err)
	}

	if len(relationships) != 0 {
		t.Errorf("expected 0 trust relationships for host-none, got %d", len(relationships))
	}
}

// TestGetTrustRelationshipByHosts tests retrieving trust by host pair and type.
func TestGetTrustRelationshipByHosts(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create a trust relationship
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_byhosts1",
		SourceHost:    "src.example.com",
		TargetHost:    "tgt.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})

	// Test successful lookup
	tr, err := store.GetTrustRelationshipByHosts("src.example.com", "tgt.example.com", TrustTypeSSHHost)
	if err != nil {
		t.Fatalf("GetTrustRelationshipByHosts failed: %v", err)
	}
	if tr.ID != "tr_byhosts1" {
		t.Errorf("expected ID 'tr_byhosts1', got '%s'", tr.ID)
	}

	// Test not found (different trust type)
	_, err = store.GetTrustRelationshipByHosts("src.example.com", "tgt.example.com", TrustTypeMTLS)
	if err == nil {
		t.Error("expected error for different trust type, got nil")
	}

	// Test not found (reversed direction)
	_, err = store.GetTrustRelationshipByHosts("tgt.example.com", "src.example.com", TrustTypeSSHHost)
	if err == nil {
		t.Error("expected error for reversed direction, got nil")
	}

	// Test not found (nonexistent hosts)
	_, err = store.GetTrustRelationshipByHosts("nonexistent.example.com", "also-nonexistent.example.com", TrustTypeSSHHost)
	if err == nil {
		t.Error("expected error for nonexistent hosts, got nil")
	}
}

// TestUpdateTrustStatus tests updating the status of a trust relationship.
func TestUpdateTrustStatus(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create a trust relationship
	tr := &TrustRelationship{
		ID:            "tr_status01",
		SourceHost:    "status-src.example.com",
		TargetHost:    "status-tgt.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	}
	store.CreateTrustRelationship(tr)

	// Verify initial status is active
	retrieved, _ := store.GetTrustRelationship("tr_status01")
	if retrieved.Status != TrustStatusActive {
		t.Errorf("expected initial status 'active', got '%s'", retrieved.Status)
	}

	// Suspend with reason
	reason := "bf3-02 attestation failed"
	err := store.UpdateTrustStatus("tr_status01", TrustStatusSuspended, &reason)
	if err != nil {
		t.Fatalf("UpdateTrustStatus failed: %v", err)
	}

	retrieved, _ = store.GetTrustRelationship("tr_status01")
	if retrieved.Status != TrustStatusSuspended {
		t.Errorf("expected status 'suspended', got '%s'", retrieved.Status)
	}
	if retrieved.SuspendReason == nil {
		t.Error("expected non-nil SuspendReason")
	} else if *retrieved.SuspendReason != reason {
		t.Errorf("expected SuspendReason '%s', got '%s'", reason, *retrieved.SuspendReason)
	}

	// Reactivate (clear reason)
	err = store.UpdateTrustStatus("tr_status01", TrustStatusActive, nil)
	if err != nil {
		t.Fatalf("UpdateTrustStatus failed: %v", err)
	}

	retrieved, _ = store.GetTrustRelationship("tr_status01")
	if retrieved.Status != TrustStatusActive {
		t.Errorf("expected status 'active', got '%s'", retrieved.Status)
	}
	if retrieved.SuspendReason != nil {
		t.Errorf("expected nil SuspendReason, got '%s'", *retrieved.SuspendReason)
	}

	// Test UpdateTrustStatus not found
	err = store.UpdateTrustStatus("nonexistent", TrustStatusSuspended, nil)
	if err == nil {
		t.Error("expected error for updating nonexistent trust relationship, got nil")
	}
}

// TestTrustRelationshipExists tests checking if a trust relationship exists (by DPU).
func TestTrustRelationshipExists(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create a trust relationship
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_exists01",
		SourceHost:    "exists-src.example.com",
		TargetHost:    "exists-tgt.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})

	// Test exists (by DPU)
	exists, err := store.TrustRelationshipExists("dpu1", "dpu2", TrustTypeSSHHost)
	if err != nil {
		t.Fatalf("TrustRelationshipExists failed: %v", err)
	}
	if !exists {
		t.Error("expected trust relationship to exist")
	}

	// Test does not exist (different trust type)
	exists, err = store.TrustRelationshipExists("dpu1", "dpu2", TrustTypeMTLS)
	if err != nil {
		t.Fatalf("TrustRelationshipExists failed: %v", err)
	}
	if exists {
		t.Error("expected trust relationship to NOT exist for different trust type")
	}

	// Test does not exist (reversed direction)
	exists, err = store.TrustRelationshipExists("dpu2", "dpu1", TrustTypeSSHHost)
	if err != nil {
		t.Fatalf("TrustRelationshipExists failed: %v", err)
	}
	if exists {
		t.Error("expected trust relationship to NOT exist for reversed direction")
	}

	// Test does not exist (different DPUs)
	exists, err = store.TrustRelationshipExists("dpu1", "dpu3", TrustTypeSSHHost)
	if err != nil {
		t.Fatalf("TrustRelationshipExists failed: %v", err)
	}
	if exists {
		t.Error("expected trust relationship to NOT exist for different DPUs")
	}
}

// TestTrustRelationshipExistsByHost tests checking if a trust relationship exists by host.
func TestTrustRelationshipExistsByHost(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create a trust relationship
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_hexists01",
		SourceHost:    "hexists-src.example.com",
		TargetHost:    "hexists-tgt.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})

	// Test exists (by host)
	exists, err := store.TrustRelationshipExistsByHost("hexists-src.example.com", "hexists-tgt.example.com", TrustTypeSSHHost)
	if err != nil {
		t.Fatalf("TrustRelationshipExistsByHost failed: %v", err)
	}
	if !exists {
		t.Error("expected trust relationship to exist")
	}

	// Test does not exist (different trust type)
	exists, err = store.TrustRelationshipExistsByHost("hexists-src.example.com", "hexists-tgt.example.com", TrustTypeMTLS)
	if err != nil {
		t.Fatalf("TrustRelationshipExistsByHost failed: %v", err)
	}
	if exists {
		t.Error("expected trust relationship to NOT exist for different trust type")
	}

	// Test does not exist (reversed direction)
	exists, err = store.TrustRelationshipExistsByHost("hexists-tgt.example.com", "hexists-src.example.com", TrustTypeSSHHost)
	if err != nil {
		t.Fatalf("TrustRelationshipExistsByHost failed: %v", err)
	}
	if exists {
		t.Error("expected trust relationship to NOT exist for reversed direction")
	}

	// Test does not exist (different hosts)
	exists, err = store.TrustRelationshipExistsByHost("hexists-src.example.com", "other.example.com", TrustTypeSSHHost)
	if err != nil {
		t.Fatalf("TrustRelationshipExistsByHost failed: %v", err)
	}
	if exists {
		t.Error("expected trust relationship to NOT exist for different hosts")
	}
}

// setupTrustTestData creates prerequisite data for trust relationship tests.
func setupTrustTestData(t *testing.T, store *Store) {
	t.Helper()

	// Create tenant
	if err := store.AddTenant("tenant1", "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
}

// TestSuspendTrustRelationshipsForDPU tests suspending all trust relationships for a DPU.
func TestSuspendTrustRelationshipsForDPU(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create trust relationships where bf3-01 is source
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_susp_src",
		SourceHost:    "susp-src-host.example.com",
		TargetHost:    "susp-tgt-host.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})

	// Create trust relationships where bf3-01 is target
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_susp_tgt",
		SourceHost:    "other-src-host.example.com",
		TargetHost:    "bf3-01-host.example.com",
		SourceDPUID:   "dpu3",
		SourceDPUName: "bf3-03",
		TargetDPUID:   "dpu1",
		TargetDPUName: "bf3-01",
		TenantID:      "tenant1",
		TrustType:     TrustTypeMTLS,
	})

	// Create unrelated trust relationship
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_unrelated",
		SourceHost:    "unrel-src.example.com",
		TargetHost:    "unrel-tgt.example.com",
		SourceDPUID:   "dpu4",
		SourceDPUName: "bf3-04",
		TargetDPUID:   "dpu5",
		TargetDPUName: "bf3-05",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})

	// Suspend trust for bf3-01
	count, err := store.SuspendTrustRelationshipsForDPU("bf3-01", "bf3-01 attestation failed")
	if err != nil {
		t.Fatalf("SuspendTrustRelationshipsForDPU failed: %v", err)
	}

	if count != 2 {
		t.Errorf("expected 2 relationships suspended, got %d", count)
	}

	// Verify both related relationships are suspended
	tr1, _ := store.GetTrustRelationship("tr_susp_src")
	if tr1.Status != TrustStatusSuspended {
		t.Errorf("expected tr_susp_src status 'suspended', got '%s'", tr1.Status)
	}
	if tr1.SuspendReason == nil || *tr1.SuspendReason != "bf3-01 attestation failed" {
		t.Errorf("expected suspend reason 'bf3-01 attestation failed', got '%v'", tr1.SuspendReason)
	}

	tr2, _ := store.GetTrustRelationship("tr_susp_tgt")
	if tr2.Status != TrustStatusSuspended {
		t.Errorf("expected tr_susp_tgt status 'suspended', got '%s'", tr2.Status)
	}

	// Verify unrelated relationship is still active
	tr3, _ := store.GetTrustRelationship("tr_unrelated")
	if tr3.Status != TrustStatusActive {
		t.Errorf("expected tr_unrelated status 'active', got '%s'", tr3.Status)
	}
}

// TestSuspendTrustRelationshipsForDPU_AlreadySuspended tests that already suspended relationships are not double-counted.
func TestSuspendTrustRelationshipsForDPU_AlreadySuspended(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create and pre-suspend a relationship
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_presuspend",
		SourceHost:    "presuspend-src.example.com",
		TargetHost:    "presuspend-tgt.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})
	reason := "previous suspension"
	store.UpdateTrustStatus("tr_presuspend", TrustStatusSuspended, &reason)

	// Create an active relationship
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_active",
		SourceHost:    "active-src.example.com",
		TargetHost:    "active-tgt.example.com",
		SourceDPUID:   "dpu3",
		SourceDPUName: "bf3-03",
		TargetDPUID:   "dpu1",
		TargetDPUName: "bf3-01",
		TenantID:      "tenant1",
		TrustType:     TrustTypeMTLS,
	})

	// Suspend trust for bf3-01
	count, err := store.SuspendTrustRelationshipsForDPU("bf3-01", "new attestation failure")
	if err != nil {
		t.Fatalf("SuspendTrustRelationshipsForDPU failed: %v", err)
	}

	// Only the active one should be counted as newly suspended
	if count != 1 {
		t.Errorf("expected 1 relationship suspended (one was already), got %d", count)
	}
}

// TestSuspendTrustRelationshipsForDPU_NoRelationships tests suspension when DPU has no relationships.
func TestSuspendTrustRelationshipsForDPU_NoRelationships(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	count, err := store.SuspendTrustRelationshipsForDPU("bf3-lonely", "no relationships")
	if err != nil {
		t.Fatalf("SuspendTrustRelationshipsForDPU failed: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 relationships suspended for nonexistent DPU, got %d", count)
	}
}

// TestReactivateTrustRelationshipsForDPU tests reactivating suspended trust relationships.
func TestReactivateTrustRelationshipsForDPU(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create and suspend relationships for bf3-01
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_react_src",
		SourceHost:    "react-src-host.example.com",
		TargetHost:    "react-tgt-host.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_react_tgt",
		SourceHost:    "other-src-host.example.com",
		TargetHost:    "react-bf3-01-host.example.com",
		SourceDPUID:   "dpu3",
		SourceDPUName: "bf3-03",
		TargetDPUID:   "dpu1",
		TargetDPUName: "bf3-01",
		TenantID:      "tenant1",
		TrustType:     TrustTypeMTLS,
	})

	// Suspend both
	reason := "bf3-01 attestation failed"
	store.UpdateTrustStatus("tr_react_src", TrustStatusSuspended, &reason)
	store.UpdateTrustStatus("tr_react_tgt", TrustStatusSuspended, &reason)

	// Create unrelated suspended relationship (should NOT be reactivated)
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_unrel_susp",
		SourceHost:    "unrel-susp-src.example.com",
		TargetHost:    "unrel-susp-tgt.example.com",
		SourceDPUID:   "dpu4",
		SourceDPUName: "bf3-04",
		TargetDPUID:   "dpu5",
		TargetDPUName: "bf3-05",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})
	reason2 := "different reason"
	store.UpdateTrustStatus("tr_unrel_susp", TrustStatusSuspended, &reason2)

	// Reactivate trust for bf3-01
	count, err := store.ReactivateTrustRelationshipsForDPU("bf3-01")
	if err != nil {
		t.Fatalf("ReactivateTrustRelationshipsForDPU failed: %v", err)
	}

	if count != 2 {
		t.Errorf("expected 2 relationships reactivated, got %d", count)
	}

	// Verify both related relationships are active
	tr1, _ := store.GetTrustRelationship("tr_react_src")
	if tr1.Status != TrustStatusActive {
		t.Errorf("expected tr_react_src status 'active', got '%s'", tr1.Status)
	}
	if tr1.SuspendReason != nil {
		t.Errorf("expected nil suspend reason after reactivation, got '%s'", *tr1.SuspendReason)
	}

	tr2, _ := store.GetTrustRelationship("tr_react_tgt")
	if tr2.Status != TrustStatusActive {
		t.Errorf("expected tr_react_tgt status 'active', got '%s'", tr2.Status)
	}

	// Verify unrelated suspended relationship is still suspended
	tr3, _ := store.GetTrustRelationship("tr_unrel_susp")
	if tr3.Status != TrustStatusSuspended {
		t.Errorf("expected tr_unrel_susp status 'suspended', got '%s'", tr3.Status)
	}
}

// TestReactivateTrustRelationshipsForDPU_AlreadyActive tests that already active relationships are not double-counted.
func TestReactivateTrustRelationshipsForDPU_AlreadyActive(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	// Create one active and one suspended relationship
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_already_active",
		SourceHost:    "already-active-src.example.com",
		TargetHost:    "already-active-tgt.example.com",
		SourceDPUID:   "dpu1",
		SourceDPUName: "bf3-01",
		TargetDPUID:   "dpu2",
		TargetDPUName: "bf3-02",
		TenantID:      "tenant1",
		TrustType:     TrustTypeSSHHost,
	})
	store.CreateTrustRelationship(&TrustRelationship{
		ID:            "tr_was_suspended",
		SourceHost:    "was-suspended-src.example.com",
		TargetHost:    "was-suspended-tgt.example.com",
		SourceDPUID:   "dpu3",
		SourceDPUName: "bf3-03",
		TargetDPUID:   "dpu1",
		TargetDPUName: "bf3-01",
		TenantID:      "tenant1",
		TrustType:     TrustTypeMTLS,
	})
	reason := "was suspended"
	store.UpdateTrustStatus("tr_was_suspended", TrustStatusSuspended, &reason)

	// Reactivate
	count, err := store.ReactivateTrustRelationshipsForDPU("bf3-01")
	if err != nil {
		t.Fatalf("ReactivateTrustRelationshipsForDPU failed: %v", err)
	}

	// Only the suspended one should be counted
	if count != 1 {
		t.Errorf("expected 1 relationship reactivated, got %d", count)
	}
}

// TestReactivateTrustRelationshipsForDPU_NoRelationships tests reactivation when DPU has no relationships.
func TestReactivateTrustRelationshipsForDPU_NoRelationships(t *testing.T) {
	store := setupTestStore(t)
	setupTrustTestData(t, store)

	count, err := store.ReactivateTrustRelationshipsForDPU("bf3-lonely")
	if err != nil {
		t.Fatalf("ReactivateTrustRelationshipsForDPU failed: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 relationships reactivated for nonexistent DPU, got %d", count)
	}
}
