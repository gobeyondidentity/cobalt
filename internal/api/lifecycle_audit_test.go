package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gobeyondidentity/cobalt/pkg/audit"
	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
	"github.com/google/uuid"
)

// captureEmitter records all emitted events for test assertions.
type captureEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureEmitter) Emit(ev audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

func (c *captureEmitter) Events() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]audit.Event, len(c.events))
	copy(cp, c.events)
	return cp
}

// setupAuditTestServer creates a test server with a captureEmitter wired in.
func setupAuditTestServer(t *testing.T) (*store.Store, *Server, *captureEmitter) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit_test.db")

	store.SetInsecureMode(true)
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test store: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		os.Remove(dbPath)
	})

	emitter := &captureEmitter{}
	srv := NewServerWithConfig(s, ServerConfig{
		AuditEmitter: emitter,
	})

	return s, srv, emitter
}

func TestLifecycleAudit_RevokeKeyMaker(t *testing.T) {
	t.Parallel()
	t.Log("Verifying lifecycle.revoke event emitted when KeyMaker is revoked")

	s, srv, emitter := setupAuditTestServer(t)

	// Setup: tenant, operator, and KeyMaker
	tenantID := "tenant_" + uuid.New().String()[:8]
	operatorID := "op_" + uuid.New().String()[:8]
	adminKID := "adm_" + uuid.New().String()[:8]
	kmID := "km_" + uuid.New().String()[:8]

	if err := s.AddTenant(tenantID, "Audit Test Tenant", "", "", nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := s.CreateOperator(operatorID, "audit@test.com", "Audit User"); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	if err := s.AddOperatorToTenant(operatorID, tenantID, "super:admin"); err != nil {
		t.Fatalf("add operator to tenant: %v", err)
	}
	ak := &store.AdminKey{
		ID: adminKID, OperatorID: operatorID, Name: "admin-key",
		PublicKey: make([]byte, 32), Kid: adminKID,
		KeyFingerprint: "fp_" + adminKID, Status: "active",
	}
	if err := s.CreateAdminKey(ak); err != nil {
		t.Fatalf("create admin key: %v", err)
	}
	km := &store.KeyMaker{
		ID: kmID, OperatorID: operatorID, Name: "test-km",
		Platform: "linux", SecureElement: "software",
		DeviceFingerprint: "fp_km", PublicKey: "ssh-ed25519 AAAA",
		Status: "active", Kid: kmID,
		KeyFingerprint: "fp_" + kmID,
	}
	if err := s.CreateKeyMaker(km); err != nil {
		t.Fatalf("create keymaker: %v", err)
	}

	// Revoke the KeyMaker
	body, _ := json.Marshal(RevokeKeyMakerRequest{Reason: "compromised credential"})
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+kmID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", kmID)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID: adminKID, CallerType: dpop.CallerTypeAdmin,
		Status: dpop.IdentityStatusActive, OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.handleRevokeKeyMaker(rec, req)

	t.Logf("Response status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify audit event
	events := emitter.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	ev := events[0]
	t.Logf("Emitted event: type=%s actor=%s details=%v", ev.Type, ev.ActorID, ev.Details)

	if ev.Type != audit.EventLifecycleRevoke {
		t.Errorf("Type = %q, want %q", ev.Type, audit.EventLifecycleRevoke)
	}
	if ev.ActorID != adminKID {
		t.Errorf("ActorID = %q, want %q", ev.ActorID, adminKID)
	}
	if ev.Details["revoked_key_id"] != kmID {
		t.Errorf("Details[revoked_key_id] = %q, want %q", ev.Details["revoked_key_id"], kmID)
	}
	if ev.Details["reason"] != "compromised credential" {
		t.Errorf("Details[reason] = %q, want %q", ev.Details["reason"], "compromised credential")
	}
	if ev.Severity != audit.SeverityWarning {
		t.Errorf("Severity = %d, want %d (WARNING)", ev.Severity, audit.SeverityWarning)
	}
}

func TestLifecycleAudit_RevokeAdminKey(t *testing.T) {
	t.Parallel()
	t.Log("Verifying lifecycle.revoke event emitted when admin key is revoked")

	s, srv, emitter := setupAuditTestServer(t)

	// Setup: tenant, two operators (super:admin), two admin keys
	tenantID := "tenant_" + uuid.New().String()[:8]
	callerOpID := "op_caller_" + uuid.New().String()[:8]
	targetOpID := "op_target_" + uuid.New().String()[:8]
	callerKID := "adm_caller_" + uuid.New().String()[:8]
	targetKID := "adm_target_" + uuid.New().String()[:8]

	if err := s.AddTenant(tenantID, "Audit Test Tenant", "", "", nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	for _, op := range []struct{ id, email string }{
		{callerOpID, "caller@test.com"},
		{targetOpID, "target@test.com"},
	} {
		if err := s.CreateOperator(op.id, op.email, "Test"); err != nil {
			t.Fatalf("create operator %s: %v", op.id, err)
		}
		if err := s.AddOperatorToTenant(op.id, tenantID, "super:admin"); err != nil {
			t.Fatalf("add to tenant %s: %v", op.id, err)
		}
	}
	for _, ak := range []struct{ id, opID string }{
		{callerKID, callerOpID},
		{targetKID, targetOpID},
	} {
		key := &store.AdminKey{
			ID: ak.id, OperatorID: ak.opID, Name: "key-" + ak.id,
			PublicKey: make([]byte, 32), Kid: ak.id,
			KeyFingerprint: "fp_" + ak.id, Status: "active",
		}
		if err := s.CreateAdminKey(key); err != nil {
			t.Fatalf("create admin key %s: %v", ak.id, err)
		}
	}

	// Revoke the target admin key
	body, _ := json.Marshal(RevokeAdminKeyRequest{Reason: "rotation policy"})
	req := httptest.NewRequest("DELETE", "/api/v1/admin-keys/"+targetKID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", targetKID)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID: callerKID, CallerType: dpop.CallerTypeAdmin,
		Status: dpop.IdentityStatusActive, OperatorID: callerOpID,
	})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.handleRevokeAdminKey(rec, req)

	t.Logf("Response status: %d", rec.Code)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify audit event
	events := emitter.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	ev := events[0]
	t.Logf("Emitted event: type=%s actor=%s details=%v", ev.Type, ev.ActorID, ev.Details)

	if ev.Type != audit.EventLifecycleRevoke {
		t.Errorf("Type = %q, want %q", ev.Type, audit.EventLifecycleRevoke)
	}
	if ev.ActorID != callerKID {
		t.Errorf("ActorID = %q, want %q", ev.ActorID, callerKID)
	}
	if ev.Details["revoked_key_id"] != targetKID {
		t.Errorf("Details[revoked_key_id] = %q, want %q", ev.Details["revoked_key_id"], targetKID)
	}
	if ev.Details["reason"] != "rotation policy" {
		t.Errorf("Details[reason] = %q, want %q", ev.Details["reason"], "rotation policy")
	}
}

func TestLifecycleAudit_SuspendOperator(t *testing.T) {
	t.Parallel()
	t.Log("Verifying lifecycle.suspend event emitted when operator is suspended")

	s, srv, emitter := setupAuditTestServer(t)

	// Setup
	tenantID := "tenant_" + uuid.New().String()[:8]
	adminOpID := "op_admin_" + uuid.New().String()[:8]
	targetOpID := "op_target_" + uuid.New().String()[:8]
	adminKID := "adm_" + uuid.New().String()[:8]

	if err := s.AddTenant(tenantID, "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := s.CreateOperator(adminOpID, "admin@test.com", "Admin"); err != nil {
		t.Fatalf("create admin operator: %v", err)
	}
	if err := s.CreateOperator(targetOpID, "target@test.com", "Target"); err != nil {
		t.Fatalf("create target operator: %v", err)
	}
	if err := s.UpdateOperatorStatus(targetOpID, "active"); err != nil {
		t.Fatalf("activate target: %v", err)
	}
	if err := s.AddOperatorToTenant(adminOpID, tenantID, "super:admin"); err != nil {
		t.Fatalf("add admin to tenant: %v", err)
	}
	if err := s.AddOperatorToTenant(targetOpID, tenantID, "operator"); err != nil {
		t.Fatalf("add target to tenant: %v", err)
	}
	ak := &store.AdminKey{
		ID: adminKID, OperatorID: adminOpID, Name: "admin-key",
		PublicKey: make([]byte, 32), Kid: adminKID,
		KeyFingerprint: "fp_" + adminKID, Status: "active",
	}
	if err := s.CreateAdminKey(ak); err != nil {
		t.Fatalf("create admin key: %v", err)
	}

	// Suspend the target operator
	body, _ := json.Marshal(SuspendOperatorRequest{Reason: "security investigation"})
	req := httptest.NewRequest("POST", "/api/v1/operators/"+targetOpID+"/suspend", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", targetOpID)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID: adminKID, CallerType: dpop.CallerTypeAdmin,
		Status: dpop.IdentityStatusActive, OperatorID: adminOpID,
	})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.handleSuspendOperator(rec, req)

	t.Logf("Response status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify audit event
	events := emitter.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	ev := events[0]
	t.Logf("Emitted event: type=%s actor=%s details=%v", ev.Type, ev.ActorID, ev.Details)

	if ev.Type != audit.EventLifecycleSuspend {
		t.Errorf("Type = %q, want %q", ev.Type, audit.EventLifecycleSuspend)
	}
	if ev.ActorID != adminKID {
		t.Errorf("ActorID = %q, want %q", ev.ActorID, adminKID)
	}
	if ev.Details["operator_id"] != targetOpID {
		t.Errorf("Details[operator_id] = %q, want %q", ev.Details["operator_id"], targetOpID)
	}
	if ev.Details["reason"] != "security investigation" {
		t.Errorf("Details[reason] = %q, want %q", ev.Details["reason"], "security investigation")
	}
	if ev.Severity != audit.SeverityWarning {
		t.Errorf("Severity = %d, want %d (WARNING)", ev.Severity, audit.SeverityWarning)
	}
}

func TestLifecycleAudit_UnsuspendOperator(t *testing.T) {
	t.Parallel()
	t.Log("Verifying lifecycle.unsuspend event emitted when operator is unsuspended")

	s, srv, emitter := setupAuditTestServer(t)

	// Setup
	tenantID := "tenant_" + uuid.New().String()[:8]
	adminOpID := "op_admin_" + uuid.New().String()[:8]
	targetOpID := "op_target_" + uuid.New().String()[:8]
	adminKID := "adm_" + uuid.New().String()[:8]

	if err := s.AddTenant(tenantID, "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := s.CreateOperator(adminOpID, "admin@test.com", "Admin"); err != nil {
		t.Fatalf("create admin operator: %v", err)
	}
	if err := s.CreateOperator(targetOpID, "target@test.com", "Target"); err != nil {
		t.Fatalf("create target operator: %v", err)
	}
	if err := s.AddOperatorToTenant(adminOpID, tenantID, "super:admin"); err != nil {
		t.Fatalf("add admin to tenant: %v", err)
	}
	if err := s.AddOperatorToTenant(targetOpID, tenantID, "operator"); err != nil {
		t.Fatalf("add target to tenant: %v", err)
	}
	ak := &store.AdminKey{
		ID: adminKID, OperatorID: adminOpID, Name: "admin-key",
		PublicKey: make([]byte, 32), Kid: adminKID,
		KeyFingerprint: "fp_" + adminKID, Status: "active",
	}
	if err := s.CreateAdminKey(ak); err != nil {
		t.Fatalf("create admin key: %v", err)
	}

	// First suspend the operator
	if err := s.SuspendOperatorAtomic(targetOpID, adminKID, "initial suspension"); err != nil {
		t.Fatalf("suspend operator: %v", err)
	}

	// Unsuspend
	body, _ := json.Marshal(UnsuspendOperatorRequest{Reason: "investigation cleared"})
	req := httptest.NewRequest("POST", "/api/v1/operators/"+targetOpID+"/unsuspend", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", targetOpID)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID: adminKID, CallerType: dpop.CallerTypeAdmin,
		Status: dpop.IdentityStatusActive, OperatorID: adminOpID,
	})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.handleUnsuspendOperator(rec, req)

	t.Logf("Response status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify audit event
	events := emitter.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	ev := events[0]
	t.Logf("Emitted event: type=%s actor=%s details=%v", ev.Type, ev.ActorID, ev.Details)

	if ev.Type != audit.EventLifecycleUnsuspend {
		t.Errorf("Type = %q, want %q", ev.Type, audit.EventLifecycleUnsuspend)
	}
	if ev.ActorID != adminKID {
		t.Errorf("ActorID = %q, want %q", ev.ActorID, adminKID)
	}
	if ev.Details["operator_id"] != targetOpID {
		t.Errorf("Details[operator_id] = %q, want %q", ev.Details["operator_id"], targetOpID)
	}
	if ev.Details["reason"] != "investigation cleared" {
		t.Errorf("Details[reason] = %q, want %q", ev.Details["reason"], "investigation cleared")
	}
	if ev.Severity != audit.SeverityNotice {
		t.Errorf("Severity = %d, want %d (NOTICE)", ev.Severity, audit.SeverityNotice)
	}
}

func TestLifecycleAudit_DecommissionDPU(t *testing.T) {
	t.Parallel()
	t.Log("Verifying lifecycle.decommission event emitted when DPU is decommissioned")

	s, srv, emitter := setupAuditTestServer(t)

	// Setup
	tenantID := "tenant_" + uuid.New().String()[:8]
	operatorID := "op_" + uuid.New().String()[:8]
	adminKID := "adm_" + uuid.New().String()[:8]
	dpuID := "dpu_" + uuid.New().String()[:8]

	if err := s.AddTenant(tenantID, "Test Tenant", "", "", nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := s.CreateOperator(operatorID, "admin@test.com", "Admin"); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	if err := s.AddOperatorToTenant(operatorID, tenantID, "super:admin"); err != nil {
		t.Fatalf("add to tenant: %v", err)
	}
	ak := &store.AdminKey{
		ID: adminKID, OperatorID: operatorID, Name: "admin-key",
		PublicKey: make([]byte, 32), Kid: adminKID,
		KeyFingerprint: "fp_" + adminKID, Status: "active",
	}
	if err := s.CreateAdminKey(ak); err != nil {
		t.Fatalf("create admin key: %v", err)
	}
	if err := s.Add(dpuID, "test-dpu", "192.168.1.100", 50051); err != nil {
		t.Fatalf("create DPU: %v", err)
	}
	if err := s.AssignDPUToTenant(dpuID, tenantID); err != nil {
		t.Fatalf("assign DPU to tenant: %v", err)
	}

	// Decommission the DPU
	body, _ := json.Marshal(DecommissionDPURequest{Reason: "hardware failure"})
	req := httptest.NewRequest("DELETE", "/api/v1/dpus/"+dpuID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", dpuID)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID: adminKID, CallerType: dpop.CallerTypeAdmin,
		Status: dpop.IdentityStatusActive, OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.handleDecommissionDPU(rec, req)

	t.Logf("Response status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify audit event
	events := emitter.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	ev := events[0]
	t.Logf("Emitted event: type=%s actor=%s details=%v", ev.Type, ev.ActorID, ev.Details)

	if ev.Type != audit.EventLifecycleDecommission {
		t.Errorf("Type = %q, want %q", ev.Type, audit.EventLifecycleDecommission)
	}
	if ev.ActorID != adminKID {
		t.Errorf("ActorID = %q, want %q", ev.ActorID, adminKID)
	}
	if ev.Details["dpu_id"] != dpuID {
		t.Errorf("Details[dpu_id] = %q, want %q", ev.Details["dpu_id"], dpuID)
	}
	if ev.Details["reason"] != "hardware failure" {
		t.Errorf("Details[reason] = %q, want %q", ev.Details["reason"], "hardware failure")
	}
	if ev.Severity != audit.SeverityWarning {
		t.Errorf("Severity = %d, want %d (WARNING)", ev.Severity, audit.SeverityWarning)
	}
}

func TestLifecycleAudit_NoSecretsInEvents(t *testing.T) {
	t.Parallel()
	t.Log("Verifying no sensitive data leaks into audit event fields")

	s, srv, emitter := setupAuditTestServer(t)

	// Setup minimal data
	tenantID := "tenant_" + uuid.New().String()[:8]
	operatorID := "op_" + uuid.New().String()[:8]
	adminKID := "adm_" + uuid.New().String()[:8]
	kmID := "km_" + uuid.New().String()[:8]

	if err := s.AddTenant(tenantID, "Test", "", "", nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := s.CreateOperator(operatorID, "secret-email@internal.com", "Secret Name"); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	if err := s.AddOperatorToTenant(operatorID, tenantID, "super:admin"); err != nil {
		t.Fatalf("add to tenant: %v", err)
	}
	ak := &store.AdminKey{
		ID: adminKID, OperatorID: operatorID, Name: "admin-key",
		PublicKey: make([]byte, 32), Kid: adminKID,
		KeyFingerprint: "fp_" + adminKID, Status: "active",
	}
	if err := s.CreateAdminKey(ak); err != nil {
		t.Fatalf("create admin key: %v", err)
	}
	km := &store.KeyMaker{
		ID: kmID, OperatorID: operatorID, Name: "test-km",
		Platform: "linux", SecureElement: "tpm",
		DeviceFingerprint: "supersecretfingerprint", PublicKey: "ssh-ed25519 SECRETKEY",
		Status: "active", Kid: kmID,
		KeyFingerprint: "fp_" + kmID,
	}
	if err := s.CreateKeyMaker(km); err != nil {
		t.Fatalf("create keymaker: %v", err)
	}

	// Revoke the keymaker
	body, _ := json.Marshal(RevokeKeyMakerRequest{Reason: "routine rotation"})
	req := httptest.NewRequest("DELETE", "/api/v1/keymakers/"+kmID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", kmID)
	ctx := dpop.ContextWithIdentity(req.Context(), &dpop.Identity{
		KID: adminKID, CallerType: dpop.CallerTypeAdmin,
		Status: dpop.IdentityStatusActive, OperatorID: operatorID,
	})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.handleRevokeKeyMaker(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	events := emitter.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	t.Log("Checking no sensitive fields leak into audit event")

	// Verify no private keys, fingerprints, or email in audit event
	sensitiveValues := []string{
		"ssh-ed25519 SECRETKEY",
		"supersecretfingerprint",
		"secret-email@internal.com",
	}
	for _, secret := range sensitiveValues {
		if ev.ActorID == secret {
			t.Errorf("ActorID contains sensitive value: %s", secret)
		}
		for k, v := range ev.Details {
			if v == secret {
				t.Errorf("Details[%s] contains sensitive value: %s", k, secret)
			}
		}
	}

	t.Log("No secrets found in lifecycle audit event")
}
