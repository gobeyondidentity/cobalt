package audit

import (
	"testing"
	"time"
)

func TestEventConstants_MatchSpec(t *testing.T) {
	t.Parallel()
	t.Log("Verifying all 10 event type constants match security-architecture.md Section 8")

	expected := map[EventType]string{
		EventAuthSuccess:           "auth.success",
		EventAuthFailure:           "auth.failure",
		EventEnrollComplete:        "enroll.complete",
		EventEnrollFailure:         "enroll.failure",
		EventLifecycleRevoke:       "lifecycle.revoke",
		EventLifecycleSuspend:      "lifecycle.suspend",
		EventLifecycleUnsuspend:    "lifecycle.unsuspend",
		EventLifecycleDecommission: "lifecycle.decommission",
		EventAttestationBypass:     "attestation.bypass",
		EventBootstrapComplete:     "bootstrap.complete",
	}

	for constant, want := range expected {
		if string(constant) != want {
			t.Errorf("EventType constant %q != expected %q", string(constant), want)
		}
	}

	t.Log("Verifying AllEventTypes() returns exactly 10 events")
	all := AllEventTypes()
	if len(all) != 10 {
		t.Fatalf("AllEventTypes() returned %d events, want 10", len(all))
	}

	// Verify AllEventTypes contains every expected event
	seen := make(map[EventType]bool)
	for _, et := range all {
		seen[et] = true
	}
	for constant := range expected {
		if !seen[constant] {
			t.Errorf("AllEventTypes() missing %q", string(constant))
		}
	}
}

func TestSeverityMapping_MatchesSpec(t *testing.T) {
	t.Parallel()
	t.Log("Verifying severity mappings match security-architecture.md Section 8 table")

	tests := []struct {
		event    EventType
		severity Severity
		syslog   int
		label    string
	}{
		{EventAuthSuccess, SeverityInfo, 6, "INFO"},
		{EventAuthFailure, SeverityWarning, 4, "WARNING"},
		{EventEnrollComplete, SeverityNotice, 5, "NOTICE"},
		{EventEnrollFailure, SeverityWarning, 4, "WARNING"},
		{EventLifecycleRevoke, SeverityWarning, 4, "WARNING"},
		{EventLifecycleSuspend, SeverityWarning, 4, "WARNING"},
		{EventLifecycleUnsuspend, SeverityNotice, 5, "NOTICE"},
		{EventLifecycleDecommission, SeverityWarning, 4, "WARNING"},
		{EventAttestationBypass, SeverityWarning, 4, "WARNING"},
		{EventBootstrapComplete, SeverityNotice, 5, "NOTICE"},
	}

	for _, tc := range tests {
		t.Logf("  %s -> %s (syslog %d)", tc.event, tc.label, tc.syslog)
		got := SeverityFor(tc.event)
		if got != tc.severity {
			t.Errorf("SeverityFor(%q) = %d (%s), want %d (%s)",
				tc.event, got, got.String(), tc.severity, tc.label)
		}
		if int(got) != tc.syslog {
			t.Errorf("SeverityFor(%q) syslog value = %d, want %d",
				tc.event, int(got), tc.syslog)
		}
	}
}

func TestSeverityForUnknown_FailsSecure(t *testing.T) {
	t.Parallel()
	t.Log("Verifying unknown event types default to WARNING (fail-secure)")

	got := SeverityFor(EventType("totally.unknown"))
	if got != SeverityWarning {
		t.Errorf("SeverityFor unknown event = %d (%s), want %d (WARNING)",
			got, got.String(), SeverityWarning)
	}
}

func TestSeverityString(t *testing.T) {
	t.Parallel()
	t.Log("Verifying Severity.String() returns correct labels")

	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityInfo, "INFO"},
		{SeverityNotice, "NOTICE"},
		{SeverityWarning, "WARNING"},
		{Severity(99), "UNKNOWN"},
	}

	for _, tc := range tests {
		got := tc.severity.String()
		if got != tc.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tc.severity, got, tc.want)
		}
	}
}

func TestNewAuthSuccess(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewAuthSuccess sets correct type, severity, and fields")

	before := time.Now()
	e := NewAuthSuccess("km_abc123", "192.168.1.100", "POST", "/api/v1/push", "req-1", 12)
	after := time.Now()

	if e.Type != EventAuthSuccess {
		t.Errorf("Type = %q, want %q", e.Type, EventAuthSuccess)
	}
	if e.Severity != SeverityInfo {
		t.Errorf("Severity = %d, want %d (INFO)", e.Severity, SeverityInfo)
	}
	if e.Timestamp.Before(before) || e.Timestamp.After(after) {
		t.Errorf("Timestamp %v not between %v and %v", e.Timestamp, before, after)
	}
	if e.ActorID != "km_abc123" {
		t.Errorf("ActorID = %q, want %q", e.ActorID, "km_abc123")
	}
	if e.IP != "192.168.1.100" {
		t.Errorf("IP = %q, want %q", e.IP, "192.168.1.100")
	}
	if e.RequestID != "req-1" {
		t.Errorf("RequestID = %q, want %q", e.RequestID, "req-1")
	}
	if e.Details["method"] != "POST" {
		t.Errorf("Details[method] = %q, want %q", e.Details["method"], "POST")
	}
	if e.Details["path"] != "/api/v1/push" {
		t.Errorf("Details[path] = %q, want %q", e.Details["path"], "/api/v1/push")
	}
	if e.Details["latency_ms"] != "12" {
		t.Errorf("Details[latency_ms] = %q, want %q", e.Details["latency_ms"], "12")
	}
}

func TestNewAuthFailure(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewAuthFailure sets correct type, severity, and reason")

	e := NewAuthFailure("km_bad", "10.0.0.1", "invalid_signature", "GET", "/api/v1/protected", "req-2")

	if e.Type != EventAuthFailure {
		t.Errorf("Type = %q, want %q", e.Type, EventAuthFailure)
	}
	if e.Severity != SeverityWarning {
		t.Errorf("Severity = %d, want %d (WARNING)", e.Severity, SeverityWarning)
	}
	if e.ActorID != "km_bad" {
		t.Errorf("ActorID = %q, want %q", e.ActorID, "km_bad")
	}
	if e.Details["reason"] != "invalid_signature" {
		t.Errorf("Details[reason] = %q, want %q", e.Details["reason"], "invalid_signature")
	}
	if e.Details["method"] != "GET" {
		t.Errorf("Details[method] = %q, want %q", e.Details["method"], "GET")
	}
	if e.Details["path"] != "/api/v1/protected" {
		t.Errorf("Details[path] = %q, want %q", e.Details["path"], "/api/v1/protected")
	}
}

func TestNewEnrollComplete(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewEnrollComplete sets correct type and severity")

	e := NewEnrollComplete("km_new", "10.0.0.2", "req-3")

	if e.Type != EventEnrollComplete {
		t.Errorf("Type = %q, want %q", e.Type, EventEnrollComplete)
	}
	if e.Severity != SeverityNotice {
		t.Errorf("Severity = %d, want %d (NOTICE)", e.Severity, SeverityNotice)
	}
	if e.ActorID != "km_new" {
		t.Errorf("ActorID = %q, want %q", e.ActorID, "km_new")
	}
}

func TestNewEnrollFailure(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewEnrollFailure sets correct type and reason (no ActorID)")

	e := NewEnrollFailure("10.0.0.3", "invalid_invite_code", "req-4")

	if e.Type != EventEnrollFailure {
		t.Errorf("Type = %q, want %q", e.Type, EventEnrollFailure)
	}
	if e.Severity != SeverityWarning {
		t.Errorf("Severity = %d, want %d (WARNING)", e.Severity, SeverityWarning)
	}
	if e.ActorID != "" {
		t.Errorf("ActorID = %q, want empty (unknown at enrollment failure)", e.ActorID)
	}
	if e.Details["reason"] != "invalid_invite_code" {
		t.Errorf("Details[reason] = %q, want %q", e.Details["reason"], "invalid_invite_code")
	}
}

func TestNewLifecycleRevoke(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewLifecycleRevoke captures revoking actor and revoked key")

	e := NewLifecycleRevoke("adm_admin1", "10.0.0.4", "km_revoked", "req-5")

	if e.Type != EventLifecycleRevoke {
		t.Errorf("Type = %q, want %q", e.Type, EventLifecycleRevoke)
	}
	if e.Severity != SeverityWarning {
		t.Errorf("Severity = %d, want %d (WARNING)", e.Severity, SeverityWarning)
	}
	if e.Details["revoked_key_id"] != "km_revoked" {
		t.Errorf("Details[revoked_key_id] = %q, want %q", e.Details["revoked_key_id"], "km_revoked")
	}
}

func TestNewLifecycleSuspend(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewLifecycleSuspend captures suspending actor and target operator")

	e := NewLifecycleSuspend("adm_admin1", "10.0.0.5", "km_target", "req-6")

	if e.Type != EventLifecycleSuspend {
		t.Errorf("Type = %q, want %q", e.Type, EventLifecycleSuspend)
	}
	if e.Severity != SeverityWarning {
		t.Errorf("Severity = %d, want %d (WARNING)", e.Severity, SeverityWarning)
	}
	if e.Details["operator_id"] != "km_target" {
		t.Errorf("Details[operator_id] = %q, want %q", e.Details["operator_id"], "km_target")
	}
}

func TestNewLifecycleUnsuspend(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewLifecycleUnsuspend uses NOTICE severity")

	e := NewLifecycleUnsuspend("adm_admin1", "10.0.0.6", "km_target", "req-7")

	if e.Type != EventLifecycleUnsuspend {
		t.Errorf("Type = %q, want %q", e.Type, EventLifecycleUnsuspend)
	}
	if e.Severity != SeverityNotice {
		t.Errorf("Severity = %d, want %d (NOTICE)", e.Severity, SeverityNotice)
	}
	if e.Details["operator_id"] != "km_target" {
		t.Errorf("Details[operator_id] = %q, want %q", e.Details["operator_id"], "km_target")
	}
}

func TestNewLifecycleDecommission(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewLifecycleDecommission captures DPU ID")

	e := NewLifecycleDecommission("adm_admin1", "10.0.0.7", "dpu_xyz", "req-8")

	if e.Type != EventLifecycleDecommission {
		t.Errorf("Type = %q, want %q", e.Type, EventLifecycleDecommission)
	}
	if e.Severity != SeverityWarning {
		t.Errorf("Severity = %d, want %d (WARNING)", e.Severity, SeverityWarning)
	}
	if e.Details["dpu_id"] != "dpu_xyz" {
		t.Errorf("Details[dpu_id] = %q, want %q", e.Details["dpu_id"], "dpu_xyz")
	}
}

func TestNewAttestationBypass(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewAttestationBypass captures DPU ID and bypass reason")

	e := NewAttestationBypass("adm_super", "10.0.0.8", "dpu_stale", "maintenance window", "req-9")

	if e.Type != EventAttestationBypass {
		t.Errorf("Type = %q, want %q", e.Type, EventAttestationBypass)
	}
	if e.Severity != SeverityWarning {
		t.Errorf("Severity = %d, want %d (WARNING)", e.Severity, SeverityWarning)
	}
	if e.Details["dpu_id"] != "dpu_stale" {
		t.Errorf("Details[dpu_id] = %q, want %q", e.Details["dpu_id"], "dpu_stale")
	}
	if e.Details["bypass_reason"] != "maintenance window" {
		t.Errorf("Details[bypass_reason] = %q, want %q", e.Details["bypass_reason"], "maintenance window")
	}
}

func TestNewBootstrapComplete(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewBootstrapComplete uses NOTICE severity")

	e := NewBootstrapComplete("adm_first", "10.0.0.9", "req-10")

	if e.Type != EventBootstrapComplete {
		t.Errorf("Type = %q, want %q", e.Type, EventBootstrapComplete)
	}
	if e.Severity != SeverityNotice {
		t.Errorf("Severity = %d, want %d (NOTICE)", e.Severity, SeverityNotice)
	}
	if e.ActorID != "adm_first" {
		t.Errorf("ActorID = %q, want %q", e.ActorID, "adm_first")
	}
}

func TestAllHelpers_SetTimestamp(t *testing.T) {
	t.Parallel()
	t.Log("Verifying all helper functions set a non-zero timestamp")

	events := []Event{
		NewAuthSuccess("a", "1.2.3.4", "GET", "/", "r", 0),
		NewAuthFailure("a", "1.2.3.4", "bad", "GET", "/", "r"),
		NewEnrollComplete("a", "1.2.3.4", "r"),
		NewEnrollFailure("1.2.3.4", "bad", "r"),
		NewLifecycleRevoke("a", "1.2.3.4", "k", "r"),
		NewLifecycleSuspend("a", "1.2.3.4", "o", "r"),
		NewLifecycleUnsuspend("a", "1.2.3.4", "o", "r"),
		NewLifecycleDecommission("a", "1.2.3.4", "d", "r"),
		NewAttestationBypass("a", "1.2.3.4", "d", "reason", "r"),
		NewBootstrapComplete("a", "1.2.3.4", "r"),
	}

	for _, e := range events {
		if e.Timestamp.IsZero() {
			t.Errorf("Event %q has zero timestamp", e.Type)
		}
	}
}

func TestAllHelpers_SeverityMatchesMapping(t *testing.T) {
	t.Parallel()
	t.Log("Verifying each helper's embedded severity matches SeverityFor()")

	events := []Event{
		NewAuthSuccess("a", "1.2.3.4", "GET", "/", "r", 0),
		NewAuthFailure("a", "1.2.3.4", "bad", "GET", "/", "r"),
		NewEnrollComplete("a", "1.2.3.4", "r"),
		NewEnrollFailure("1.2.3.4", "bad", "r"),
		NewLifecycleRevoke("a", "1.2.3.4", "k", "r"),
		NewLifecycleSuspend("a", "1.2.3.4", "o", "r"),
		NewLifecycleUnsuspend("a", "1.2.3.4", "o", "r"),
		NewLifecycleDecommission("a", "1.2.3.4", "d", "r"),
		NewAttestationBypass("a", "1.2.3.4", "d", "reason", "r"),
		NewBootstrapComplete("a", "1.2.3.4", "r"),
	}

	for _, e := range events {
		expected := SeverityFor(e.Type)
		if e.Severity != expected {
			t.Errorf("Event %q: helper severity %d != SeverityFor() %d",
				e.Type, e.Severity, expected)
		}
	}
}
