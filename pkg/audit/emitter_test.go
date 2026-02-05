package audit

import (
	"log/slog"
	"sync"
	"testing"
)

// recordingEmitter captures emitted events for test verification.
type recordingEmitter struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingEmitter) Emit(ev Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func (r *recordingEmitter) last() Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.events[len(r.events)-1]
}

func (r *recordingEmitter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func TestBypassEventEmitter_EmitAttestationBypass(t *testing.T) {
	t.Parallel()
	t.Log("Verifying BypassEventEmitter constructs and emits attestation.bypass event")

	rec := &recordingEmitter{}
	emitter := NewBypassEventEmitter(slog.Default(), rec)

	t.Log("Emitting attestation bypass for stale DPU")
	emitter.EmitAttestationBypass(
		"adm_super1",
		"192.168.1.100",
		"dpu_target1",
		"maintenance window",
		"stale",
		"req-bypass-1",
	)

	if rec.count() != 1 {
		t.Fatalf("expected 1 event, got %d", rec.count())
	}

	ev := rec.last()
	if ev.Type != EventAttestationBypass {
		t.Errorf("Type = %q, want %q", ev.Type, EventAttestationBypass)
	}
	if ev.Severity != SeverityWarning {
		t.Errorf("Severity = %d, want %d (WARNING)", ev.Severity, SeverityWarning)
	}
	if ev.ActorID != "adm_super1" {
		t.Errorf("ActorID = %q, want %q", ev.ActorID, "adm_super1")
	}
	if ev.IP != "192.168.1.100" {
		t.Errorf("IP = %q, want %q", ev.IP, "192.168.1.100")
	}
	if ev.RequestID != "req-bypass-1" {
		t.Errorf("RequestID = %q, want %q", ev.RequestID, "req-bypass-1")
	}
	if ev.Details["dpu_id"] != "dpu_target1" {
		t.Errorf("Details[dpu_id] = %q, want %q", ev.Details["dpu_id"], "dpu_target1")
	}
	if ev.Details["operator_id"] != "adm_super1" {
		t.Errorf("Details[operator_id] = %q, want %q", ev.Details["operator_id"], "adm_super1")
	}
	if ev.Details["bypass_reason"] != "maintenance window" {
		t.Errorf("Details[bypass_reason] = %q, want %q", ev.Details["bypass_reason"], "maintenance window")
	}
	if ev.Details["attestation_status"] != "stale" {
		t.Errorf("Details[attestation_status] = %q, want %q", ev.Details["attestation_status"], "stale")
	}
}

func TestBypassEventEmitter_MultipleBackends(t *testing.T) {
	t.Parallel()
	t.Log("Verifying BypassEventEmitter forwards to all backends")

	rec1 := &recordingEmitter{}
	rec2 := &recordingEmitter{}
	emitter := NewBypassEventEmitter(slog.Default(), rec1, rec2)

	t.Log("Emitting attestation bypass with two backends")
	emitter.EmitAttestationBypass("adm_x", "10.0.0.1", "dpu_y", "emergency", "unavailable", "req-2")

	if rec1.count() != 1 {
		t.Errorf("backend 1: expected 1 event, got %d", rec1.count())
	}
	if rec2.count() != 1 {
		t.Errorf("backend 2: expected 1 event, got %d", rec2.count())
	}

	// Both should have the same event type
	if rec1.last().Type != EventAttestationBypass {
		t.Errorf("backend 1: Type = %q, want %q", rec1.last().Type, EventAttestationBypass)
	}
	if rec2.last().Type != EventAttestationBypass {
		t.Errorf("backend 2: Type = %q, want %q", rec2.last().Type, EventAttestationBypass)
	}
}

func TestBypassEventEmitter_NilLogger(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NewBypassEventEmitter accepts nil logger without panic")

	rec := &recordingEmitter{}
	emitter := NewBypassEventEmitter(nil, rec)
	emitter.EmitAttestationBypass("a", "1.2.3.4", "d", "reason", "stale", "r")

	if rec.count() != 1 {
		t.Errorf("expected 1 event, got %d", rec.count())
	}
}

func TestAuthEventEmitter_EmitAuthSuccess(t *testing.T) {
	t.Parallel()
	t.Log("Verifying AuthEventEmitter constructs and emits auth.success event")

	rec := &recordingEmitter{}
	emitter := NewAuthEventEmitter(slog.Default(), rec)

	emitter.EmitAuthSuccess("km_abc", "10.0.0.1", "POST", "/api/v1/push", 42)

	if rec.count() != 1 {
		t.Fatalf("expected 1 event, got %d", rec.count())
	}

	ev := rec.last()
	if ev.Type != EventAuthSuccess {
		t.Errorf("Type = %q, want %q", ev.Type, EventAuthSuccess)
	}
	if ev.ActorID != "km_abc" {
		t.Errorf("ActorID = %q, want %q", ev.ActorID, "km_abc")
	}
}

func TestAuthEventEmitter_EmitAuthFailure(t *testing.T) {
	t.Parallel()
	t.Log("Verifying AuthEventEmitter constructs and emits auth.failure event")

	rec := &recordingEmitter{}
	emitter := NewAuthEventEmitter(slog.Default(), rec)

	emitter.EmitAuthFailure("km_bad", "10.0.0.2", "invalid_sig", "GET", "/api/v1/protected")

	if rec.count() != 1 {
		t.Fatalf("expected 1 event, got %d", rec.count())
	}

	ev := rec.last()
	if ev.Type != EventAuthFailure {
		t.Errorf("Type = %q, want %q", ev.Type, EventAuthFailure)
	}
	if ev.Details["reason"] != "invalid_sig" {
		t.Errorf("Details[reason] = %q, want %q", ev.Details["reason"], "invalid_sig")
	}
}

func TestNopEmitter_Discard(t *testing.T) {
	t.Parallel()
	t.Log("Verifying NopEmitter discards events without error")

	err := NopEmitter{}.Emit(Event{Type: EventAuthSuccess})
	if err != nil {
		t.Errorf("NopEmitter.Emit returned error: %v", err)
	}
}
