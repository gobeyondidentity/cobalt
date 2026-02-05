package audit

import "time"

// Severity represents syslog severity levels per RFC 5424.
type Severity int

const (
	SeverityWarning Severity = 4
	SeverityNotice  Severity = 5
	SeverityInfo    Severity = 6
)

// String returns the human-readable name for a severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityNotice:
		return "NOTICE"
	case SeverityWarning:
		return "WARNING"
	default:
		return "UNKNOWN"
	}
}

// EventType identifies a security-relevant audit event.
type EventType string

const (
	EventAuthSuccess            EventType = "auth.success"
	EventAuthFailure            EventType = "auth.failure"
	EventEnrollComplete         EventType = "enroll.complete"
	EventEnrollFailure          EventType = "enroll.failure"
	EventLifecycleRevoke        EventType = "lifecycle.revoke"
	EventLifecycleSuspend       EventType = "lifecycle.suspend"
	EventLifecycleUnsuspend     EventType = "lifecycle.unsuspend"
	EventLifecycleDecommission  EventType = "lifecycle.decommission"
	EventAttestationBypass      EventType = "attestation.bypass"
	EventBootstrapComplete      EventType = "bootstrap.complete"
)

// AllEventTypes returns every defined event type for iteration and validation.
func AllEventTypes() []EventType {
	return []EventType{
		EventAuthSuccess,
		EventAuthFailure,
		EventEnrollComplete,
		EventEnrollFailure,
		EventLifecycleRevoke,
		EventLifecycleSuspend,
		EventLifecycleUnsuspend,
		EventLifecycleDecommission,
		EventAttestationBypass,
		EventBootstrapComplete,
	}
}

// severityMap maps each event type to its syslog severity per security-architecture.md Section 8.
var severityMap = map[EventType]Severity{
	EventAuthSuccess:           SeverityInfo,    // 6
	EventAuthFailure:           SeverityWarning, // 4
	EventEnrollComplete:        SeverityNotice,  // 5
	EventEnrollFailure:         SeverityWarning, // 4
	EventLifecycleRevoke:       SeverityWarning, // 4
	EventLifecycleSuspend:      SeverityWarning, // 4
	EventLifecycleUnsuspend:    SeverityNotice,  // 5
	EventLifecycleDecommission: SeverityWarning, // 4
	EventAttestationBypass:     SeverityWarning, // 4
	EventBootstrapComplete:     SeverityNotice,  // 5
}

// SeverityFor returns the syslog severity for a given event type.
// Unknown event types return SeverityWarning (fail-secure: treat unknowns as concerning).
func SeverityFor(et EventType) Severity {
	if s, ok := severityMap[et]; ok {
		return s
	}
	return SeverityWarning
}

// Event represents a security-relevant audit event with structured fields.
type Event struct {
	Type      EventType
	Severity  Severity
	Timestamp time.Time
	ActorID   string            // kid, operator_id, or dpu_id depending on event
	IP        string            // Client IP address
	RequestID string            // Correlation ID for request tracing
	Details   map[string]string // Event-specific fields
}

// NewAuthSuccess creates an auth.success event for accepted DPoP proofs.
func NewAuthSuccess(actorID, ip, method, path, requestID string, latencyMS int64) Event {
	return Event{
		Type:      EventAuthSuccess,
		Severity:  SeverityInfo,
		Timestamp: time.Now(),
		ActorID:   actorID,
		IP:        ip,
		RequestID: requestID,
		Details: map[string]string{
			"method":     method,
			"path":       path,
			"latency_ms": formatInt(latencyMS),
		},
	}
}

// NewAuthFailure creates an auth.failure event for rejected authentication.
func NewAuthFailure(actorID, ip, reason, method, path, requestID string) Event {
	return Event{
		Type:      EventAuthFailure,
		Severity:  SeverityWarning,
		Timestamp: time.Now(),
		ActorID:   actorID,
		IP:        ip,
		RequestID: requestID,
		Details: map[string]string{
			"reason": reason,
			"method": method,
			"path":   path,
		},
	}
}

// NewEnrollComplete creates an enroll.complete event for successful enrollments.
func NewEnrollComplete(actorID, ip, requestID string) Event {
	return Event{
		Type:      EventEnrollComplete,
		Severity:  SeverityNotice,
		Timestamp: time.Now(),
		ActorID:   actorID,
		IP:        ip,
		RequestID: requestID,
		Details:   map[string]string{},
	}
}

// NewEnrollFailure creates an enroll.failure event for failed enrollment attempts.
func NewEnrollFailure(ip, reason, requestID string) Event {
	return Event{
		Type:      EventEnrollFailure,
		Severity:  SeverityWarning,
		Timestamp: time.Now(),
		IP:        ip,
		RequestID: requestID,
		Details: map[string]string{
			"reason": reason,
		},
	}
}

// NewLifecycleRevoke creates a lifecycle.revoke event for key revocations.
func NewLifecycleRevoke(actorID, ip, revokedKeyID, requestID string) Event {
	return Event{
		Type:      EventLifecycleRevoke,
		Severity:  SeverityWarning,
		Timestamp: time.Now(),
		ActorID:   actorID,
		IP:        ip,
		RequestID: requestID,
		Details: map[string]string{
			"revoked_key_id": revokedKeyID,
		},
	}
}

// NewLifecycleSuspend creates a lifecycle.suspend event for operator suspensions.
func NewLifecycleSuspend(actorID, ip, operatorID, requestID string) Event {
	return Event{
		Type:      EventLifecycleSuspend,
		Severity:  SeverityWarning,
		Timestamp: time.Now(),
		ActorID:   actorID,
		IP:        ip,
		RequestID: requestID,
		Details: map[string]string{
			"operator_id": operatorID,
		},
	}
}

// NewLifecycleUnsuspend creates a lifecycle.unsuspend event for operator unsuspensions.
func NewLifecycleUnsuspend(actorID, ip, operatorID, requestID string) Event {
	return Event{
		Type:      EventLifecycleUnsuspend,
		Severity:  SeverityNotice,
		Timestamp: time.Now(),
		ActorID:   actorID,
		IP:        ip,
		RequestID: requestID,
		Details: map[string]string{
			"operator_id": operatorID,
		},
	}
}

// NewLifecycleDecommission creates a lifecycle.decommission event for DPU decommissions.
func NewLifecycleDecommission(actorID, ip, dpuID, requestID string) Event {
	return Event{
		Type:      EventLifecycleDecommission,
		Severity:  SeverityWarning,
		Timestamp: time.Now(),
		ActorID:   actorID,
		IP:        ip,
		RequestID: requestID,
		Details: map[string]string{
			"dpu_id": dpuID,
		},
	}
}

// NewAttestationBypass creates an attestation.bypass event for force bypass usage.
func NewAttestationBypass(actorID, ip, dpuID, bypassReason, requestID string) Event {
	return Event{
		Type:      EventAttestationBypass,
		Severity:  SeverityWarning,
		Timestamp: time.Now(),
		ActorID:   actorID,
		IP:        ip,
		RequestID: requestID,
		Details: map[string]string{
			"dpu_id":        dpuID,
			"bypass_reason": bypassReason,
		},
	}
}

// NewBootstrapComplete creates a bootstrap.complete event for first admin enrollment.
func NewBootstrapComplete(actorID, ip, requestID string) Event {
	return Event{
		Type:      EventBootstrapComplete,
		Severity:  SeverityNotice,
		Timestamp: time.Now(),
		ActorID:   actorID,
		IP:        ip,
		RequestID: requestID,
		Details:   map[string]string{},
	}
}

// formatInt converts an int64 to its string representation.
func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
