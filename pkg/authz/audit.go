package authz

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// AuthzAuditEntry represents a single authorization decision for audit logging.
// All authorization decisions flow through this structure for compliance tracking.
type AuthzAuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	RequestID   string    `json:"request_id"`
	Principal   string    `json:"principal"`
	PrincipalType string  `json:"principal_type"`
	Role        string    `json:"role"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	ResourceType string   `json:"resource_type"`
	TenantID    string    `json:"tenant_id,omitempty"`
	Decision    string    `json:"decision"` // "allow" or "deny"
	Reason      string    `json:"reason"`
	PolicyID    string    `json:"policy_id,omitempty"`
	DurationUS  int64     `json:"duration_us"` // Microseconds

	// Force bypass fields (only populated when bypass used)
	ForceBypass       bool   `json:"force_bypass,omitempty"`
	BypassReason      string `json:"bypass_reason,omitempty"`
	AttestationStatus string `json:"attestation_status,omitempty"`
}

// AuditLogger records authorization decisions for compliance and forensics.
type AuditLogger interface {
	// LogDecision records an authorization decision.
	LogDecision(ctx context.Context, entry AuthzAuditEntry) error
}

// StoreAuditLogger writes authorization decisions to the store's audit log.
type StoreAuditLogger struct {
	store AuditStore
}

// AuditStore is the interface for storing audit entries.
// Matches the methods from pkg/store.Store that we need.
type AuditStore interface {
	InsertAuditEntry(entry *AuditEntry) (int64, error)
}

// AuditEntry matches the store.AuditEntry structure.
type AuditEntry struct {
	Timestamp time.Time
	Action    string
	Target    string
	Decision  string
	Details   map[string]string
}

// NewStoreAuditLogger creates an audit logger that writes to the store.
func NewStoreAuditLogger(store AuditStore) *StoreAuditLogger {
	return &StoreAuditLogger{store: store}
}

// LogDecision writes an authorization decision to the audit log.
func (l *StoreAuditLogger) LogDecision(ctx context.Context, entry AuthzAuditEntry) error {
	details := map[string]string{
		"principal":      entry.Principal,
		"principal_type": entry.PrincipalType,
		"role":           entry.Role,
		"action":         entry.Action,
		"resource":       entry.Resource,
		"resource_type":  entry.ResourceType,
		"reason":         entry.Reason,
		"duration_us":    formatInt64(entry.DurationUS),
	}

	if entry.RequestID != "" {
		details["request_id"] = entry.RequestID
	}
	if entry.TenantID != "" {
		details["tenant_id"] = entry.TenantID
	}
	if entry.PolicyID != "" {
		details["policy_id"] = entry.PolicyID
	}
	if entry.ForceBypass {
		details["force_bypass"] = "true"
		details["bypass_reason"] = entry.BypassReason
		details["attestation_status"] = entry.AttestationStatus
	}

	storeEntry := &AuditEntry{
		Timestamp: entry.Timestamp,
		Action:    "authorization_decision",
		Target:    entry.Resource,
		Decision:  entry.Decision,
		Details:   details,
	}

	_, err := l.store.InsertAuditEntry(storeEntry)
	return err
}

// formatInt64 converts int64 to string for JSON storage.
func formatInt64(n int64) string {
	return json.Number(json.Number(formatInt64Raw(n))).String()
}

func formatInt64Raw(n int64) string {
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
	// Reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

// SlogAuditLogger writes authorization decisions to structured logging.
// Use this for JSON log output compatible with SIEM/log aggregation tools.
type SlogAuditLogger struct {
	logger *slog.Logger
}

// NewSlogAuditLogger creates an audit logger that writes to slog.
func NewSlogAuditLogger(logger *slog.Logger) *SlogAuditLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &SlogAuditLogger{logger: logger}
}

// LogDecision writes an authorization decision to structured logging.
func (l *SlogAuditLogger) LogDecision(ctx context.Context, entry AuthzAuditEntry) error {
	level := slog.LevelInfo
	if entry.ForceBypass {
		level = slog.LevelWarn
	}

	attrs := []slog.Attr{
		slog.String("event", "authorization_decision"),
		slog.Time("timestamp", entry.Timestamp),
		slog.String("request_id", entry.RequestID),
		slog.String("principal", entry.Principal),
		slog.String("principal_type", entry.PrincipalType),
		slog.String("role", entry.Role),
		slog.String("action", entry.Action),
		slog.String("resource", entry.Resource),
		slog.String("resource_type", entry.ResourceType),
		slog.String("decision", entry.Decision),
		slog.String("reason", entry.Reason),
		slog.String("policy_id", entry.PolicyID),
		slog.Int64("duration_us", entry.DurationUS),
	}

	if entry.TenantID != "" {
		attrs = append(attrs, slog.String("tenant_id", entry.TenantID))
	}

	if entry.ForceBypass {
		attrs = append(attrs,
			slog.Bool("force_bypass", true),
			slog.String("bypass_reason", entry.BypassReason),
			slog.String("attestation_status", entry.AttestationStatus),
		)
	}

	l.logger.LogAttrs(ctx, level, "authorization decision", attrs...)
	return nil
}

// MultiAuditLogger writes to multiple audit loggers.
type MultiAuditLogger struct {
	loggers []AuditLogger
}

// NewMultiAuditLogger creates an audit logger that writes to multiple destinations.
func NewMultiAuditLogger(loggers ...AuditLogger) *MultiAuditLogger {
	return &MultiAuditLogger{loggers: loggers}
}

// LogDecision writes to all configured loggers.
func (l *MultiAuditLogger) LogDecision(ctx context.Context, entry AuthzAuditEntry) error {
	var firstErr error
	for _, logger := range l.loggers {
		if err := logger.LogDecision(ctx, entry); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// NopAuditLogger discards all audit entries. Use for testing.
type NopAuditLogger struct{}

// LogDecision does nothing.
func (NopAuditLogger) LogDecision(ctx context.Context, entry AuthzAuditEntry) error {
	return nil
}
