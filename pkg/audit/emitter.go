package audit

import (
	"log/slog"
)

// EventEmitter accepts structured audit events for recording.
type EventEmitter interface {
	Emit(Event) error
}

// NopEmitter discards all events. Use when no audit backend is configured.
type NopEmitter struct{}

// Emit discards the event.
func (NopEmitter) Emit(Event) error { return nil }

// AuthEventEmitter bridges the DPoP middleware's AuditEmitter interface
// (defined in pkg/dpop to avoid import cycles) with audit.Event constructors
// and one or more EventEmitter backends. It satisfies dpop.AuditEmitter
// through Go's structural typing without importing pkg/dpop.
type AuthEventEmitter struct {
	backends []EventEmitter
	logger   *slog.Logger
}

// NewAuthEventEmitter creates an emitter that forwards auth events to the given backends.
// If logger is nil, slog.Default() is used for error reporting.
func NewAuthEventEmitter(logger *slog.Logger, backends ...EventEmitter) *AuthEventEmitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuthEventEmitter{
		backends: backends,
		logger:   logger,
	}
}

// EmitAuthSuccess creates an auth.success Event and writes it to all backends.
// Errors are logged but do not propagate; audit failures must not block requests.
func (e *AuthEventEmitter) EmitAuthSuccess(kid, ip, method, path string, latencyMS int64) {
	ev := NewAuthSuccess(kid, ip, method, path, "", latencyMS)
	for _, b := range e.backends {
		if err := b.Emit(ev); err != nil {
			e.logger.Error("audit emit failed", "event", "auth.success", "error", err)
		}
	}
}

// EmitAuthFailure creates an auth.failure Event and writes it to all backends.
// Errors are logged but do not propagate; audit failures must not block requests.
func (e *AuthEventEmitter) EmitAuthFailure(kid, ip, reason, method, path string) {
	ev := NewAuthFailure(kid, ip, reason, method, path, "")
	for _, b := range e.backends {
		if err := b.Emit(ev); err != nil {
			e.logger.Error("audit emit failed", "event", "auth.failure", "error", err)
		}
	}
}
