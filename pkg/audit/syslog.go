package audit

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/gobeyondidentity/cobalt/pkg/authz"
)

// SyslogAuditLogger writes authorization audit events to the local syslog daemon
// as RFC 5424 messages with structured data. It implements authz.AuditLogger
// and slots into the existing MultiAuditLogger composition pattern.
type SyslogAuditLogger struct {
	conn     net.Conn
	hostname string
	appName  string
	facility Facility
	mu       sync.Mutex
}

// SyslogConfig holds configuration for the syslog writer.
type SyslogConfig struct {
	SocketPath string   // Default: "/dev/log"
	Hostname   string   // Default: os.Hostname()
	AppName    string   // Default: "nexus"
	Facility   Facility // Default: FacLocal0
}

// NewSyslogWriter creates a SyslogAuditLogger that writes RFC 5424 messages
// to the local syslog daemon. Returns an error if the syslog socket is unavailable.
// Callers should degrade gracefully on error (SQLite-only audit is acceptable).
func NewSyslogWriter(cfg SyslogConfig) (*SyslogAuditLogger, error) {
	if cfg.SocketPath == "" {
		cfg.SocketPath = "/dev/log"
	}
	if cfg.Hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			cfg.Hostname = "unknown"
		} else {
			cfg.Hostname = h
		}
	}
	if cfg.AppName == "" {
		cfg.AppName = "nexus"
	}
	if cfg.Facility == 0 {
		cfg.Facility = FacLocal0
	}

	conn, err := dialSyslog(cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("syslog connect: %w", err)
	}

	return &SyslogAuditLogger{
		conn:     conn,
		hostname: cfg.Hostname,
		appName:  cfg.AppName,
		facility: cfg.Facility,
	}, nil
}

// LogDecision converts an authorization audit entry to an RFC 5424 message
// and writes it to the syslog socket. Implements authz.AuditLogger.
func (w *SyslogAuditLogger) LogDecision(_ context.Context, entry authz.AuthzAuditEntry) error {
	eventType, severity := deriveEventType(entry)

	params := []SDParam{
		{Name: "principal", Value: entry.Principal},
		{Name: "action", Value: entry.Action},
		{Name: "resource", Value: entry.Resource},
		{Name: "decision", Value: entry.Decision},
	}

	if entry.RequestID != "" {
		params = append(params, SDParam{Name: "request_id", Value: entry.RequestID})
	}
	if entry.PrincipalType != "" {
		params = append(params, SDParam{Name: "principal_type", Value: entry.PrincipalType})
	}
	if entry.ResourceType != "" {
		params = append(params, SDParam{Name: "resource_type", Value: entry.ResourceType})
	}
	if entry.PolicyID != "" {
		params = append(params, SDParam{Name: "policy_id", Value: entry.PolicyID})
	}
	if entry.DurationUS > 0 {
		params = append(params, SDParam{Name: "latency_us", Value: strconv.FormatInt(entry.DurationUS, 10)})
	}
	if entry.ForceBypass {
		params = append(params, SDParam{Name: "bypass_reason", Value: entry.BypassReason})
		params = append(params, SDParam{Name: "attestation_status", Value: entry.AttestationStatus})
	}

	msg := Message{
		Facility:  w.facility,
		Severity:  severity,
		Timestamp: entry.Timestamp,
		Hostname:  w.hostname,
		AppName:   w.appName,
		MessageID: eventType,
		SD: []SDElement{{
			ID:     "cobalt",
			Params: params,
		}},
		Text: entry.Reason,
	}

	data := FormatMessage(msg)

	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.conn.Write(data)
	return err
}

// Emit converts an audit Event to an RFC 5424 message and writes it to the
// syslog socket. Implements EventEmitter for authentication events.
func (w *SyslogAuditLogger) Emit(ev Event) error {
	params := []SDParam{
		{Name: "actor_id", Value: ev.ActorID},
		{Name: "ip", Value: ev.IP},
	}
	if ev.RequestID != "" {
		params = append(params, SDParam{Name: "request_id", Value: ev.RequestID})
	}
	for k, v := range ev.Details {
		params = append(params, SDParam{Name: k, Value: v})
	}

	msg := Message{
		Facility:  w.facility,
		Severity:  ev.Severity,
		Timestamp: ev.Timestamp,
		Hostname:  w.hostname,
		AppName:   w.appName,
		MessageID: string(ev.Type),
		SD: []SDElement{{
			ID:     "cobalt",
			Params: params,
		}},
	}

	data := FormatMessage(msg)

	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.conn.Write(data)
	return err
}

// Close closes the syslog socket connection.
func (w *SyslogAuditLogger) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn.Close()
}

// deriveEventType maps an AuthzAuditEntry to an event type string and severity.
func deriveEventType(entry authz.AuthzAuditEntry) (string, Severity) {
	if entry.ForceBypass {
		return "attestation.bypass", SeverityWarning
	}
	switch entry.Decision {
	case "allow":
		return "auth.success", SeverityInfo
	case "deny":
		return "auth.failure", SeverityWarning
	default:
		return "auth.unknown", SeverityInfo
	}
}

// dialSyslog connects to the local syslog daemon. Tries unixgram (datagram) first,
// falls back to unix (stream) for compatibility with different syslog implementations.
func dialSyslog(socketPath string) (net.Conn, error) {
	conn, err := net.Dial("unixgram", socketPath)
	if err == nil {
		return conn, nil
	}
	return net.Dial("unix", socketPath)
}
