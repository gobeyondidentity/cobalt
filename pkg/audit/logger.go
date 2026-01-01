// Package audit provides audit logging functionality for DPU operations.
package audit

import (
	"fmt"
	"time"

	"github.com/beyondidentity/fabric-console/pkg/store"
)

// AuditEntry represents a single audit log record.
type AuditEntry struct {
	ID                  int64
	Timestamp           time.Time
	Action              string // "gate_decision", "credential_distributed", "attestation_verified"
	Target              string // DPU name
	Decision            string // "allowed", "blocked", "forced"
	AttestationSnapshot *AttestationSnapshot
	Details             map[string]string
}

// AttestationSnapshot captures attestation state at the time of an audit event.
type AttestationSnapshot struct {
	DPUName       string
	Status        string
	LastValidated time.Time
	Age           time.Duration
}

// AuditFilter specifies criteria for querying audit entries.
type AuditFilter struct {
	Action string
	Target string
	Since  time.Time
	Limit  int
}

// Logger provides audit logging functionality backed by a Store.
type Logger struct {
	store *store.Store
}

// NewLogger creates a new audit Logger with the given store.
func NewLogger(s *store.Store) *Logger {
	return &Logger{store: s}
}

// Log writes an audit entry to the store.
func (l *Logger) Log(entry AuditEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	storeEntry := &store.AuditEntry{
		Timestamp: entry.Timestamp,
		Action:    entry.Action,
		Target:    entry.Target,
		Decision:  entry.Decision,
		Details:   entry.Details,
	}

	if entry.AttestationSnapshot != nil {
		storeEntry.AttestationSnapshot = &store.AttestationSnapshot{
			DPUName:       entry.AttestationSnapshot.DPUName,
			Status:        entry.AttestationSnapshot.Status,
			LastValidated: entry.AttestationSnapshot.LastValidated,
			Age:           entry.AttestationSnapshot.Age,
		}
	}

	_, err := l.store.InsertAuditEntry(storeEntry)
	if err != nil {
		return fmt.Errorf("failed to log audit entry: %w", err)
	}

	return nil
}

// Query retrieves audit entries matching the given filter.
func (l *Logger) Query(filter AuditFilter) ([]AuditEntry, error) {
	storeFilter := store.AuditFilter{
		Action: filter.Action,
		Target: filter.Target,
		Since:  filter.Since,
		Limit:  filter.Limit,
	}

	storeEntries, err := l.store.QueryAuditEntries(storeFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit entries: %w", err)
	}

	entries := make([]AuditEntry, 0, len(storeEntries))
	for _, se := range storeEntries {
		entry := AuditEntry{
			ID:        se.ID,
			Timestamp: se.Timestamp,
			Action:    se.Action,
			Target:    se.Target,
			Decision:  se.Decision,
			Details:   se.Details,
		}

		if se.AttestationSnapshot != nil {
			entry.AttestationSnapshot = &AttestationSnapshot{
				DPUName:       se.AttestationSnapshot.DPUName,
				Status:        se.AttestationSnapshot.Status,
				LastValidated: se.AttestationSnapshot.LastValidated,
				Age:           se.AttestationSnapshot.Age,
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
