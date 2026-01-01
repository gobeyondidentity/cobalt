// Package store provides SQLite-based storage for audit logging.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuditEntry represents a single audit log record.
type AuditEntry struct {
	ID                  int64
	Timestamp           time.Time
	Action              string
	Target              string
	Decision            string
	AttestationSnapshot *AttestationSnapshot
	Details             map[string]string
}

// AttestationSnapshot captures attestation state at the time of an audit event.
type AttestationSnapshot struct {
	DPUName       string        `json:"dpu_name"`
	Status        string        `json:"status"`
	LastValidated time.Time     `json:"last_validated"`
	Age           time.Duration `json:"age"`
}

// AuditFilter specifies criteria for querying audit entries.
type AuditFilter struct {
	Action string
	Target string
	Since  time.Time
	Limit  int
}

// InsertAuditEntry adds a new audit log entry to the database.
func (s *Store) InsertAuditEntry(entry *AuditEntry) (int64, error) {
	var snapshotJSON sql.NullString
	if entry.AttestationSnapshot != nil {
		data, err := json.Marshal(entry.AttestationSnapshot)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal attestation snapshot: %w", err)
		}
		snapshotJSON.String = string(data)
		snapshotJSON.Valid = true
	}

	var detailsJSON sql.NullString
	if len(entry.Details) > 0 {
		data, err := json.Marshal(entry.Details)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal details: %w", err)
		}
		detailsJSON.String = string(data)
		detailsJSON.Valid = true
	}

	result, err := s.db.Exec(
		`INSERT INTO audit_log (timestamp, action, target, decision, attestation_snapshot, details)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		entry.Timestamp.Unix(),
		entry.Action,
		entry.Target,
		entry.Decision,
		snapshotJSON,
		detailsJSON,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to insert audit entry: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return id, nil
}

// QueryAuditEntries retrieves audit entries matching the given filter.
func (s *Store) QueryAuditEntries(filter AuditFilter) ([]*AuditEntry, error) {
	var conditions []string
	var args []interface{}

	if filter.Action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, filter.Action)
	}

	if filter.Target != "" {
		conditions = append(conditions, "target = ?")
		args = append(args, filter.Target)
	}

	if !filter.Since.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.Since.Unix())
	}

	query := `SELECT id, timestamp, action, target, decision, attestation_snapshot, details
	          FROM audit_log`

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit entries: %w", err)
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		entry, err := s.scanAuditEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// GetAuditEntry retrieves a single audit entry by ID.
func (s *Store) GetAuditEntry(id int64) (*AuditEntry, error) {
	row := s.db.QueryRow(
		`SELECT id, timestamp, action, target, decision, attestation_snapshot, details
		 FROM audit_log WHERE id = ?`,
		id,
	)

	var entry AuditEntry
	var timestamp int64
	var snapshotJSON, detailsJSON sql.NullString

	err := row.Scan(&entry.ID, &timestamp, &entry.Action, &entry.Target, &entry.Decision, &snapshotJSON, &detailsJSON)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("audit entry not found: %d", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan audit entry: %w", err)
	}

	entry.Timestamp = time.Unix(timestamp, 0)

	if snapshotJSON.Valid && snapshotJSON.String != "" {
		var snapshot AttestationSnapshot
		if err := json.Unmarshal([]byte(snapshotJSON.String), &snapshot); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attestation snapshot: %w", err)
		}
		entry.AttestationSnapshot = &snapshot
	}

	if detailsJSON.Valid && detailsJSON.String != "" {
		entry.Details = make(map[string]string)
		if err := json.Unmarshal([]byte(detailsJSON.String), &entry.Details); err != nil {
			return nil, fmt.Errorf("failed to unmarshal details: %w", err)
		}
	}

	return &entry, nil
}

func (s *Store) scanAuditEntry(rows *sql.Rows) (*AuditEntry, error) {
	var entry AuditEntry
	var timestamp int64
	var snapshotJSON, detailsJSON sql.NullString

	err := rows.Scan(&entry.ID, &timestamp, &entry.Action, &entry.Target, &entry.Decision, &snapshotJSON, &detailsJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to scan audit entry: %w", err)
	}

	entry.Timestamp = time.Unix(timestamp, 0)

	if snapshotJSON.Valid && snapshotJSON.String != "" {
		var snapshot AttestationSnapshot
		if err := json.Unmarshal([]byte(snapshotJSON.String), &snapshot); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attestation snapshot: %w", err)
		}
		entry.AttestationSnapshot = &snapshot
	}

	if detailsJSON.Valid && detailsJSON.String != "" {
		entry.Details = make(map[string]string)
		if err := json.Unmarshal([]byte(detailsJSON.String), &entry.Details); err != nil {
			return nil, fmt.Errorf("failed to unmarshal details: %w", err)
		}
	}

	return &entry, nil
}
