// Package store provides SQLite-based storage for DPU registry.
// This file contains methods for credential queue persistence (aegis state persistence).
package store

import (
	"database/sql"
	"fmt"
	"time"
)

// QueuedCredential represents a credential waiting to be delivered to a host.
type QueuedCredential struct {
	ID        int64
	DPUName   string
	CredType  string
	CredName  string
	Data      []byte
	QueuedAt  time.Time
}

// QueueCredential adds a credential to the queue for a specific DPU.
func (s *Store) QueueCredential(dpuName, credType, credName string, data []byte) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(
		`INSERT INTO credential_queue (dpu_name, cred_type, cred_name, data, queued_at)
		VALUES (?, ?, ?, ?, ?)`,
		dpuName, credType, credName, data, now,
	)
	if err != nil {
		return fmt.Errorf("failed to queue credential: %w", err)
	}
	return nil
}

// GetQueuedCredentials returns all queued credentials for a specific DPU.
// This does NOT clear the queue; use ClearQueuedCredentials after successful delivery.
func (s *Store) GetQueuedCredentials(dpuName string) ([]*QueuedCredential, error) {
	rows, err := s.db.Query(
		`SELECT id, dpu_name, cred_type, cred_name, data, queued_at
		FROM credential_queue
		WHERE dpu_name = ?
		ORDER BY queued_at`,
		dpuName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get queued credentials: %w", err)
	}
	defer rows.Close()

	var creds []*QueuedCredential
	for rows.Next() {
		var c QueuedCredential
		var queuedAt int64
		err := rows.Scan(&c.ID, &c.DPUName, &c.CredType, &c.CredName, &c.Data, &queuedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan queued credential: %w", err)
		}
		c.QueuedAt = time.Unix(queuedAt, 0)
		creds = append(creds, &c)
	}
	return creds, rows.Err()
}

// ClearQueuedCredentials removes all queued credentials for a specific DPU.
func (s *Store) ClearQueuedCredentials(dpuName string) error {
	_, err := s.db.Exec(
		`DELETE FROM credential_queue WHERE dpu_name = ?`,
		dpuName,
	)
	if err != nil {
		return fmt.Errorf("failed to clear credential queue: %w", err)
	}
	return nil
}

// ClearQueuedCredential removes a specific credential from the queue by ID.
func (s *Store) ClearQueuedCredential(id int64) error {
	result, err := s.db.Exec(
		`DELETE FROM credential_queue WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to clear queued credential: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("queued credential not found: %d", id)
	}
	return nil
}

// CountQueuedCredentials returns the number of queued credentials for a DPU.
func (s *Store) CountQueuedCredentials(dpuName string) (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM credential_queue WHERE dpu_name = ?`,
		dpuName,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count queued credentials: %w", err)
	}
	return count, nil
}

// UpdateAgentHostByDPU updates or creates an agent host record for the given DPU.
// If a host already exists for this DPU, it updates the hostname and ID.
// This is used by aegis to persist pairing state.
func (s *Store) UpdateAgentHostByDPU(dpuName, dpuID, hostname, hostID string) error {
	// Check if a host already exists for this DPU
	row := s.db.QueryRow(
		`SELECT id FROM agent_hosts WHERE dpu_name = ?`,
		dpuName,
	)
	var existingID string
	err := row.Scan(&existingID)

	now := time.Now().Unix()

	if err == sql.ErrNoRows {
		// No existing host, create new
		_, err := s.db.Exec(
			`INSERT INTO agent_hosts (id, dpu_name, dpu_id, hostname, registered_at, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			hostID, dpuName, dpuID, hostname, now, now,
		)
		if err != nil {
			return fmt.Errorf("failed to create agent host: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to query agent host: %w", err)
	}

	// Update existing host
	_, err = s.db.Exec(
		`UPDATE agent_hosts SET hostname = ?, last_seen_at = ? WHERE dpu_name = ?`,
		hostname, now, dpuName,
	)
	if err != nil {
		return fmt.Errorf("failed to update agent host: %w", err)
	}
	return nil
}
