// Package store provides SQLite-based storage for DPU registry.
// This file contains methods for enrollment entities: EnrollmentSession, BootstrapState, and DPU enrollment expiration.
package store

import (
	"database/sql"
	"fmt"
	"time"
)

// ----- Enrollment Session Methods -----

// CreateEnrollmentSession stores a new enrollment session.
// For operator enrollment, inviteID is the invite code ID.
// For DPU enrollment, inviteID is nil.
func (s *Store) CreateEnrollmentSession(id string, inviteID *string, challenge string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO enrollment_sessions (id, invite_id, challenge, expires_at, status) VALUES (?, ?, ?, ?, 'pending')`,
		id, inviteID, challenge, expiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to create enrollment session: %w", err)
	}
	return nil
}

// GetEnrollmentSession retrieves an enrollment session by ID.
func (s *Store) GetEnrollmentSession(id string) (*EnrollmentSession, error) {
	row := s.db.QueryRow(
		`SELECT id, invite_id, challenge, created_at, expires_at, status FROM enrollment_sessions WHERE id = ?`,
		id,
	)
	return s.scanEnrollmentSession(row)
}

// CompleteEnrollmentSession atomically marks a session as completed.
// Returns error if session not pending (prevents concurrent completion).
// Uses: UPDATE ... WHERE status='pending' and checks affected rows.
func (s *Store) CompleteEnrollmentSession(id string) error {
	result, err := s.db.Exec(
		`UPDATE enrollment_sessions SET status = 'completed' WHERE id = ? AND status = 'pending'`,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to complete enrollment session: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("session not found or not pending")
	}
	return nil
}

// CleanupExpiredSessions marks expired sessions.
func (s *Store) CleanupExpiredSessions() error {
	now := time.Now().Unix()
	_, err := s.db.Exec(
		`UPDATE enrollment_sessions SET status = 'expired' WHERE status = 'pending' AND expires_at < ?`,
		now,
	)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	return nil
}

func (s *Store) scanEnrollmentSession(row *sql.Row) (*EnrollmentSession, error) {
	var es EnrollmentSession
	var inviteID sql.NullString
	var createdAt, expiresAt int64

	err := row.Scan(&es.ID, &inviteID, &es.Challenge, &createdAt, &expiresAt, &es.Status)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("enrollment session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan enrollment session: %w", err)
	}

	if inviteID.Valid {
		es.InviteID = &inviteID.String
	}
	es.CreatedAt = time.Unix(createdAt, 0)
	es.ExpiresAt = time.Unix(expiresAt, 0)

	return &es, nil
}

// ----- Bootstrap State Methods -----

// GetBootstrapState returns the bootstrap state, creating initial record if needed.
func (s *Store) GetBootstrapState() (*BootstrapState, error) {
	// Try to get existing record
	row := s.db.QueryRow(`SELECT id, first_start_at, completed_at FROM bootstrap_state WHERE id = 1`)

	var bs BootstrapState
	var firstStartAt int64
	var completedAt sql.NullInt64

	err := row.Scan(&bs.ID, &firstStartAt, &completedAt)
	if err == sql.ErrNoRows {
		// Create initial record
		now := time.Now().Unix()
		_, err = s.db.Exec(`INSERT INTO bootstrap_state (id, first_start_at) VALUES (1, ?)`, now)
		if err != nil {
			return nil, fmt.Errorf("failed to create bootstrap state: %w", err)
		}

		bs.ID = 1
		bs.FirstStartAt = time.Unix(now, 0)
		return &bs, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap state: %w", err)
	}

	bs.FirstStartAt = time.Unix(firstStartAt, 0)
	if completedAt.Valid {
		t := time.Unix(completedAt.Int64, 0)
		bs.CompletedAt = &t
	}

	return &bs, nil
}

// SetBootstrapCompleted marks bootstrap as complete.
func (s *Store) SetBootstrapCompleted() error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`UPDATE bootstrap_state SET completed_at = ? WHERE id = 1`, now)
	if err != nil {
		return fmt.Errorf("failed to set bootstrap completed: %w", err)
	}
	return nil
}

// ----- DPU Enrollment Expiration Methods -----

// SetDPUEnrollmentExpires sets the enrollment expiration for a DPU.
func (s *Store) SetDPUEnrollmentExpires(dpuID string, expiresAt time.Time) error {
	result, err := s.db.Exec(
		`UPDATE dpus SET enrollment_expires_at = ? WHERE id = ? OR name = ?`,
		expiresAt.Unix(), dpuID, dpuID,
	)
	if err != nil {
		return fmt.Errorf("failed to set DPU enrollment expiration: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("DPU not found: %s", dpuID)
	}
	return nil
}

// ClearDPUEnrollmentExpires clears the enrollment expiration (after successful enrollment).
func (s *Store) ClearDPUEnrollmentExpires(dpuID string) error {
	result, err := s.db.Exec(
		`UPDATE dpus SET enrollment_expires_at = NULL WHERE id = ? OR name = ?`,
		dpuID, dpuID,
	)
	if err != nil {
		return fmt.Errorf("failed to clear DPU enrollment expiration: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("DPU not found: %s", dpuID)
	}
	return nil
}
