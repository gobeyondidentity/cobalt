// Package store provides SQLite-based storage for DPU registry.
// This file contains methods for enrollment session management.
package store

import (
	"database/sql"
	"fmt"
	"time"
)

// EnrollmentSession represents a challenge-response enrollment session.
type EnrollmentSession struct {
	ID            string
	SessionType   string  // bootstrap, operator, dpu
	ChallengeHash string  // SHA256 of challenge
	PublicKeyB64  *string // Optional, set on bootstrap init
	InviteCodeID  *string // Optional, set for operator enrollment
	IPAddress     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// CreateEnrollmentSession stores a new enrollment session.
func (s *Store) CreateEnrollmentSession(session *EnrollmentSession) error {
	_, err := s.db.Exec(
		`INSERT INTO enrollment_sessions (id, session_type, challenge_hash, public_key_b64, invite_code_id, ip_address, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.SessionType, session.ChallengeHash, session.PublicKeyB64,
		session.InviteCodeID, session.IPAddress, session.CreatedAt.Unix(), session.ExpiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to create enrollment session: %w", err)
	}
	return nil
}

// GetEnrollmentSession retrieves an enrollment session by ID.
// Returns nil if the session does not exist.
func (s *Store) GetEnrollmentSession(id string) (*EnrollmentSession, error) {
	row := s.db.QueryRow(
		`SELECT id, session_type, challenge_hash, public_key_b64, invite_code_id, ip_address, created_at, expires_at
		 FROM enrollment_sessions WHERE id = ?`,
		id,
	)

	var session EnrollmentSession
	var publicKeyB64 sql.NullString
	var inviteCodeID sql.NullString
	var ipAddress sql.NullString
	var createdAt, expiresAt int64

	err := row.Scan(&session.ID, &session.SessionType, &session.ChallengeHash,
		&publicKeyB64, &inviteCodeID, &ipAddress, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get enrollment session: %w", err)
	}

	if publicKeyB64.Valid {
		session.PublicKeyB64 = &publicKeyB64.String
	}
	if inviteCodeID.Valid {
		session.InviteCodeID = &inviteCodeID.String
	}
	if ipAddress.Valid {
		session.IPAddress = ipAddress.String
	}
	session.CreatedAt = time.Unix(createdAt, 0)
	session.ExpiresAt = time.Unix(expiresAt, 0)

	return &session, nil
}

// DeleteEnrollmentSession removes an enrollment session by ID.
// This operation is idempotent; it succeeds even if the session doesn't exist.
func (s *Store) DeleteEnrollmentSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM enrollment_sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete enrollment session: %w", err)
	}
	return nil
}

// CleanupExpiredSessions deletes all expired enrollment sessions.
// Returns the count of deleted sessions.
func (s *Store) CleanupExpiredSessions() (int64, error) {
	now := time.Now().Unix()
	result, err := s.db.Exec(`DELETE FROM enrollment_sessions WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get cleanup count: %w", err)
	}

	return count, nil
}
