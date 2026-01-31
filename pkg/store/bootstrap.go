// Package store provides SQLite-based storage for DPU registry.
// This file contains methods for bootstrap state management.
package store

import (
	"database/sql"
	"fmt"
	"time"
)

// BootstrapState represents the bootstrap window state for first-admin enrollment.
type BootstrapState struct {
	WindowOpenedAt time.Time
	CompletedAt    *time.Time
	FirstAdminID   *string
}

// GetBootstrapState retrieves the current bootstrap state.
// Returns nil if no bootstrap window has been initialized.
func (s *Store) GetBootstrapState() (*BootstrapState, error) {
	row := s.db.QueryRow(`SELECT window_opened_at, completed_at, first_admin_id FROM bootstrap_state WHERE id = 1`)

	var windowOpenedAt int64
	var completedAt sql.NullInt64
	var firstAdminID sql.NullString

	err := row.Scan(&windowOpenedAt, &completedAt, &firstAdminID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap state: %w", err)
	}

	state := &BootstrapState{
		WindowOpenedAt: time.Unix(windowOpenedAt, 0),
	}

	if completedAt.Valid {
		t := time.Unix(completedAt.Int64, 0)
		state.CompletedAt = &t
	}

	if firstAdminID.Valid {
		state.FirstAdminID = &firstAdminID.String
	}

	return state, nil
}

// InitBootstrapWindow initializes a new bootstrap window.
// Returns an error if a bootstrap window already exists.
func (s *Store) InitBootstrapWindow() error {
	// Check if bootstrap state already exists
	existing, err := s.GetBootstrapState()
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("bootstrap window already exists")
	}

	now := time.Now().Unix()
	_, err = s.db.Exec(`INSERT INTO bootstrap_state (id, window_opened_at) VALUES (1, ?)`, now)
	if err != nil {
		return fmt.Errorf("failed to initialize bootstrap window: %w", err)
	}

	return nil
}

// CompleteBootstrap marks the bootstrap as complete with the first admin ID.
// Returns an error if bootstrap window doesn't exist or is already completed.
func (s *Store) CompleteBootstrap(adminID string) error {
	// Check current state
	state, err := s.GetBootstrapState()
	if err != nil {
		return err
	}
	if state == nil {
		return fmt.Errorf("bootstrap state not found")
	}
	if state.CompletedAt != nil {
		return fmt.Errorf("bootstrap already completed")
	}

	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE bootstrap_state SET completed_at = ?, first_admin_id = ? WHERE id = 1 AND completed_at IS NULL`,
		now, adminID,
	)
	if err != nil {
		return fmt.Errorf("failed to complete bootstrap: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("bootstrap already completed")
	}

	return nil
}

// ResetBootstrapWindow deletes the bootstrap state.
// This is used when no admin enrolled and the window expired, allowing restart.
// This operation is idempotent; it succeeds even if no state exists.
func (s *Store) ResetBootstrapWindow() error {
	_, err := s.db.Exec(`DELETE FROM bootstrap_state WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("failed to reset bootstrap window: %w", err)
	}
	return nil
}

// HasFirstAdmin returns true if a first admin has been enrolled.
func (s *Store) HasFirstAdmin() (bool, error) {
	state, err := s.GetBootstrapState()
	if err != nil {
		return false, err
	}
	if state == nil {
		return false, nil
	}
	return state.FirstAdminID != nil, nil
}
