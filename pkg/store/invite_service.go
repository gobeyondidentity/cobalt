// This file contains the InviteService which combines crypto primitives with store operations.
package store

import (
	"fmt"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/enrollment"
	"github.com/google/uuid"
)

// InviteService combines crypto primitives with store operations for invite codes.
type InviteService struct {
	store *Store
}

// NewInviteService creates a new InviteService with the given store.
func NewInviteService(store *Store) *InviteService {
	return &InviteService{store: store}
}

// CreateInviteCodeRequest contains parameters for creating an invite code.
type CreateInviteCodeRequest struct {
	OperatorEmail string        // Target operator's email address
	TenantID      string        // Tenant the operator will join
	Role          string        // Role within the tenant (admin, operator)
	CreatedBy     string        // ID of admin creating the invite
	TTL           time.Duration // Time-to-live; defaults to 1 hour if zero
}

// CreateInviteCodeResult contains the result of creating an invite code.
type CreateInviteCodeResult struct {
	ID        string    // Unique identifier for the invite code record
	Plaintext string    // The plaintext code to give to the user (never stored)
	ExpiresAt time.Time // When the code expires
}

// DefaultInviteTTL is the default time-to-live for invite codes (1 hour).
const DefaultInviteTTL = 1 * time.Hour

// CreateInviteCode generates a new invite code, hashes it, stores the hash,
// and returns the plaintext to the admin. Logs an audit entry.
//
// The plaintext code should be transmitted to the target user once and then
// discarded by the caller. Only the hash is stored in the database.
func (s *InviteService) CreateInviteCode(req CreateInviteCodeRequest) (*CreateInviteCodeResult, error) {
	// Apply default TTL if not specified
	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultInviteTTL
	}

	// Generate cryptographically random invite code (128-bit)
	plaintext, err := enrollment.GenerateInviteCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate invite code: %w", err)
	}

	// Compute hash for storage (never store plaintext)
	codeHash := enrollment.HashCode(plaintext)

	// Generate unique ID
	id := "inv_" + uuid.New().String()[:8]

	// Calculate expiration time
	expiresAt := time.Now().Add(ttl)

	// Create the invite code record
	ic := &InviteCode{
		ID:            id,
		CodeHash:      codeHash,
		OperatorEmail: req.OperatorEmail,
		TenantID:      req.TenantID,
		Role:          req.Role,
		CreatedBy:     req.CreatedBy,
		ExpiresAt:     expiresAt,
		Status:        "pending",
	}

	// Store in database
	if err := s.store.CreateInviteCode(ic); err != nil {
		return nil, fmt.Errorf("failed to store invite code: %w", err)
	}

	// Log audit entry
	_, err = s.store.InsertAuditEntry(&AuditEntry{
		Timestamp: time.Now(),
		Action:    "invite_code.created",
		Target:    id,
		Decision:  "allowed",
		Details: map[string]string{
			"creator":      req.CreatedBy,
			"target_email": req.OperatorEmail,
			"tenant_id":    req.TenantID,
			"role":         req.Role,
			"expires_at":   expiresAt.Format(time.RFC3339),
		},
	})
	if err != nil {
		// Log error but don't fail the operation
		// Audit logging is important but not critical path
	}

	return &CreateInviteCodeResult{
		ID:        id,
		Plaintext: plaintext,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateInviteCode validates a plaintext code without consuming it.
// Returns the InviteCode metadata on success, or enrollment errors:
//   - enrollment.ErrInvalidCode() if not found
//   - enrollment.ErrExpiredCode() if TTL exceeded
//   - enrollment.ErrCodeConsumed() if already used
func (s *InviteService) ValidateInviteCode(plaintext string) (*InviteCode, error) {
	// Compute hash to look up in database
	codeHash := enrollment.HashCode(plaintext)

	// Look up by hash
	ic, err := s.store.GetInviteCodeByHash(codeHash)
	if err != nil {
		// Code not found
		return nil, enrollment.ErrInvalidCode()
	}

	// Check if already consumed
	if ic.Status == "used" {
		return nil, enrollment.ErrCodeConsumed()
	}

	// Check if expired (server-side check)
	if time.Now().After(ic.ExpiresAt) {
		return nil, enrollment.ErrExpiredCode()
	}

	// Check for revoked status
	if ic.Status == "revoked" {
		return nil, enrollment.ErrInvalidCode()
	}

	return ic, nil
}

// ConsumeInviteCode atomically marks a code as consumed.
// Validates first, then consumes. Logs an audit entry.
// Returns the InviteCode metadata on success, or enrollment errors:
//   - enrollment.ErrInvalidCode() if not found
//   - enrollment.ErrExpiredCode() if TTL exceeded
//   - enrollment.ErrCodeConsumed() if already used or race condition
func (s *InviteService) ConsumeInviteCode(plaintext, keymakerID string) (*InviteCode, error) {
	// Validate first to get metadata and check state
	ic, err := s.ValidateInviteCode(plaintext)
	if err != nil {
		return nil, err
	}

	// Atomically consume the code
	// This uses UPDATE WHERE status='pending' to prevent race conditions
	if err := s.store.ConsumeInviteCode(ic.ID, keymakerID); err != nil {
		// Race condition: another goroutine consumed it
		return nil, enrollment.ErrCodeConsumed()
	}

	// Log audit entry
	_, err = s.store.InsertAuditEntry(&AuditEntry{
		Timestamp: time.Now(),
		Action:    "invite_code.consumed",
		Target:    ic.ID,
		Decision:  "allowed",
		Details: map[string]string{
			"consumer_keymaker": keymakerID,
			"original_creator":  ic.CreatedBy,
			"target_email":      ic.OperatorEmail,
			"tenant_id":         ic.TenantID,
		},
	})
	if err != nil {
		// Log error but don't fail the operation
	}

	return ic, nil
}
