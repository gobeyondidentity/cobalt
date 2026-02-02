// This file contains methods for TrustRelationship entities (M2M trust).
package store

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// TrustType represents the type of trust relationship.
type TrustType string

const (
	TrustTypeSSHHost TrustType = "ssh_host"
	TrustTypeMTLS    TrustType = "mtls"
)

// TrustStatus represents the status of a trust relationship.
type TrustStatus string

const (
	TrustStatusActive    TrustStatus = "active"
	TrustStatusSuspended TrustStatus = "suspended"
)

// TrustRelationship represents a trust relationship between two hosts, gated by DPU attestation.
// Trust is between HOSTS (the machines communicating), while DPUs provide the attestation
// that gates whether trust is established.
type TrustRelationship struct {
	ID               string
	SourceHost       string      // Hostname of source (accepts connections)
	TargetHost       string      // Hostname of target (initiates connections)
	SourceDPUID      string      // DPU paired with source host (for attestation)
	SourceDPUName    string      // Source DPU name (for display)
	TargetDPUID      string      // DPU paired with target host (for attestation)
	TargetDPUName    string      // Target DPU name (for display)
	TenantID         string      // Tenant both hosts belong to
	TrustType        TrustType   // ssh_host or mtls
	Bidirectional    bool        // If true, trust goes both ways
	Status           TrustStatus // active or suspended
	SuspendReason    *string     // Why suspended (e.g., "bf3-02 attestation failed")
	TargetCertSerial *uint64     // Serial number of host certificate issued to target
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// generateTrustID generates a unique ID with format "tr_" + first 8 chars of UUID.
func generateTrustID() string {
	u := uuid.New().String()
	return "tr_" + u[:8]
}

// CreateTrustRelationship inserts a new trust relationship.
func (s *Store) CreateTrustRelationship(t *TrustRelationship) error {
	if t.ID == "" {
		t.ID = generateTrustID()
	}
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	if t.UpdatedAt.IsZero() {
		t.UpdatedAt = now
	}
	if t.Status == "" {
		t.Status = TrustStatusActive
	}

	bidirectional := 0
	if t.Bidirectional {
		bidirectional = 1
	}

	var suspendReason sql.NullString
	if t.SuspendReason != nil {
		suspendReason = sql.NullString{String: *t.SuspendReason, Valid: true}
	}

	var targetCertSerial sql.NullInt64
	if t.TargetCertSerial != nil {
		targetCertSerial = sql.NullInt64{Int64: int64(*t.TargetCertSerial), Valid: true}
	}

	_, err := s.db.Exec(
		`INSERT INTO trust_relationships
		(id, source_host, target_host, source_dpu_id, source_dpu_name, target_dpu_id, target_dpu_name, tenant_id, trust_type, bidirectional, status, suspend_reason, target_cert_serial, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.SourceHost, t.TargetHost, t.SourceDPUID, t.SourceDPUName, t.TargetDPUID, t.TargetDPUName,
		t.TenantID, string(t.TrustType), bidirectional, string(t.Status),
		suspendReason, targetCertSerial, t.CreatedAt.Unix(), t.UpdatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to create trust relationship: %w", err)
	}
	return nil
}

// GetTrustRelationship retrieves a trust relationship by ID.
func (s *Store) GetTrustRelationship(id string) (*TrustRelationship, error) {
	row := s.db.QueryRow(
		`SELECT id, source_host, target_host, source_dpu_id, source_dpu_name, target_dpu_id, target_dpu_name, tenant_id, trust_type, bidirectional, status, suspend_reason, target_cert_serial, created_at, updated_at
		FROM trust_relationships WHERE id = ?`,
		id,
	)
	return s.scanTrustRelationship(row)
}

// ListTrustRelationships returns all trust relationships for a tenant.
func (s *Store) ListTrustRelationships(tenantID string) ([]*TrustRelationship, error) {
	rows, err := s.db.Query(
		`SELECT id, source_host, target_host, source_dpu_id, source_dpu_name, target_dpu_id, target_dpu_name, tenant_id, trust_type, bidirectional, status, suspend_reason, target_cert_serial, created_at, updated_at
		FROM trust_relationships WHERE tenant_id = ? ORDER BY created_at DESC`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list trust relationships: %w", err)
	}
	defer rows.Close()

	return s.scanTrustRelationshipRows(rows)
}

// ListAllTrustRelationships returns all trust relationships across all tenants.
func (s *Store) ListAllTrustRelationships() ([]*TrustRelationship, error) {
	rows, err := s.db.Query(
		`SELECT id, source_host, target_host, source_dpu_id, source_dpu_name, target_dpu_id, target_dpu_name, tenant_id, trust_type, bidirectional, status, suspend_reason, target_cert_serial, created_at, updated_at
		FROM trust_relationships ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list all trust relationships: %w", err)
	}
	defer rows.Close()

	return s.scanTrustRelationshipRows(rows)
}

// ListTrustRelationshipsByDPU returns all trust relationships involving a specific DPU.
func (s *Store) ListTrustRelationshipsByDPU(dpuID string) ([]*TrustRelationship, error) {
	rows, err := s.db.Query(
		`SELECT id, source_host, target_host, source_dpu_id, source_dpu_name, target_dpu_id, target_dpu_name, tenant_id, trust_type, bidirectional, status, suspend_reason, target_cert_serial, created_at, updated_at
		FROM trust_relationships WHERE source_dpu_id = ? OR target_dpu_id = ? ORDER BY created_at DESC`,
		dpuID, dpuID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list trust relationships by DPU: %w", err)
	}
	defer rows.Close()

	return s.scanTrustRelationshipRows(rows)
}

// ListTrustRelationshipsByHost returns all trust relationships involving a specific host.
func (s *Store) ListTrustRelationshipsByHost(hostname string) ([]*TrustRelationship, error) {
	rows, err := s.db.Query(
		`SELECT id, source_host, target_host, source_dpu_id, source_dpu_name, target_dpu_id, target_dpu_name, tenant_id, trust_type, bidirectional, status, suspend_reason, target_cert_serial, created_at, updated_at
		FROM trust_relationships WHERE source_host = ? OR target_host = ? ORDER BY created_at DESC`,
		hostname, hostname,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list trust relationships by host: %w", err)
	}
	defer rows.Close()

	return s.scanTrustRelationshipRows(rows)
}

// GetTrustRelationshipByHosts retrieves a trust relationship by source/target hosts and trust type.
func (s *Store) GetTrustRelationshipByHosts(sourceHost, targetHost string, trustType TrustType) (*TrustRelationship, error) {
	row := s.db.QueryRow(
		`SELECT id, source_host, target_host, source_dpu_id, source_dpu_name, target_dpu_id, target_dpu_name, tenant_id, trust_type, bidirectional, status, suspend_reason, target_cert_serial, created_at, updated_at
		FROM trust_relationships WHERE source_host = ? AND target_host = ? AND trust_type = ?`,
		sourceHost, targetHost, string(trustType),
	)
	return s.scanTrustRelationship(row)
}

// UpdateTargetCertSerial updates the certificate serial number for a trust relationship.
func (s *Store) UpdateTargetCertSerial(id string, serial uint64) error {
	now := time.Now().Unix()

	result, err := s.db.Exec(
		`UPDATE trust_relationships SET target_cert_serial = ?, updated_at = ? WHERE id = ?`,
		int64(serial), now, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update target cert serial: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("trust relationship not found: %s", id)
	}
	return nil
}

// UpdateTrustStatus updates the status of a trust relationship.
func (s *Store) UpdateTrustStatus(id string, status TrustStatus, reason *string) error {
	now := time.Now().Unix()

	var suspendReason sql.NullString
	if reason != nil {
		suspendReason = sql.NullString{String: *reason, Valid: true}
	}

	result, err := s.db.Exec(
		`UPDATE trust_relationships SET status = ?, suspend_reason = ?, updated_at = ? WHERE id = ?`,
		string(status), suspendReason, now, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update trust status: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("trust relationship not found: %s", id)
	}
	return nil
}

// DeleteTrustRelationship removes a trust relationship by ID.
func (s *Store) DeleteTrustRelationship(id string) error {
	result, err := s.db.Exec(`DELETE FROM trust_relationships WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete trust relationship: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("trust relationship not found: %s", id)
	}
	return nil
}

// TrustRelationshipExists checks if a trust relationship exists between two DPUs for a specific trust type.
func (s *Store) TrustRelationshipExists(sourceID, targetID string, trustType TrustType) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM trust_relationships
		WHERE source_dpu_id = ? AND target_dpu_id = ? AND trust_type = ?`,
		sourceID, targetID, string(trustType),
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check trust relationship existence: %w", err)
	}
	return count > 0, nil
}

// TrustRelationshipExistsByHost checks if a trust relationship exists between two hosts for a specific trust type.
func (s *Store) TrustRelationshipExistsByHost(sourceHost, targetHost string, trustType TrustType) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM trust_relationships
		WHERE source_host = ? AND target_host = ? AND trust_type = ?`,
		sourceHost, targetHost, string(trustType),
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check trust relationship existence: %w", err)
	}
	return count > 0, nil
}

func (s *Store) scanTrustRelationship(row *sql.Row) (*TrustRelationship, error) {
	var tr TrustRelationship
	var trustType, status string
	var bidirectional int
	var suspendReason sql.NullString
	var targetCertSerial sql.NullInt64
	var createdAt, updatedAt int64

	err := row.Scan(&tr.ID, &tr.SourceHost, &tr.TargetHost, &tr.SourceDPUID, &tr.SourceDPUName, &tr.TargetDPUID, &tr.TargetDPUName,
		&tr.TenantID, &trustType, &bidirectional, &status, &suspendReason, &targetCertSerial, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("trust relationship not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan trust relationship: %w", err)
	}

	tr.TrustType = TrustType(trustType)
	tr.Status = TrustStatus(status)
	tr.Bidirectional = bidirectional != 0
	if suspendReason.Valid {
		tr.SuspendReason = &suspendReason.String
	}
	if targetCertSerial.Valid {
		val := uint64(targetCertSerial.Int64)
		tr.TargetCertSerial = &val
	}
	tr.CreatedAt = time.Unix(createdAt, 0)
	tr.UpdatedAt = time.Unix(updatedAt, 0)

	return &tr, nil
}

func (s *Store) scanTrustRelationshipRows(rows *sql.Rows) ([]*TrustRelationship, error) {
	var results []*TrustRelationship
	for rows.Next() {
		var tr TrustRelationship
		var trustType, status string
		var bidirectional int
		var suspendReason sql.NullString
		var targetCertSerial sql.NullInt64
		var createdAt, updatedAt int64

		err := rows.Scan(&tr.ID, &tr.SourceHost, &tr.TargetHost, &tr.SourceDPUID, &tr.SourceDPUName, &tr.TargetDPUID, &tr.TargetDPUName,
			&tr.TenantID, &trustType, &bidirectional, &status, &suspendReason, &targetCertSerial, &createdAt, &updatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan trust relationship: %w", err)
		}

		tr.TrustType = TrustType(trustType)
		tr.Status = TrustStatus(status)
		tr.Bidirectional = bidirectional != 0
		if suspendReason.Valid {
			tr.SuspendReason = &suspendReason.String
		}
		if targetCertSerial.Valid {
			val := uint64(targetCertSerial.Int64)
			tr.TargetCertSerial = &val
		}
		tr.CreatedAt = time.Unix(createdAt, 0)
		tr.UpdatedAt = time.Unix(updatedAt, 0)

		results = append(results, &tr)
	}
	return results, rows.Err()
}

// SuspendTrustRelationshipsForDPU suspends all active trust relationships where the
// specified DPU is either source or target. Returns the count of newly suspended relationships.
func (s *Store) SuspendTrustRelationshipsForDPU(dpuName string, reason string) (int, error) {
	now := time.Now().Unix()

	// Update all active trust relationships where this DPU is involved
	result, err := s.db.Exec(
		`UPDATE trust_relationships
		SET status = ?, suspend_reason = ?, updated_at = ?
		WHERE (source_dpu_name = ? OR target_dpu_name = ?) AND status = ?`,
		string(TrustStatusSuspended), reason, now, dpuName, dpuName, string(TrustStatusActive),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to suspend trust relationships: %w", err)
	}

	rows, _ := result.RowsAffected()
	return int(rows), nil
}

// ReactivateTrustRelationshipsForDPU reactivates all suspended trust relationships where
// the specified DPU is either source or target. Returns the count of reactivated relationships.
func (s *Store) ReactivateTrustRelationshipsForDPU(dpuName string) (int, error) {
	now := time.Now().Unix()

	// Update all suspended trust relationships where this DPU is involved
	result, err := s.db.Exec(
		`UPDATE trust_relationships
		SET status = ?, suspend_reason = NULL, updated_at = ?
		WHERE (source_dpu_name = ? OR target_dpu_name = ?) AND status = ?`,
		string(TrustStatusActive), now, dpuName, dpuName, string(TrustStatusSuspended),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to reactivate trust relationships: %w", err)
	}

	rows, _ := result.RowsAffected()
	return int(rows), nil
}
