// Package store provides SQLite-based storage for DPU registry.
package store

import (
	"database/sql"
	"fmt"
	"time"
)

// DistributionOutcome represents the result of a credential distribution attempt.
type DistributionOutcome string

const (
	DistributionOutcomeSuccess       DistributionOutcome = "success"
	DistributionOutcomeBlockedStale  DistributionOutcome = "blocked-stale"
	DistributionOutcomeBlockedFailed DistributionOutcome = "blocked-failed"
	DistributionOutcomeForced        DistributionOutcome = "forced"
)

// Distribution represents a credential distribution event.
type Distribution struct {
	ID                 int64
	DPUName            string
	CredentialType     string              // e.g., "ssh-ca"
	CredentialName     string              // e.g., CA name
	Outcome            DistributionOutcome // success, blocked-stale, blocked-failed, forced
	AttestationStatus  *string             // Status at distribution time (nullable)
	AttestationAgeSecs *int                // Age in seconds at distribution time (nullable)
	InstalledPath      *string             // Where credential was installed (nullable if blocked)
	ErrorMessage       *string             // Error if failed (nullable)
	CreatedAt          time.Time
}

// RecordDistribution inserts a new distribution record.
func (s *Store) RecordDistribution(d *Distribution) error {
	result, err := s.db.Exec(`
		INSERT INTO distribution_history
			(dpu_name, credential_type, credential_name, outcome, attestation_status, attestation_age_seconds, installed_path, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, d.DPUName, d.CredentialType, d.CredentialName, string(d.Outcome),
		nullableString(d.AttestationStatus),
		nullableInt(d.AttestationAgeSecs),
		nullableString(d.InstalledPath),
		nullableString(d.ErrorMessage))

	if err != nil {
		return fmt.Errorf("failed to record distribution: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	d.ID = id

	return nil
}

// GetDistributionHistory retrieves distribution history for a specific DPU.
// Results are ordered by created_at DESC, id DESC (most recent first).
func (s *Store) GetDistributionHistory(dpuName string) ([]*Distribution, error) {
	rows, err := s.db.Query(`
		SELECT id, dpu_name, credential_type, credential_name, outcome,
		       attestation_status, attestation_age_seconds, installed_path, error_message, created_at
		FROM distribution_history
		WHERE dpu_name = ?
		ORDER BY created_at DESC, id DESC
	`, dpuName)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution history: %w", err)
	}
	defer rows.Close()

	return s.scanDistributionRows(rows)
}

// GetDistributionHistoryByCredential retrieves distribution history for a specific credential.
// Results are ordered by created_at DESC, id DESC (most recent first).
func (s *Store) GetDistributionHistoryByCredential(credentialName string) ([]*Distribution, error) {
	rows, err := s.db.Query(`
		SELECT id, dpu_name, credential_type, credential_name, outcome,
		       attestation_status, attestation_age_seconds, installed_path, error_message, created_at
		FROM distribution_history
		WHERE credential_name = ?
		ORDER BY created_at DESC, id DESC
	`, credentialName)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution history by credential: %w", err)
	}
	defer rows.Close()

	return s.scanDistributionRows(rows)
}

// ListRecentDistributions returns the most recent N distributions across all DPUs.
// Results are ordered by created_at DESC, id DESC (most recent first).
func (s *Store) ListRecentDistributions(limit int) ([]*Distribution, error) {
	rows, err := s.db.Query(`
		SELECT id, dpu_name, credential_type, credential_name, outcome,
		       attestation_status, attestation_age_seconds, installed_path, error_message, created_at
		FROM distribution_history
		ORDER BY created_at DESC, id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list recent distributions: %w", err)
	}
	defer rows.Close()

	return s.scanDistributionRows(rows)
}

// scanDistributionRows scans multiple distribution rows into a slice.
func (s *Store) scanDistributionRows(rows *sql.Rows) ([]*Distribution, error) {
	var distributions []*Distribution
	for rows.Next() {
		d, err := s.scanDistribution(rows)
		if err != nil {
			return nil, err
		}
		distributions = append(distributions, d)
	}
	return distributions, rows.Err()
}

// scanDistribution scans a single distribution row.
func (s *Store) scanDistribution(rows *sql.Rows) (*Distribution, error) {
	var d Distribution
	var outcome string
	var createdAt int64
	var attestationStatus sql.NullString
	var attestationAgeSecs sql.NullInt64
	var installedPath sql.NullString
	var errorMessage sql.NullString

	err := rows.Scan(
		&d.ID,
		&d.DPUName,
		&d.CredentialType,
		&d.CredentialName,
		&outcome,
		&attestationStatus,
		&attestationAgeSecs,
		&installedPath,
		&errorMessage,
		&createdAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan distribution: %w", err)
	}

	d.Outcome = DistributionOutcome(outcome)
	d.CreatedAt = time.Unix(createdAt, 0)

	if attestationStatus.Valid {
		d.AttestationStatus = &attestationStatus.String
	}
	if attestationAgeSecs.Valid {
		age := int(attestationAgeSecs.Int64)
		d.AttestationAgeSecs = &age
	}
	if installedPath.Valid {
		d.InstalledPath = &installedPath.String
	}
	if errorMessage.Valid {
		d.ErrorMessage = &errorMessage.String
	}

	return &d, nil
}

// nullableString converts a *string to sql.NullString for database insertion.
func nullableString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

// nullableInt converts a *int to sql.NullInt64 for database insertion.
func nullableInt(i *int) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*i), Valid: true}
}
