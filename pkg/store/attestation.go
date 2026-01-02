// Package store provides SQLite-based storage for DPU registry.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// AttestationStatus represents the status of an attestation.
type AttestationStatus string

const (
	AttestationStatusVerified    AttestationStatus = "verified"
	AttestationStatusFailed      AttestationStatus = "failed"
	AttestationStatusUnavailable AttestationStatus = "unavailable"
	AttestationStatusStale       AttestationStatus = "stale"
	AttestationStatusPending     AttestationStatus = "pending"
)

// Attestation represents a stored attestation result.
type Attestation struct {
	ID               int64
	DPUName          string
	Status           AttestationStatus
	LastValidated    time.Time
	DICEChainHash    string            // SHA256 of DICE chain
	MeasurementsHash string            // SHA256 of SPDM measurements
	RawData          map[string]any    // Full response data
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Age returns the time since the attestation was last validated.
func (a *Attestation) Age() time.Duration {
	return time.Since(a.LastValidated)
}

// SaveAttestation upserts an attestation record by DPU name.
func (s *Store) SaveAttestation(att *Attestation) error {
	now := time.Now().Unix()

	// Serialize raw data to JSON
	var rawDataJSON []byte
	var err error
	if att.RawData != nil {
		rawDataJSON, err = json.Marshal(att.RawData)
		if err != nil {
			return fmt.Errorf("failed to serialize raw data: %w", err)
		}
	}

	// Upsert: INSERT OR REPLACE
	_, err = s.db.Exec(`
		INSERT INTO attestations (dpu_name, status, last_validated, dice_chain_hash, measurements_hash, raw_data, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(dpu_name) DO UPDATE SET
			status = excluded.status,
			last_validated = excluded.last_validated,
			dice_chain_hash = excluded.dice_chain_hash,
			measurements_hash = excluded.measurements_hash,
			raw_data = excluded.raw_data,
			updated_at = excluded.updated_at
	`, att.DPUName, string(att.Status), att.LastValidated.Unix(), att.DICEChainHash, att.MeasurementsHash, rawDataJSON, now)

	if err != nil {
		return fmt.Errorf("failed to save attestation: %w", err)
	}
	return nil
}

// GetAttestation retrieves an attestation by DPU name.
func (s *Store) GetAttestation(dpuName string) (*Attestation, error) {
	row := s.db.QueryRow(`
		SELECT id, dpu_name, status, last_validated, dice_chain_hash, measurements_hash, raw_data, created_at, updated_at
		FROM attestations WHERE dpu_name = ?
	`, dpuName)

	return s.scanAttestation(row)
}

// ListAttestations returns all attestations.
func (s *Store) ListAttestations() ([]*Attestation, error) {
	rows, err := s.db.Query(`
		SELECT id, dpu_name, status, last_validated, dice_chain_hash, measurements_hash, raw_data, created_at, updated_at
		FROM attestations ORDER BY dpu_name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list attestations: %w", err)
	}
	defer rows.Close()

	var attestations []*Attestation
	for rows.Next() {
		att, err := s.scanAttestationRows(rows)
		if err != nil {
			return nil, err
		}
		attestations = append(attestations, att)
	}
	return attestations, rows.Err()
}

// ListAttestationsByStatus returns attestations filtered by status.
func (s *Store) ListAttestationsByStatus(status AttestationStatus) ([]*Attestation, error) {
	rows, err := s.db.Query(`
		SELECT id, dpu_name, status, last_validated, dice_chain_hash, measurements_hash, raw_data, created_at, updated_at
		FROM attestations WHERE status = ? ORDER BY dpu_name
	`, string(status))
	if err != nil {
		return nil, fmt.Errorf("failed to list attestations by status: %w", err)
	}
	defer rows.Close()

	var attestations []*Attestation
	for rows.Next() {
		att, err := s.scanAttestationRows(rows)
		if err != nil {
			return nil, err
		}
		attestations = append(attestations, att)
	}
	return attestations, rows.Err()
}

// DeleteAttestation removes an attestation by DPU name.
func (s *Store) DeleteAttestation(dpuName string) error {
	result, err := s.db.Exec(`DELETE FROM attestations WHERE dpu_name = ?`, dpuName)
	if err != nil {
		return fmt.Errorf("failed to delete attestation: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("attestation not found: %s", dpuName)
	}
	return nil
}

// AttestationExists checks if an attestation exists for a DPU.
func (s *Store) AttestationExists(dpuName string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM attestations WHERE dpu_name = ?`, dpuName).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check attestation existence: %w", err)
	}
	return count > 0, nil
}

func (s *Store) scanAttestation(row *sql.Row) (*Attestation, error) {
	var att Attestation
	var status string
	var lastValidated, createdAt, updatedAt int64
	var diceChainHash, measurementsHash sql.NullString
	var rawDataJSON sql.NullString

	err := row.Scan(&att.ID, &att.DPUName, &status, &lastValidated, &diceChainHash, &measurementsHash, &rawDataJSON, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("attestation not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan attestation: %w", err)
	}

	att.Status = AttestationStatus(status)
	att.LastValidated = time.Unix(lastValidated, 0)
	att.CreatedAt = time.Unix(createdAt, 0)
	att.UpdatedAt = time.Unix(updatedAt, 0)

	if diceChainHash.Valid {
		att.DICEChainHash = diceChainHash.String
	}
	if measurementsHash.Valid {
		att.MeasurementsHash = measurementsHash.String
	}
	if rawDataJSON.Valid && rawDataJSON.String != "" {
		if err := json.Unmarshal([]byte(rawDataJSON.String), &att.RawData); err != nil {
			// Log but don't fail on corrupted JSON
			att.RawData = nil
		}
	}

	return &att, nil
}

func (s *Store) scanAttestationRows(rows *sql.Rows) (*Attestation, error) {
	var att Attestation
	var status string
	var lastValidated, createdAt, updatedAt int64
	var diceChainHash, measurementsHash sql.NullString
	var rawDataJSON sql.NullString

	err := rows.Scan(&att.ID, &att.DPUName, &status, &lastValidated, &diceChainHash, &measurementsHash, &rawDataJSON, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to scan attestation: %w", err)
	}

	att.Status = AttestationStatus(status)
	att.LastValidated = time.Unix(lastValidated, 0)
	att.CreatedAt = time.Unix(createdAt, 0)
	att.UpdatedAt = time.Unix(updatedAt, 0)

	if diceChainHash.Valid {
		att.DICEChainHash = diceChainHash.String
	}
	if measurementsHash.Valid {
		att.MeasurementsHash = measurementsHash.String
	}
	if rawDataJSON.Valid && rawDataJSON.String != "" {
		if err := json.Unmarshal([]byte(rawDataJSON.String), &att.RawData); err != nil {
			att.RawData = nil
		}
	}

	return &att, nil
}
