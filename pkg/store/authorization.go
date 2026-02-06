// This file contains methods for authorization entities.
// Type definitions are in sqlite.go.
package store

import (
	"database/sql"
	"fmt"
	"time"
)

// CreateAuthorization creates a new authorization grant.
// caIDs is a list of CA IDs the operator can access.
// deviceIDs is a list of device IDs, or []string{"all"} for all devices.
func (s *Store) CreateAuthorization(id, operatorID, tenantID string, caIDs, deviceIDs []string, createdBy string, expiresAt *time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert the authorization
	var expiresAtVal interface{}
	if expiresAt != nil {
		expiresAtVal = expiresAt.Unix()
	}

	_, err = tx.Exec(
		`INSERT INTO authorizations (id, operator_id, tenant_id, created_by, expires_at) VALUES (?, ?, ?, ?, ?)`,
		id, operatorID, tenantID, createdBy, expiresAtVal,
	)
	if err != nil {
		return fmt.Errorf("failed to create authorization: %w", err)
	}

	// Insert CA associations
	for _, caID := range caIDs {
		_, err = tx.Exec(
			`INSERT INTO authorization_cas (authorization_id, ca_id) VALUES (?, ?)`,
			id, caID,
		)
		if err != nil {
			return fmt.Errorf("failed to add CA to authorization: %w", err)
		}
	}

	// Insert device associations
	for _, deviceID := range deviceIDs {
		_, err = tx.Exec(
			`INSERT INTO authorization_devices (authorization_id, device_id) VALUES (?, ?)`,
			id, deviceID,
		)
		if err != nil {
			return fmt.Errorf("failed to add device to authorization: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit authorization: %w", err)
	}

	return nil
}

// GetAuthorization retrieves an authorization by ID with its CAs and devices.
func (s *Store) GetAuthorization(id string) (*Authorization, error) {
	row := s.db.QueryRow(
		`SELECT id, operator_id, tenant_id, created_at, created_by, expires_at FROM authorizations WHERE id = ?`,
		id,
	)

	auth, err := s.scanAuthorization(row)
	if err != nil {
		return nil, err
	}

	// Fetch associated CAs
	auth.CAIDs, err = s.getAuthorizationCAIDs(id)
	if err != nil {
		return nil, err
	}

	// Fetch associated devices
	auth.DeviceIDs, err = s.getAuthorizationDeviceIDs(id)
	if err != nil {
		return nil, err
	}

	return auth, nil
}

// ListAuthorizationsByOperator returns all authorizations for an operator.
func (s *Store) ListAuthorizationsByOperator(operatorID string) ([]*Authorization, error) {
	rows, err := s.db.Query(
		`SELECT id, operator_id, tenant_id, created_at, created_by, expires_at FROM authorizations WHERE operator_id = ? ORDER BY created_at DESC`,
		operatorID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list authorizations: %w", err)
	}
	defer rows.Close()

	return s.scanAuthorizationsWithJoins(rows)
}

// ListAuthorizationsByTenant returns all authorizations in a tenant.
func (s *Store) ListAuthorizationsByTenant(tenantID string) ([]*Authorization, error) {
	rows, err := s.db.Query(
		`SELECT id, operator_id, tenant_id, created_at, created_by, expires_at FROM authorizations WHERE tenant_id = ? ORDER BY created_at DESC`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list authorizations: %w", err)
	}
	defer rows.Close()

	return s.scanAuthorizationsWithJoins(rows)
}

// DeleteAuthorization removes an authorization grant.
func (s *Store) DeleteAuthorization(id string) error {
	result, err := s.db.Exec(`DELETE FROM authorizations WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete authorization: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("authorization not found: %s", id)
	}
	return nil
}

// HasAnyAuthorization returns true if the operator has at least one active
// authorization grant. Used by the authz middleware for coarse-grained Cedar
// pre-filtering (handlers do fine-grained CA+device checks).
func (s *Store) HasAnyAuthorization(operatorID string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM authorizations WHERE operator_id = ?`,
		operatorID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check authorization: %w", err)
	}
	return count > 0, nil
}

// CheckCAAuthorization checks if an operator is authorized for a specific CA.
// The caIDOrName parameter can be either a CA ID (e.g., "ca_abc123") or
// a CA name (e.g., "test-ca"). The authorization check will match against
// both the stored value in authorization_cas and the corresponding CA in ssh_cas.
// Returns true if authorized, false otherwise.
func (s *Store) CheckCAAuthorization(operatorID, caIDOrName string) (bool, error) {
	var count int
	// Match if authorization_cas.ca_id equals the input directly,
	// OR if the input matches a CA's ID/name and authorization_cas.ca_id matches the other identifier.
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM authorizations a
		 INNER JOIN authorization_cas ac ON a.id = ac.authorization_id
		 LEFT JOIN ssh_cas sc ON ac.ca_id = sc.id OR ac.ca_id = sc.name
		 WHERE a.operator_id = ?
		   AND (ac.ca_id = ? OR sc.id = ? OR sc.name = ?)`,
		operatorID, caIDOrName, caIDOrName, caIDOrName,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check CA authorization: %w", err)
	}
	return count > 0, nil
}

// CheckDeviceAuthorization checks if an operator is authorized for a specific device.
// Returns true if authorized (explicit device ID match or "all" selector).
func (s *Store) CheckDeviceAuthorization(operatorID, deviceID string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM authorizations a
		 INNER JOIN authorization_devices ad ON a.id = ad.authorization_id
		 WHERE a.operator_id = ? AND (ad.device_id = ? OR ad.device_id = 'all')`,
		operatorID, deviceID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check device authorization: %w", err)
	}
	return count > 0, nil
}

// CheckFullAuthorization checks if an operator is authorized for both a CA and a device.
// The caIDOrName parameter can be either a CA ID (e.g., "ca_abc123") or
// a CA name (e.g., "test-ca"). This is used for distribution which requires both.
func (s *Store) CheckFullAuthorization(operatorID, caIDOrName, deviceID string) (bool, error) {
	// An operator is fully authorized if they have at least one authorization
	// that grants access to both the specified CA and device (or "all" devices).
	// The CA can be matched by ID or name in either authorization_cas or ssh_cas.
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM authorizations a
		 INNER JOIN authorization_cas ac ON a.id = ac.authorization_id
		 INNER JOIN authorization_devices ad ON a.id = ad.authorization_id
		 LEFT JOIN ssh_cas sc ON ac.ca_id = sc.id OR ac.ca_id = sc.name
		 WHERE a.operator_id = ?
		   AND (ac.ca_id = ? OR sc.id = ? OR sc.name = ?)
		   AND (ad.device_id = ? OR ad.device_id = 'all')`,
		operatorID, caIDOrName, caIDOrName, caIDOrName, deviceID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check full authorization: %w", err)
	}
	return count > 0, nil
}

// ----- Helper Methods -----

func (s *Store) scanAuthorization(row *sql.Row) (*Authorization, error) {
	var auth Authorization
	var createdAt int64
	var expiresAt sql.NullInt64

	err := row.Scan(&auth.ID, &auth.OperatorID, &auth.TenantID, &createdAt, &auth.CreatedBy, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("authorization not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan authorization: %w", err)
	}

	auth.CreatedAt = time.Unix(createdAt, 0)
	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0)
		auth.ExpiresAt = &t
	}

	return &auth, nil
}

func (s *Store) scanAuthorizationRows(rows *sql.Rows) (*Authorization, error) {
	var auth Authorization
	var createdAt int64
	var expiresAt sql.NullInt64

	err := rows.Scan(&auth.ID, &auth.OperatorID, &auth.TenantID, &createdAt, &auth.CreatedBy, &expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to scan authorization: %w", err)
	}

	auth.CreatedAt = time.Unix(createdAt, 0)
	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0)
		auth.ExpiresAt = &t
	}

	return &auth, nil
}

func (s *Store) scanAuthorizationsWithJoins(rows *sql.Rows) ([]*Authorization, error) {
	// Scan all rows first to release the database connection. With
	// SetMaxOpenConns(1), holding rows open while making sub-queries deadlocks.
	var auths []*Authorization
	for rows.Next() {
		auth, err := s.scanAuthorizationRows(rows)
		if err != nil {
			return nil, err
		}
		auths = append(auths, auth)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	// Now fetch associated data (connection is free for sub-queries)
	for _, auth := range auths {
		var err error
		auth.CAIDs, err = s.getAuthorizationCAIDs(auth.ID)
		if err != nil {
			return nil, err
		}
		auth.DeviceIDs, err = s.getAuthorizationDeviceIDs(auth.ID)
		if err != nil {
			return nil, err
		}
	}
	return auths, nil
}

func (s *Store) getAuthorizationCAIDs(authID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT ca_id FROM authorization_cas WHERE authorization_id = ?`,
		authID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA IDs: %w", err)
	}
	defer rows.Close()

	var caIDs []string
	for rows.Next() {
		var caID string
		if err := rows.Scan(&caID); err != nil {
			return nil, fmt.Errorf("failed to scan CA ID: %w", err)
		}
		caIDs = append(caIDs, caID)
	}
	return caIDs, rows.Err()
}

func (s *Store) getAuthorizationDeviceIDs(authID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT device_id FROM authorization_devices WHERE authorization_id = ?`,
		authID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get device IDs: %w", err)
	}
	defer rows.Close()

	var deviceIDs []string
	for rows.Next() {
		var deviceID string
		if err := rows.Scan(&deviceID); err != nil {
			return nil, fmt.Errorf("failed to scan device ID: %w", err)
		}
		deviceIDs = append(deviceIDs, deviceID)
	}
	return deviceIDs, rows.Err()
}
