// Operator and OperatorTenant store methods.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ErrOperatorAlreadySuspended is returned when attempting to suspend an already-suspended Operator.
var ErrOperatorAlreadySuspended = fmt.Errorf("operator already suspended")

// ErrOperatorNotSuspended is returned when attempting to unsuspend an Operator that is not suspended.
var ErrOperatorNotSuspended = fmt.Errorf("operator is not suspended")

// ----- Operator Methods -----

// CreateOperator creates a new operator with pending status.
func (s *Store) CreateOperator(id, email, displayName string) error {
	_, err := s.db.Exec(
		`INSERT INTO operators (id, email, display_name, status) VALUES (?, ?, ?, 'pending')`,
		id, email, displayName,
	)
	if err != nil {
		return fmt.Errorf("failed to create operator: %w", err)
	}
	return nil
}

// GetOperator retrieves an operator by ID or email.
func (s *Store) GetOperator(idOrEmail string) (*Operator, error) {
	row := s.db.QueryRow(
		`SELECT id, email, display_name, status, created_at, last_login, suspended_at, suspended_by, suspended_reason FROM operators WHERE id = ? OR email = ?`,
		idOrEmail, idOrEmail,
	)
	return s.scanOperator(row)
}

// GetOperatorByEmail retrieves an operator by email address.
func (s *Store) GetOperatorByEmail(email string) (*Operator, error) {
	row := s.db.QueryRow(
		`SELECT id, email, display_name, status, created_at, last_login, suspended_at, suspended_by, suspended_reason FROM operators WHERE email = ?`,
		email,
	)
	return s.scanOperator(row)
}

// ListOperators returns all operators.
func (s *Store) ListOperators() ([]*Operator, error) {
	rows, err := s.db.Query(
		`SELECT id, email, display_name, status, created_at, last_login, suspended_at, suspended_by, suspended_reason FROM operators ORDER BY email`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list operators: %w", err)
	}
	defer rows.Close()

	var operators []*Operator
	for rows.Next() {
		op, err := s.scanOperatorRows(rows)
		if err != nil {
			return nil, err
		}
		operators = append(operators, op)
	}
	return operators, rows.Err()
}

// ListOperatorsByTenant returns all operators for a specific tenant.
func (s *Store) ListOperatorsByTenant(tenantID string) ([]*Operator, error) {
	rows, err := s.db.Query(
		`SELECT o.id, o.email, o.display_name, o.status, o.created_at, o.last_login, o.suspended_at, o.suspended_by, o.suspended_reason
		 FROM operators o
		 INNER JOIN operator_tenants ot ON o.id = ot.operator_id
		 WHERE ot.tenant_id = ?
		 ORDER BY o.email`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list operators by tenant: %w", err)
	}
	defer rows.Close()

	var operators []*Operator
	for rows.Next() {
		op, err := s.scanOperatorRows(rows)
		if err != nil {
			return nil, err
		}
		operators = append(operators, op)
	}
	return operators, rows.Err()
}

// UpdateOperatorStatus updates an operator's status.
func (s *Store) UpdateOperatorStatus(id, status string) error {
	result, err := s.db.Exec(
		`UPDATE operators SET status = ? WHERE id = ?`,
		status, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update operator status: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

// UpdateOperatorLastLogin updates the last login timestamp for an operator.
func (s *Store) UpdateOperatorLastLogin(id string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE operators SET last_login = ? WHERE id = ?`,
		now, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update operator last login: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

// SuspendOperator suspends an operator, blocking all their KeyMakers.
// Records who performed the suspension and why for audit compliance.
func (s *Store) SuspendOperator(id, suspendedBy, reason string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE operators SET status = 'suspended', suspended_at = ?, suspended_by = ?, suspended_reason = ? WHERE id = ?`,
		now, suspendedBy, reason, id,
	)
	if err != nil {
		return fmt.Errorf("failed to suspend operator: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

// UnsuspendOperator restores a suspended operator to active status.
// Clears the suspension tracking fields.
func (s *Store) UnsuspendOperator(id string) error {
	result, err := s.db.Exec(
		`UPDATE operators SET status = 'active', suspended_at = NULL, suspended_by = NULL, suspended_reason = NULL WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to unsuspend operator: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

// SuspendOperatorAtomic atomically suspends an operator if not already suspended.
// Returns ErrOperatorAlreadySuspended if the operator is already suspended (for 409 response).
// Returns "operator not found" error if the operator does not exist.
func (s *Store) SuspendOperatorAtomic(id, suspendedBy, reason string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE operators SET status = 'suspended', suspended_at = ?, suspended_by = ?, suspended_reason = ?
		 WHERE id = ? AND status != 'suspended'`,
		now, suspendedBy, reason, id,
	)
	if err != nil {
		return fmt.Errorf("failed to suspend operator: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Check if the operator exists but is already suspended
		op, err := s.GetOperator(id)
		if err != nil {
			return fmt.Errorf("operator not found: %s", id)
		}
		if op.Status == "suspended" {
			return ErrOperatorAlreadySuspended
		}
		// This shouldn't happen, but handle it
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

// UnsuspendOperatorAtomic atomically unsuspends an operator if currently suspended.
// Returns ErrOperatorNotSuspended if the operator is not suspended (for 409 response).
// Returns "operator not found" error if the operator does not exist.
func (s *Store) UnsuspendOperatorAtomic(id string) error {
	result, err := s.db.Exec(
		`UPDATE operators SET status = 'active', suspended_at = NULL, suspended_by = NULL, suspended_reason = NULL
		 WHERE id = ? AND status = 'suspended'`,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to unsuspend operator: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Check if the operator exists but is not suspended
		op, err := s.GetOperator(id)
		if err != nil {
			return fmt.Errorf("operator not found: %s", id)
		}
		if op.Status != "suspended" {
			return ErrOperatorNotSuspended
		}
		// This shouldn't happen, but handle it
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

// DeleteOperator deletes an operator by ID.
// Returns error if operator has dependencies (keymakers, authorizations).
// Tenant memberships are removed automatically.
func (s *Store) DeleteOperator(id string) error {
	// Check for keymakers
	keymakers, err := s.ListKeyMakersByOperator(id)
	if err != nil {
		return fmt.Errorf("failed to check keymakers: %w", err)
	}
	if len(keymakers) > 0 {
		return fmt.Errorf("operator has %d keymaker(s) that must be removed first", len(keymakers))
	}

	// Check for authorizations
	auths, err := s.ListAuthorizationsByOperator(id)
	if err != nil {
		return fmt.Errorf("failed to check authorizations: %w", err)
	}
	if len(auths) > 0 {
		return fmt.Errorf("operator has %d authorization(s) that must be revoked first", len(auths))
	}

	// Remove all tenant memberships first
	_, err = s.db.Exec(`DELETE FROM operator_tenants WHERE operator_id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to remove tenant memberships: %w", err)
	}

	// Delete operator
	result, err := s.db.Exec(`DELETE FROM operators WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete operator: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator not found: %s", id)
	}
	return nil
}

func (s *Store) scanOperator(row *sql.Row) (*Operator, error) {
	var op Operator
	var displayName sql.NullString
	var lastLogin sql.NullInt64
	var createdAt int64
	var suspendedAt sql.NullInt64
	var suspendedBy sql.NullString
	var suspendedReason sql.NullString

	err := row.Scan(&op.ID, &op.Email, &displayName, &op.Status, &createdAt, &lastLogin,
		&suspendedAt, &suspendedBy, &suspendedReason)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("operator not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan operator: %w", err)
	}

	if displayName.Valid {
		op.DisplayName = displayName.String
	}
	if lastLogin.Valid {
		t := time.Unix(lastLogin.Int64, 0)
		op.LastLogin = &t
	}
	op.CreatedAt = time.Unix(createdAt, 0)
	if suspendedAt.Valid {
		t := time.Unix(suspendedAt.Int64, 0)
		op.SuspendedAt = &t
	}
	if suspendedBy.Valid {
		op.SuspendedBy = &suspendedBy.String
	}
	if suspendedReason.Valid {
		op.SuspendedReason = &suspendedReason.String
	}

	return &op, nil
}

func (s *Store) scanOperatorRows(rows *sql.Rows) (*Operator, error) {
	var op Operator
	var displayName sql.NullString
	var lastLogin sql.NullInt64
	var createdAt int64
	var suspendedAt sql.NullInt64
	var suspendedBy sql.NullString
	var suspendedReason sql.NullString

	err := rows.Scan(&op.ID, &op.Email, &displayName, &op.Status, &createdAt, &lastLogin,
		&suspendedAt, &suspendedBy, &suspendedReason)
	if err != nil {
		return nil, fmt.Errorf("failed to scan operator: %w", err)
	}

	if displayName.Valid {
		op.DisplayName = displayName.String
	}
	if lastLogin.Valid {
		t := time.Unix(lastLogin.Int64, 0)
		op.LastLogin = &t
	}
	op.CreatedAt = time.Unix(createdAt, 0)
	if suspendedAt.Valid {
		t := time.Unix(suspendedAt.Int64, 0)
		op.SuspendedAt = &t
	}
	if suspendedBy.Valid {
		op.SuspendedBy = &suspendedBy.String
	}
	if suspendedReason.Valid {
		op.SuspendedReason = &suspendedReason.String
	}

	return &op, nil
}

// ----- Operator-Tenant Methods -----

// AddOperatorToTenant adds an operator to a tenant with a specific role.
func (s *Store) AddOperatorToTenant(operatorID, tenantID, role string) error {
	_, err := s.db.Exec(
		`INSERT INTO operator_tenants (operator_id, tenant_id, role) VALUES (?, ?, ?)`,
		operatorID, tenantID, role,
	)
	if err != nil {
		return fmt.Errorf("failed to add operator to tenant: %w", err)
	}
	return nil
}

// UpdateOperatorRole updates or creates an operator's role in a tenant.
// Uses upsert semantics: if the membership exists, updates the role;
// if it doesn't exist, creates a new membership.
func (s *Store) UpdateOperatorRole(operatorID, tenantID, role string) error {
	_, err := s.db.Exec(
		`INSERT INTO operator_tenants (operator_id, tenant_id, role) VALUES (?, ?, ?)
		 ON CONFLICT(operator_id, tenant_id) DO UPDATE SET role = excluded.role`,
		operatorID, tenantID, role,
	)
	if err != nil {
		return fmt.Errorf("failed to update operator role: %w", err)
	}
	return nil
}

// RemoveOperatorFromTenant removes an operator from a tenant.
func (s *Store) RemoveOperatorFromTenant(operatorID, tenantID string) error {
	result, err := s.db.Exec(
		`DELETE FROM operator_tenants WHERE operator_id = ? AND tenant_id = ?`,
		operatorID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove operator from tenant: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("operator-tenant membership not found")
	}
	return nil
}

// GetOperatorTenants returns all tenant memberships for an operator.
func (s *Store) GetOperatorTenants(operatorID string) ([]*OperatorTenant, error) {
	rows, err := s.db.Query(
		`SELECT operator_id, tenant_id, role, created_at FROM operator_tenants WHERE operator_id = ?`,
		operatorID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get operator tenants: %w", err)
	}
	defer rows.Close()

	var memberships []*OperatorTenant
	for rows.Next() {
		var ot OperatorTenant
		var createdAt int64
		err := rows.Scan(&ot.OperatorID, &ot.TenantID, &ot.Role, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan operator tenant: %w", err)
		}
		ot.CreatedAt = time.Unix(createdAt, 0)
		memberships = append(memberships, &ot)
	}
	return memberships, rows.Err()
}

// OperatorTenantWithName extends OperatorTenant with the tenant name.
// Used for batch queries that need to avoid N+1 lookups for tenant names.
type OperatorTenantWithName struct {
	OperatorID string
	TenantID   string
	TenantName string
	Role       string
	CreatedAt  time.Time
}

// GetOperatorTenantsForOperators returns all tenant memberships for a list of operators.
// Returns a map from operatorID to their memberships with tenant names included.
// Uses a single JOIN query to avoid N+1 queries when listing operators.
func (s *Store) GetOperatorTenantsForOperators(operatorIDs []string) (map[string][]*OperatorTenantWithName, error) {
	result := make(map[string][]*OperatorTenantWithName)

	if len(operatorIDs) == 0 {
		return result, nil
	}

	// Build placeholders for IN clause
	placeholders := make([]string, len(operatorIDs))
	args := make([]interface{}, len(operatorIDs))
	for i, id := range operatorIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(`
		SELECT ot.operator_id, ot.tenant_id, t.name, ot.role, ot.created_at
		FROM operator_tenants ot
		INNER JOIN tenants t ON ot.tenant_id = t.id
		WHERE ot.operator_id IN (%s)
		ORDER BY ot.operator_id, t.name`,
		strings.Join(placeholders, ","))

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get operator tenants: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var m OperatorTenantWithName
		var createdAt int64
		err := rows.Scan(&m.OperatorID, &m.TenantID, &m.TenantName, &m.Role, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan operator tenant: %w", err)
		}
		m.CreatedAt = time.Unix(createdAt, 0)
		result[m.OperatorID] = append(result[m.OperatorID], &m)
	}

	return result, rows.Err()
}

// GetOperatorRole returns the role of an operator in a specific tenant.
func (s *Store) GetOperatorRole(operatorID, tenantID string) (string, error) {
	var role string
	err := s.db.QueryRow(
		`SELECT role FROM operator_tenants WHERE operator_id = ? AND tenant_id = ?`,
		operatorID, tenantID,
	).Scan(&role)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("operator-tenant membership not found")
	}
	if err != nil {
		return "", fmt.Errorf("failed to get operator role: %w", err)
	}
	return role, nil
}

// IsSuperAdmin checks if an operator has super:admin role in any tenant.
// Per ADR-011, super:admin in any tenant grants global access.
func (s *Store) IsSuperAdmin(operatorID string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM operator_tenants WHERE operator_id = ? AND role = 'super:admin'`,
		operatorID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check super admin status: %w", err)
	}
	return count > 0, nil
}

// ----- Filtered List Methods -----

// ListOptions contains options for filtered list queries.
type ListOptions struct {
	Status   string // Filter by status (e.g., "active", "suspended", "revoked")
	TenantID string // Filter by tenant ID
	Limit    int    // Maximum number of results (0 = no limit)
	Offset   int    // Number of results to skip
}

// ListOperatorsFiltered returns operators with optional status and tenant filters.
// If tenantID is provided, only returns operators who are members of that tenant.
// Returns operators ordered by email with lifecycle fields populated.
func (s *Store) ListOperatorsFiltered(opts ListOptions) ([]*Operator, int, error) {
	// Build query based on filters
	var query string
	var countQuery string
	var args []interface{}

	if opts.TenantID != "" {
		// Join with operator_tenants to filter by tenant
		query = `SELECT DISTINCT o.id, o.email, o.display_name, o.status, o.created_at, o.last_login,
				o.suspended_at, o.suspended_by, o.suspended_reason
				FROM operators o
				INNER JOIN operator_tenants ot ON o.id = ot.operator_id
				WHERE ot.tenant_id = ?`
		countQuery = `SELECT COUNT(DISTINCT o.id) FROM operators o
				INNER JOIN operator_tenants ot ON o.id = ot.operator_id
				WHERE ot.tenant_id = ?`
		args = append(args, opts.TenantID)
	} else {
		query = `SELECT id, email, display_name, status, created_at, last_login,
				suspended_at, suspended_by, suspended_reason
				FROM operators WHERE 1=1`
		countQuery = `SELECT COUNT(*) FROM operators WHERE 1=1`
	}

	// Add status filter
	if opts.Status != "" {
		query += " AND o.status = ?"
		countQuery += " AND o.status = ?"
		if opts.TenantID == "" {
			// Adjust for non-joined query
			query = strings.Replace(query, "AND o.status", "AND status", 1)
			countQuery = strings.Replace(countQuery, "AND o.status", "AND status", 1)
		}
		args = append(args, opts.Status)
	}

	// Get total count first
	var total int
	err := s.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count operators: %w", err)
	}

	// Add ordering and pagination
	query += " ORDER BY email"
	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", opts.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list operators: %w", err)
	}
	defer rows.Close()

	var operators []*Operator
	for rows.Next() {
		op, err := s.scanOperatorRows(rows)
		if err != nil {
			return nil, 0, err
		}
		operators = append(operators, op)
	}
	return operators, total, rows.Err()
}
