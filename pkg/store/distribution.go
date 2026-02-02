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
	ID                  int64
	DPUName             string
	CredentialType      string              // e.g., "ssh-ca"
	CredentialName      string              // e.g., CA name
	Outcome             DistributionOutcome // success, blocked-stale, blocked-failed, forced
	AttestationStatus   *string             // Status at distribution time (nullable)
	AttestationAgeSecs  *int                // Age in seconds at distribution time (nullable)
	InstalledPath       *string             // Where credential was installed (nullable if blocked)
	ErrorMessage        *string             // Error if failed (nullable)
	OperatorID          string              // Who performed the distribution
	OperatorEmail       string              // Operator email for display
	TenantID            string              // Tenant context
	AttestationSnapshot *string             // JSON blob of measurements at distribution time
	BlockedReason       *string             // Why distribution was blocked (if blocked)
	ForcedBy            *string             // Who authorized the override (if forced)
	CreatedAt           time.Time
}

// DistributionQueryOpts specifies filters for querying distributions.
type DistributionQueryOpts struct {
	TargetDPU     string
	OperatorID    string
	OperatorEmail string // Filter by operator email (matches operator_email column)
	TenantID      string
	Outcome       *DistributionOutcome
	OutcomePrefix string // Match outcomes starting with this prefix (e.g., "blocked" matches blocked-stale and blocked-failed)
	From          *time.Time
	To            *time.Time
	Limit         int
}

// RecordDistribution inserts a new distribution record.
func (s *Store) RecordDistribution(d *Distribution) error {
	result, err := s.db.Exec(`
		INSERT INTO distribution_history
			(dpu_name, credential_type, credential_name, outcome, attestation_status, attestation_age_seconds,
			 installed_path, error_message, operator_id, operator_email, tenant_id,
			 attestation_snapshot, blocked_reason, forced_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, d.DPUName, d.CredentialType, d.CredentialName, string(d.Outcome),
		nullableString(d.AttestationStatus),
		nullableInt(d.AttestationAgeSecs),
		nullableString(d.InstalledPath),
		nullableString(d.ErrorMessage),
		d.OperatorID,
		d.OperatorEmail,
		d.TenantID,
		nullableString(d.AttestationSnapshot),
		nullableString(d.BlockedReason),
		nullableString(d.ForcedBy))

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

// distributionColumns is the standard set of columns to select for distribution queries.
const distributionColumns = `id, dpu_name, credential_type, credential_name, outcome,
	attestation_status, attestation_age_seconds, installed_path, error_message,
	operator_id, operator_email, tenant_id, attestation_snapshot, blocked_reason, forced_by, created_at`

// GetDistributionHistory retrieves distribution history for a specific DPU.
// Results are ordered by created_at DESC, id DESC (most recent first).
func (s *Store) GetDistributionHistory(dpuName string) ([]*Distribution, error) {
	rows, err := s.db.Query(`
		SELECT `+distributionColumns+`
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
		SELECT `+distributionColumns+`
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
		SELECT `+distributionColumns+`
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
	var attestationSnapshot sql.NullString
	var blockedReason sql.NullString
	var forcedBy sql.NullString

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
		&d.OperatorID,
		&d.OperatorEmail,
		&d.TenantID,
		&attestationSnapshot,
		&blockedReason,
		&forcedBy,
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
	if attestationSnapshot.Valid {
		d.AttestationSnapshot = &attestationSnapshot.String
	}
	if blockedReason.Valid {
		d.BlockedReason = &blockedReason.String
	}
	if forcedBy.Valid {
		d.ForcedBy = &forcedBy.String
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

// ListDistributionsByOperator returns distributions by a specific operator.
// Results are ordered by created_at DESC, id DESC (most recent first).
func (s *Store) ListDistributionsByOperator(operatorID string, limit int) ([]*Distribution, error) {
	rows, err := s.db.Query(`
		SELECT `+distributionColumns+`
		FROM distribution_history
		WHERE operator_id = ?
		ORDER BY created_at DESC, id DESC
		LIMIT ?
	`, operatorID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list distributions by operator: %w", err)
	}
	defer rows.Close()

	return s.scanDistributionRows(rows)
}

// ListDistributionsByTenant returns distributions within a tenant.
// Results are ordered by created_at DESC, id DESC (most recent first).
func (s *Store) ListDistributionsByTenant(tenantID string, limit int) ([]*Distribution, error) {
	rows, err := s.db.Query(`
		SELECT `+distributionColumns+`
		FROM distribution_history
		WHERE tenant_id = ?
		ORDER BY created_at DESC, id DESC
		LIMIT ?
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list distributions by tenant: %w", err)
	}
	defer rows.Close()

	return s.scanDistributionRows(rows)
}

// ListDistributionsByOutcome returns distributions with a specific outcome.
// Results are ordered by created_at DESC, id DESC (most recent first).
func (s *Store) ListDistributionsByOutcome(outcome DistributionOutcome, limit int) ([]*Distribution, error) {
	rows, err := s.db.Query(`
		SELECT `+distributionColumns+`
		FROM distribution_history
		WHERE outcome = ?
		ORDER BY created_at DESC, id DESC
		LIMIT ?
	`, string(outcome), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list distributions by outcome: %w", err)
	}
	defer rows.Close()

	return s.scanDistributionRows(rows)
}

// ListDistributionsInTimeRange returns distributions within a time window.
// Results are ordered by created_at DESC, id DESC (most recent first).
func (s *Store) ListDistributionsInTimeRange(from, to time.Time, limit int) ([]*Distribution, error) {
	rows, err := s.db.Query(`
		SELECT `+distributionColumns+`
		FROM distribution_history
		WHERE created_at >= ? AND created_at <= ?
		ORDER BY created_at DESC, id DESC
		LIMIT ?
	`, from.Unix(), to.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list distributions in time range: %w", err)
	}
	defer rows.Close()

	return s.scanDistributionRows(rows)
}

// ListDistributionsWithFilters returns distributions matching multiple criteria.
// Results are ordered by created_at DESC, id DESC (most recent first).
func (s *Store) ListDistributionsWithFilters(opts DistributionQueryOpts) ([]*Distribution, error) {
	query := "SELECT " + distributionColumns + " FROM distribution_history WHERE 1=1"
	args := []interface{}{}

	if opts.TargetDPU != "" {
		query += " AND dpu_name = ?"
		args = append(args, opts.TargetDPU)
	}
	if opts.OperatorID != "" {
		query += " AND operator_id = ?"
		args = append(args, opts.OperatorID)
	}
	if opts.OperatorEmail != "" {
		query += " AND operator_email = ?"
		args = append(args, opts.OperatorEmail)
	}
	if opts.TenantID != "" {
		query += " AND tenant_id = ?"
		args = append(args, opts.TenantID)
	}
	if opts.Outcome != nil {
		query += " AND outcome = ?"
		args = append(args, string(*opts.Outcome))
	}
	if opts.OutcomePrefix != "" {
		query += " AND outcome LIKE ?"
		args = append(args, opts.OutcomePrefix+"%")
	}
	if opts.From != nil {
		query += " AND created_at >= ?"
		args = append(args, opts.From.Unix())
	}
	if opts.To != nil {
		query += " AND created_at <= ?"
		args = append(args, opts.To.Unix())
	}

	query += " ORDER BY created_at DESC, id DESC"

	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list distributions with filters: %w", err)
	}
	defer rows.Close()

	return s.scanDistributionRows(rows)
}
