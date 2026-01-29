// Package store provides SQLite-based storage for DPU registry.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DPU represents a registered DPU in the store.
type DPU struct {
	ID        string
	Name      string
	Host      string
	Port      int
	Status    string
	LastSeen  *time.Time
	CreatedAt time.Time
	TenantID  *string
	Labels    map[string]string
}

// Tenant represents a logical grouping of DPUs.
type Tenant struct {
	ID          string
	Name        string
	Description string
	Contact     string
	Tags        []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Host represents a host machine with a Host Agent.
type Host struct {
	ID        string
	Name      string
	Address   string
	Port      int
	Status    string
	LastSeen  *time.Time
	CreatedAt time.Time
	DPUID     *string // Associated DPU (optional)
}

// Operator represents a user who can manage DPUs.
type Operator struct {
	ID          string
	Email       string
	DisplayName string
	Status      string // pending, active, suspended
	CreatedAt   time.Time
	LastLogin   *time.Time
}

// InviteCode represents a one-time code for operator onboarding.
type InviteCode struct {
	ID             string
	CodeHash       string // SHA-256 hash of code
	OperatorEmail  string
	TenantID       string
	Role           string // admin, operator
	CreatedBy      string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	UsedAt         *time.Time
	UsedByKeyMaker *string // KeyMaker ID that used this code
	Status         string  // pending, used, expired, revoked
}

// OperatorTenant represents an operator's membership in a tenant with a specific role.
type OperatorTenant struct {
	OperatorID string
	TenantID   string
	Role       string // admin, operator
	CreatedAt  time.Time
}

// KeyMaker represents a hardware-bound device credential for an operator.
type KeyMaker struct {
	ID                string
	OperatorID        string
	Name              string
	Platform          string // darwin, linux, windows
	SecureElement     string // tpm, secure_enclave, software
	DeviceFingerprint string
	PublicKey         string
	BoundAt           time.Time
	LastSeen          *time.Time
	Status            string // active, revoked
}

// Authorization grants an operator access to specific CAs and devices.
type Authorization struct {
	ID         string
	OperatorID string
	TenantID   string
	CreatedAt  time.Time
	CreatedBy  string
	ExpiresAt  *time.Time
	CAIDs      []string // Populated by join
	DeviceIDs  []string // Populated by join, "all" means all devices
}

// GRPCAddress returns the gRPC address for this Host Agent.
func (h *Host) GRPCAddress() string {
	return fmt.Sprintf("%s:%d", h.Address, h.Port)
}

// Address returns the gRPC address for this DPU.
func (d *DPU) Address() string {
	return fmt.Sprintf("%s:%d", d.Host, d.Port)
}

// Store provides DPU registry operations.
type Store struct {
	db *sql.DB
}

// DefaultPath returns the default database path following XDG spec.
func DefaultPath() string {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, _ := os.UserHomeDir()
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, "bluectl", "dpus.db")
}

// Open opens or creates a SQLite database at the given path.
func Open(path string) (*Store, error) {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable foreign key constraints
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Enable WAL mode for better concurrent access across processes.
	// WAL mode allows readers to see committed changes immediately without
	// blocking writers, which is essential when CLI creates invite codes
	// and a long-running server needs to validate them.
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return store, nil
}

// migrate creates the schema if it doesn't exist and applies migrations.
func (s *Store) migrate() error {
	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS tenants (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		description TEXT DEFAULT '',
		contact TEXT DEFAULT '',
		tags TEXT DEFAULT '',
		created_at INTEGER DEFAULT (strftime('%s', 'now')),
		updated_at INTEGER DEFAULT (strftime('%s', 'now'))
	);
	CREATE INDEX IF NOT EXISTS idx_tenants_name ON tenants(name);

	CREATE TABLE IF NOT EXISTS dpus (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		host TEXT NOT NULL,
		port INTEGER DEFAULT 18051,
		status TEXT DEFAULT 'unknown',
		last_seen INTEGER,
		created_at INTEGER DEFAULT (strftime('%s', 'now'))
	);
	CREATE INDEX IF NOT EXISTS idx_dpus_name ON dpus(name);

	CREATE TABLE IF NOT EXISTS hosts (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		address TEXT NOT NULL,
		port INTEGER DEFAULT 50052,
		status TEXT DEFAULT 'unknown',
		last_seen INTEGER,
		created_at INTEGER DEFAULT (strftime('%s', 'now')),
		dpu_id TEXT REFERENCES dpus(id) ON DELETE SET NULL
	);
	CREATE INDEX IF NOT EXISTS idx_hosts_name ON hosts(name);
	CREATE INDEX IF NOT EXISTS idx_hosts_dpu ON hosts(dpu_id);

	CREATE TABLE IF NOT EXISTS ssh_cas (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		public_key BLOB NOT NULL,
		encrypted_private_key BLOB NOT NULL,
		key_type TEXT DEFAULT 'ed25519',
		created_at INTEGER DEFAULT (strftime('%s', 'now'))
	);
	CREATE INDEX IF NOT EXISTS idx_ssh_cas_name ON ssh_cas(name);

	CREATE TABLE IF NOT EXISTS attestations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		dpu_name TEXT NOT NULL UNIQUE,
		status TEXT NOT NULL,
		last_validated INTEGER,
		dice_chain_hash TEXT,
		measurements_hash TEXT,
		raw_data TEXT,
		created_at INTEGER DEFAULT (strftime('%s', 'now')),
		updated_at INTEGER DEFAULT (strftime('%s', 'now'))
	);
	CREATE INDEX IF NOT EXISTS idx_attestations_dpu ON attestations(dpu_name);
	CREATE INDEX IF NOT EXISTS idx_attestations_status ON attestations(status);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp INTEGER NOT NULL,
		action TEXT NOT NULL,
		target TEXT,
		decision TEXT,
		attestation_snapshot TEXT,
		details TEXT,
		created_at INTEGER DEFAULT (strftime('%s', 'now'))
	);
	CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
	CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target);

	CREATE TABLE IF NOT EXISTS distribution_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		dpu_name TEXT NOT NULL,
		credential_type TEXT NOT NULL,
		credential_name TEXT NOT NULL,
		outcome TEXT NOT NULL,
		attestation_status TEXT,
		attestation_age_seconds INTEGER,
		installed_path TEXT,
		error_message TEXT,
		operator_id TEXT DEFAULT '',
		operator_email TEXT DEFAULT '',
		tenant_id TEXT DEFAULT '',
		attestation_snapshot TEXT,
		blocked_reason TEXT,
		forced_by TEXT,
		created_at INTEGER DEFAULT (strftime('%s', 'now'))
	);
	CREATE INDEX IF NOT EXISTS idx_distribution_history_dpu ON distribution_history(dpu_name);
	CREATE INDEX IF NOT EXISTS idx_distribution_history_credential ON distribution_history(credential_name);
	CREATE INDEX IF NOT EXISTS idx_distribution_history_operator ON distribution_history(operator_id);
	CREATE INDEX IF NOT EXISTS idx_distribution_history_tenant ON distribution_history(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_distribution_history_outcome ON distribution_history(outcome);
	CREATE INDEX IF NOT EXISTS idx_distribution_history_created ON distribution_history(created_at);

	-- Operators
	CREATE TABLE IF NOT EXISTS operators (
		id TEXT PRIMARY KEY,
		email TEXT NOT NULL UNIQUE,
		display_name TEXT,
		created_at INTEGER DEFAULT (strftime('%s', 'now')),
		last_login INTEGER,
		status TEXT NOT NULL DEFAULT 'pending'
	);
	CREATE INDEX IF NOT EXISTS idx_operators_email ON operators(email);
	CREATE INDEX IF NOT EXISTS idx_operators_status ON operators(status);

	-- Operator-Tenant membership (many-to-many)
	CREATE TABLE IF NOT EXISTS operator_tenants (
		operator_id TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		role TEXT NOT NULL DEFAULT 'operator',
		created_at INTEGER DEFAULT (strftime('%s', 'now')),
		PRIMARY KEY (operator_id, tenant_id)
	);

	-- KeyMakers (bound devices)
	CREATE TABLE IF NOT EXISTS keymakers (
		id TEXT PRIMARY KEY,
		operator_id TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		platform TEXT NOT NULL,
		secure_element TEXT NOT NULL,
		device_fingerprint TEXT NOT NULL,
		public_key TEXT NOT NULL,
		bound_at INTEGER DEFAULT (strftime('%s', 'now')),
		last_seen INTEGER,
		status TEXT NOT NULL DEFAULT 'active'
	);
	CREATE INDEX IF NOT EXISTS idx_keymakers_operator ON keymakers(operator_id);

	-- Invite Codes (hashed, never plaintext)
	CREATE TABLE IF NOT EXISTS invite_codes (
		id TEXT PRIMARY KEY,
		code_hash TEXT NOT NULL,
		operator_email TEXT NOT NULL,
		tenant_id TEXT NOT NULL REFERENCES tenants(id),
		role TEXT NOT NULL DEFAULT 'operator',
		created_by TEXT NOT NULL,
		created_at INTEGER DEFAULT (strftime('%s', 'now')),
		expires_at INTEGER NOT NULL,
		used_at INTEGER,
		used_by_keymaker TEXT,
		status TEXT NOT NULL DEFAULT 'pending'
	);
	CREATE INDEX IF NOT EXISTS idx_invite_codes_hash ON invite_codes(code_hash);
	CREATE INDEX IF NOT EXISTS idx_invite_codes_email ON invite_codes(operator_email);

	-- Authorization
	CREATE TABLE IF NOT EXISTS authorizations (
		id TEXT PRIMARY KEY,
		operator_id TEXT NOT NULL REFERENCES operators(id),
		tenant_id TEXT NOT NULL REFERENCES tenants(id),
		created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
		created_by TEXT NOT NULL,
		expires_at INTEGER
	);

	CREATE TABLE IF NOT EXISTS authorization_cas (
		authorization_id TEXT NOT NULL REFERENCES authorizations(id) ON DELETE CASCADE,
		ca_id TEXT NOT NULL,
		PRIMARY KEY (authorization_id, ca_id)
	);

	CREATE TABLE IF NOT EXISTS authorization_devices (
		authorization_id TEXT NOT NULL REFERENCES authorizations(id) ON DELETE CASCADE,
		device_id TEXT NOT NULL,
		PRIMARY KEY (authorization_id, device_id)
	);

	CREATE INDEX IF NOT EXISTS idx_authorizations_operator ON authorizations(operator_id);
	CREATE INDEX IF NOT EXISTS idx_authorizations_tenant ON authorizations(tenant_id);

	-- Trust Relationships (host-to-host trust, gated by DPU attestation)
	CREATE TABLE IF NOT EXISTS trust_relationships (
		id TEXT PRIMARY KEY,
		source_host TEXT NOT NULL,
		target_host TEXT NOT NULL,
		source_dpu_id TEXT NOT NULL,
		source_dpu_name TEXT NOT NULL,
		target_dpu_id TEXT NOT NULL,
		target_dpu_name TEXT NOT NULL,
		tenant_id TEXT NOT NULL,
		trust_type TEXT NOT NULL,
		bidirectional INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'active',
		suspend_reason TEXT,
		target_cert_serial INTEGER,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		FOREIGN KEY (tenant_id) REFERENCES tenants(id)
	);
	CREATE INDEX IF NOT EXISTS idx_trust_tenant ON trust_relationships(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_trust_source_host ON trust_relationships(source_host);
	CREATE INDEX IF NOT EXISTS idx_trust_target_host ON trust_relationships(target_host);
	CREATE INDEX IF NOT EXISTS idx_trust_source_dpu ON trust_relationships(source_dpu_id);
	CREATE INDEX IF NOT EXISTS idx_trust_target_dpu ON trust_relationships(target_dpu_id);

	-- Agent Hosts (Phase 5: hosts with security posture linked to DPUs)
	CREATE TABLE IF NOT EXISTS agent_hosts (
		id TEXT PRIMARY KEY,
		dpu_name TEXT NOT NULL,
		dpu_id TEXT NOT NULL,
		hostname TEXT NOT NULL UNIQUE,
		tenant_id TEXT,
		registered_at INTEGER NOT NULL,
		last_seen_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_agent_hosts_dpu ON agent_hosts(dpu_name);
	CREATE INDEX IF NOT EXISTS idx_agent_hosts_tenant ON agent_hosts(tenant_id);

	CREATE TABLE IF NOT EXISTS agent_host_posture (
		host_id TEXT PRIMARY KEY,
		secure_boot INTEGER,
		disk_encryption TEXT,
		os_version TEXT,
		kernel_version TEXT,
		tpm_present INTEGER,
		posture_hash TEXT,
		collected_at INTEGER NOT NULL,
		FOREIGN KEY (host_id) REFERENCES agent_hosts(id) ON DELETE CASCADE
	);

	-- Credential Queue (aegis state persistence: queued credentials awaiting delivery)
	CREATE TABLE IF NOT EXISTS credential_queue (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		dpu_name TEXT NOT NULL,
		cred_type TEXT NOT NULL,
		cred_name TEXT NOT NULL,
		data BLOB NOT NULL,
		queued_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_credential_queue_dpu ON credential_queue(dpu_name);
	CREATE INDEX IF NOT EXISTS idx_credential_queue_queued ON credential_queue(queued_at);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Apply column migrations for existing databases
	migrations := []string{
		"ALTER TABLE dpus ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL",
		"ALTER TABLE dpus ADD COLUMN labels TEXT DEFAULT '{}'",
		"ALTER TABLE ssh_cas ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL",
		// Distribution history Phase 3 audit trail enhancements
		"ALTER TABLE distribution_history ADD COLUMN operator_id TEXT DEFAULT ''",
		"ALTER TABLE distribution_history ADD COLUMN operator_email TEXT DEFAULT ''",
		"ALTER TABLE distribution_history ADD COLUMN tenant_id TEXT DEFAULT ''",
		"ALTER TABLE distribution_history ADD COLUMN attestation_snapshot TEXT",
		"ALTER TABLE distribution_history ADD COLUMN blocked_reason TEXT",
		"ALTER TABLE distribution_history ADD COLUMN forced_by TEXT",
		// Host-to-host trust model: add host columns and cert serial
		"ALTER TABLE trust_relationships ADD COLUMN source_host TEXT DEFAULT ''",
		"ALTER TABLE trust_relationships ADD COLUMN target_host TEXT DEFAULT ''",
		"ALTER TABLE trust_relationships ADD COLUMN target_cert_serial INTEGER",
	}

	for _, m := range migrations {
		// Ignore errors for columns that already exist
		s.db.Exec(m)
	}

	// Create indexes that may not exist
	indexes := `
	CREATE INDEX IF NOT EXISTS idx_dpus_tenant ON dpus(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_trust_source_host ON trust_relationships(source_host);
	CREATE INDEX IF NOT EXISTS idx_trust_target_host ON trust_relationships(target_host);
	`
	_, err := s.db.Exec(indexes)
	return err
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Add registers a new DPU.
func (s *Store) Add(id, name, host string, port int) error {
	_, err := s.db.Exec(
		`INSERT INTO dpus (id, name, host, port) VALUES (?, ?, ?, ?)`,
		id, name, host, port,
	)
	if err != nil {
		return fmt.Errorf("failed to add DPU: %w", err)
	}
	return nil
}

// Remove deletes a DPU by ID or name.
func (s *Store) Remove(idOrName string) error {
	result, err := s.db.Exec(
		`DELETE FROM dpus WHERE id = ? OR name = ?`,
		idOrName, idOrName,
	)
	if err != nil {
		return fmt.Errorf("failed to remove DPU: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("DPU not found: %s", idOrName)
	}
	return nil
}

// Get retrieves a DPU by ID or name.
func (s *Store) Get(idOrName string) (*DPU, error) {
	row := s.db.QueryRow(
		`SELECT id, name, host, port, status, last_seen, created_at, tenant_id, labels FROM dpus WHERE id = ? OR name = ?`,
		idOrName, idOrName,
	)
	return s.scanDPU(row)
}

// GetDPUByAddress returns a DPU with the given host:port, or nil if not found.
func (s *Store) GetDPUByAddress(host string, port int) (*DPU, error) {
	row := s.db.QueryRow(
		`SELECT id, name, host, port, status, last_seen, created_at, tenant_id, labels FROM dpus WHERE host = ? AND port = ?`,
		host, port,
	)

	var dpu DPU
	var lastSeen sql.NullInt64
	var createdAt int64
	var tenantID sql.NullString
	var labelsJSON string

	err := row.Scan(&dpu.ID, &dpu.Name, &dpu.Host, &dpu.Port, &dpu.Status, &lastSeen, &createdAt, &tenantID, &labelsJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan DPU: %w", err)
	}

	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		dpu.LastSeen = &t
	}
	dpu.CreatedAt = time.Unix(createdAt, 0)
	if tenantID.Valid {
		dpu.TenantID = &tenantID.String
	}
	dpu.Labels = make(map[string]string)
	if labelsJSON != "" {
		json.Unmarshal([]byte(labelsJSON), &dpu.Labels)
	}

	return &dpu, nil
}

// List returns all registered DPUs.
func (s *Store) List() ([]*DPU, error) {
	rows, err := s.db.Query(
		`SELECT id, name, host, port, status, last_seen, created_at, tenant_id, labels FROM dpus ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list DPUs: %w", err)
	}
	defer rows.Close()

	var dpus []*DPU
	for rows.Next() {
		dpu, err := s.scanDPURows(rows)
		if err != nil {
			return nil, err
		}
		dpus = append(dpus, dpu)
	}
	return dpus, rows.Err()
}

// UpdateStatus updates the status and last_seen time for a DPU.
func (s *Store) UpdateStatus(idOrName, status string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE dpus SET status = ?, last_seen = ? WHERE id = ? OR name = ?`,
		status, now, idOrName, idOrName,
	)
	if err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("DPU not found: %s", idOrName)
	}
	return nil
}

// SetDPULabels updates the labels for a DPU.
func (s *Store) SetDPULabels(idOrName string, labels map[string]string) error {
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("failed to marshal labels: %w", err)
	}

	result, err := s.db.Exec(
		`UPDATE dpus SET labels = ? WHERE id = ? OR name = ?`,
		string(labelsJSON), idOrName, idOrName,
	)
	if err != nil {
		return fmt.Errorf("failed to set DPU labels: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("DPU not found: %s", idOrName)
	}
	return nil
}

func (s *Store) scanDPU(row *sql.Row) (*DPU, error) {
	var dpu DPU
	var lastSeen sql.NullInt64
	var createdAt int64
	var tenantID sql.NullString
	var labelsJSON string

	err := row.Scan(&dpu.ID, &dpu.Name, &dpu.Host, &dpu.Port, &dpu.Status, &lastSeen, &createdAt, &tenantID, &labelsJSON)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("DPU not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan DPU: %w", err)
	}

	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		dpu.LastSeen = &t
	}
	dpu.CreatedAt = time.Unix(createdAt, 0)
	if tenantID.Valid {
		dpu.TenantID = &tenantID.String
	}
	dpu.Labels = make(map[string]string)
	if labelsJSON != "" {
		json.Unmarshal([]byte(labelsJSON), &dpu.Labels)
	}

	return &dpu, nil
}

func (s *Store) scanDPURows(rows *sql.Rows) (*DPU, error) {
	var dpu DPU
	var lastSeen sql.NullInt64
	var createdAt int64
	var tenantID sql.NullString
	var labelsJSON string

	err := rows.Scan(&dpu.ID, &dpu.Name, &dpu.Host, &dpu.Port, &dpu.Status, &lastSeen, &createdAt, &tenantID, &labelsJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to scan DPU: %w", err)
	}

	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		dpu.LastSeen = &t
	}
	dpu.CreatedAt = time.Unix(createdAt, 0)
	if tenantID.Valid {
		dpu.TenantID = &tenantID.String
	}
	dpu.Labels = make(map[string]string)
	if labelsJSON != "" {
		json.Unmarshal([]byte(labelsJSON), &dpu.Labels)
	}

	return &dpu, nil
}

// ----- Tenant Methods -----

// AddTenant creates a new tenant.
func (s *Store) AddTenant(id, name, description, contact string, tags []string) error {
	tagsStr := strings.Join(tags, ",")
	_, err := s.db.Exec(
		`INSERT INTO tenants (id, name, description, contact, tags) VALUES (?, ?, ?, ?, ?)`,
		id, name, description, contact, tagsStr,
	)
	if err != nil {
		// Check for unique constraint violation and return user-friendly error
		if strings.Contains(err.Error(), "UNIQUE constraint failed: tenants.name") {
			return fmt.Errorf("tenant '%s' already exists", name)
		}
		return fmt.Errorf("failed to add tenant: %w", err)
	}
	return nil
}

// GetTenant retrieves a tenant by ID or name.
func (s *Store) GetTenant(idOrName string) (*Tenant, error) {
	row := s.db.QueryRow(
		`SELECT id, name, description, contact, tags, created_at, updated_at FROM tenants WHERE id = ? OR name = ?`,
		idOrName, idOrName,
	)
	return s.scanTenant(row)
}

// ListTenants returns all tenants.
func (s *Store) ListTenants() ([]*Tenant, error) {
	rows, err := s.db.Query(
		`SELECT id, name, description, contact, tags, created_at, updated_at FROM tenants ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		tenant, err := s.scanTenantRows(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}

// UpdateTenant updates a tenant's details.
func (s *Store) UpdateTenant(id, name, description, contact string, tags []string) error {
	tagsStr := strings.Join(tags, ",")
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE tenants SET name = ?, description = ?, contact = ?, tags = ?, updated_at = ? WHERE id = ?`,
		name, description, contact, tagsStr, now, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("tenant not found: %s", id)
	}
	return nil
}

// RemoveTenant deletes a tenant by ID.
func (s *Store) RemoveTenant(id string) error {
	result, err := s.db.Exec(`DELETE FROM tenants WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to remove tenant: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("tenant not found: %s", id)
	}
	return nil
}

// AssignDPUToTenant assigns a DPU to a tenant.
func (s *Store) AssignDPUToTenant(dpuID, tenantID string) error {
	result, err := s.db.Exec(
		`UPDATE dpus SET tenant_id = ? WHERE id = ? OR name = ?`,
		tenantID, dpuID, dpuID,
	)
	if err != nil {
		return fmt.Errorf("failed to assign DPU to tenant: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("DPU not found: %s", dpuID)
	}
	return nil
}

// UnassignDPUFromTenant removes a DPU from its tenant.
func (s *Store) UnassignDPUFromTenant(dpuID string) error {
	result, err := s.db.Exec(
		`UPDATE dpus SET tenant_id = NULL WHERE id = ? OR name = ?`,
		dpuID, dpuID,
	)
	if err != nil {
		return fmt.Errorf("failed to unassign DPU from tenant: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("DPU not found: %s", dpuID)
	}
	return nil
}

// ListDPUsByTenant returns all DPUs for a specific tenant.
func (s *Store) ListDPUsByTenant(tenantID string) ([]*DPU, error) {
	rows, err := s.db.Query(
		`SELECT id, name, host, port, status, last_seen, created_at, tenant_id, labels FROM dpus WHERE tenant_id = ? ORDER BY name`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list DPUs by tenant: %w", err)
	}
	defer rows.Close()

	var dpus []*DPU
	for rows.Next() {
		dpu, err := s.scanDPURows(rows)
		if err != nil {
			return nil, err
		}
		dpus = append(dpus, dpu)
	}
	return dpus, rows.Err()
}

// GetTenantDPUCount returns the number of DPUs assigned to a tenant.
func (s *Store) GetTenantDPUCount(tenantID string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM dpus WHERE tenant_id = ?`, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count DPUs: %w", err)
	}
	return count, nil
}

// TenantDependencies holds all entities that reference a tenant.
type TenantDependencies struct {
	DPUs               []string // DPU names assigned to tenant
	Operators          []string // Operator emails in tenant
	CAs                []string // SSH CA names in tenant
	TrustRelationships int      // Count of trust relationships
	Invites            int      // Count of pending invite codes
}

// HasAny returns true if the tenant has any dependencies.
func (d *TenantDependencies) HasAny() bool {
	return len(d.DPUs) > 0 || len(d.Operators) > 0 || len(d.CAs) > 0 || d.TrustRelationships > 0 || d.Invites > 0
}

// GetTenantDependencies returns all entities that reference the given tenant.
func (s *Store) GetTenantDependencies(tenantID string) (*TenantDependencies, error) {
	deps := &TenantDependencies{
		DPUs:      []string{},
		Operators: []string{},
		CAs:       []string{},
	}

	// Query DPU names
	dpuRows, err := s.db.Query(`SELECT name FROM dpus WHERE tenant_id = ? ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query DPUs: %w", err)
	}
	defer dpuRows.Close()
	for dpuRows.Next() {
		var name string
		if err := dpuRows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to scan DPU name: %w", err)
		}
		deps.DPUs = append(deps.DPUs, name)
	}
	if err := dpuRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating DPU rows: %w", err)
	}

	// Query operator emails via operator_tenants
	opRows, err := s.db.Query(
		`SELECT o.email FROM operators o
		 INNER JOIN operator_tenants ot ON o.id = ot.operator_id
		 WHERE ot.tenant_id = ?
		 ORDER BY o.email`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query operators: %w", err)
	}
	defer opRows.Close()
	for opRows.Next() {
		var email string
		if err := opRows.Scan(&email); err != nil {
			return nil, fmt.Errorf("failed to scan operator email: %w", err)
		}
		deps.Operators = append(deps.Operators, email)
	}
	if err := opRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating operator rows: %w", err)
	}

	// Query SSH CA names
	caRows, err := s.db.Query(`SELECT name FROM ssh_cas WHERE tenant_id = ? ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query CAs: %w", err)
	}
	defer caRows.Close()
	for caRows.Next() {
		var name string
		if err := caRows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to scan CA name: %w", err)
		}
		deps.CAs = append(deps.CAs, name)
	}
	if err := caRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating CA rows: %w", err)
	}

	// Query trust relationships count
	var trustCount int
	err = s.db.QueryRow(`SELECT COUNT(*) FROM trust_relationships WHERE tenant_id = ?`, tenantID).Scan(&trustCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count trust relationships: %w", err)
	}
	deps.TrustRelationships = trustCount

	// Query pending invite codes count
	var inviteCount int
	err = s.db.QueryRow(`SELECT COUNT(*) FROM invite_codes WHERE tenant_id = ? AND status = 'pending'`, tenantID).Scan(&inviteCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count invites: %w", err)
	}
	deps.Invites = inviteCount

	return deps, nil
}

func (s *Store) scanTenant(row *sql.Row) (*Tenant, error) {
	var tenant Tenant
	var tagsStr string
	var createdAt, updatedAt int64

	err := row.Scan(&tenant.ID, &tenant.Name, &tenant.Description, &tenant.Contact, &tagsStr, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("tenant not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan tenant: %w", err)
	}

	tenant.CreatedAt = time.Unix(createdAt, 0)
	tenant.UpdatedAt = time.Unix(updatedAt, 0)
	if tagsStr != "" {
		tenant.Tags = strings.Split(tagsStr, ",")
	} else {
		tenant.Tags = []string{}
	}

	return &tenant, nil
}

func (s *Store) scanTenantRows(rows *sql.Rows) (*Tenant, error) {
	var tenant Tenant
	var tagsStr string
	var createdAt, updatedAt int64

	err := rows.Scan(&tenant.ID, &tenant.Name, &tenant.Description, &tenant.Contact, &tagsStr, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to scan tenant: %w", err)
	}

	tenant.CreatedAt = time.Unix(createdAt, 0)
	tenant.UpdatedAt = time.Unix(updatedAt, 0)
	if tagsStr != "" {
		tenant.Tags = strings.Split(tagsStr, ",")
	} else {
		tenant.Tags = []string{}
	}

	return &tenant, nil
}

// ----- Host Methods -----

// AddHost registers a new host agent.
func (s *Store) AddHost(id, name, address string, port int) error {
	_, err := s.db.Exec(
		`INSERT INTO hosts (id, name, address, port) VALUES (?, ?, ?, ?)`,
		id, name, address, port,
	)
	if err != nil {
		return fmt.Errorf("failed to add host: %w", err)
	}
	return nil
}

// GetHost retrieves a host by ID or name.
func (s *Store) GetHost(idOrName string) (*Host, error) {
	row := s.db.QueryRow(
		`SELECT id, name, address, port, status, last_seen, created_at, dpu_id FROM hosts WHERE id = ? OR name = ?`,
		idOrName, idOrName,
	)
	return s.scanHost(row)
}

// ListHosts returns all registered hosts.
func (s *Store) ListHosts() ([]*Host, error) {
	rows, err := s.db.Query(
		`SELECT id, name, address, port, status, last_seen, created_at, dpu_id FROM hosts ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list hosts: %w", err)
	}
	defer rows.Close()

	var hosts []*Host
	for rows.Next() {
		host, err := s.scanHostRows(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, rows.Err()
}

// RemoveHost deletes a host by ID or name.
func (s *Store) RemoveHost(idOrName string) error {
	result, err := s.db.Exec(
		`DELETE FROM hosts WHERE id = ? OR name = ?`,
		idOrName, idOrName,
	)
	if err != nil {
		return fmt.Errorf("failed to remove host: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("host not found: %s", idOrName)
	}
	return nil
}

// UpdateHostStatus updates the status and last_seen time for a host.
func (s *Store) UpdateHostStatus(idOrName, status string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE hosts SET status = ?, last_seen = ? WHERE id = ? OR name = ?`,
		status, now, idOrName, idOrName,
	)
	if err != nil {
		return fmt.Errorf("failed to update host status: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("host not found: %s", idOrName)
	}
	return nil
}

// LinkHostToDPU associates a host with a DPU.
func (s *Store) LinkHostToDPU(hostID, dpuID string) error {
	result, err := s.db.Exec(
		`UPDATE hosts SET dpu_id = ? WHERE id = ? OR name = ?`,
		dpuID, hostID, hostID,
	)
	if err != nil {
		return fmt.Errorf("failed to link host to DPU: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("host not found: %s", hostID)
	}
	return nil
}

// UnlinkHostFromDPU removes the DPU association from a host.
func (s *Store) UnlinkHostFromDPU(hostID string) error {
	result, err := s.db.Exec(
		`UPDATE hosts SET dpu_id = NULL WHERE id = ? OR name = ?`,
		hostID, hostID,
	)
	if err != nil {
		return fmt.Errorf("failed to unlink host from DPU: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("host not found: %s", hostID)
	}
	return nil
}

// GetHostByDPU returns the host associated with a DPU.
func (s *Store) GetHostByDPU(dpuID string) (*Host, error) {
	row := s.db.QueryRow(
		`SELECT id, name, address, port, status, last_seen, created_at, dpu_id FROM hosts WHERE dpu_id = ?`,
		dpuID,
	)
	return s.scanHost(row)
}

func (s *Store) scanHost(row *sql.Row) (*Host, error) {
	var host Host
	var lastSeen sql.NullInt64
	var createdAt int64
	var dpuID sql.NullString

	err := row.Scan(&host.ID, &host.Name, &host.Address, &host.Port, &host.Status, &lastSeen, &createdAt, &dpuID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("host not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan host: %w", err)
	}

	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		host.LastSeen = &t
	}
	host.CreatedAt = time.Unix(createdAt, 0)
	if dpuID.Valid {
		host.DPUID = &dpuID.String
	}

	return &host, nil
}

func (s *Store) scanHostRows(rows *sql.Rows) (*Host, error) {
	var host Host
	var lastSeen sql.NullInt64
	var createdAt int64
	var dpuID sql.NullString

	err := rows.Scan(&host.ID, &host.Name, &host.Address, &host.Port, &host.Status, &lastSeen, &createdAt, &dpuID)
	if err != nil {
		return nil, fmt.Errorf("failed to scan host: %w", err)
	}

	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		host.LastSeen = &t
	}
	host.CreatedAt = time.Unix(createdAt, 0)
	if dpuID.Valid {
		host.DPUID = &dpuID.String
	}

	return &host, nil
}

// QueryRaw executes a raw SQL query and returns the rows.
// This is intended for API handlers that need flexible queries with dynamic filtering.
func (s *Store) QueryRaw(query string, args ...interface{}) (*sql.Rows, error) {
	return s.db.Query(query, args...)
}
