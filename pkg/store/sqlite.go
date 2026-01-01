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

	_ "github.com/mattn/go-sqlite3"
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

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
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
		port INTEGER DEFAULT 50051,
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
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Apply column migrations for existing databases
	migrations := []string{
		"ALTER TABLE dpus ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL",
		"ALTER TABLE dpus ADD COLUMN labels TEXT DEFAULT '{}'",
	}

	for _, m := range migrations {
		// Ignore errors for columns that already exist
		s.db.Exec(m)
	}

	// Create indexes that may not exist
	indexes := `
	CREATE INDEX IF NOT EXISTS idx_dpus_tenant ON dpus(tenant_id);
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
