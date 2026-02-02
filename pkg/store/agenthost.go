// This file contains methods for AgentHost and AgentHostPosture entities (Phase 5: Host Agent).
package store

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AgentHost represents a host machine with posture linked to a DPU.
type AgentHost struct {
	ID           string
	DPUName      string    // Linked DPU name
	DPUID        string    // Linked DPU ID
	Hostname     string    // Host's hostname
	TenantID     string    // Tenant (inherited from DPU)
	RegisteredAt time.Time
	LastSeenAt   time.Time
}

// AgentHostPosture represents the security posture of a host.
type AgentHostPosture struct {
	HostID         string
	SecureBoot     *bool     // nil if unknown
	DiskEncryption string    // "luks", "filevault", "bitlocker", "none", ""
	OSVersion      string    // "Ubuntu 24.04 LTS"
	KernelVersion  string    // "6.8.0-generic"
	TPMPresent     *bool     // nil if unknown
	PostureHash    string    // SHA256 of sorted posture fields
	CollectedAt    time.Time
}

// generateAgentHostID generates a unique ID with format "host_" + first 8 chars of UUID.
func generateAgentHostID() string {
	u := uuid.New().String()
	return "host_" + u[:8]
}

// RegisterAgentHost registers a new host agent, generating an ID automatically.
func (s *Store) RegisterAgentHost(h *AgentHost) error {
	if h.ID == "" {
		h.ID = generateAgentHostID()
	}
	now := time.Now()
	if h.RegisteredAt.IsZero() {
		h.RegisteredAt = now
	}
	if h.LastSeenAt.IsZero() {
		h.LastSeenAt = now
	}

	var tenantID sql.NullString
	if h.TenantID != "" {
		tenantID = sql.NullString{String: h.TenantID, Valid: true}
	}

	_, err := s.db.Exec(
		`INSERT INTO agent_hosts (id, dpu_name, dpu_id, hostname, tenant_id, registered_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.DPUName, h.DPUID, h.Hostname, tenantID, h.RegisteredAt.Unix(), h.LastSeenAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to register agent host: %w", err)
	}
	return nil
}

// GetAgentHost retrieves an agent host by ID.
func (s *Store) GetAgentHost(id string) (*AgentHost, error) {
	row := s.db.QueryRow(
		`SELECT id, dpu_name, dpu_id, hostname, tenant_id, registered_at, last_seen_at
		FROM agent_hosts WHERE id = ?`,
		id,
	)
	return s.scanAgentHost(row)
}

// GetAgentHostByDPU retrieves an agent host linked to a specific DPU name.
func (s *Store) GetAgentHostByDPU(dpuName string) (*AgentHost, error) {
	row := s.db.QueryRow(
		`SELECT id, dpu_name, dpu_id, hostname, tenant_id, registered_at, last_seen_at
		FROM agent_hosts WHERE dpu_name = ?`,
		dpuName,
	)
	return s.scanAgentHost(row)
}

// GetAgentHostByHostname retrieves an agent host by hostname.
func (s *Store) GetAgentHostByHostname(hostname string) (*AgentHost, error) {
	row := s.db.QueryRow(
		`SELECT id, dpu_name, dpu_id, hostname, tenant_id, registered_at, last_seen_at
		FROM agent_hosts WHERE hostname = ?`,
		hostname,
	)
	return s.scanAgentHost(row)
}

// ListAgentHosts returns all agent hosts, optionally filtered by tenant.
// If tenantID is empty, returns all hosts.
func (s *Store) ListAgentHosts(tenantID string) ([]*AgentHost, error) {
	var rows *sql.Rows
	var err error

	if tenantID == "" {
		rows, err = s.db.Query(
			`SELECT id, dpu_name, dpu_id, hostname, tenant_id, registered_at, last_seen_at
			FROM agent_hosts ORDER BY hostname`,
		)
	} else {
		rows, err = s.db.Query(
			`SELECT id, dpu_name, dpu_id, hostname, tenant_id, registered_at, last_seen_at
			FROM agent_hosts WHERE tenant_id = ? ORDER BY hostname`,
			tenantID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list agent hosts: %w", err)
	}
	defer rows.Close()

	return s.scanAgentHostRows(rows)
}

// UpdateAgentHostLastSeen updates the last_seen_at timestamp for an agent host.
func (s *Store) UpdateAgentHostLastSeen(id string) error {
	now := time.Now().Unix()
	result, err := s.db.Exec(
		`UPDATE agent_hosts SET last_seen_at = ? WHERE id = ?`,
		now, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update agent host last seen: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("agent host not found: %s", id)
	}
	return nil
}

// DeleteAgentHost removes an agent host by ID.
// Due to ON DELETE CASCADE, this also removes the associated posture record.
func (s *Store) DeleteAgentHost(id string) error {
	result, err := s.db.Exec(`DELETE FROM agent_hosts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete agent host: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("agent host not found: %s", id)
	}
	return nil
}

// UpdateAgentHostPosture inserts or updates the posture record for a host.
func (s *Store) UpdateAgentHostPosture(p *AgentHostPosture) error {
	if p.CollectedAt.IsZero() {
		p.CollectedAt = time.Now()
	}

	var secureBoot, tpmPresent sql.NullInt64
	if p.SecureBoot != nil {
		if *p.SecureBoot {
			secureBoot = sql.NullInt64{Int64: 1, Valid: true}
		} else {
			secureBoot = sql.NullInt64{Int64: 0, Valid: true}
		}
	}
	if p.TPMPresent != nil {
		if *p.TPMPresent {
			tpmPresent = sql.NullInt64{Int64: 1, Valid: true}
		} else {
			tpmPresent = sql.NullInt64{Int64: 0, Valid: true}
		}
	}

	_, err := s.db.Exec(`
		INSERT INTO agent_host_posture (host_id, secure_boot, disk_encryption, os_version, kernel_version, tpm_present, posture_hash, collected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host_id) DO UPDATE SET
			secure_boot = excluded.secure_boot,
			disk_encryption = excluded.disk_encryption,
			os_version = excluded.os_version,
			kernel_version = excluded.kernel_version,
			tpm_present = excluded.tpm_present,
			posture_hash = excluded.posture_hash,
			collected_at = excluded.collected_at
	`, p.HostID, secureBoot, p.DiskEncryption, p.OSVersion, p.KernelVersion, tpmPresent, p.PostureHash, p.CollectedAt.Unix())

	if err != nil {
		return fmt.Errorf("failed to update agent host posture: %w", err)
	}
	return nil
}

// GetAgentHostPosture retrieves the current posture for a host.
func (s *Store) GetAgentHostPosture(hostID string) (*AgentHostPosture, error) {
	row := s.db.QueryRow(
		`SELECT host_id, secure_boot, disk_encryption, os_version, kernel_version, tpm_present, posture_hash, collected_at
		FROM agent_host_posture WHERE host_id = ?`,
		hostID,
	)

	var p AgentHostPosture
	var secureBoot, tpmPresent sql.NullInt64
	var diskEncryption, osVersion, kernelVersion, postureHash sql.NullString
	var collectedAt int64

	err := row.Scan(&p.HostID, &secureBoot, &diskEncryption, &osVersion, &kernelVersion, &tpmPresent, &postureHash, &collectedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("agent host posture not found: %s", hostID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan agent host posture: %w", err)
	}

	if secureBoot.Valid {
		val := secureBoot.Int64 != 0
		p.SecureBoot = &val
	}
	if tpmPresent.Valid {
		val := tpmPresent.Int64 != 0
		p.TPMPresent = &val
	}
	if diskEncryption.Valid {
		p.DiskEncryption = diskEncryption.String
	}
	if osVersion.Valid {
		p.OSVersion = osVersion.String
	}
	if kernelVersion.Valid {
		p.KernelVersion = kernelVersion.String
	}
	if postureHash.Valid {
		p.PostureHash = postureHash.String
	}
	p.CollectedAt = time.Unix(collectedAt, 0)

	return &p, nil
}

func (s *Store) scanAgentHost(row *sql.Row) (*AgentHost, error) {
	var h AgentHost
	var tenantID sql.NullString
	var registeredAt, lastSeenAt int64

	err := row.Scan(&h.ID, &h.DPUName, &h.DPUID, &h.Hostname, &tenantID, &registeredAt, &lastSeenAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("agent host not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan agent host: %w", err)
	}

	if tenantID.Valid {
		h.TenantID = tenantID.String
	}
	h.RegisteredAt = time.Unix(registeredAt, 0)
	h.LastSeenAt = time.Unix(lastSeenAt, 0)

	return &h, nil
}

func (s *Store) scanAgentHostRows(rows *sql.Rows) ([]*AgentHost, error) {
	var results []*AgentHost
	for rows.Next() {
		var h AgentHost
		var tenantID sql.NullString
		var registeredAt, lastSeenAt int64

		err := rows.Scan(&h.ID, &h.DPUName, &h.DPUID, &h.Hostname, &tenantID, &registeredAt, &lastSeenAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan agent host: %w", err)
		}

		if tenantID.Valid {
			h.TenantID = tenantID.String
		}
		h.RegisteredAt = time.Unix(registeredAt, 0)
		h.LastSeenAt = time.Unix(lastSeenAt, 0)

		results = append(results, &h)
	}
	return results, rows.Err()
}
