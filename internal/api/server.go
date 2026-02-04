package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gobeyondidentity/cobalt/internal/version"
	"github.com/gobeyondidentity/cobalt/pkg/attestation"
	"github.com/gobeyondidentity/cobalt/pkg/grpcclient"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// UUIDShortLength is the number of characters used when truncating UUIDs for IDs.
// Example: "enroll_" + uuid.New().String()[:UUIDShortLength] produces "enroll_abc12345"
const UUIDShortLength = 8

// ServerConfig holds configuration options for the API server.
type ServerConfig struct {
	// AttestationStaleAfter is the duration after which attestation is considered stale.
	// Defaults to 1 hour if zero.
	AttestationStaleAfter time.Duration
}

// Server is the HTTP API server.
type Server struct {
	store *store.Store
	gate  *attestation.Gate
}

// NewServer creates a new API server with default configuration.
func NewServer(s *store.Store) *Server {
	return NewServerWithConfig(s, ServerConfig{})
}

// NewServerWithConfig creates a new API server with the given configuration.
func NewServerWithConfig(s *store.Store, cfg ServerConfig) *Server {
	gate := attestation.NewGate(s)

	// Apply attestation staleness configuration
	if cfg.AttestationStaleAfter > 0 {
		gate.FreshnessWindow = cfg.AttestationStaleAfter
	}

	return &Server{
		store: s,
		gate:  gate,
	}
}

// Gate returns the attestation gate for testing configuration.
func (s *Server) Gate() *attestation.Gate {
	return s.gate
}

// RegisterRoutes registers all API routes.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// DPU routes
	mux.HandleFunc("GET /api/v1/dpus", s.handleListDPUs)
	mux.HandleFunc("POST /api/v1/dpus", s.handleAddDPU)
	mux.HandleFunc("GET /api/v1/dpus/{id}", s.handleGetDPU)
	mux.HandleFunc("DELETE /api/v1/dpus/{id}", s.handleDeleteDPU)
	mux.HandleFunc("GET /api/v1/dpus/{id}/info", s.handleGetSystemInfo)
	mux.HandleFunc("GET /api/v1/dpus/{id}/flows", s.handleGetFlows)
	mux.HandleFunc("GET /api/v1/dpus/{id}/attestation", s.handleGetAttestation)
	mux.HandleFunc("GET /api/v1/dpus/{id}/attestation/chains", s.handleGetAttestationChains)
	mux.HandleFunc("GET /api/v1/dpus/{id}/inventory", s.handleGetInventory)
	mux.HandleFunc("GET /api/v1/dpus/{id}/health", s.handleHealthCheck)
	mux.HandleFunc("GET /api/v1/dpus/{id}/measurements", s.handleGetMeasurements)
	mux.HandleFunc("GET /api/v1/dpus/{id}/corim/validate", s.handleValidateCoRIM)

	// Tenant routes
	mux.HandleFunc("GET /api/v1/tenants", s.handleListTenants)
	mux.HandleFunc("POST /api/v1/tenants", s.handleCreateTenant)
	mux.HandleFunc("GET /api/v1/tenants/{id}", s.handleGetTenant)
	mux.HandleFunc("PUT /api/v1/tenants/{id}", s.handleUpdateTenant)
	mux.HandleFunc("DELETE /api/v1/tenants/{id}", s.handleDeleteTenant)
	mux.HandleFunc("GET /api/v1/tenants/{id}/dpus", s.handleListTenantDPUs)
	mux.HandleFunc("POST /api/v1/tenants/{id}/dpus", s.handleAssignDPUToTenant)
	mux.HandleFunc("DELETE /api/v1/tenants/{id}/dpus/{dpuId}", s.handleUnassignDPUFromTenant)


	// CoRIM routes
	mux.HandleFunc("GET /api/v1/corim/list", s.handleListCoRIMs)

	// Credential routes
	mux.HandleFunc("GET /api/v1/credentials/ssh-cas", s.handleListSSHCAs)
	mux.HandleFunc("GET /api/v1/credentials/ssh-cas/{name}", s.handleGetSSHCA)

	// Distribution routes
	mux.HandleFunc("GET /api/v1/distribution/history", s.handleDistributionHistory)

	// Health routes (no auth required - bypassed in middleware)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)

	// KeyMaker routes
	mux.HandleFunc("POST /api/v1/keymakers/bind", s.handleBindKeyMaker)
	mux.HandleFunc("GET /api/v1/keymakers", s.handleListKeyMakers)
	mux.HandleFunc("GET /api/v1/keymakers/{id}", s.handleGetKeyMaker)
	mux.HandleFunc("DELETE /api/v1/keymakers/{id}", s.handleRevokeKeyMaker)

	// Admin Key routes (Phase 4: Lifecycle Management)
	mux.HandleFunc("DELETE /api/v1/admin-keys/{id}", s.handleRevokeAdminKey)

	// Operator routes
	mux.HandleFunc("GET /api/v1/operators", s.handleListOperators)
	mux.HandleFunc("POST /api/v1/operators/invite", s.handleInviteOperator)
	mux.HandleFunc("GET /api/v1/operators/{email}", s.handleGetOperator)
	mux.HandleFunc("PATCH /api/v1/operators/{email}/status", s.handleUpdateOperatorStatus)
	mux.HandleFunc("DELETE /api/v1/operators/{email}", s.handleDeleteOperator)

	// Role management routes
	mux.HandleFunc("POST /api/v1/operators/{id}/roles", s.handleAssignRole)
	mux.HandleFunc("DELETE /api/v1/operators/{id}/roles/{tenant_id}", s.handleRemoveRole)

	// Invite routes
	mux.HandleFunc("DELETE /api/v1/invites/{code}", s.handleDeleteInvite)

	// Authorization routes
	mux.HandleFunc("POST /api/v1/authorizations", s.handleCreateAuthorization)
	mux.HandleFunc("GET /api/v1/authorizations", s.handleListAuthorizations)
	mux.HandleFunc("GET /api/v1/authorizations/{id}", s.handleGetAuthorization)
	mux.HandleFunc("DELETE /api/v1/authorizations/{id}", s.handleDeleteAuthorization)
	mux.HandleFunc("POST /api/v1/authorizations/check", s.handleCheckAuthorization)

	// SSH CA registration routes
	mux.HandleFunc("POST /api/v1/ssh-cas", s.handleCreateSSHCA)

	// Credential push routes
	mux.HandleFunc("POST /api/v1/push", s.handlePush)

	// Trust routes
	mux.HandleFunc("POST /api/v1/trust", s.handleCreateTrust)
	mux.HandleFunc("GET /api/v1/trust", s.handleListTrust)
	mux.HandleFunc("GET /api/v1/trust/{id}", s.handleGetTrust)
	mux.HandleFunc("DELETE /api/v1/trust/{id}", s.handleDeleteTrust)
	mux.HandleFunc("PATCH /api/v1/trust/{id}/status", s.handleUpdateTrustStatus)

	// Host agent routes (Phase 5)
	mux.HandleFunc("POST /api/v1/hosts/register", s.handleHostRegister)
	mux.HandleFunc("POST /api/v1/hosts/{id}/posture", s.handleHostPostureUpdate)
	mux.HandleFunc("GET /api/v1/hosts", s.handleListAgentHosts)
	mux.HandleFunc("GET /api/v1/hosts/{id}", s.handleGetAgentHost)
	mux.HandleFunc("GET /api/v1/hosts/{dpuName}/posture", s.handleGetHostPostureByDPU)
	mux.HandleFunc("DELETE /api/v1/hosts/{id}", s.handleDeleteAgentHost)

	// Host certificate issuance (DPU Agent calls on behalf of Host Agent)
	mux.HandleFunc("POST /api/v1/hosts/{hostname}/cert", s.handleHostCertRequest)

	// Host scan endpoint (triggers SSH key scan on host-agent)
	mux.HandleFunc("POST /api/v1/hosts/{hostname}/scan", s.handleHostScan)

	// Bootstrap routes
	mux.HandleFunc("POST /api/v1/admin/bootstrap", s.handleAdminBootstrap)
	mux.HandleFunc("POST /api/v1/enroll/complete", s.handleEnrollComplete)

	// Operator enrollment routes
	mux.HandleFunc("POST /api/v1/enroll/init", s.handleEnrollInit)

	// DPU enrollment routes
	mux.HandleFunc("POST /api/v1/enroll/dpu/init", s.handleDPUEnrollInit)
}

// ----- DPU Types -----

type addDPURequest struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type dpuResponse struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	Status   string            `json:"status"`
	LastSeen *string           `json:"lastSeen,omitempty"`
	TenantID *string           `json:"tenantId,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

func dpuToResponse(d *store.DPU) dpuResponse {
	resp := dpuResponse{
		ID:       d.ID,
		Name:     d.Name,
		Host:     d.Host,
		Port:     d.Port,
		Status:   d.Status,
		TenantID: d.TenantID,
		Labels:   d.Labels,
	}
	if d.LastSeen != nil {
		t := d.LastSeen.Format(time.RFC3339)
		resp.LastSeen = &t
	}
	return resp
}

// ----- Tenant Types -----

type createTenantRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Contact     string   `json:"contact"`
	Tags        []string `json:"tags"`
}

type updateTenantRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Contact     string   `json:"contact"`
	Tags        []string `json:"tags"`
}

type assignDPURequest struct {
	DPUID string `json:"dpuId"`
}

type tenantResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Contact     string   `json:"contact"`
	Tags        []string `json:"tags"`
	DPUCount    int      `json:"dpuCount"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
}

func tenantToResponse(t *store.Tenant, dpuCount int) tenantResponse {
	return tenantResponse{
		ID:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		Contact:     t.Contact,
		Tags:        t.Tags,
		DPUCount:    dpuCount,
		CreatedAt:   t.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   t.UpdatedAt.Format(time.RFC3339),
	}
}

func (s *Server) handleListDPUs(w http.ResponseWriter, r *http.Request) {
	dpus, err := s.store.List()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to list DPUs: "+err.Error())
		return
	}

	result := make([]dpuResponse, 0, len(dpus))
	for _, d := range dpus {
		result = append(result, dpuToResponse(d))
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAddDPU(w http.ResponseWriter, r *http.Request) {
	var req addDPURequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.Name == "" || req.Host == "" {
		writeError(w, r, http.StatusBadRequest, "Name and host are required")
		return
	}

	if req.Port == 0 {
		req.Port = 18051
	}

	id := uuid.New().String()[:UUIDShortLength]

	if err := s.store.Add(id, req.Name, req.Host, req.Port); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeError(w, r, http.StatusConflict, "DPU with this name already exists")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "Failed to add DPU: "+err.Error())
		return
	}

	// Check connectivity and fetch system info
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(fmt.Sprintf("%s:%d", req.Host, req.Port))
	if err != nil {
		s.store.UpdateStatus(id, "offline")
	} else {
		defer client.Close()
		if _, err := client.HealthCheck(ctx); err != nil {
			s.store.UpdateStatus(id, "unhealthy")
		} else {
			// Fetch and store serial number for enrollment lookup
			if info, err := client.GetSystemInfo(ctx); err == nil && info.SerialNumber != "" {
				s.store.SetDPUSerialNumber(id, info.SerialNumber)
			}
		}
	}

	// Set pending enrollment status with 24h expiration
	s.store.SetDPUEnrollmentPending(id, time.Now().Add(24*time.Hour))

	dpu, _ := s.store.Get(id)
	writeJSON(w, http.StatusCreated, dpuToResponse(dpu))
}

func (s *Server) handleGetDPU(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}
	writeJSON(w, http.StatusOK, dpuToResponse(dpu))
}

func (s *Server) handleDeleteDPU(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.Remove(id); err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetSystemInfo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	info, err := client.GetSystemInfo(ctx)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to get system info: "+err.Error())
		return
	}

	s.store.UpdateStatus(id, "healthy")

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hostname":        info.Hostname,
		"model":           info.Model,
		"serialNumber":    info.SerialNumber,
		"firmwareVersion": info.FirmwareVersion,
		"docaVersion":     info.DocaVersion,
		"ovsVersion":      info.OvsVersion,
		"kernelVersion":   info.KernelVersion,
		"armCores":        info.ArmCores,
		"memoryGb":        info.MemoryGb,
		"uptimeSeconds":   info.UptimeSeconds,
	})
}

func (s *Server) handleGetFlows(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	bridge := r.URL.Query().Get("bridge")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.GetFlows(ctx, bridge)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to get flows: "+err.Error())
		return
	}

	s.store.UpdateStatus(id, "healthy")

	flows := make([]map[string]interface{}, 0, len(resp.Flows))
	for _, f := range resp.Flows {
		flows = append(flows, map[string]interface{}{
			"cookie":   f.Cookie,
			"table":    f.Table,
			"priority": f.Priority,
			"match":    f.Match,
			"actions":  f.Actions,
			"packets":  f.Packets,
			"bytes":    f.Bytes,
			"age":      f.Age,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"flows": flows,
	})
}

func (s *Server) handleGetAttestation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	// Get target from query param (default: IRoT)
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "IRoT"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.GetAttestation(ctx, target)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to get attestation: "+err.Error())
		return
	}

	s.store.UpdateStatus(id, "healthy")

	certs := make([]map[string]interface{}, 0, len(resp.Certificates))
	for _, c := range resp.Certificates {
		certs = append(certs, map[string]interface{}{
			"level":     c.Level,
			"subject":   c.Subject,
			"issuer":    c.Issuer,
			"notBefore": c.NotBefore,
			"notAfter":  c.NotAfter,
			"algorithm": c.Algorithm,
			"pem":       c.Pem,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       resp.Status.String(),
		"certificates": certs,
		"measurements": resp.Measurements,
	})
}

// handleGetAttestationChains returns both IRoT and ERoT certificate chains
func (s *Server) handleGetAttestationChains(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	// Fetch both chains in parallel
	type chainResult struct {
		chain []map[string]interface{}
		err   error
	}

	var wg sync.WaitGroup
	irotChan := make(chan chainResult, 1)
	erotChan := make(chan chainResult, 1)

	fetchChain := func(target string, ch chan<- chainResult) {
		defer wg.Done()
		resp, err := client.GetAttestation(ctx, target)
		if err != nil {
			ch <- chainResult{nil, err}
			return
		}
		certs := make([]map[string]interface{}, 0, len(resp.Certificates))
		for _, c := range resp.Certificates {
			certs = append(certs, map[string]interface{}{
				"level":       c.Level,
				"subject":     c.Subject,
				"issuer":      c.Issuer,
				"notBefore":   c.NotBefore,
				"notAfter":    c.NotAfter,
				"algorithm":   c.Algorithm,
				"pem":         c.Pem,
				"fingerprint": c.FingerprintSha256,
			})
		}
		ch <- chainResult{certs, nil}
	}

	wg.Add(2)
	go fetchChain("IRoT", irotChan)
	go fetchChain("ERoT", erotChan)
	wg.Wait()

	irotResult := <-irotChan
	erotResult := <-erotChan

	s.store.UpdateStatus(id, "healthy")

	// Build response
	response := map[string]interface{}{
		"irot": map[string]interface{}{
			"certificates": irotResult.chain,
			"error":        nil,
		},
		"erot": map[string]interface{}{
			"certificates": erotResult.chain,
			"error":        nil,
		},
	}

	if irotResult.err != nil {
		response["irot"].(map[string]interface{})["error"] = irotResult.err.Error()
	}
	if erotResult.err != nil {
		response["erot"].(map[string]interface{})["error"] = erotResult.err.Error()
	}

	// Find shared root (if any)
	if len(irotResult.chain) > 0 && len(erotResult.chain) > 0 {
		irotRoot := irotResult.chain[len(irotResult.chain)-1]
		erotRoot := erotResult.chain[len(erotResult.chain)-1]
		if irotRoot["fingerprint"] == erotRoot["fingerprint"] {
			response["sharedRoot"] = irotRoot
		}
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleGetInventory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.GetDPUInventory(ctx)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to get inventory: "+err.Error())
		return
	}

	s.store.UpdateStatus(id, "healthy")

	firmwares := make([]map[string]interface{}, 0, len(resp.Firmwares))
	for _, f := range resp.Firmwares {
		firmwares = append(firmwares, map[string]interface{}{
			"name":      f.Name,
			"version":   f.Version,
			"buildDate": f.BuildDate,
		})
	}

	packages := make([]map[string]interface{}, 0, len(resp.Packages))
	for _, p := range resp.Packages {
		packages = append(packages, map[string]interface{}{
			"name":    p.Name,
			"version": p.Version,
		})
	}

	modules := make([]map[string]interface{}, 0, len(resp.Modules))
	for _, m := range resp.Modules {
		modules = append(modules, map[string]interface{}{
			"name":   m.Name,
			"size":   m.Size,
			"usedBy": m.UsedBy,
		})
	}

	var boot map[string]interface{}
	if resp.Boot != nil {
		boot = map[string]interface{}{
			"uefiMode":   resp.Boot.UefiMode,
			"secureBoot": resp.Boot.SecureBoot,
			"bootDevice": resp.Boot.BootDevice,
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"firmwares":     firmwares,
		"packages":      packages,
		"modules":       modules,
		"boot":          boot,
		"operationMode": resp.OperationMode,
	})
}

func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.HealthCheck(ctx)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, r, http.StatusServiceUnavailable, "Health check failed: "+err.Error())
		return
	}

	if resp.Healthy {
		s.store.UpdateStatus(id, "healthy")
	} else {
		s.store.UpdateStatus(id, "unhealthy")
	}

	components := make(map[string]interface{})
	for name, comp := range resp.Components {
		components[name] = map[string]interface{}{
			"healthy": comp.Healthy,
			"message": comp.Message,
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"healthy":       resp.Healthy,
		"version":       resp.Version,
		"uptimeSeconds": resp.UptimeSeconds,
		"components":    components,
	})
}

// handleHealth is the liveness probe endpoint.
// Returns 200 if the process is alive. Used by k8s liveness probes.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"version": version.Version,
	})
}

// handleReady is the readiness probe endpoint.
// Returns 200 if ready to serve traffic, 503 if not ready.
// Used by k8s readiness probes and load balancer health checks.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	allOK := true

	// Check DB connectivity
	if err := s.store.DB().PingContext(r.Context()); err != nil {
		checks["database"] = "failed"
		allOK = false
	} else {
		checks["database"] = "ok"
	}

	// Check bootstrap status
	bootstrapStatus, err := s.getBootstrapStatus()
	if err != nil {
		checks["bootstrap"] = "error"
		allOK = false
	} else if bootstrapStatus != nil && bootstrapStatus.Status == "enrolled" {
		checks["bootstrap"] = "ok"
	} else {
		checks["bootstrap"] = "pending"
		// Not ready until bootstrap is complete
		allOK = false
	}

	response := map[string]interface{}{
		"status": "ready",
		"checks": checks,
	}

	if !allOK {
		response["status"] = "not_ready"
		writeJSON(w, http.StatusServiceUnavailable, response)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// BootstrapHealthStatus represents the bootstrap status included in health checks.
type BootstrapHealthStatus struct {
	Status    string     // "open", "closed", "enrolled"
	ExpiresAt *time.Time // Only when status is "open"
	AdminID   string     // Only when status is "enrolled"
}

// getBootstrapStatus returns the current bootstrap status for health endpoint.
func (s *Server) getBootstrapStatus() (*BootstrapHealthStatus, error) {
	// Check if first admin exists
	hasAdmin, err := s.store.HasFirstAdmin()
	if err != nil {
		return nil, err
	}
	if hasAdmin {
		state, _ := s.store.GetBootstrapState()
		adminID := ""
		if state != nil && state.FirstAdminID != nil {
			adminID = *state.FirstAdminID
		}
		return &BootstrapHealthStatus{
			Status:  "enrolled",
			AdminID: adminID,
		}, nil
	}

	// Get bootstrap state
	state, err := s.store.GetBootstrapState()
	if err != nil {
		return nil, err
	}
	if state == nil {
		return &BootstrapHealthStatus{Status: "closed"}, nil
	}

	// Check if window expired
	expiresAt := state.WindowOpenedAt.Add(BootstrapWindowDuration)
	if time.Now().After(expiresAt) {
		return &BootstrapHealthStatus{Status: "closed"}, nil
	}

	return &BootstrapHealthStatus{
		Status:    "open",
		ExpiresAt: &expiresAt,
	}, nil
}

func (s *Server) handleGetMeasurements(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	target := r.URL.Query().Get("target")
	if target == "" {
		target = "IRoT"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.GetSignedMeasurements(ctx, "", nil, target)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to get measurements: "+err.Error())
		return
	}

	s.store.UpdateStatus(id, "healthy")

	measurements := make([]map[string]interface{}, 0, len(resp.Measurements))
	for _, m := range resp.Measurements {
		measurements = append(measurements, map[string]interface{}{
			"index":       m.Index,
			"description": m.Description,
			"algorithm":   m.Algorithm,
			"digest":      m.Digest,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"measurements":     measurements,
		"hashingAlgorithm": resp.HashingAlgorithm,
		"signingAlgorithm": resp.SigningAlgorithm,
		"spdmVersion":      resp.SpdmVersion,
	})
}

func (s *Server) handleValidateCoRIM(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	target := r.URL.Query().Get("target")
	if target == "" {
		target = "IRoT"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	// Connect to DPU
	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	// Get inventory to find firmware version
	inv, err := client.GetDPUInventory(ctx)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to get inventory: "+err.Error())
		return
	}

	// Find NIC firmware version
	var nicVersion string
	for _, fw := range inv.Firmwares {
		if strings.Contains(strings.ToLower(fw.Name), "nic") {
			nicVersion = fw.Version
			break
		}
	}

	if nicVersion == "" {
		writeError(w, r, http.StatusBadRequest, "Could not determine NIC firmware version")
		return
	}

	// Fetch CoRIM from NVIDIA
	rimClient := attestation.NewRIMClient()
	entry, err := rimClient.FindRIMForFirmware(ctx, nicVersion)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "No CoRIM found for firmware version: "+nicVersion)
		return
	}

	manifest, err := attestation.ParseCoRIM(entry.RIM)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to parse CoRIM: "+err.Error())
		return
	}

	// Get live measurements
	measResp, err := client.GetSignedMeasurements(ctx, "", nil, target)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, r, http.StatusServiceUnavailable, "Failed to get measurements: "+err.Error())
		return
	}

	// Convert to internal types for comparison
	var liveMeas []attestation.SPDMMeasurement
	for _, m := range measResp.Measurements {
		liveMeas = append(liveMeas, attestation.SPDMMeasurement{
			Index:       int(m.Index),
			Description: m.Description,
			Algorithm:   m.Algorithm,
			Digest:      m.Digest,
		})
	}

	// Validate
	summary := attestation.ValidateMeasurements(liveMeas, manifest.ReferenceValues)
	summary.FirmwareVersion = nicVersion
	summary.CoRIMID = entry.ID

	if summary.Valid {
		s.store.UpdateStatus(id, "healthy")
	} else {
		s.store.UpdateStatus(id, "unhealthy")
	}

	// Convert results for JSON
	results := make([]map[string]interface{}, 0, len(summary.Results))
	for _, r := range summary.Results {
		results = append(results, map[string]interface{}{
			"index":           r.Index,
			"description":     r.Description,
			"referenceDigest": r.ReferenceDigest,
			"liveDigest":      r.LiveDigest,
			"match":           r.Match,
			"status":          r.Status,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":           summary.Valid,
		"totalChecked":    summary.TotalChecked,
		"matched":         summary.Matched,
		"mismatched":      summary.Mismatched,
		"missingRef":      summary.MissingRef,
		"missingLive":     summary.MissingLive,
		"results":         results,
		"firmwareVersion": summary.FirmwareVersion,
		"corimId":         summary.CoRIMID,
	})
}

func (s *Server) handleListCoRIMs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	client := attestation.NewRIMClient()
	ids, err := client.ListRIMIDs(ctx)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "Failed to fetch RIM list: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ids":   ids,
		"count": len(ids),
	})
}

// ----- Tenant Handlers -----

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.store.ListTenants()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to list tenants: "+err.Error())
		return
	}

	result := make([]tenantResponse, 0, len(tenants))
	for _, t := range tenants {
		count, _ := s.store.GetTenantDPUCount(t.ID)
		result = append(result, tenantToResponse(t, count))
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.Name == "" {
		writeError(w, r, http.StatusBadRequest, "Name is required")
		return
	}

	if req.Tags == nil {
		req.Tags = []string{}
	}

	id := uuid.New().String()[:UUIDShortLength]

	if err := s.store.AddTenant(id, req.Name, req.Description, req.Contact, req.Tags); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, r, http.StatusConflict, err.Error())
			return
		}
		writeError(w, r, http.StatusInternalServerError, "Failed to create tenant: "+err.Error())
		return
	}

	tenant, _ := s.store.GetTenant(id)
	writeJSON(w, http.StatusCreated, tenantToResponse(tenant, 0))
}

func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tenant, err := s.store.GetTenant(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Tenant not found")
		return
	}

	count, _ := s.store.GetTenantDPUCount(tenant.ID)
	writeJSON(w, http.StatusOK, tenantToResponse(tenant, count))
}

func (s *Server) handleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Check if tenant exists
	existing, err := s.store.GetTenant(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Tenant not found")
		return
	}

	var req updateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Use existing values for fields not provided
	name := req.Name
	if name == "" {
		name = existing.Name
	}
	tags := req.Tags
	if tags == nil {
		tags = existing.Tags
	}

	if err := s.store.UpdateTenant(id, name, req.Description, req.Contact, tags); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeError(w, r, http.StatusConflict, "Tenant with this name already exists")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "Failed to update tenant: "+err.Error())
		return
	}

	tenant, _ := s.store.GetTenant(id)
	count, _ := s.store.GetTenantDPUCount(id)
	writeJSON(w, http.StatusOK, tenantToResponse(tenant, count))
}

func (s *Server) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Check if tenant exists first
	if _, err := s.store.GetTenant(id); err != nil {
		writeError(w, r, http.StatusNotFound, "Tenant not found")
		return
	}

	// Check for dependencies that would prevent deletion
	deps, err := s.store.GetTenantDependencies(id)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to check dependencies: "+err.Error())
		return
	}

	if deps.HasAny() {
		// Build detailed message listing dependencies
		var parts []string
		if len(deps.DPUs) > 0 {
			parts = append(parts, fmt.Sprintf("%d DPUs", len(deps.DPUs)))
		}
		if len(deps.Operators) > 0 {
			parts = append(parts, fmt.Sprintf("%d operators", len(deps.Operators)))
		}
		if len(deps.CAs) > 0 {
			parts = append(parts, fmt.Sprintf("%d SSH CAs", len(deps.CAs)))
		}
		if deps.TrustRelationships > 0 {
			parts = append(parts, fmt.Sprintf("%d trust relationships", deps.TrustRelationships))
		}
		if deps.Invites > 0 {
			parts = append(parts, fmt.Sprintf("%d invites", deps.Invites))
		}
		msg := "Cannot delete tenant: " + strings.Join(parts, ", ") + " depend on it"
		writeError(w, r, http.StatusConflict, msg)
		return
	}

	if err := s.store.RemoveTenant(id); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to delete tenant: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListTenantDPUs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Check if tenant exists
	_, err := s.store.GetTenant(id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Tenant not found")
		return
	}

	dpus, err := s.store.ListDPUsByTenant(id)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to list DPUs: "+err.Error())
		return
	}

	result := make([]dpuResponse, 0, len(dpus))
	for _, d := range dpus {
		result = append(result, dpuToResponse(d))
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAssignDPUToTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")

	// Check if tenant exists
	_, err := s.store.GetTenant(tenantID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Tenant not found")
		return
	}

	var req assignDPURequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.DPUID == "" {
		writeError(w, r, http.StatusBadRequest, "dpuId is required")
		return
	}

	// Check if DPU exists
	dpu, err := s.store.Get(req.DPUID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	if err := s.store.AssignDPUToTenant(dpu.ID, tenantID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to assign DPU: "+err.Error())
		return
	}

	dpu, _ = s.store.Get(dpu.ID)
	writeJSON(w, http.StatusOK, dpuToResponse(dpu))
}

func (s *Server) handleUnassignDPUFromTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	dpuID := r.PathValue("dpuId")

	// Check if tenant exists
	_, err := s.store.GetTenant(tenantID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Tenant not found")
		return
	}

	// Check if DPU exists and belongs to this tenant
	dpu, err := s.store.Get(dpuID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found")
		return
	}

	if dpu.TenantID == nil || *dpu.TenantID != tenantID {
		writeError(w, r, http.StatusBadRequest, "DPU is not assigned to this tenant")
		return
	}

	if err := s.store.UnassignDPUFromTenant(dpuID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to unassign DPU: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode JSON: %v", err)
	}
}

func writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	log.Printf("ERROR: %s %s: %s", r.Method, r.URL.Path, message)
	writeJSON(w, status, map[string]string{"error": message})
}

// writeInternalError logs the detailed error internally and returns a generic message to the client.
// Use this for errors that might leak implementation details.
func writeInternalError(w http.ResponseWriter, r *http.Request, err error, genericMsg string) {
	log.Printf("ERROR: %s %s: %s: %v", r.Method, r.URL.Path, genericMsg, err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": genericMsg})
}
