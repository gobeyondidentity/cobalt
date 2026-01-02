// Package api implements the HTTP API server for the dashboard.
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

	"github.com/beyondidentity/fabric-console/pkg/attestation"
	"github.com/beyondidentity/fabric-console/pkg/grpcclient"
	"github.com/beyondidentity/fabric-console/pkg/hostclient"
	"github.com/beyondidentity/fabric-console/pkg/store"
	"github.com/google/uuid"
)

// Server is the HTTP API server.
type Server struct {
	store *store.Store
}

// NewServer creates a new API server.
func NewServer(s *store.Store) *Server {
	return &Server{store: s}
}

// RegisterRoutes registers all API routes.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// DPU routes
	mux.HandleFunc("GET /api/dpus", s.handleListDPUs)
	mux.HandleFunc("POST /api/dpus", s.handleAddDPU)
	mux.HandleFunc("GET /api/dpus/{id}", s.handleGetDPU)
	mux.HandleFunc("DELETE /api/dpus/{id}", s.handleDeleteDPU)
	mux.HandleFunc("GET /api/dpus/{id}/info", s.handleGetSystemInfo)
	mux.HandleFunc("GET /api/dpus/{id}/flows", s.handleGetFlows)
	mux.HandleFunc("GET /api/dpus/{id}/attestation", s.handleGetAttestation)
	mux.HandleFunc("GET /api/dpus/{id}/attestation/chains", s.handleGetAttestationChains)
	mux.HandleFunc("GET /api/dpus/{id}/inventory", s.handleGetInventory)
	mux.HandleFunc("GET /api/dpus/{id}/health", s.handleHealthCheck)
	mux.HandleFunc("GET /api/dpus/{id}/measurements", s.handleGetMeasurements)
	mux.HandleFunc("GET /api/dpus/{id}/corim/validate", s.handleValidateCoRIM)

	// Tenant routes
	mux.HandleFunc("GET /api/tenants", s.handleListTenants)
	mux.HandleFunc("POST /api/tenants", s.handleCreateTenant)
	mux.HandleFunc("GET /api/tenants/{id}", s.handleGetTenant)
	mux.HandleFunc("PUT /api/tenants/{id}", s.handleUpdateTenant)
	mux.HandleFunc("DELETE /api/tenants/{id}", s.handleDeleteTenant)
	mux.HandleFunc("GET /api/tenants/{id}/dpus", s.handleListTenantDPUs)
	mux.HandleFunc("POST /api/tenants/{id}/dpus", s.handleAssignDPUToTenant)
	mux.HandleFunc("DELETE /api/tenants/{id}/dpus/{dpuId}", s.handleUnassignDPUFromTenant)

	// Host routes
	mux.HandleFunc("GET /api/hosts", s.handleListHosts)
	mux.HandleFunc("POST /api/hosts", s.handleAddHost)
	mux.HandleFunc("GET /api/hosts/{id}", s.handleGetHost)
	mux.HandleFunc("DELETE /api/hosts/{id}", s.handleDeleteHost)
	mux.HandleFunc("GET /api/hosts/{id}/info", s.handleGetHostInfo)
	mux.HandleFunc("GET /api/hosts/{id}/gpus", s.handleGetHostGPUs)
	mux.HandleFunc("GET /api/hosts/{id}/security", s.handleGetHostSecurity)
	mux.HandleFunc("GET /api/hosts/{id}/health", s.handleHostHealthCheck)
	mux.HandleFunc("POST /api/hosts/{id}/link/{dpuId}", s.handleLinkHostToDPU)
	mux.HandleFunc("DELETE /api/hosts/{id}/link", s.handleUnlinkHostFromDPU)

	// DPU host info (get host info for a DPU)
	mux.HandleFunc("GET /api/dpus/{id}/host", s.handleGetDPUHost)

	// CoRIM routes
	mux.HandleFunc("GET /api/corim/list", s.handleListCoRIMs)

	// Credential routes
	mux.HandleFunc("GET /api/credentials/ssh-cas", s.handleListSSHCAs)
	mux.HandleFunc("GET /api/credentials/ssh-cas/{name}", s.handleGetSSHCA)

	// Distribution routes
	mux.HandleFunc("GET /api/distribution/history", s.handleDistributionHistory)

	// Health routes
	mux.HandleFunc("GET /api/health", s.handleAPIHealth)

	// KeyMaker routes
	mux.HandleFunc("POST /api/v1/keymakers/bind", s.handleBindKeyMaker)

	// Authorization routes
	mux.HandleFunc("POST /api/v1/authorizations", s.handleCreateAuthorization)
	mux.HandleFunc("GET /api/v1/authorizations", s.handleListAuthorizations)
	mux.HandleFunc("GET /api/v1/authorizations/{id}", s.handleGetAuthorization)
	mux.HandleFunc("DELETE /api/v1/authorizations/{id}", s.handleDeleteAuthorization)
	mux.HandleFunc("POST /api/v1/authorizations/check", s.handleCheckAuthorization)

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
	mux.HandleFunc("DELETE /api/v1/hosts/{id}", s.handleDeleteAgentHost)

	// Host certificate issuance (DPU Agent calls on behalf of Host Agent)
	mux.HandleFunc("POST /api/v1/hosts/{hostname}/cert", s.handleHostCertRequest)
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
		writeError(w, http.StatusInternalServerError, "Failed to list DPUs: "+err.Error())
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
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.Name == "" || req.Host == "" {
		writeError(w, http.StatusBadRequest, "Name and host are required")
		return
	}

	if req.Port == 0 {
		req.Port = 50051
	}

	id := uuid.New().String()[:8]

	if err := s.store.Add(id, req.Name, req.Host, req.Port); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeError(w, http.StatusConflict, "DPU with this name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to add DPU: "+err.Error())
		return
	}

	// Check connectivity
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
			s.store.UpdateStatus(id, "healthy")
		}
	}

	dpu, _ := s.store.Get(id)
	writeJSON(w, http.StatusCreated, dpuToResponse(dpu))
}

func (s *Server) handleGetDPU(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}
	writeJSON(w, http.StatusOK, dpuToResponse(dpu))
}

func (s *Server) handleDeleteDPU(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.Remove(id); err != nil {
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetSystemInfo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	info, err := client.GetSystemInfo(ctx)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Failed to get system info: "+err.Error())
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
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}

	bridge := r.URL.Query().Get("bridge")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.GetFlows(ctx, bridge)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Failed to get flows: "+err.Error())
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
		writeError(w, http.StatusNotFound, "DPU not found")
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
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.GetAttestation(ctx, target)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Failed to get attestation: "+err.Error())
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
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
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
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.GetDPUInventory(ctx)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Failed to get inventory: "+err.Error())
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
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := grpcclient.NewClient(dpu.Address())
	if err != nil {
		s.store.UpdateStatus(id, "offline")
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.HealthCheck(ctx)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Health check failed: "+err.Error())
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

func (s *Server) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"version": "0.1.0",
	})
}

func (s *Server) handleGetMeasurements(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dpu, err := s.store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "DPU not found")
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
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.GetSignedMeasurements(ctx, "", nil, target)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Failed to get measurements: "+err.Error())
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
		writeError(w, http.StatusNotFound, "DPU not found")
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
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	// Get inventory to find firmware version
	inv, err := client.GetDPUInventory(ctx)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Failed to get inventory: "+err.Error())
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
		writeError(w, http.StatusBadRequest, "Could not determine NIC firmware version")
		return
	}

	// Fetch CoRIM from NVIDIA
	rimClient := attestation.NewRIMClient()
	entry, err := rimClient.FindRIMForFirmware(ctx, nicVersion)
	if err != nil {
		writeError(w, http.StatusNotFound, "No CoRIM found for firmware version: "+nicVersion)
		return
	}

	manifest, err := attestation.ParseCoRIM(entry.RIM)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to parse CoRIM: "+err.Error())
		return
	}

	// Get live measurements
	measResp, err := client.GetSignedMeasurements(ctx, "", nil, target)
	if err != nil {
		s.store.UpdateStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Failed to get measurements: "+err.Error())
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
		writeError(w, http.StatusServiceUnavailable, "Failed to fetch RIM list: "+err.Error())
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
		writeError(w, http.StatusInternalServerError, "Failed to list tenants: "+err.Error())
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
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Name is required")
		return
	}

	if req.Tags == nil {
		req.Tags = []string{}
	}

	id := uuid.New().String()[:8]

	if err := s.store.AddTenant(id, req.Name, req.Description, req.Contact, req.Tags); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeError(w, http.StatusConflict, "Tenant with this name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to create tenant: "+err.Error())
		return
	}

	tenant, _ := s.store.GetTenant(id)
	writeJSON(w, http.StatusCreated, tenantToResponse(tenant, 0))
}

func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tenant, err := s.store.GetTenant(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Tenant not found")
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
		writeError(w, http.StatusNotFound, "Tenant not found")
		return
	}

	var req updateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
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
			writeError(w, http.StatusConflict, "Tenant with this name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to update tenant: "+err.Error())
		return
	}

	tenant, _ := s.store.GetTenant(id)
	count, _ := s.store.GetTenantDPUCount(id)
	writeJSON(w, http.StatusOK, tenantToResponse(tenant, count))
}

func (s *Server) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Check for assigned DPUs
	count, _ := s.store.GetTenantDPUCount(id)
	if count > 0 {
		writeError(w, http.StatusConflict, fmt.Sprintf("Cannot delete tenant with %d assigned DPUs", count))
		return
	}

	if err := s.store.RemoveTenant(id); err != nil {
		writeError(w, http.StatusNotFound, "Tenant not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListTenantDPUs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Check if tenant exists
	_, err := s.store.GetTenant(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Tenant not found")
		return
	}

	dpus, err := s.store.ListDPUsByTenant(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list DPUs: "+err.Error())
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
		writeError(w, http.StatusNotFound, "Tenant not found")
		return
	}

	var req assignDPURequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.DPUID == "" {
		writeError(w, http.StatusBadRequest, "dpuId is required")
		return
	}

	// Check if DPU exists
	dpu, err := s.store.Get(req.DPUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}

	if err := s.store.AssignDPUToTenant(dpu.ID, tenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to assign DPU: "+err.Error())
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
		writeError(w, http.StatusNotFound, "Tenant not found")
		return
	}

	// Check if DPU exists and belongs to this tenant
	dpu, err := s.store.Get(dpuID)
	if err != nil {
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}

	if dpu.TenantID == nil || *dpu.TenantID != tenantID {
		writeError(w, http.StatusBadRequest, "DPU is not assigned to this tenant")
		return
	}

	if err := s.store.UnassignDPUFromTenant(dpuID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to unassign DPU: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ----- Host Types -----

type addHostRequest struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type hostResponse struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Address  string  `json:"address"`
	Port     int     `json:"port"`
	Status   string  `json:"status"`
	LastSeen *string `json:"lastSeen,omitempty"`
	DPUID    *string `json:"dpuId,omitempty"`
}

func hostToResponse(h *store.Host) hostResponse {
	resp := hostResponse{
		ID:      h.ID,
		Name:    h.Name,
		Address: h.Address,
		Port:    h.Port,
		Status:  h.Status,
		DPUID:   h.DPUID,
	}
	if h.LastSeen != nil {
		t := h.LastSeen.Format(time.RFC3339)
		resp.LastSeen = &t
	}
	return resp
}

// ----- Host Handlers -----

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.ListHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list hosts: "+err.Error())
		return
	}

	result := make([]hostResponse, 0, len(hosts))
	for _, h := range hosts {
		result = append(result, hostToResponse(h))
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAddHost(w http.ResponseWriter, r *http.Request) {
	var req addHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.Name == "" || req.Address == "" {
		writeError(w, http.StatusBadRequest, "Name and address are required")
		return
	}

	if req.Port == 0 {
		req.Port = 50052
	}

	id := uuid.New().String()[:8]

	if err := s.store.AddHost(id, req.Name, req.Address, req.Port); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeError(w, http.StatusConflict, "Host with this name already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to add host: "+err.Error())
		return
	}

	// Check connectivity
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	client, err := hostclient.NewClient(fmt.Sprintf("%s:%d", req.Address, req.Port))
	if err != nil {
		s.store.UpdateHostStatus(id, "offline")
	} else {
		defer client.Close()
		if _, err := client.HealthCheck(ctx); err != nil {
			s.store.UpdateHostStatus(id, "unhealthy")
		} else {
			s.store.UpdateHostStatus(id, "healthy")
		}
	}

	host, _ := s.store.GetHost(id)
	writeJSON(w, http.StatusCreated, hostToResponse(host))
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	host, err := s.store.GetHost(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Host not found")
		return
	}
	writeJSON(w, http.StatusOK, hostToResponse(host))
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.RemoveHost(id); err != nil {
		writeError(w, http.StatusNotFound, "Host not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetHostInfo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	host, err := s.store.GetHost(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Host not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := hostclient.NewClient(host.GRPCAddress())
	if err != nil {
		s.store.UpdateHostStatus(id, "offline")
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	info, err := client.GetHostInfo(ctx)
	if err != nil {
		s.store.UpdateHostStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Failed to get host info: "+err.Error())
		return
	}

	s.store.UpdateHostStatus(id, "healthy")

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hostname":      info.Hostname,
		"osName":        info.OsName,
		"osVersion":     info.OsVersion,
		"kernelVersion": info.KernelVersion,
		"architecture":  info.Architecture,
		"cpuCores":      info.CpuCores,
		"memoryGb":      info.MemoryGb,
		"uptimeSeconds": info.UptimeSeconds,
	})
}

func (s *Server) handleGetHostGPUs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	host, err := s.store.GetHost(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Host not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := hostclient.NewClient(host.GRPCAddress())
	if err != nil {
		s.store.UpdateHostStatus(id, "offline")
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.GetGPUInfo(ctx)
	if err != nil {
		s.store.UpdateHostStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Failed to get GPU info: "+err.Error())
		return
	}

	s.store.UpdateHostStatus(id, "healthy")

	gpus := make([]map[string]interface{}, 0, len(resp.Gpus))
	for _, g := range resp.Gpus {
		gpus = append(gpus, map[string]interface{}{
			"index":          g.Index,
			"name":           g.Name,
			"uuid":           g.Uuid,
			"driverVersion":  g.DriverVersion,
			"cudaVersion":    g.CudaVersion,
			"memoryMb":       g.MemoryMb,
			"temperatureC":   g.TemperatureC,
			"powerUsageW":    g.PowerUsageW,
			"utilizationPct": g.UtilizationPct,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"gpus": gpus,
	})
}

func (s *Server) handleGetHostSecurity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	host, err := s.store.GetHost(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Host not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := hostclient.NewClient(host.GRPCAddress())
	if err != nil {
		s.store.UpdateHostStatus(id, "offline")
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	info, err := client.GetSecurityInfo(ctx)
	if err != nil {
		s.store.UpdateHostStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Failed to get security info: "+err.Error())
		return
	}

	s.store.UpdateHostStatus(id, "healthy")

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secureBootEnabled": info.SecureBootEnabled,
		"tpmPresent":        info.TpmPresent,
		"tpmVersion":        info.TpmVersion,
		"uefiMode":          info.UefiMode,
		"firewallStatus":    info.FirewallStatus,
		"selinuxStatus":     info.SelinuxStatus,
	})
}

func (s *Server) handleHostHealthCheck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	host, err := s.store.GetHost(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Host not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := hostclient.NewClient(host.GRPCAddress())
	if err != nil {
		s.store.UpdateHostStatus(id, "offline")
		writeError(w, http.StatusServiceUnavailable, "Failed to connect: "+err.Error())
		return
	}
	defer client.Close()

	resp, err := client.HealthCheck(ctx)
	if err != nil {
		s.store.UpdateHostStatus(id, "unhealthy")
		writeError(w, http.StatusServiceUnavailable, "Health check failed: "+err.Error())
		return
	}

	if resp.Healthy {
		s.store.UpdateHostStatus(id, "healthy")
	} else {
		s.store.UpdateHostStatus(id, "unhealthy")
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

func (s *Server) handleLinkHostToDPU(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	dpuID := r.PathValue("dpuId")

	// Check host exists
	_, err := s.store.GetHost(hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Host not found")
		return
	}

	// Check DPU exists
	_, err = s.store.Get(dpuID)
	if err != nil {
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}

	if err := s.store.LinkHostToDPU(hostID, dpuID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to link host to DPU: "+err.Error())
		return
	}

	host, _ := s.store.GetHost(hostID)
	writeJSON(w, http.StatusOK, hostToResponse(host))
}

func (s *Server) handleUnlinkHostFromDPU(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")

	// Check host exists
	host, err := s.store.GetHost(hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Host not found")
		return
	}

	if host.DPUID == nil {
		writeError(w, http.StatusBadRequest, "Host is not linked to any DPU")
		return
	}

	if err := s.store.UnlinkHostFromDPU(hostID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to unlink host from DPU: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetDPUHost(w http.ResponseWriter, r *http.Request) {
	dpuID := r.PathValue("id")

	// Check DPU exists
	_, err := s.store.Get(dpuID)
	if err != nil {
		writeError(w, http.StatusNotFound, "DPU not found")
		return
	}

	host, err := s.store.GetHostByDPU(dpuID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"host":    nil,
			"message": "No host agent linked to this DPU",
		})
		return
	}

	// Try to get live host info
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	client, err := hostclient.NewClient(host.GRPCAddress())
	if err != nil {
		s.store.UpdateHostStatus(host.ID, "offline")
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"host":   hostToResponse(host),
			"info":   nil,
			"status": "offline",
		})
		return
	}
	defer client.Close()

	info, err := client.GetHostInfo(ctx)
	if err != nil {
		s.store.UpdateHostStatus(host.ID, "unhealthy")
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"host":   hostToResponse(host),
			"info":   nil,
			"status": "unhealthy",
		})
		return
	}

	security, _ := client.GetSecurityInfo(ctx)
	gpuInfo, _ := client.GetGPUInfo(ctx)

	s.store.UpdateHostStatus(host.ID, "healthy")

	var gpus []map[string]interface{}
	if gpuInfo != nil {
		for _, g := range gpuInfo.Gpus {
			gpus = append(gpus, map[string]interface{}{
				"name":          g.Name,
				"driverVersion": g.DriverVersion,
				"cudaVersion":   g.CudaVersion,
			})
		}
	}

	var securityInfo map[string]interface{}
	if security != nil {
		securityInfo = map[string]interface{}{
			"secureBootEnabled": security.SecureBootEnabled,
			"tpmPresent":        security.TpmPresent,
			"uefiMode":          security.UefiMode,
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host": hostToResponse(host),
		"info": map[string]interface{}{
			"hostname":      info.Hostname,
			"osName":        info.OsName,
			"osVersion":     info.OsVersion,
			"kernelVersion": info.KernelVersion,
		},
		"security": securityInfo,
		"gpus":     gpus,
		"status":   "healthy",
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode JSON: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
