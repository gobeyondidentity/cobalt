package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
)

// NexusClient provides HTTP client access to the Nexus API.
type NexusClient struct {
	baseURL       string
	httpClient    *http.Client
	proofGen      dpop.ProofGenerator
	kid           string
	dpopEnabled   bool
}

// NewNexusClient creates a new client for the Nexus API.
func NewNexusClient(baseURL string) *NexusClient {
	return &NexusClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewNexusClientWithDPoP creates a NexusClient with DPoP authentication if keys exist.
// It loads the key from ~/.bluectl/key.pem and kid from ~/.bluectl/kid.
// If keys don't exist (pre-enrollment), it returns an unauthenticated client.
// Returns an error if keys exist but cannot be loaded (permission issues, corrupt files).
func NewNexusClientWithDPoP(baseURL string) (*NexusClient, error) {
	keyPath, kidPath := dpop.DefaultKeyPaths("bluectl")
	return newNexusClientWithDPoPFromPaths(baseURL, keyPath, kidPath)
}

// newNexusClientWithDPoPFromPaths is the internal implementation that accepts explicit paths.
// This allows testing with temporary directories.
func newNexusClientWithDPoPFromPaths(baseURL, keyPath, kidPath string) (*NexusClient, error) {
	// Create base client
	client := NewNexusClient(baseURL)

	// Create key stores
	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)

	// Check if both exist; if neither exists, return unauthenticated (pre-enrollment)
	keyExists := keyStore.Exists()
	kidExists := kidStore.Exists()

	if !keyExists && !kidExists {
		return client, nil
	}

	// If only one exists, something is wrong
	if !keyExists {
		return nil, fmt.Errorf("kid file exists but key file missing: %s", keyPath)
	}
	if !kidExists {
		return nil, fmt.Errorf("key file exists but kid file missing: %s", kidPath)
	}

	// Load key (will check permissions)
	key, err := keyStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}

	// Load kid
	kid, err := kidStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load kid: %w", err)
	}

	// Create generator and enable DPoP
	proofGen := dpop.NewEd25519Generator(key)
	client.SetDPoP(proofGen, kid)

	return client, nil
}

// SetDPoP configures DPoP authentication for the client.
// proofGen is the DPoP proof generator, and kid is the server-assigned key identifier.
func (c *NexusClient) SetDPoP(proofGen dpop.ProofGenerator, kid string) {
	c.proofGen = proofGen
	c.kid = kid
	c.dpopEnabled = true
}

// IsDPoPEnabled returns true if DPoP authentication is configured.
func (c *NexusClient) IsDPoPEnabled() bool {
	return c.dpopEnabled
}

// doRequest executes an HTTP request, adding DPoP authentication if configured.
// It handles 401/403 responses by returning a user-friendly error from dpop.ParseAuthError.
func (c *NexusClient) doRequest(req *http.Request) (*http.Response, error) {
	// Add DPoP header if configured
	if c.dpopEnabled && c.proofGen != nil {
		uri := c.baseURL + req.URL.Path
		if req.URL.RawQuery != "" {
			uri += "?" + req.URL.RawQuery
		}
		proof, err := c.proofGen.Generate(req.Method, uri, c.kid)
		if err != nil {
			return nil, fmt.Errorf("generate dpop proof: %w", err)
		}
		req.Header.Set("DPoP", proof)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Check for authentication errors on 401/403
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		authErr := dpop.ParseAuthError(resp)
		if authErr != nil {
			return nil, fmt.Errorf("%s", authErr.UserFriendlyMessage())
		}
	}

	return resp, nil
}

// addDPURequest is the request body for adding a DPU.
type addDPURequest struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// dpuResponse matches the API response for DPU operations.
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

// tenantResponse matches the API response for tenant operations.
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

// createTenantRequest is the request body for creating a tenant.
type createTenantRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Contact     string   `json:"contact"`
	Tags        []string `json:"tags"`
}

// updateTenantRequest is the request body for updating a tenant.
type updateTenantRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Contact     string   `json:"contact"`
	Tags        []string `json:"tags"`
}

// assignDPURequest is the request body for assigning a DPU to a tenant.
type assignDPURequest struct {
	DPUID string `json:"dpuId"`
}

// AddDPU registers a new DPU with the Nexus server.
func (c *NexusClient) AddDPU(ctx context.Context, name, host string, port int) (*dpuResponse, error) {
	reqBody := addDPURequest{
		Name: name,
		Host: host,
		Port: port,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/dpus", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var dpu dpuResponse
	if err := json.NewDecoder(resp.Body).Decode(&dpu); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &dpu, nil
}

// ListDPUs retrieves all registered DPUs from the Nexus server, optionally filtered by status.
func (c *NexusClient) ListDPUs(ctx context.Context, status string) ([]dpuResponse, error) {
	url := c.baseURL + "/api/v1/dpus"
	if status != "" {
		url += "?status=" + status
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var dpus []dpuResponse
	if err := json.NewDecoder(resp.Body).Decode(&dpus); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return dpus, nil
}

// RemoveDPU deletes a DPU from the Nexus server.
func (c *NexusClient) RemoveDPU(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/dpus/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ----- Tenant Methods -----

// ListTenants retrieves all tenants from the Nexus server.
func (c *NexusClient) ListTenants(ctx context.Context) ([]tenantResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/tenants", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var tenants []tenantResponse
	if err := json.NewDecoder(resp.Body).Decode(&tenants); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return tenants, nil
}

// CreateTenant creates a new tenant on the Nexus server.
func (c *NexusClient) CreateTenant(ctx context.Context, name, description, contact string, tags []string) (*tenantResponse, error) {
	reqBody := createTenantRequest{
		Name:        name,
		Description: description,
		Contact:     contact,
		Tags:        tags,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/tenants", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var tenant tenantResponse
	if err := json.NewDecoder(resp.Body).Decode(&tenant); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tenant, nil
}

// GetTenant retrieves a tenant by ID from the Nexus server.
func (c *NexusClient) GetTenant(ctx context.Context, id string) (*tenantResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/tenants/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var tenant tenantResponse
	if err := json.NewDecoder(resp.Body).Decode(&tenant); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tenant, nil
}

// UpdateTenant updates an existing tenant on the Nexus server.
func (c *NexusClient) UpdateTenant(ctx context.Context, id, name, description, contact string, tags []string) (*tenantResponse, error) {
	reqBody := updateTenantRequest{
		Name:        name,
		Description: description,
		Contact:     contact,
		Tags:        tags,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/api/v1/tenants/"+id, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var tenant tenantResponse
	if err := json.NewDecoder(resp.Body).Decode(&tenant); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tenant, nil
}

// DeleteTenant removes a tenant from the Nexus server.
func (c *NexusClient) DeleteTenant(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/tenants/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// AssignDPUToTenant assigns a DPU to a tenant on the Nexus server.
func (c *NexusClient) AssignDPUToTenant(ctx context.Context, tenantID, dpuID string) error {
	reqBody := assignDPURequest{
		DPUID: dpuID,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/tenants/"+tenantID+"/dpus", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// UnassignDPUFromTenant removes a DPU from a tenant on the Nexus server.
func (c *NexusClient) UnassignDPUFromTenant(ctx context.Context, tenantID, dpuID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/tenants/"+tenantID+"/dpus/"+dpuID, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ----- Operator Methods -----

// inviteOperatorRequest is the request body for inviting an operator.
type inviteOperatorRequest struct {
	Email      string `json:"email"`
	TenantName string `json:"tenant_name"`
	Role       string `json:"role"`
}

// inviteOperatorResponse is the response for a successful operator invite.
type inviteOperatorResponse struct {
	Status     string `json:"status"`
	InviteCode string `json:"invite_code,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Operator   struct {
		ID     string `json:"id"`
		Email  string `json:"email"`
		Status string `json:"status"`
	} `json:"operator"`
}

// InviteOperator creates an invite for an operator to join a tenant on the Nexus server.
func (c *NexusClient) InviteOperator(ctx context.Context, email, tenantName, role string) (*inviteOperatorResponse, error) {
	reqBody := inviteOperatorRequest{
		Email:      email,
		TenantName: tenantName,
		Role:       role,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/operators/invite", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var result inviteOperatorResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// RemoveOperator removes an operator from the Nexus server.
func (c *NexusClient) RemoveOperator(ctx context.Context, email string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/operators/"+email, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveInviteCode removes/revokes an invite code on the Nexus server.
func (c *NexusClient) RemoveInviteCode(ctx context.Context, code string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/invites/"+code, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// operatorResponse matches the API response for operator operations.
type operatorResponse struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	Role       string `json:"role"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// updateOperatorStatusRequest is the request body for updating operator status.
type updateOperatorStatusRequest struct {
	Status string `json:"status"`
}

// ListOperators retrieves all operators from the Nexus server, optionally filtered by tenant and/or status.
func (c *NexusClient) ListOperators(ctx context.Context, tenant, status string) ([]operatorResponse, error) {
	url := c.baseURL + "/api/v1/operators"
	params := []string{}
	if tenant != "" {
		params = append(params, "tenant="+tenant)
	}
	if status != "" {
		params = append(params, "status="+status)
	}
	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var operators []operatorResponse
	if err := json.NewDecoder(resp.Body).Decode(&operators); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return operators, nil
}

// GetOperator retrieves an operator by email from the Nexus server.
func (c *NexusClient) GetOperator(ctx context.Context, email string) (*operatorResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/operators/"+email, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("operator not found: %s", email)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var operator operatorResponse
	if err := json.NewDecoder(resp.Body).Decode(&operator); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &operator, nil
}

// UpdateOperatorStatus updates the status of an operator (active or suspended).
func (c *NexusClient) UpdateOperatorStatus(ctx context.Context, email, status string) error {
	reqBody := updateOperatorStatusRequest{
		Status: status,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+"/api/v1/operators/"+email+"/status", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetDPU retrieves a DPU by name or ID from the Nexus server.
func (c *NexusClient) GetDPU(ctx context.Context, nameOrID string) (*dpuResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/dpus/"+nameOrID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("DPU not found: %s", nameOrID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var dpu dpuResponse
	if err := json.NewDecoder(resp.Body).Decode(&dpu); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &dpu, nil
}

// ----- Trust Methods -----

// createTrustRequest is the request body for creating a trust relationship.
type createTrustRequest struct {
	SourceHost    string `json:"source_host"`
	TargetHost    string `json:"target_host"`
	TrustType     string `json:"trust_type"`
	Bidirectional bool   `json:"bidirectional"`
}

// trustResponse matches the API response for trust operations.
type trustResponse struct {
	ID            string `json:"id"`
	SourceHost    string `json:"source_host"`
	TargetHost    string `json:"target_host"`
	SourceDPUID   string `json:"source_dpu_id"`
	TargetDPUID   string `json:"target_dpu_id"`
	TenantID      string `json:"tenant_id"`
	TrustType     string `json:"trust_type"`
	Bidirectional bool   `json:"bidirectional"`
	Status        string `json:"status"`
	CreatedAt     string `json:"created_at"`
}

// CreateTrust creates a trust relationship between two hosts on the Nexus server.
func (c *NexusClient) CreateTrust(ctx context.Context, req createTrustRequest) (*trustResponse, error) {
	return c.CreateTrustWithForceBypass(ctx, req, "")
}

// CreateTrustWithForceBypass creates a trust relationship with optional force bypass.
// If forceReason is non-empty, sends X-Force-Bypass header to bypass attestation checks.
func (c *NexusClient) CreateTrustWithForceBypass(ctx context.Context, req createTrustRequest, forceReason string) (*trustResponse, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/trust", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Add force bypass header if reason provided
	if forceReason != "" {
		httpReq.Header.Set("X-Force-Bypass", forceReason)
		fmt.Printf("  SECURITY WARNING: Bypassing attestation check. Reason: %s\n", forceReason)
	}

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var trust trustResponse
	if err := json.NewDecoder(resp.Body).Decode(&trust); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &trust, nil
}

// ListTrust retrieves all trust relationships from the Nexus server, optionally filtered by tenant.
func (c *NexusClient) ListTrust(ctx context.Context, tenant string) ([]trustResponse, error) {
	url := c.baseURL + "/api/v1/trust"
	if tenant != "" {
		url += "?tenant=" + tenant
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var trusts []trustResponse
	if err := json.NewDecoder(resp.Body).Decode(&trusts); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return trusts, nil
}

// DeleteTrust removes a trust relationship from the Nexus server.
func (c *NexusClient) DeleteTrust(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/trust/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ----- Agent Host Methods -----

// agentHostResponse matches the API response for agent host operations.
type agentHostResponse struct {
	ID         string `json:"id"`
	DPUName    string `json:"dpu_name"`
	Hostname   string `json:"hostname"`
	LastSeenAt string `json:"last_seen_at"`
}

// ListAgentHosts retrieves all agent hosts from the Nexus server, optionally filtered by tenant.
func (c *NexusClient) ListAgentHosts(ctx context.Context, tenant string) ([]agentHostResponse, error) {
	url := c.baseURL + "/api/v1/hosts"
	if tenant != "" {
		url += "?tenant=" + tenant
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	// API returns wrapped response: {"hosts": [...]}
	var wrapper struct {
		Hosts []agentHostResponse `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return wrapper.Hosts, nil
}

// GetAgentHost retrieves an agent host by ID from the Nexus server.
func (c *NexusClient) GetAgentHost(ctx context.Context, id string) (*agentHostResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/hosts/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("agent host not found: %s", id)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var host agentHostResponse
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &host, nil
}

// DeleteAgentHost removes an agent host from the Nexus server.
func (c *NexusClient) DeleteAgentHost(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/hosts/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ----- SSH CA Methods -----

// sshCAResponse matches the API response for SSH CA operations.
type sshCAResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	KeyType       string `json:"keyType"`
	PublicKey     string `json:"publicKey,omitempty"`
	CreatedAt     string `json:"createdAt"`
	Distributions int    `json:"distributions"`
}

// ListSSHCAs retrieves all SSH CAs from the Nexus server.
func (c *NexusClient) ListSSHCAs(ctx context.Context) ([]sshCAResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/credentials/ssh-cas", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var cas []sshCAResponse
	if err := json.NewDecoder(resp.Body).Decode(&cas); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return cas, nil
}

// GetSSHCA retrieves an SSH CA by name from the Nexus server.
func (c *NexusClient) GetSSHCA(ctx context.Context, name string) (*sshCAResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/credentials/ssh-cas/"+name, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("SSH CA not found: %s", name)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var ca sshCAResponse
	if err := json.NewDecoder(resp.Body).Decode(&ca); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &ca, nil
}

// ----- Authorization Methods -----

// grantAuthorizationRequest is the request body for granting authorization.
type grantAuthorizationRequest struct {
	OperatorEmail string   `json:"operator_email"`
	TenantID      string   `json:"tenant_id"`
	CAIDs         []string `json:"ca_ids"`
	DeviceIDs     []string `json:"device_ids"`
}

// authorizationResponse matches the API response for authorization operations.
type authorizationResponse struct {
	ID          string   `json:"id"`
	OperatorID  string   `json:"operator_id"`
	TenantID    string   `json:"tenant_id"`
	CAIDs       []string `json:"ca_ids"`
	CANames     []string `json:"ca_names"`
	DeviceIDs   []string `json:"device_ids"`
	DeviceNames []string `json:"device_names"`
	CreatedAt   string   `json:"created_at"`
	CreatedBy   string   `json:"created_by"`
	ExpiresAt   *string  `json:"expires_at,omitempty"`
}

// GrantAuthorization creates an authorization for an operator to access CAs and devices.
func (c *NexusClient) GrantAuthorization(ctx context.Context, email, tenantID string, caIDs, deviceIDs []string) (*authorizationResponse, error) {
	reqBody := grantAuthorizationRequest{
		OperatorEmail: email,
		TenantID:      tenantID,
		CAIDs:         caIDs,
		DeviceIDs:     deviceIDs,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/authorizations", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var auth authorizationResponse
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &auth, nil
}

// GetOperatorAuthorizations retrieves all authorizations for an operator by their ID.
func (c *NexusClient) GetOperatorAuthorizations(ctx context.Context, operatorID string) ([]authorizationResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/authorizations?operator_id="+operatorID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var auths []authorizationResponse
	if err := json.NewDecoder(resp.Body).Decode(&auths); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return auths, nil
}

// DeleteAuthorization deletes an authorization by ID.
// API: DELETE /api/v1/authorizations/{id}
func (c *NexusClient) DeleteAuthorization(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/authorizations/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("authorization not found: %s", id)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ----- Role Management Methods -----

// assignRoleRequest is the request body for assigning a role.
type assignRoleRequest struct {
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

// AssignRole assigns or updates a role for an operator in a tenant.
// API: POST /api/v1/operators/{id}/roles
func (c *NexusClient) AssignRole(ctx context.Context, operatorID, tenantID, role string) error {
	reqBody := assignRoleRequest{
		TenantID: tenantID,
		Role:     role,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/operators/"+operatorID+"/roles", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveRole removes an operator's role in a specific tenant.
// API: DELETE /api/v1/operators/{id}/roles/{tenant_id}
func (c *NexusClient) RemoveRole(ctx context.Context, operatorID, tenantID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/operators/"+operatorID+"/roles/"+tenantID, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ----- KeyMaker Methods -----

// keymakerResponse matches the API response for KeyMaker operations.
type keymakerResponse struct {
	ID            string  `json:"id"`
	OperatorID    string  `json:"operator_id"`
	OperatorEmail string  `json:"operator_email"`
	Name          string  `json:"name"`
	Platform      string  `json:"platform"`
	SecureElement string  `json:"secure_element"`
	BoundAt       string  `json:"bound_at"`
	LastSeen      *string `json:"last_seen,omitempty"`
	Status        string  `json:"status"`
}

// ListKeyMakers retrieves all KeyMakers from the Nexus server, optionally filtered by operator and/or status.
func (c *NexusClient) ListKeyMakers(ctx context.Context, operatorID, status string) ([]keymakerResponse, error) {
	url := c.baseURL + "/api/v1/keymakers"
	params := []string{}
	if operatorID != "" {
		params = append(params, "operator_id="+operatorID)
	}
	if status != "" {
		params = append(params, "status="+status)
	}
	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var keymakers []keymakerResponse
	if err := json.NewDecoder(resp.Body).Decode(&keymakers); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return keymakers, nil
}

// GetKeyMaker retrieves a KeyMaker by ID from the Nexus server.
func (c *NexusClient) GetKeyMaker(ctx context.Context, id string) (*keymakerResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/keymakers/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("KeyMaker not found: %s", id)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var km keymakerResponse
	if err := json.NewDecoder(resp.Body).Decode(&km); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &km, nil
}

// RevokeKeyMaker revokes a KeyMaker by ID.
func (c *NexusClient) RevokeKeyMaker(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/keymakers/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ----- Host Posture Methods -----

// postureResponse matches the API response for host posture.
type postureResponse struct {
	SecureBoot     *bool  `json:"secure_boot"`
	DiskEncryption string `json:"disk_encryption"`
	OSVersion      string `json:"os_version"`
	KernelVersion  string `json:"kernel_version"`
	TPMPresent     *bool  `json:"tpm_present"`
	PostureHash    string `json:"posture_hash"`
	CollectedAt    string `json:"collected_at"`
}

// ErrNoPostureData indicates no posture data is available for the host.
var ErrNoPostureData = fmt.Errorf("no posture data available")

// GetHostPostureByDPU retrieves the posture data for the host paired with a DPU.
func (c *NexusClient) GetHostPostureByDPU(ctx context.Context, dpuName string) (*postureResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/hosts/"+dpuName+"/posture", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoPostureData
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var posture postureResponse
	if err := json.NewDecoder(resp.Body).Decode(&posture); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &posture, nil
}

// ----- Admin Key Methods -----

// adminKeyResponse matches the API response for admin key operations.
type adminKeyResponse struct {
	ID             string  `json:"id"`
	OperatorID     string  `json:"operator_id"`
	Name           string  `json:"name,omitempty"`
	Kid            string  `json:"kid"`
	KeyFingerprint string  `json:"key_fingerprint"`
	Status         string  `json:"status"`
	BoundAt        string  `json:"bound_at"`
	LastSeen       *string `json:"last_seen,omitempty"`
	RevokedAt      *string `json:"revoked_at,omitempty"`
	RevokedBy      *string `json:"revoked_by,omitempty"`
	RevokedReason  *string `json:"revoked_reason,omitempty"`
}

// revokeAdminKeyRequest is the request body for revoking an admin key.
type revokeAdminKeyRequest struct {
	Reason string `json:"reason"`
}

// ListAdminKeys retrieves all admin keys from the Nexus server, optionally filtered by status.
func (c *NexusClient) ListAdminKeys(ctx context.Context, status string) ([]adminKeyResponse, error) {
	url := c.baseURL + "/api/v1/admin-keys"
	if status != "" {
		url += "?status=" + status
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var adminKeys []adminKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&adminKeys); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return adminKeys, nil
}

// GetAdminKey retrieves an admin key by ID from the Nexus server.
func (c *NexusClient) GetAdminKey(ctx context.Context, id string) (*adminKeyResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/admin-keys/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("admin key not found: %s", id)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var ak adminKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&ak); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &ak, nil
}

// RevokeAdminKey revokes an admin key by ID with a reason.
func (c *NexusClient) RevokeAdminKey(ctx context.Context, id, reason string) error {
	reqBody := revokeAdminKeyRequest{
		Reason: reason,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/admin-keys/"+id, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ----- DPU Decommission Methods -----

// decommissionDPURequest is the request body for decommissioning a DPU.
type decommissionDPURequest struct {
	Reason           string `json:"reason"`
	ScrubCredentials bool   `json:"scrub_credentials"`
}

// DecommissionDPUResponse is the response for a successful DPU decommissioning.
type DecommissionDPUResponse struct {
	ID                  string `json:"id"`
	Status              string `json:"status"`
	DecommissionedAt    string `json:"decommissioned_at"`
	CredentialsScrubbed int    `json:"credentials_scrubbed"`
}

// DecommissionDPU decommissions a DPU by ID with a reason.
// This blocks authentication, optionally scrubs credentials, and retains audit records.
func (c *NexusClient) DecommissionDPU(ctx context.Context, id, reason string, scrubCredentials bool) (*DecommissionDPUResponse, error) {
	reqBody := decommissionDPURequest{
		Reason:           reason,
		ScrubCredentials: scrubCredentials,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v1/dpus/"+id, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("DPU not found: %s", id)
	}
	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("DPU already decommissioned")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var result DecommissionDPUResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// ----- DPU Reactivate Methods -----

// reactivateDPURequest is the request body for reactivating a decommissioned DPU.
type reactivateDPURequest struct {
	Reason string `json:"reason"`
}

// ReactivateDPUResponse is the response for a successful DPU reactivation.
type ReactivateDPUResponse struct {
	ID                  string `json:"id"`
	Status              string `json:"status"`
	ReactivatedAt       string `json:"reactivated_at"`
	ReactivatedBy       string `json:"reactivated_by"`
	EnrollmentExpiresAt string `json:"enrollment_expires_at"`
}

// ReactivateDPU reactivates a decommissioned DPU by ID with a reason.
// This sets status to pending, clears old public key, and creates a 24h enrollment window.
// Only super:admin can call this endpoint.
func (c *NexusClient) ReactivateDPU(ctx context.Context, id, reason string) (*ReactivateDPUResponse, error) {
	reqBody := reactivateDPURequest{
		Reason: reason,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/dpus/"+id+"/reactivate", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("DPU not found: %s", id)
	}
	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("DPU is not decommissioned")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var result ReactivateDPUResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}
