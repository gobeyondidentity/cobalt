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
)

// NexusClient provides HTTP client access to the Nexus API.
type NexusClient struct {
	baseURL    string
	httpClient *http.Client
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/dpus", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
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

// ListDPUs retrieves all registered DPUs from the Nexus server.
func (c *NexusClient) ListDPUs(ctx context.Context) ([]dpuResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/dpus", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/dpus/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/tenants", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/tenants", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/tenants/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/api/tenants/"+id, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/tenants/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/tenants/"+tenantID+"/dpus", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/tenants/"+tenantID+"/dpus/"+dpuID, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
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

	resp, err := c.httpClient.Do(req)
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
