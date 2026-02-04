package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gobeyondidentity/cobalt/pkg/dpop"
)

// ControlPlaneClient handles communication with the Control Plane.
type ControlPlaneClient struct {
	baseURL string
	// dpopClient is the DPoP-authenticated HTTP client (preferred)
	dpopClient *dpop.Client
	// httpClient is the fallback plain HTTP client (deprecated)
	httpClient *http.Client
}

// do performs an HTTP request using DPoP client if available, otherwise plain HTTP.
// It handles 401 responses with appropriate error logging.
func (c *ControlPlaneClient) do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	if c.dpopClient != nil {
		resp, err = c.dpopClient.Do(req)
	} else {
		resp, err = c.httpClient.Do(req)
	}

	if err != nil {
		return nil, err
	}

	// Handle authentication errors with user-friendly logging
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		authErr := dpop.ParseAuthError(resp)
		if authErr != nil {
			log.Printf("controlplane: authentication error: %s", authErr.UserFriendlyMessage())
			return resp, fmt.Errorf("authentication failed: %s", authErr.Code)
		}
	}

	return resp, nil
}

// Ping checks if the Control Plane is reachable.
func (c *ControlPlaneClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/health", nil)
	if err != nil {
		return err
	}

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("control plane unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane returned status %d", resp.StatusCode)
	}

	return nil
}

// RegisterHost proxies a host registration request to the Control Plane.
func (c *ControlPlaneClient) RegisterHost(ctx context.Context, req *ProxiedRegisterRequest) (*ProxiedRegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/hosts/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-DPU-Name", req.DPUName)
	httpReq.Header.Set("X-DPU-Attestation", req.AttestationStatus)

	resp, err := c.do(httpReq)
	if err != nil {
		// Check if this is an auth error (already logged)
		if strings.Contains(err.Error(), "authentication failed") {
			return nil, err
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result ProxiedRegisterResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// UpdatePosture proxies a posture update to the Control Plane.
func (c *ControlPlaneClient) UpdatePosture(ctx context.Context, req *ProxiedPostureRequest) error {
	body, err := json.Marshal(req.Posture)
	if err != nil {
		return fmt.Errorf("failed to marshal posture: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/hosts/%s/posture", c.baseURL, req.HostID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-DPU-Name", req.DPUName)
	httpReq.Header.Set("X-DPU-Attestation", req.AttestationStatus)

	resp, err := c.do(httpReq)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			return err
		}
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// RequestCertificate proxies a certificate request to the Control Plane.
func (c *ControlPlaneClient) RequestCertificate(ctx context.Context, req *ProxiedCertRequest) (*ProxiedCertResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/certs/sign", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-DPU-Name", req.DPUName)
	httpReq.Header.Set("X-DPU-Attestation", req.AttestationStatus)

	resp, err := c.do(httpReq)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			return nil, err
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result ProxiedCertResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}
