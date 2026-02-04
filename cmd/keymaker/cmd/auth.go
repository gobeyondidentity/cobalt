package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gobeyondidentity/cobalt/pkg/clierror"
	"github.com/gobeyondidentity/cobalt/pkg/dpop"
)

// AuthorizationCheckRequest is sent to the server to check authorization.
type AuthorizationCheckRequest struct {
	OperatorID  string `json:"operator_id"`
	CAID        string `json:"ca_id"`
	DeviceID    string `json:"device_id,omitempty"`
	KeyMakerID  string `json:"keymaker_id,omitempty"`
}

// AuthorizationCheckResponse is returned from the server.
type AuthorizationCheckResponse struct {
	Authorized bool   `json:"authorized"`
	Reason     string `json:"reason,omitempty"`
}

// Authorization represents a single authorization entry from the server.
type Authorization struct {
	ID          string   `json:"id"`
	OperatorID  string   `json:"operator_id"`
	TenantID    string   `json:"tenant_id"`
	CAIDs       []string `json:"ca_ids"`
	CANames     []string `json:"ca_names"`
	DeviceIDs   []string `json:"device_ids"`
	DeviceNames []string `json:"device_names"`
	CreatedAt   string   `json:"created_at"`
	// Legacy fields for backward compatibility with existing code
	CAID    string   `json:"ca_id"`
	CAName  string   `json:"ca_name"`
	Devices []string `json:"devices"`
}

// checkAuthorization verifies that the operator is authorized for the given CA and optionally device.
// Returns nil if authorized, or an error with appropriate message if not.
// caName is the human-readable CA name (e.g., "test-ca"), which is resolved to a CA ID via API lookup.
// deviceName is the human-readable device name, which is resolved to a device ID via API lookup.
func checkAuthorization(caName, deviceName string) error {
	config, err := loadConfig()
	if err != nil {
		return clierror.ConfigMissing()
	}

	// Get DPoP-enabled HTTP client
	httpClient, err := getDPoPHTTPClient(config.ServerURL)
	if err != nil {
		return clierror.InternalError(err)
	}

	// Look up CA ID by name
	caReq, err := http.NewRequest("GET", config.ServerURL+"/api/v1/credentials/ssh-cas/"+url.QueryEscape(caName), nil)
	if err != nil {
		return clierror.InternalError(fmt.Errorf("failed to create CA lookup request: %w", err))
	}
	caResp, err := httpClient.Do(caReq)
	if err != nil {
		return clierror.ConnectionFailed("server")
	}
	defer caResp.Body.Close()

	// Handle auth errors with user-friendly messages
	if authErr := handleAuthError(caResp); authErr != nil {
		return authErr
	}

	if caResp.StatusCode == http.StatusNotFound {
		return &AuthorizationError{Type: "ca", Resource: caName}
	}
	if caResp.StatusCode != http.StatusOK {
		return clierror.InternalError(fmt.Errorf("failed to look up CA: HTTP %d", caResp.StatusCode))
	}

	var caInfo struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(caResp.Body).Decode(&caInfo); err != nil {
		return clierror.InternalError(fmt.Errorf("failed to parse CA response: %w", err))
	}

	// Look up device ID by name if a device is specified
	var deviceID string
	if deviceName != "" {
		dpuReq, err := http.NewRequest("GET", config.ServerURL+"/api/v1/dpus/"+url.QueryEscape(deviceName), nil)
		if err != nil {
			return clierror.InternalError(fmt.Errorf("failed to create device lookup request: %w", err))
		}
		dpuResp, err := httpClient.Do(dpuReq)
		if err != nil {
			return clierror.ConnectionFailed("server")
		}
		defer dpuResp.Body.Close()

		// Handle auth errors with user-friendly messages
		if authErr := handleAuthError(dpuResp); authErr != nil {
			return authErr
		}

		if dpuResp.StatusCode == http.StatusNotFound {
			return &AuthorizationError{Type: "device", Resource: deviceName}
		}
		if dpuResp.StatusCode != http.StatusOK {
			return clierror.InternalError(fmt.Errorf("failed to look up device: HTTP %d", dpuResp.StatusCode))
		}

		var dpuInfo struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(dpuResp.Body).Decode(&dpuInfo); err != nil {
			return clierror.InternalError(fmt.Errorf("failed to parse device response: %w", err))
		}
		deviceID = dpuInfo.ID
	}

	// Now use caInfo.ID and deviceID for the authorization check
	// Check if operator_id is available (populated during enrollment)
	if config.OperatorID == "" {
		return clierror.ConfigMissing()
	}

	reqBody := AuthorizationCheckRequest{
		OperatorID: config.OperatorID,
		CAID:       caInfo.ID,
		KeyMakerID: config.KeyMakerID,
	}
	if deviceID != "" {
		reqBody.DeviceID = deviceID
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return clierror.InternalError(fmt.Errorf("failed to marshal authorization request: %w", err))
	}

	req, err := http.NewRequest("POST", config.ServerURL+"/api/v1/authorizations/check", bytes.NewReader(jsonBody))
	if err != nil {
		return clierror.InternalError(fmt.Errorf("failed to create authorization request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return clierror.ConnectionFailed("server")
	}
	defer resp.Body.Close()

	// Handle auth errors with user-friendly messages
	if authErr := handleAuthError(resp); authErr != nil {
		return authErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return clierror.InternalError(fmt.Errorf("failed to read authorization response: %w", err))
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			// Handle device revoked error specially
			if errResp.Error == "device revoked" {
				return &DeviceRevokedError{}
			}
			// Map internal field name errors to user-friendly messages
			if errResp.Error == "operator_id is required" {
				return clierror.ConfigMissing()
			}
			return clierror.InternalError(fmt.Errorf("authorization check failed: %s", errResp.Error))
		}
		return clierror.InternalError(fmt.Errorf("authorization check failed: HTTP %d", resp.StatusCode))
	}

	var authResp AuthorizationCheckResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return clierror.InternalError(fmt.Errorf("failed to parse authorization response: %w", err))
	}

	if !authResp.Authorized {
		if deviceID != "" && authResp.Reason != "" && authResp.Reason == "device_not_authorized" {
			return &AuthorizationError{
				Type:     "device",
				Resource: deviceID,
			}
		}
		return &AuthorizationError{
			Type:     "ca",
			Resource: caName,
		}
	}

	return nil
}

// getAuthorizations fetches the list of authorizations for the current operator.
func getAuthorizations() ([]Authorization, error) {
	config, err := loadConfig()
	if err != nil {
		return nil, clierror.ConfigMissing()
	}

	// Get DPoP-enabled HTTP client
	httpClient, err := getDPoPHTTPClient(config.ServerURL)
	if err != nil {
		return nil, clierror.InternalError(err)
	}

	// Use keymaker_id (KID) instead of operator_id since that's what we have stored
	kid := config.KID
	if kid == "" {
		// Fallback for legacy config
		kid = config.KeyMakerID
	}
	reqURL := fmt.Sprintf("%s/api/v1/authorizations?keymaker_id=%s",
		config.ServerURL, url.QueryEscape(kid))

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, clierror.InternalError(fmt.Errorf("failed to create authorizations request: %w", err))
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, clierror.ConnectionFailed("server")
	}
	defer resp.Body.Close()

	// Handle auth errors with user-friendly messages
	if authErr := handleAuthError(resp); authErr != nil {
		return nil, authErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, clierror.InternalError(fmt.Errorf("failed to read authorizations response: %w", err))
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, clierror.InternalError(fmt.Errorf("failed to fetch authorizations: %s", errResp.Error))
		}
		return nil, clierror.InternalError(fmt.Errorf("failed to fetch authorizations: HTTP %d", resp.StatusCode))
	}

	var authorizations []Authorization
	if err := json.Unmarshal(body, &authorizations); err != nil {
		return nil, clierror.InternalError(fmt.Errorf("failed to parse authorizations response: %w", err))
	}

	return authorizations, nil
}

// AuthorizationError represents an authorization failure with structured information.
type AuthorizationError struct {
	Type     string // "ca" or "device"
	Resource string // The CA name or device name that was not authorized
}

func (e *AuthorizationError) Error() string {
	if e.Type == "device" {
		return fmt.Sprintf("Error: Not authorized for device '%s'\nHint: Contact your tenant admin for access.", e.Resource)
	}
	return fmt.Sprintf("Error: Not authorized for CA '%s'\nHint: Contact your tenant admin for access.", e.Resource)
}

// DeviceRevokedError indicates the KeyMaker has been revoked and cannot perform operations.
type DeviceRevokedError struct{}

func (e *DeviceRevokedError) Error() string {
	return "Error: This device has been revoked.\nHint: Contact your tenant admin to re-enroll this device."
}

// handleAuthError checks for DPoP authentication errors and returns user-friendly messages.
// Returns nil if the response is not an auth error (2xx or other non-auth error).
func handleAuthError(resp *http.Response) error {
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return nil
	}

	// Try to parse the error body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// Can't read body, return generic error
		if resp.StatusCode == http.StatusUnauthorized {
			return clierror.AuthFailed()
		}
		return clierror.NotAuthorized("this operation")
	}

	// Try to parse as JSON error
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		// Check for DPoP-specific errors
		authErr := &dpop.AuthError{
			StatusCode: resp.StatusCode,
			Code:       errResp.Error,
		}
		return fmt.Errorf("%s", authErr.UserFriendlyMessage())
	}

	// Generic auth error
	if resp.StatusCode == http.StatusUnauthorized {
		return clierror.AuthFailed()
	}
	return clierror.NotAuthorized("this operation")
}
