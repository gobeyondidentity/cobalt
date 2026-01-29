package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/nmelo/secure-infra/pkg/clierror"
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
		return clierror.TokenExpired()
	}

	// Look up CA ID by name
	caResp, err := http.Get(config.ControlPlaneURL + "/api/credentials/ssh-cas/" + url.QueryEscape(caName))
	if err != nil {
		return clierror.ConnectionFailed("server")
	}
	defer caResp.Body.Close()

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
		dpuResp, err := http.Get(config.ControlPlaneURL + "/api/dpus/" + url.QueryEscape(deviceName))
		if err != nil {
			return clierror.ConnectionFailed("server")
		}
		defer dpuResp.Body.Close()

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
	reqBody := AuthorizationCheckRequest{
		OperatorID:  config.OperatorID,
		CAID:        caInfo.ID,
		KeyMakerID:  config.KeyMakerID,
	}
	if deviceID != "" {
		reqBody.DeviceID = deviceID
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return clierror.InternalError(fmt.Errorf("failed to marshal authorization request: %w", err))
	}

	resp, err := http.Post(
		config.ControlPlaneURL+"/api/v1/authorizations/check",
		"application/json",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return clierror.ConnectionFailed("server")
	}
	defer resp.Body.Close()

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
		return nil, clierror.TokenExpired()
	}

	reqURL := fmt.Sprintf("%s/api/v1/authorizations?operator_id=%s",
		config.ControlPlaneURL, url.QueryEscape(config.OperatorID))

	resp, err := http.Get(reqURL)
	if err != nil {
		return nil, clierror.ConnectionFailed("server")
	}
	defer resp.Body.Close()

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
