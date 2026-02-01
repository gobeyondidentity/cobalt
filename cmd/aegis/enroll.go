// Package main provides the aegis CLI entry point.
// This file implements the DPU enrollment command.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
	"github.com/gobeyondidentity/secure-infra/pkg/enrollment"
)

// EnrollConfig holds the configuration for DPU enrollment.
type EnrollConfig struct {
	Serial          string
	ServerURL       string
	SkipAttestation bool
	BMCAddr         string // BMC address for SPDM attestation (optional)
	Timeout         time.Duration
}

// EnrollInitRequest is the request body for POST /api/v1/enroll/dpu/init.
type EnrollInitRequest struct {
	Serial string `json:"serial"`
}

// EnrollInitResponse is the response from POST /api/v1/enroll/dpu/init.
type EnrollInitResponse struct {
	Challenge    string `json:"challenge"`
	EnrollmentID string `json:"enrollment_id"`
}

// EnrollCompleteRequest is the request body for POST /api/v1/enroll/complete.
type EnrollCompleteRequest struct {
	EnrollmentID    string `json:"enrollment_id"`
	PublicKey       string `json:"public_key"`
	SignedChallenge string `json:"signed_challenge"`
	SPDMAttestation string `json:"spdm_attestation,omitempty"`
}

// EnrollCompleteResponse is the response from POST /api/v1/enroll/complete.
type EnrollCompleteResponse struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
}

// EnrollErrorResponse is the error response format from the server.
type EnrollErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// RunEnrollment performs the DPU enrollment flow.
// Returns the assigned device ID and fingerprint on success.
func RunEnrollment(ctx context.Context, cfg EnrollConfig) (string, string, error) {
	// Validate configuration
	if cfg.Serial == "" {
		return "", "", fmt.Errorf("serial number is required")
	}
	if cfg.ServerURL == "" {
		return "", "", fmt.Errorf("server URL is required")
	}

	// Check if already enrolled
	keyPath, kidPath := dpop.DefaultKeyPaths("aegis")
	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)
	idCfg := dpop.IdentityConfig{
		KeyStore:  keyStore,
		KIDStore:  kidStore,
		ServerURL: cfg.ServerURL,
	}
	if dpop.IsEnrolled(idCfg) {
		kid, err := kidStore.Load()
		if err != nil {
			return "", "", fmt.Errorf("aegis is already enrolled but failed to read kid: %w", err)
		}
		return "", "", fmt.Errorf("aegis is already enrolled (kid: %s). Use --force to re-enroll", kid)
	}

	// Create HTTP client with timeout
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	httpClient := &http.Client{Timeout: timeout}

	// Step 1: Generate Ed25519 keypair
	fmt.Println("Generating Ed25519 keypair...")
	pubKey, privKey, err := dpop.GenerateKeyPair()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Step 2: Initiate enrollment with serial number
	fmt.Printf("Initiating enrollment for DPU serial: %s\n", cfg.Serial)
	initResp, err := initiateEnrollment(ctx, httpClient, cfg.ServerURL, cfg.Serial)
	if err != nil {
		return "", "", err
	}
	fmt.Printf("Received challenge (enrollment_id: %s)\n", initResp.EnrollmentID)

	// Step 3: Decode challenge and compute binding nonce
	challengeBytes, err := base64.StdEncoding.DecodeString(initResp.Challenge)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode challenge: %w", err)
	}

	bindingNonce := enrollment.ComputeBindingNonce(challengeBytes, pubKey)
	_ = bindingNonce // Will be used for SPDM attestation when implemented

	// Step 4: Get SPDM attestation (or skip in dev mode)
	var spdmAttestation string
	if cfg.SkipAttestation {
		fmt.Println("WARNING: Skipping SPDM attestation (development mode)")
		fmt.Println("         This mode is NOT secure for production use.")
	} else {
		// For MVP, SPDM attestation via BMC is stubbed out
		// Real implementation would call:
		//   POST https://{bmc_addr}/redfish/v1/Systems/DPU_SPDM/Oem/Nvidia/Attestation
		//   Body: {"Nonce": "<base64(binding_nonce)>"}
		//
		// Until BMC integration is implemented, require --skip-attestation flag
		return "", "", fmt.Errorf("SPDM attestation not yet implemented. Use --skip-attestation for development")
	}

	// Step 5: Sign the challenge
	fmt.Println("Signing challenge...")
	signature := ed25519.Sign(privKey, challengeBytes)

	// Step 6: Complete enrollment
	fmt.Println("Completing enrollment...")
	completeResp, err := completeEnrollment(ctx, httpClient, cfg.ServerURL, EnrollCompleteRequest{
		EnrollmentID:    initResp.EnrollmentID,
		PublicKey:       base64.StdEncoding.EncodeToString(pubKey),
		SignedChallenge: base64.StdEncoding.EncodeToString(signature),
		SPDMAttestation: spdmAttestation,
	})
	if err != nil {
		return "", "", err
	}

	// Step 7: Save identity to disk
	fmt.Println("Saving identity...")
	if err := dpop.CompleteEnrollment("aegis", privKey, completeResp.ID); err != nil {
		return "", "", fmt.Errorf("failed to save identity: %w", err)
	}

	fmt.Printf("Enrollment complete. Device ID: %s\n", completeResp.ID)
	fmt.Printf("Key fingerprint: %s\n", completeResp.Fingerprint)
	fmt.Printf("Identity saved to %s\n", keyPath)

	return completeResp.ID, completeResp.Fingerprint, nil
}

// initiateEnrollment calls POST /api/v1/enroll/dpu/init.
func initiateEnrollment(ctx context.Context, client *http.Client, baseURL, serial string) (*EnrollInitResponse, error) {
	reqBody, err := json.Marshal(EnrollInitRequest{Serial: serial})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := baseURL + "/api/v1/enroll/dpu/init"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to control plane: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseEnrollmentError(resp.StatusCode, body)
	}

	var result EnrollInitResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// completeEnrollment calls POST /api/v1/enroll/complete.
func completeEnrollment(ctx context.Context, client *http.Client, baseURL string, reqData EnrollCompleteRequest) (*EnrollCompleteResponse, error) {
	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := baseURL + "/api/v1/enroll/complete"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to control plane: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseEnrollmentError(resp.StatusCode, body)
	}

	var result EnrollCompleteResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// parseEnrollmentError converts HTTP error responses into user-friendly errors.
func parseEnrollmentError(statusCode int, body []byte) error {
	var errResp EnrollErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return fmt.Errorf("server returned HTTP %d: %s", statusCode, string(body))
	}

	// Map error codes to user-friendly messages
	switch errResp.Error {
	case "":
		// No structured error, use the raw body
		return fmt.Errorf("server returned HTTP %d: %s", statusCode, string(body))

	case enrollment.ErrCodeExpiredCode:
		return fmt.Errorf("enrollment window expired (24h). Ask admin to re-register this DPU")

	case enrollment.ErrCodeDICESerialMismatch:
		return fmt.Errorf("DICE serial doesn't match registration. Contact admin to verify DPU serial")

	case enrollment.ErrCodeAttestationNonceMismatch:
		return fmt.Errorf("attestation evidence is stale or tampered. Retry enrollment")

	case enrollment.ErrCodeInvalidSignature:
		return fmt.Errorf("challenge signature verification failed")

	case enrollment.ErrCodeKeyExists:
		return fmt.Errorf("this key is already enrolled")

	case enrollment.ErrCodeInvalidSession:
		return fmt.Errorf("enrollment session not found or expired")

	case enrollment.ErrCodeChallengeExpired:
		return fmt.Errorf("challenge expired. Restart enrollment")
	}

	// Handle by HTTP status code
	switch statusCode {
	case http.StatusNotFound:
		return fmt.Errorf("DPU serial not registered. Ask admin to register this DPU first")
	case http.StatusConflict:
		return fmt.Errorf("DPU already enrolled or decommissioned")
	case http.StatusUnauthorized:
		if errResp.Message != "" {
			return fmt.Errorf("authentication failed: %s", errResp.Message)
		}
		return fmt.Errorf("authentication failed: %s", errResp.Error)
	default:
		if errResp.Message != "" {
			return fmt.Errorf("%s: %s", errResp.Error, errResp.Message)
		}
		return fmt.Errorf("enrollment failed: %s", errResp.Error)
	}
}

// EnrollCommand runs the enrollment subcommand.
// This is called from main.go when --enroll flag is set.
func EnrollCommand(serial, serverURL string, skipAttestation bool) error {
	// Validate required flags
	if serial == "" {
		fmt.Fprintln(os.Stderr, "Error: --serial is required for enrollment")
		fmt.Fprintln(os.Stderr, "Usage: aegis --enroll --serial <dpu-serial> --server <url>")
		return fmt.Errorf("missing required flag: --serial")
	}
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --server is required for enrollment")
		fmt.Fprintln(os.Stderr, "Usage: aegis --enroll --serial <dpu-serial> --server <url>")
		return fmt.Errorf("missing required flag: --server")
	}

	ctx := context.Background()
	_, _, err := RunEnrollment(ctx, EnrollConfig{
		Serial:          serial,
		ServerURL:       serverURL,
		SkipAttestation: skipAttestation,
		Timeout:         30 * time.Second,
	})
	return err
}
