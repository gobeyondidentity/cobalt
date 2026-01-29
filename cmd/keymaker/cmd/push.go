package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nmelo/secure-infra/pkg/clierror"
	"github.com/spf13/cobra"
)

// pushHTTPClient is the HTTP client used for push requests. Package-level for testing.
var pushHTTPClient HTTPClient = http.DefaultClient

// HTTPClient interface for mocking HTTP requests in tests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func init() {
	rootCmd.AddCommand(pushCmd)
	pushCmd.AddCommand(pushSSHCACmd)

	// Flags for push ssh-ca
	pushSSHCACmd.Flags().Bool("force", false, "Force push even with stale attestation (audited)")
}

var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push credentials to DPUs",
	Long: `Push credentials to DPUs with attestation gate checks.

Push requires the target DPU to have recent verified attestation.
Use --force to bypass stale attestation (this action is audited).`,
}

var pushSSHCACmd = &cobra.Command{
	Use:   "ssh-ca <ca-name> <target>",
	Short: "Push an SSH CA to a DPU",
	Long: `Push an SSH CA's public key to a target DPU.

This command verifies the attestation gate before allowing the push.
The CA public key is sent to the DPU agent, which installs it and reloads sshd.

Attestation Requirements:
- DPU must have a verified attestation record
- Attestation must be fresh (less than 1 hour old by default)
- Use --force to bypass stale attestation (logged to audit trail)

Examples:
  km push ssh-ca ops-ca bf3-lab
  km push ssh-ca ops-ca bf3-lab --force`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		caName := args[0]
		targetDPU := args[1]
		force, _ := cmd.Flags().GetBool("force")

		// Load operator context from config
		config, err := loadConfig()
		if err != nil {
			return clierror.TokenExpired()
		}

		fmt.Printf("Pushing CA '%s' to %s...\n", caName, targetDPU)

		// Call server push endpoint
		resp, err := callPushAPI(config, caName, targetDPU, force)
		if err != nil {
			return err
		}

		// Display attestation status
		if resp.AttestationStatus != "" {
			if resp.Success {
				fmt.Printf("  Attestation: %s (%s ago)\n\n", resp.AttestationStatus, resp.AttestationAge)
			} else if resp.AttestationStatus == "failed" {
				fmt.Printf("x Attestation failed: device failed integrity verification\n\n")
			} else if strings.Contains(resp.Message, "stale") {
				fmt.Printf("x Attestation stale (%s ago)\n\n", resp.AttestationAge)
			} else {
				fmt.Printf("x Attestation %s\n\n", resp.AttestationStatus)
			}
		}

		// Handle failure
		if !resp.Success {
			fmt.Printf("Push blocked: %s\n", resp.Message)
			if strings.Contains(resp.Message, "stale") {
				fmt.Printf("Hint: Use --force to bypass (audited)\n")
			} else if strings.Contains(resp.Message, "failed") {
				fmt.Printf("Contact your infrastructure team. This event has been logged.\n")
			}
			// Error already returned from callPushAPI
			return nil
		}

		// Success output per ADR-006 format
		if resp.InstalledPath != "" {
			fmt.Printf("CA installed at %s\n", resp.InstalledPath)
		} else {
			fmt.Printf("CA installed.\n")
		}
		if resp.SSHDReloaded {
			fmt.Printf("sshd reloaded.\n")
		}

		return nil
	},
}

// pushRequest is the request body for pushing credentials to a DPU.
type pushRequest struct {
	CAName    string `json:"ca_name"`
	TargetDPU string `json:"target_dpu"`
	Force     bool   `json:"force"`
}

// pushResponse is the response from the push API.
type pushResponse struct {
	Success           bool   `json:"success"`
	InstalledPath     string `json:"installed_path,omitempty"`
	SSHDReloaded      bool   `json:"sshd_reloaded"`
	AttestationStatus string `json:"attestation_status"`
	AttestationAge    string `json:"attestation_age,omitempty"`
	Message           string `json:"message,omitempty"`
}

// callPushAPI calls the server push endpoint and handles the response.
func callPushAPI(config *KMConfig, caName, targetDPU string, force bool) (*pushResponse, error) {
	reqBody := pushRequest{
		CAName:    caName,
		TargetDPU: targetDPU,
		Force:     force,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, clierror.InternalError(fmt.Errorf("failed to marshal push request: %w", err))
	}

	req, err := http.NewRequest(
		http.MethodPost,
		config.ControlPlaneURL+"/api/v1/push",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return nil, clierror.InternalError(fmt.Errorf("failed to create push request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")

	// Sign request with KeyMaker credentials
	if err := signRequest(req, config, jsonBody); err != nil {
		return nil, clierror.InternalError(fmt.Errorf("failed to sign request: %w", err))
	}

	resp, err := pushHTTPClient.Do(req)
	if err != nil {
		return nil, clierror.ConnectionFailed("server")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, clierror.InternalError(fmt.Errorf("failed to read push response: %w", err))
	}

	// Handle error status codes
	if resp.StatusCode != http.StatusOK {
		return handlePushError(resp.StatusCode, body, caName, targetDPU)
	}

	// Parse successful response
	var pushResp pushResponse
	if err := json.Unmarshal(body, &pushResp); err != nil {
		return nil, clierror.InternalError(fmt.Errorf("failed to parse push response: %w", err))
	}

	return &pushResp, nil
}

// handlePushError maps HTTP error codes to appropriate CLI errors.
func handlePushError(statusCode int, body []byte, caName, targetDPU string) (*pushResponse, error) {
	// Try to parse error response
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	json.Unmarshal(body, &errResp) // Ignore parse errors, use status code

	// Also try to parse as pushResponse (for 412 responses)
	var pushResp pushResponse
	if json.Unmarshal(body, &pushResp) == nil && pushResp.Message != "" {
		errResp.Error = pushResp.Message
		errResp.Message = pushResp.Message
	}

	errMsg := errResp.Error
	if errMsg == "" {
		errMsg = errResp.Message
	}

	switch statusCode {
	case http.StatusBadRequest:
		return nil, clierror.InternalError(fmt.Errorf("invalid request: %s", errMsg))

	case http.StatusUnauthorized, http.StatusForbidden:
		if strings.Contains(errMsg, "device") || strings.Contains(errMsg, "DPU") {
			return nil, clierror.NotAuthorized(fmt.Sprintf("device '%s'", targetDPU))
		}
		return nil, clierror.NotAuthorized(fmt.Sprintf("CA '%s'", caName))

	case http.StatusNotFound:
		if strings.Contains(errMsg, "CA") || strings.Contains(errMsg, "ca") {
			return nil, clierror.CANotFound(caName)
		}
		if strings.Contains(errMsg, "DPU") || strings.Contains(errMsg, "dpu") || strings.Contains(errMsg, "device") {
			return nil, clierror.DeviceNotFound(targetDPU)
		}
		if strings.Contains(errMsg, "operator") {
			return nil, clierror.OperatorNotFound(errMsg)
		}
		// Default to device not found for 404
		return nil, clierror.DeviceNotFound(targetDPU)

	case http.StatusPreconditionFailed:
		// Parse the pushResponse for attestation details
		if pushResp.Message != "" {
			if strings.Contains(pushResp.Message, "failed") {
				return &pushResp, clierror.AttestationFailed("device failed integrity verification")
			}
			// Stale attestation
			age := pushResp.AttestationAge
			if age == "" {
				age = "unknown"
			}
			return &pushResp, clierror.AttestationStale(age)
		}
		return nil, clierror.AttestationUnavailable()

	case http.StatusServiceUnavailable:
		return nil, clierror.ConnectionFailed(targetDPU)

	default:
		return nil, clierror.InternalError(fmt.Errorf("server error (HTTP %d): %s", statusCode, errMsg))
	}
}

