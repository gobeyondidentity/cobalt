// Package attestation provides DICE/SPDM attestation retrieval and validation
// via the BlueField BMC Redfish API.
package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/netutil"
)

// RedfishClient provides access to BMC Redfish API for attestation
type RedfishClient struct {
	baseURL  string
	username string
	password string
	client   *http.Client
}

// NewRedfishClient creates a new Redfish client with SSRF protection.
// bmcAddr should be the BMC IP address or hostname (e.g., "192.168.1.203").
// Returns an error if the address resolves to loopback or link-local ranges.
// Private IP ranges (10/8, 172.16/12, 192.168/16) are allowed since BMCs
// are typically on private networks.
func NewRedfishClient(bmcAddr, username, password string) (*RedfishClient, error) {
	// Validate endpoint for SSRF protection (allows private ranges for BMC)
	if err := netutil.ValidateEndpoint(bmcAddr); err != nil {
		return nil, fmt.Errorf("redfish: invalid BMC address: %w", err)
	}

	return &RedfishClient{
		baseURL:  fmt.Sprintf("https://%s", bmcAddr),
		username: username,
		password: password,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // BMC uses self-signed cert
			},
		},
	}, nil
}

// redfishCertChainResponse represents the Redfish Certificate Chain response
type redfishCertChainResponse struct {
	ODataID              string   `json:"@odata.id"`
	ODataType            string   `json:"@odata.type"`
	CertificateString    string   `json:"CertificateString"`
	CertificateType      string   `json:"CertificateType"`
	CertificateUsageTypes []string `json:"CertificateUsageTypes"`
	ID                   string   `json:"Id"`
	Name                 string   `json:"Name"`
	SPDM                 struct {
		SlotID int `json:"SlotId"`
	} `json:"SPDM"`
}

// redfishComponentIntegrityResponse represents the ComponentIntegrity response
type redfishComponentIntegrityResponse struct {
	ODataID                     string `json:"@odata.id"`
	ComponentIntegrityEnabled   bool   `json:"ComponentIntegrityEnabled"`
	ComponentIntegrityType      string `json:"ComponentIntegrityType"`
	ComponentIntegrityTypeVersion string `json:"ComponentIntegrityTypeVersion"`
	ID                          string `json:"Id"`
	Name                        string `json:"Name"`
	SPDM                        struct {
		IdentityAuthentication struct {
			ResponderAuthentication struct {
				ComponentCertificate struct {
					ODataID string `json:"@odata.id"`
				} `json:"ComponentCertificate"`
			} `json:"ResponderAuthentication"`
		} `json:"IdentityAuthentication"`
	} `json:"SPDM"`
}

// Certificate represents a certificate in the DICE chain
type Certificate struct {
	Level       int    `json:"level"`       // Position in chain (0 = leaf, higher = toward root)
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   string `json:"notBefore"`
	NotAfter    string `json:"notAfter"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"` // SHA256 fingerprint
	PEM         string `json:"pem"`         // PEM encoded certificate
}

// BMC Firmware Version Requirements for SPDM Attestation
//
// SPDM attestation requires BMC firmware v25.04 or later.
//
// Version History:
//   - BF-24.10-17: No SPDM support. ComponentIntegrity endpoints return "Internal Error"
//                  or "No route to host" because SPDM daemon is not present.
//   - BF-25.04-xx: SPDM attestation documentation first appears in NVIDIA docs.
//   - BF-25.10-15: Confirmed working. "Added BMC Redfish support for remote attestation
//                  over Redfish specifically for BlueField-3 cards."
//
// Minimum Required: BF-25.04 (recommended: BF-25.10+)
const (
	// MinSPDMFirmwareMajor is the minimum major version required for SPDM support
	MinSPDMFirmwareMajor = 25
	// MinSPDMFirmwareMinor is the minimum minor version required for SPDM support
	MinSPDMFirmwareMinor = 4
)

// ErrSPDMNotSupported indicates the BMC firmware does not support SPDM attestation
var ErrSPDMNotSupported = fmt.Errorf("SPDM attestation requires BMC firmware v25.04+")

// AttestationTarget identifies an attestation target on the DPU
type AttestationTarget string

const (
	// TargetIRoT is the Internal Root of Trust (PSC - Platform Security Controller)
	TargetIRoT AttestationTarget = "Bluefield_DPU_IRoT"
	// TargetERoT is the External Root of Trust (BMC)
	TargetERoT AttestationTarget = "Bluefield_ERoT"
)

// NormalizeTarget converts user-friendly target names to Redfish resource names.
// Accepts: "IRoT", "irot", "Bluefield_DPU_IRoT" -> TargetIRoT
// Accepts: "ERoT", "erot", "Bluefield_ERoT" -> TargetERoT
func NormalizeTarget(target string) AttestationTarget {
	lower := strings.ToLower(target)
	switch {
	case lower == "irot" || lower == "bluefield_dpu_irot":
		return TargetIRoT
	case lower == "erot" || lower == "bluefield_erot":
		return TargetERoT
	default:
		// Return as-is if not recognized (will likely fail at API level)
		return AttestationTarget(target)
	}
}

// AttestationResult contains the full attestation data
type AttestationResult struct {
	Target           AttestationTarget     `json:"target"`
	SPDMVersion      string                `json:"spdmVersion"`
	CertificateChain []Certificate         `json:"certificateChain"`
	Measurements     map[string]string     `json:"measurements,omitempty"`
	Nonce            string                `json:"nonce,omitempty"`
	Signature        string                `json:"signature,omitempty"`
}

// GetBMCFirmwareVersion retrieves the BMC firmware version
func (c *RedfishClient) GetBMCFirmwareVersion(ctx context.Context) (string, error) {
	url := c.baseURL + "/redfish/v1/UpdateService/FirmwareInventory/BMC_Firmware"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get firmware version: status %d", resp.StatusCode)
	}

	var result struct {
		Version string `json:"Version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Version, nil
}

// CheckSPDMSupport verifies the BMC firmware supports SPDM attestation
func (c *RedfishClient) CheckSPDMSupport(ctx context.Context) error {
	version, err := c.GetBMCFirmwareVersion(ctx)
	if err != nil {
		return fmt.Errorf("cannot verify SPDM support: %w", err)
	}

	// Parse version like "BF-25.10-15" -> major=25, minor=10
	var major, minor int
	if _, err := fmt.Sscanf(version, "BF-%d.%d", &major, &minor); err != nil {
		return fmt.Errorf("cannot parse firmware version %q: %w", version, err)
	}

	if major < MinSPDMFirmwareMajor || (major == MinSPDMFirmwareMajor && minor < MinSPDMFirmwareMinor) {
		return fmt.Errorf("%w (current: %s)", ErrSPDMNotSupported, version)
	}

	return nil
}

// GetCertificateChain retrieves the certificate chain for an attestation target
func (c *RedfishClient) GetCertificateChain(ctx context.Context, target AttestationTarget) (*AttestationResult, error) {
	// First get component integrity info to find cert chain URL and SPDM version
	integrityURL := fmt.Sprintf("%s/redfish/v1/ComponentIntegrity/%s", c.baseURL, target)

	req, err := http.NewRequestWithContext(ctx, "GET", integrityURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Check for common errors indicating SPDM not supported
		if strings.Contains(string(body), "Internal Error") || strings.Contains(string(body), "No route to host") {
			return nil, fmt.Errorf("%w: %s", ErrSPDMNotSupported, string(body))
		}
		return nil, fmt.Errorf("ComponentIntegrity error %d: %s", resp.StatusCode, string(body))
	}

	var integrity redfishComponentIntegrityResponse
	if err := json.NewDecoder(resp.Body).Decode(&integrity); err != nil {
		return nil, fmt.Errorf("failed to parse ComponentIntegrity: %w", err)
	}

	if !integrity.ComponentIntegrityEnabled {
		return nil, fmt.Errorf("ComponentIntegrity is disabled for %s", target)
	}

	// Get the certificate chain
	certURL := c.baseURL + integrity.SPDM.IdentityAuthentication.ResponderAuthentication.ComponentCertificate.ODataID
	req, err = http.NewRequestWithContext(ctx, "GET", certURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err = c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("CertificateChain error %d: %s", resp.StatusCode, string(body))
	}

	var certChain redfishCertChainResponse
	if err := json.NewDecoder(resp.Body).Decode(&certChain); err != nil {
		return nil, fmt.Errorf("failed to parse CertificateChain: %w", err)
	}

	// Parse the PEM chain into individual certificates
	certs, err := parsePEMChain(certChain.CertificateString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PEM chain: %w", err)
	}

	return &AttestationResult{
		Target:           target,
		SPDMVersion:      integrity.ComponentIntegrityTypeVersion,
		CertificateChain: certs,
	}, nil
}

// parsePEMChain parses a PEM chain string into individual Certificate structs
func parsePEMChain(pemChain string) ([]Certificate, error) {
	var certs []Certificate
	data := []byte(pemChain)
	level := 0

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			data = rest
			continue
		}

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate at level %d: %w", level, err)
		}

		// Calculate SHA256 fingerprint
		fingerprint := sha256.Sum256(block.Bytes)

		cert := Certificate{
			Level:       level,
			Subject:     x509Cert.Subject.String(),
			Issuer:      x509Cert.Issuer.String(),
			NotBefore:   x509Cert.NotBefore.Format("2006-01-02T15:04:05Z"),
			NotAfter:    x509Cert.NotAfter.Format("2006-01-02T15:04:05Z"),
			Algorithm:   x509Cert.SignatureAlgorithm.String(),
			Fingerprint: hex.EncodeToString(fingerprint[:]),
			PEM:         string(pem.EncodeToMemory(block)),
		}
		certs = append(certs, cert)
		level++
		data = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM chain")
	}

	return certs, nil
}

// GetSPDMIdentity retrieves the SPDM identity certificate chain from the IRoT
// Deprecated: Use GetCertificateChain(ctx, TargetIRoT) instead
func (c *RedfishClient) GetSPDMIdentity(ctx context.Context) (*AttestationResult, error) {
	return c.GetCertificateChain(ctx, TargetIRoT)
}

// FirmwareInfo represents a firmware component from the BMC
type FirmwareInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	BuildDate string `json:"buildDate,omitempty"`
}

// redfishFirmwareInventory represents the Redfish FirmwareInventory collection
type redfishFirmwareInventory struct {
	Members []struct {
		ODataID string `json:"@odata.id"`
	} `json:"Members"`
	MembersCount int `json:"Members@odata.count"`
}

// redfishFirmwareItem represents a single firmware inventory item
type redfishFirmwareItem struct {
	ID          string `json:"Id"`
	Name        string `json:"Name"`
	Version     string `json:"Version"`
	ReleaseDate string `json:"ReleaseDate,omitempty"`
	Updateable  bool   `json:"Updateable"`
}

// GetFirmwareInventory retrieves all firmware versions from the BMC
func (c *RedfishClient) GetFirmwareInventory(ctx context.Context) ([]FirmwareInfo, error) {
	// Get firmware inventory collection
	url := c.baseURL + "/redfish/v1/UpdateService/FirmwareInventory"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get firmware inventory: status %d", resp.StatusCode)
	}

	var inventory redfishFirmwareInventory
	if err := json.NewDecoder(resp.Body).Decode(&inventory); err != nil {
		return nil, err
	}

	var firmwares []FirmwareInfo
	for _, member := range inventory.Members {
		fw, err := c.getFirmwareItem(ctx, member.ODataID)
		if err != nil {
			// Log but continue with other items
			continue
		}
		firmwares = append(firmwares, *fw)
	}

	return firmwares, nil
}

// getFirmwareItem retrieves a single firmware inventory item
func (c *RedfishClient) getFirmwareItem(ctx context.Context, path string) (*FirmwareInfo, error) {
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get firmware item: status %d", resp.StatusCode)
	}

	var item redfishFirmwareItem
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return nil, err
	}

	// Derive a clean name from the ID or Name field
	name := item.ID
	if item.Name != "" && item.Name != item.ID {
		name = item.Name
	}
	// Normalize common names
	name = normalizeFirmwareName(name)

	return &FirmwareInfo{
		Name:      name,
		Version:   item.Version,
		BuildDate: item.ReleaseDate,
	}, nil
}

// normalizeFirmwareName cleans up firmware names for display
func normalizeFirmwareName(name string) string {
	// Map common Redfish firmware IDs to cleaner names
	switch {
	case strings.Contains(strings.ToLower(name), "bmc"):
		return "bmc"
	case strings.Contains(strings.ToLower(name), "uefi"):
		return "uefi"
	case strings.Contains(strings.ToLower(name), "cpld"):
		return "cpld"
	case strings.Contains(strings.ToLower(name), "bios"):
		return "bios"
	case strings.Contains(strings.ToLower(name), "psc"):
		return "psc"
	case strings.Contains(strings.ToLower(name), "arm"):
		return "arm"
	default:
		return strings.ToLower(name)
	}
}

// SignedMeasurementsRequest represents the request for signed measurements
type SignedMeasurementsRequest struct {
	SlotID             int   `json:"SlotId"`
	Nonce              string `json:"Nonce"`
	MeasurementIndices []int  `json:"MeasurementIndices,omitempty"`
}

// SignedMeasurementsResponse represents the Redfish response for signed measurements
type SignedMeasurementsResponse struct {
	HashingAlgorithm   string `json:"HashingAlgorithm"`
	SignedMeasurements string `json:"SignedMeasurements"` // Base64-encoded
	SigningAlgorithm   string `json:"SigningAlgorithm"`
	Version            string `json:"Version"`
}

// GetSignedMeasurements requests signed SPDM measurements from the DPU
// The nonce should be a 64-character hex string for freshness
// If indices is nil, all measurements are returned
func (c *RedfishClient) GetSignedMeasurements(ctx context.Context, target AttestationTarget, nonce string, indices []int) (*SignedMeasurementsResponse, error) {
	actionURL := fmt.Sprintf("%s/redfish/v1/ComponentIntegrity/%s/Actions/ComponentIntegrity.SPDMGetSignedMeasurements",
		c.baseURL, target)

	request := SignedMeasurementsRequest{
		SlotID: 0,
		Nonce:  nonce,
	}
	if len(indices) > 0 {
		request.MeasurementIndices = indices
	}

	payloadBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", actionURL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for task-based response (202 Accepted)
	if resp.StatusCode == http.StatusAccepted {
		// Task was created, need to poll
		location := resp.Header.Get("Location")
		if location != "" {
			return c.pollMeasurementsTask(ctx, location)
		}
		return nil, fmt.Errorf("task created but no Location header provided")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("measurement request failed %d: %s", resp.StatusCode, string(body))
	}

	var result SignedMeasurementsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse measurements response: %w", err)
	}

	return &result, nil
}

// pollMeasurementsTask polls a Redfish task until completion
func (c *RedfishClient) pollMeasurementsTask(ctx context.Context, taskURL string) (*SignedMeasurementsResponse, error) {
	// The Location header points to the Monitor endpoint, but we need to poll the Task endpoint
	// Example: /redfish/v1/TaskService/Tasks/4/Monitor -> /redfish/v1/TaskService/Tasks/4
	taskURL = strings.TrimSuffix(taskURL, "/Monitor")

	// Ensure URL is absolute
	if !strings.HasPrefix(taskURL, "http") {
		taskURL = c.baseURL + taskURL
	}

	// Poll for up to 30 seconds
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", taskURL, nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(c.username, c.password)

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		// Check task status
		var task struct {
			TaskState  string `json:"TaskState"`
			TaskStatus string `json:"TaskStatus"`
			Messages   []struct {
				Message string `json:"Message"`
			} `json:"Messages"`
			Payload struct {
				HttpHeaders []string        `json:"HttpHeaders"`
				JsonBody    json.RawMessage `json:"JsonBody"`
			} `json:"Payload,omitempty"`
		}

		if err := json.Unmarshal(body, &task); err != nil {
			return nil, fmt.Errorf("failed to parse task response: %w", err)
		}

		switch task.TaskState {
		case "Completed":
			// Look for Location header in Payload.HttpHeaders
			var dataURL string
			for _, header := range task.Payload.HttpHeaders {
				if strings.HasPrefix(header, "Location:") {
					dataURL = strings.TrimSpace(strings.TrimPrefix(header, "Location:"))
					break
				}
			}

			// If we found a Location URL, fetch the data from there
			if dataURL != "" {
				return c.fetchMeasurementsData(ctx, dataURL)
			}

			// Fallback: try to extract measurements from the task payload
			if task.Payload.JsonBody != nil && len(task.Payload.JsonBody) > 2 {
				var result SignedMeasurementsResponse
				if err := json.Unmarshal(task.Payload.JsonBody, &result); err != nil {
					return nil, fmt.Errorf("failed to parse measurements from task: %w", err)
				}
				return &result, nil
			}
			return nil, fmt.Errorf("task completed but no data location or payload found")

		case "Exception", "Killed", "Cancelled":
			msg := "unknown error"
			if len(task.Messages) > 0 {
				msg = task.Messages[0].Message
			}
			return nil, fmt.Errorf("task failed: %s", msg)

		default:
			// Still running, wait and retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}

	return nil, fmt.Errorf("task polling timed out after %d attempts", maxAttempts)
}

// fetchMeasurementsData retrieves measurements from the data URL
func (c *RedfishClient) fetchMeasurementsData(ctx context.Context, dataURL string) (*SignedMeasurementsResponse, error) {
	if !strings.HasPrefix(dataURL, "http") {
		dataURL = c.baseURL + dataURL
	}

	req, err := http.NewRequestWithContext(ctx, "GET", dataURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch measurements data: %d %s", resp.StatusCode, string(body))
	}

	var result SignedMeasurementsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse measurements data: %w", err)
	}

	return &result, nil
}

// GetAttestation requests a signed attestation with measurements
func (c *RedfishClient) GetAttestation(ctx context.Context, target AttestationTarget, nonce string) (*AttestationResult, error) {
	// First get the certificate chain
	result, err := c.GetCertificateChain(ctx, target)
	if err != nil {
		return nil, err
	}

	// Request signed measurements
	measResp, err := c.GetSignedMeasurements(ctx, target, nonce, nil)
	if err != nil {
		// Measurements may fail on older firmware, still return certs
		result.Nonce = nonce
		return result, nil
	}

	result.Nonce = nonce

	// Parse the measurements and add to result
	if measResp.SignedMeasurements != "" {
		measurements, err := ParseSPDMMeasurements(measResp.SignedMeasurements, measResp.HashingAlgorithm)
		if err == nil {
			result.Measurements = make(map[string]string)
			for _, m := range measurements {
				key := fmt.Sprintf("%d", m.Index)
				result.Measurements[key] = m.Digest
			}
		}
	}

	return result, nil
}
