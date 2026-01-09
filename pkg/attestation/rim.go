// Package attestation provides DICE/SPDM attestation retrieval and validation
// via the BlueField BMC Redfish API and NVIDIA RIM service.
//
// NOTE: As of January 2026, BlueField-3 CoRIM files are not available in NVIDIA's RIM service.
// We have an open inquiry with NVIDIA about availability:
// https://forums.developer.nvidia.com/t/bluefield-3-corim-availability-in-nvidia-rim-service/356231
package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	// NVIDIARIMServiceURL is the base URL for NVIDIA's Reference Integrity Manifest service
	NVIDIARIMServiceURL = "https://rim.attestation.nvidia.com/v1/rim"
)

// RIMClient provides access to NVIDIA's RIM (Reference Integrity Manifest) service
type RIMClient struct {
	baseURL string
	client  *http.Client
}

// NewRIMClient creates a new NVIDIA RIM service client
func NewRIMClient() *RIMClient {
	return &RIMClient{
		baseURL: NVIDIARIMServiceURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// RIMEntry represents a single RIM entry from the NVIDIA service
type RIMEntry struct {
	ID          string `json:"id"`
	RIM         string `json:"rim"`          // Base64-encoded CoRIM file
	SHA256      string `json:"sha256"`       // Integrity verification hash
	LastUpdated string `json:"last_updated"` // Timestamp of latest modification
}

// RIMListResponse represents the response from listing RIM IDs
type RIMListResponse struct {
	IDs []string `json:"ids"`
}

// CoRIMManifest represents a parsed CoRIM (Concise Reference Integrity Manifest)
type CoRIMManifest struct {
	ID               string                  `json:"id"`
	Profile          string                  `json:"profile,omitempty"`
	Validity         *CoRIMValidity          `json:"validity,omitempty"`
	Entities         []CoRIMEntity           `json:"entities,omitempty"`
	ReferenceValues  []CoRIMMeasurement      `json:"referenceValues"`
	RawCBOR          []byte                  `json:"-"`
}

// CoRIMValidity represents the validity period of a CoRIM
type CoRIMValidity struct {
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
}

// CoRIMEntity represents an entity in the CoRIM (signer, manufacturer, etc.)
type CoRIMEntity struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles,omitempty"`
}

// CoRIMMeasurement represents a reference measurement from a CoRIM
type CoRIMMeasurement struct {
	Index       int    `json:"index"`
	Description string `json:"description"`
	Algorithm   string `json:"algorithm"`
	Digest      string `json:"digest"` // Hex-encoded hash
}

// BlueField3MeasurementDescriptions maps measurement indices to their purpose
var BlueField3MeasurementDescriptions = map[int]string{
	1:  "FW config version (Semver)",
	2:  "PSC firmware hash",
	3:  "NIC firmware hash",
	4:  "ARM firmware hash",
	5:  "NIC rollback counters",
	6:  "ARM rollback counters",
	7:  "NIC security config",
	8:  "ARM security config",
	9:  "PSC FMC security config",
	10: "PSC runtime FW security config",
	11: "Device identifier (DID, VID, SVID, SID)",
}

// ListRIMIDs retrieves all available RIM identifiers from NVIDIA
func (c *RIMClient) ListRIMIDs(ctx context.Context) ([]string, error) {
	url := c.baseURL + "/ids"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch RIM IDs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("RIM service error %d: %s", resp.StatusCode, string(body))
	}

	var result RIMListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse RIM list: %w", err)
	}

	return result.IDs, nil
}

// GetRIM retrieves a specific RIM by ID
func (c *RIMClient) GetRIM(ctx context.Context, id string) (*RIMEntry, error) {
	url := c.baseURL + "/" + id

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch RIM: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("RIM service error %d: %s", resp.StatusCode, string(body))
	}

	var entry RIMEntry
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
		return nil, fmt.Errorf("failed to parse RIM entry: %w", err)
	}

	return &entry, nil
}

// FindRIMForFirmware searches for a RIM matching the given firmware version
// Firmware version format: "32.47.1088" (NIC firmware version)
func (c *RIMClient) FindRIMForFirmware(ctx context.Context, fwVersion string) (*RIMEntry, error) {
	ids, err := c.ListRIMIDs(ctx)
	if err != nil {
		return nil, err
	}

	// Look for a matching RIM ID
	// Format: NV_NIC_FIRMWARE_BF3_<version>_<sku>
	normalizedVersion := strings.ReplaceAll(fwVersion, ".", "_")
	for _, id := range ids {
		if strings.Contains(id, "BF3") && strings.Contains(id, normalizedVersion) {
			return c.GetRIM(ctx, id)
		}
	}

	// Try exact version match
	for _, id := range ids {
		if strings.Contains(id, fwVersion) {
			return c.GetRIM(ctx, id)
		}
	}

	return nil, fmt.Errorf("no RIM found for firmware version %s", fwVersion)
}

// ParseCoRIM parses a base64-encoded CoRIM from the NVIDIA RIM service
func ParseCoRIM(base64Data string) (*CoRIMManifest, error) {
	// Decode base64
	rawData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	return ParseCoRIMBytes(rawData)
}

// ParseCoRIMBytes parses raw CoRIM CBOR bytes
// NVIDIA CoRIM files have a 6-byte IANA tag prefix that must be stripped
func ParseCoRIMBytes(data []byte) (*CoRIMManifest, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("CoRIM data too short: %d bytes", len(data))
	}

	// Strip the 6-byte IANA tag prefix used by NVIDIA
	// The tag identifies this as a CoRIM (tag 500-502)
	strippedData := data[6:]

	// Parse CBOR structure
	var rawCoRIM map[interface{}]interface{}
	if err := cbor.Unmarshal(strippedData, &rawCoRIM); err != nil {
		return nil, fmt.Errorf("failed to parse CBOR: %w", err)
	}

	manifest := &CoRIMManifest{
		RawCBOR: data,
	}

	// Extract fields from the CBOR map
	// CoRIM uses integer keys per the CDDL specification
	for key, value := range rawCoRIM {
		switch k := key.(type) {
		case uint64:
			switch k {
			case 0: // corim-id
				if id, ok := value.(string); ok {
					manifest.ID = id
				}
			case 1: // corim-tags (contains CoMID array)
				if err := parseCoRIMTags(manifest, value); err != nil {
					return nil, fmt.Errorf("failed to parse CoRIM tags: %w", err)
				}
			}
		case string:
			switch k {
			case "id":
				if id, ok := value.(string); ok {
					manifest.ID = id
				}
			case "profile":
				if profile, ok := value.(string); ok {
					manifest.Profile = profile
				}
			}
		}
	}

	return manifest, nil
}

// parseCoRIMTags extracts measurements from CoRIM tag array
func parseCoRIMTags(manifest *CoRIMManifest, tags interface{}) error {
	tagArray, ok := tags.([]interface{})
	if !ok {
		return fmt.Errorf("expected tag array, got %T", tags)
	}

	for _, tag := range tagArray {
		// Each tag is a CBOR-encoded CoMID
		tagBytes, ok := tag.([]byte)
		if !ok {
			continue
		}

		var comid map[interface{}]interface{}
		if err := cbor.Unmarshal(tagBytes, &comid); err != nil {
			continue
		}

		// Extract reference values from CoMID
		if err := parseCoMIDMeasurements(manifest, comid); err != nil {
			continue
		}
	}

	return nil
}

// parseCoMIDMeasurements extracts measurements from a CoMID structure
func parseCoMIDMeasurements(manifest *CoRIMManifest, comid map[interface{}]interface{}) error {
	// CoMID uses integer keys
	// Key 2 = triples, which contains reference values
	for key, value := range comid {
		k, ok := key.(uint64)
		if !ok {
			continue
		}

		if k == 2 { // triples
			triplesMap, ok := value.(map[interface{}]interface{})
			if !ok {
				continue
			}

			// Key 0 = reference-values
			for tripKey, tripValue := range triplesMap {
				if tk, ok := tripKey.(uint64); ok && tk == 0 {
					parseReferenceValues(manifest, tripValue)
				}
			}
		}
	}

	return nil
}

// parseReferenceValues extracts reference values from triples
func parseReferenceValues(manifest *CoRIMManifest, refValues interface{}) {
	refArray, ok := refValues.([]interface{})
	if !ok {
		return
	}

	for _, ref := range refArray {
		refMap, ok := ref.(map[interface{}]interface{})
		if !ok {
			continue
		}

		// Extract measurement from reference value
		for key, value := range refMap {
			if k, ok := key.(uint64); ok && k == 1 { // measurement-values
				parseMeasurementValues(manifest, value)
			}
		}
	}
}

// parseMeasurementValues extracts individual measurements
func parseMeasurementValues(manifest *CoRIMManifest, measValues interface{}) {
	measArray, ok := measValues.([]interface{})
	if !ok {
		return
	}

	for _, meas := range measArray {
		measMap, ok := meas.(map[interface{}]interface{})
		if !ok {
			continue
		}

		var measurement CoRIMMeasurement

		for key, value := range measMap {
			k, ok := key.(uint64)
			if !ok {
				continue
			}

			switch k {
			case 0: // measurement index
				if idx, ok := value.(uint64); ok {
					measurement.Index = int(idx)
					if desc, exists := BlueField3MeasurementDescriptions[measurement.Index]; exists {
						measurement.Description = desc
					}
				}
			case 2: // digest array [algorithm-id, hash-bytes]
				if digestArray, ok := value.([]interface{}); ok && len(digestArray) >= 2 {
					if algID, ok := digestArray[0].(uint64); ok {
						measurement.Algorithm = digestAlgorithmName(algID)
					}
					if hashBytes, ok := digestArray[1].([]byte); ok {
						measurement.Digest = hex.EncodeToString(hashBytes)
					}
				}
			}
		}

		if measurement.Index > 0 && measurement.Digest != "" {
			manifest.ReferenceValues = append(manifest.ReferenceValues, measurement)
		}
	}
}

// digestAlgorithmName maps COSE algorithm IDs to names
func digestAlgorithmName(algID uint64) string {
	switch algID {
	case 1:
		return "SHA-256"
	case 2:
		return "SHA-384"
	case 3:
		return "SHA-512"
	case 7:
		return "SHA3-256"
	case 8:
		return "SHA3-384"
	case 9:
		return "SHA3-512"
	default:
		return fmt.Sprintf("ALG-%d", algID)
	}
}

// VerifyRIMIntegrity verifies the SHA256 hash of a RIM entry
func VerifyRIMIntegrity(entry *RIMEntry) (bool, error) {
	if entry == nil {
		return false, fmt.Errorf("nil RIM entry")
	}
	if entry.RIM == "" {
		return false, fmt.Errorf("empty RIM data")
	}
	rawData, err := base64.StdEncoding.DecodeString(entry.RIM)
	if err != nil {
		return false, fmt.Errorf("failed to decode RIM: %w", err)
	}

	computed := sha256.Sum256(rawData)
	computedHex := hex.EncodeToString(computed[:])

	return strings.EqualFold(computedHex, entry.SHA256), nil
}
