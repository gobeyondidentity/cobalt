package attestation

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// SPDMMeasurement represents a single SPDM measurement from the DPU
type SPDMMeasurement struct {
	Index       int    `json:"index"`
	Description string `json:"description"`
	Algorithm   string `json:"algorithm"`
	Digest      string `json:"digest"` // Hex-encoded hash
	RawValue    []byte `json:"-"`
}

// SPDMMeasurementResponse represents the response from GetSignedMeasurements
type SPDMMeasurementResponse struct {
	Version          string            `json:"version"`
	HashingAlgorithm string            `json:"hashingAlgorithm"`
	SigningAlgorithm string            `json:"signingAlgorithm"`
	Measurements     []SPDMMeasurement `json:"measurements"`
	Signature        []byte            `json:"-"`
	RawResponse      []byte            `json:"-"`
}

// MeasurementValidationResult represents the result of comparing live vs reference
type MeasurementValidationResult struct {
	Index            int    `json:"index"`
	Description      string `json:"description"`
	ReferenceDigest  string `json:"referenceDigest,omitempty"`
	LiveDigest       string `json:"liveDigest,omitempty"`
	Match            bool   `json:"match"`
	Status           string `json:"status"` // "match", "mismatch", "missing_reference", "missing_live"
}

// ValidationSummary represents the overall validation result
type ValidationSummary struct {
	Valid           bool                          `json:"valid"`
	TotalChecked    int                           `json:"totalChecked"`
	Matched         int                           `json:"matched"`
	Mismatched      int                           `json:"mismatched"`
	MissingRef      int                           `json:"missingReference"`
	MissingLive     int                           `json:"missingLive"`
	Results         []MeasurementValidationResult `json:"results"`
	FirmwareVersion string                        `json:"firmwareVersion,omitempty"`
	CoRIMID         string                        `json:"corimId,omitempty"`
}

// ParseSPDMMeasurements parses the base64-encoded SignedMeasurements response
// The format follows SPDM specification for GET_MEASUREMENTS response
func ParseSPDMMeasurements(b64Data string, algorithm string) ([]SPDMMeasurement, error) {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode measurements: %w", err)
	}

	return ParseSPDMMeasurementsRaw(data, algorithm)
}

// ParseSPDMMeasurementsRaw parses raw SPDM measurement bytes
// SPDM measurement block format (per DMTF DSP0274):
//
//	Byte 0: Number of blocks
//	Each block:
//	  Byte 0: Index (1-based)
//	  Byte 1: Measurement specification (0x01 = DMTF)
//	  Bytes 2-3: Measurement size (little-endian)
//	  Bytes 4-5: DMTFSpecMeasurementValueType
//	  Bytes 6-7: DMTFSpecMeasurementValueSize
//	  Remaining: Measurement value (hash)
func ParseSPDMMeasurementsRaw(data []byte, algorithm string) ([]SPDMMeasurement, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("measurement data too short")
	}

	var measurements []SPDMMeasurement
	offset := 0

	// First byte is number of measurement blocks (in some formats)
	// or we iterate until data is exhausted
	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}

		index := int(data[offset])
		if index == 0 {
			// End marker or padding
			break
		}

		// Skip measurement specification byte
		offset++
		if offset >= len(data) {
			break
		}
		offset++ // spec byte

		if offset+2 > len(data) {
			break
		}

		// Measurement size (little-endian 16-bit)
		measSize := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if measSize == 0 || offset+measSize > len(data) {
			break
		}

		// Extract the measurement value
		measValue := data[offset : offset+measSize]
		offset += measSize

		// The measurement value may have a header (DMTFSpecMeasurementValueType)
		// For digests, the actual hash starts after a 4-byte header
		var digest []byte
		if measSize > 4 {
			digest = measValue[4:]
		} else {
			digest = measValue
		}

		meas := SPDMMeasurement{
			Index:     index,
			Algorithm: algorithm,
			Digest:    hex.EncodeToString(digest),
			RawValue:  digest,
		}

		if desc, exists := BlueField3MeasurementDescriptions[index]; exists {
			meas.Description = desc
		} else {
			meas.Description = fmt.Sprintf("Measurement %d", index)
		}

		measurements = append(measurements, meas)
	}

	// If the simple parsing didn't work, try alternate format
	// where measurements are just concatenated hashes at known offsets
	if len(measurements) == 0 {
		return parseSimpleMeasurements(data, algorithm)
	}

	return measurements, nil
}

// parseSimpleMeasurements handles a simpler format where measurements
// are just concatenated at fixed positions
func parseSimpleMeasurements(data []byte, algorithm string) ([]SPDMMeasurement, error) {
	var measurements []SPDMMeasurement
	hashSize := getHashSize(algorithm)
	if hashSize == 0 {
		hashSize = 64 // Default to SHA-512 (64 bytes)
	}

	// Try to extract measurements at fixed offsets
	// This handles formats where the response is just raw measurement data
	offset := 0
	index := 1

	for offset+hashSize <= len(data) && index <= 11 {
		digest := data[offset : offset+hashSize]

		// Skip empty measurements (all zeros)
		allZero := true
		for _, b := range digest {
			if b != 0 {
				allZero = false
				break
			}
		}

		if !allZero {
			meas := SPDMMeasurement{
				Index:     index,
				Algorithm: algorithm,
				Digest:    hex.EncodeToString(digest),
				RawValue:  digest,
			}

			if desc, exists := BlueField3MeasurementDescriptions[index]; exists {
				meas.Description = desc
			}

			measurements = append(measurements, meas)
		}

		offset += hashSize
		index++
	}

	return measurements, nil
}

// getHashSize returns the hash size in bytes for an algorithm
func getHashSize(algorithm string) int {
	switch algorithm {
	case "SHA-256", "TPM_ALG_SHA_256", "TPM_ALG_SHA256":
		return 32
	case "SHA-384", "TPM_ALG_SHA_384", "TPM_ALG_SHA384":
		return 48
	case "SHA-512", "TPM_ALG_SHA_512", "TPM_ALG_SHA512":
		return 64
	default:
		return 0
	}
}

// ValidateMeasurements compares live measurements against reference values from CoRIM
func ValidateMeasurements(live []SPDMMeasurement, reference []CoRIMMeasurement) *ValidationSummary {
	summary := &ValidationSummary{
		Valid: true,
	}

	// Build lookup maps
	liveMap := make(map[int]SPDMMeasurement)
	for _, m := range live {
		liveMap[m.Index] = m
	}

	refMap := make(map[int]CoRIMMeasurement)
	for _, m := range reference {
		refMap[m.Index] = m
	}

	// Check all reference measurements against live
	for _, ref := range reference {
		result := MeasurementValidationResult{
			Index:           ref.Index,
			Description:     ref.Description,
			ReferenceDigest: ref.Digest,
		}

		if liveMeas, exists := liveMap[ref.Index]; exists {
			result.LiveDigest = liveMeas.Digest
			if normalizeDigest(ref.Digest) == normalizeDigest(liveMeas.Digest) {
				result.Match = true
				result.Status = "match"
				summary.Matched++
			} else {
				result.Match = false
				result.Status = "mismatch"
				summary.Mismatched++
				summary.Valid = false
			}
		} else {
			result.Status = "missing_live"
			summary.MissingLive++
			summary.Valid = false
		}

		summary.Results = append(summary.Results, result)
		summary.TotalChecked++
	}

	// Check for live measurements without reference
	for _, liveMeas := range live {
		if _, exists := refMap[liveMeas.Index]; !exists {
			result := MeasurementValidationResult{
				Index:       liveMeas.Index,
				Description: liveMeas.Description,
				LiveDigest:  liveMeas.Digest,
				Status:      "missing_reference",
			}
			summary.Results = append(summary.Results, result)
			summary.MissingRef++
			// Missing reference is a warning, not a failure
		}
	}

	return summary
}

// normalizeDigest normalizes a digest string for comparison
func normalizeDigest(digest string) string {
	return strings.ToLower(strings.TrimSpace(digest))
}
