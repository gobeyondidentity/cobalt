package attestation

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestParseCoRIM_InvalidBase64(t *testing.T) {
	t.Log("Testing ParseCoRIM with invalid base64 input")

	_, err := ParseCoRIM("!!!not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}

	t.Logf("Got expected error: %v", err)
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("error should mention base64 decoding failure: %v", err)
	}
}

func TestParseCoRIMBytes_DataTooShort(t *testing.T) {
	t.Log("Testing ParseCoRIMBytes with data too short (< 6 bytes)")

	shortData := []byte{0x01, 0x02, 0x03, 0x04, 0x05} // 5 bytes

	_, err := ParseCoRIMBytes(shortData)
	if err == nil {
		t.Fatal("expected error for data too short")
	}

	t.Logf("Got expected error: %v", err)
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error should mention data too short: %v", err)
	}
}

func TestParseCoRIMBytes_InvalidCBOR(t *testing.T) {
	t.Log("Testing ParseCoRIMBytes with invalid CBOR after prefix")

	// 6-byte prefix followed by invalid CBOR
	invalidData := make([]byte, 10)
	copy(invalidData[0:6], []byte{0xd9, 0x01, 0xf4, 0x00, 0x00, 0x00}) // Tag prefix
	copy(invalidData[6:], []byte{0xff, 0xff, 0xff, 0xff})             // Invalid CBOR

	_, err := ParseCoRIMBytes(invalidData)
	if err == nil {
		t.Fatal("expected error for invalid CBOR")
	}

	t.Logf("Got expected error: %v", err)
	if !strings.Contains(err.Error(), "CBOR") {
		t.Errorf("error should mention CBOR parsing failure: %v", err)
	}
}

func TestParseCoRIMBytes_ValidEmptyCoRIM(t *testing.T) {
	t.Log("Testing ParseCoRIMBytes with valid but empty CoRIM structure")

	// Create a valid CBOR map with no content
	emptyMap := map[interface{}]interface{}{}
	cborData, err := cbor.Marshal(emptyMap)
	if err != nil {
		t.Fatalf("failed to create test CBOR: %v", err)
	}

	// Prepend 6-byte IANA tag prefix
	data := make([]byte, 6+len(cborData))
	copy(data[0:6], []byte{0xd9, 0x01, 0xf4, 0x00, 0x00, 0x00})
	copy(data[6:], cborData)

	t.Log("Parsing empty CoRIM structure")
	manifest, err := ParseCoRIMBytes(data)
	if err != nil {
		t.Fatalf("ParseCoRIMBytes failed: %v", err)
	}

	t.Logf("Parsed manifest: ID=%q, ReferenceValues=%d", manifest.ID, len(manifest.ReferenceValues))

	if manifest.ID != "" {
		t.Errorf("expected empty ID for empty CoRIM, got %q", manifest.ID)
	}
	if len(manifest.ReferenceValues) != 0 {
		t.Errorf("expected no reference values, got %d", len(manifest.ReferenceValues))
	}
}

func TestParseCoRIMBytes_WithStringID(t *testing.T) {
	t.Log("Testing ParseCoRIMBytes extracts string ID")

	// Create CoRIM with string-keyed ID
	corimMap := map[interface{}]interface{}{
		"id":      "test-corim-id",
		"profile": "nvidia.corim.1",
	}
	cborData, err := cbor.Marshal(corimMap)
	if err != nil {
		t.Fatalf("failed to create test CBOR: %v", err)
	}

	data := make([]byte, 6+len(cborData))
	copy(data[0:6], []byte{0xd9, 0x01, 0xf4, 0x00, 0x00, 0x00})
	copy(data[6:], cborData)

	t.Log("Parsing CoRIM with string ID")
	manifest, err := ParseCoRIMBytes(data)
	if err != nil {
		t.Fatalf("ParseCoRIMBytes failed: %v", err)
	}

	t.Logf("Parsed manifest: ID=%q, Profile=%q", manifest.ID, manifest.Profile)

	if manifest.ID != "test-corim-id" {
		t.Errorf("expected ID 'test-corim-id', got %q", manifest.ID)
	}
	if manifest.Profile != "nvidia.corim.1" {
		t.Errorf("expected Profile 'nvidia.corim.1', got %q", manifest.Profile)
	}
}

func TestParseCoRIMBytes_WithIntegerKeyedID(t *testing.T) {
	t.Log("Testing ParseCoRIMBytes extracts integer-keyed ID (CDDL format)")

	// CoRIM uses integer keys per CDDL spec: key 0 = corim-id
	corimMap := map[interface{}]interface{}{
		uint64(0): "integer-key-id",
	}
	cborData, err := cbor.Marshal(corimMap)
	if err != nil {
		t.Fatalf("failed to create test CBOR: %v", err)
	}

	data := make([]byte, 6+len(cborData))
	copy(data[0:6], []byte{0xd9, 0x01, 0xf4, 0x00, 0x00, 0x00})
	copy(data[6:], cborData)

	t.Log("Parsing CoRIM with integer-keyed ID")
	manifest, err := ParseCoRIMBytes(data)
	if err != nil {
		t.Fatalf("ParseCoRIMBytes failed: %v", err)
	}

	t.Logf("Parsed manifest: ID=%q", manifest.ID)

	if manifest.ID != "integer-key-id" {
		t.Errorf("expected ID 'integer-key-id', got %q", manifest.ID)
	}
}

func TestParseCoRIM_ValidBase64(t *testing.T) {
	t.Log("Testing ParseCoRIM with valid base64-encoded CoRIM")

	// Create a simple CoRIM structure
	corimMap := map[interface{}]interface{}{
		"id": "base64-test-id",
	}
	cborData, err := cbor.Marshal(corimMap)
	if err != nil {
		t.Fatalf("failed to create test CBOR: %v", err)
	}

	data := make([]byte, 6+len(cborData))
	copy(data[0:6], []byte{0xd9, 0x01, 0xf4, 0x00, 0x00, 0x00})
	copy(data[6:], cborData)

	base64Data := base64.StdEncoding.EncodeToString(data)
	t.Logf("Base64 encoded length: %d bytes", len(base64Data))

	manifest, err := ParseCoRIM(base64Data)
	if err != nil {
		t.Fatalf("ParseCoRIM failed: %v", err)
	}

	t.Logf("Parsed manifest: ID=%q", manifest.ID)

	if manifest.ID != "base64-test-id" {
		t.Errorf("expected ID 'base64-test-id', got %q", manifest.ID)
	}
	if manifest.RawCBOR == nil {
		t.Error("expected RawCBOR to be preserved")
	}
}

func TestParseCoRIMTags_EmptyTags(t *testing.T) {
	t.Log("Testing parseCoRIMTags with empty tag array")

	// Create CoRIM with key 1 = empty tags array
	corimMap := map[interface{}]interface{}{
		uint64(1): []interface{}{}, // Empty tags array
	}
	cborData, err := cbor.Marshal(corimMap)
	if err != nil {
		t.Fatalf("failed to create test CBOR: %v", err)
	}

	data := make([]byte, 6+len(cborData))
	copy(data[0:6], []byte{0xd9, 0x01, 0xf4, 0x00, 0x00, 0x00})
	copy(data[6:], cborData)

	t.Log("Parsing CoRIM with empty tags array")
	manifest, err := ParseCoRIMBytes(data)
	if err != nil {
		t.Fatalf("ParseCoRIMBytes failed: %v", err)
	}

	t.Logf("Reference values count: %d", len(manifest.ReferenceValues))

	if len(manifest.ReferenceValues) != 0 {
		t.Errorf("expected 0 reference values for empty tags, got %d", len(manifest.ReferenceValues))
	}
}

func TestParseCoRIMTags_InvalidTagType(t *testing.T) {
	t.Log("Testing parseCoRIMTags gracefully handles non-array tags")

	// Create CoRIM with key 1 = non-array (should not crash)
	corimMap := map[interface{}]interface{}{
		uint64(1): "not-an-array",
	}
	cborData, err := cbor.Marshal(corimMap)
	if err != nil {
		t.Fatalf("failed to create test CBOR: %v", err)
	}

	data := make([]byte, 6+len(cborData))
	copy(data[0:6], []byte{0xd9, 0x01, 0xf4, 0x00, 0x00, 0x00})
	copy(data[6:], cborData)

	t.Log("Parsing CoRIM with non-array tags (should not panic)")
	_, err = ParseCoRIMBytes(data)
	if err == nil {
		t.Log("ParseCoRIMBytes handled invalid tag type gracefully")
	} else {
		t.Logf("ParseCoRIMBytes returned error (acceptable): %v", err)
	}
}

func TestParseCoRIMBytes_PreservesRawCBOR(t *testing.T) {
	t.Log("Testing that ParseCoRIMBytes preserves original raw CBOR")

	corimMap := map[interface{}]interface{}{
		"id": "raw-test",
	}
	cborData, err := cbor.Marshal(corimMap)
	if err != nil {
		t.Fatalf("failed to create test CBOR: %v", err)
	}

	data := make([]byte, 6+len(cborData))
	copy(data[0:6], []byte{0xd9, 0x01, 0xf4, 0x00, 0x00, 0x00})
	copy(data[6:], cborData)

	manifest, err := ParseCoRIMBytes(data)
	if err != nil {
		t.Fatalf("ParseCoRIMBytes failed: %v", err)
	}

	if manifest.RawCBOR == nil {
		t.Fatal("expected RawCBOR to be preserved")
	}
	if len(manifest.RawCBOR) != len(data) {
		t.Errorf("expected RawCBOR length %d, got %d", len(data), len(manifest.RawCBOR))
	}

	t.Logf("RawCBOR preserved: %d bytes", len(manifest.RawCBOR))
}

func TestDigestAlgorithmName_AllKnownAlgorithms(t *testing.T) {
	t.Log("Testing digestAlgorithmName for all COSE algorithm IDs")

	tests := []struct {
		algID    uint64
		expected string
	}{
		{1, "SHA-256"},
		{2, "SHA-384"},
		{3, "SHA-512"},
		{7, "SHA3-256"},
		{8, "SHA3-384"},
		{9, "SHA3-512"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			result := digestAlgorithmName(tc.algID)
			if result != tc.expected {
				t.Errorf("digestAlgorithmName(%d) = %q, want %q", tc.algID, result, tc.expected)
			}
		})
	}
}

func TestDigestAlgorithmName_UnknownAlgorithms(t *testing.T) {
	t.Log("Testing digestAlgorithmName for unknown algorithm IDs")

	unknownIDs := []uint64{0, 4, 5, 6, 10, 100, 255, 1000}

	for _, id := range unknownIDs {
		result := digestAlgorithmName(id)
		expected := "ALG-"
		if !strings.HasPrefix(result, expected) {
			t.Errorf("digestAlgorithmName(%d) = %q, expected prefix %q", id, result, expected)
		}
		t.Logf("digestAlgorithmName(%d) = %q", id, result)
	}
}
