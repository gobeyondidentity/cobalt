package dpop

import (
	"encoding/json"
	"testing"
)

func TestHeaderJSONMarshal(t *testing.T) {
	t.Parallel()
	t.Log("Marshaling DPoP header with kid (post-enrollment)")
	h := Header{
		Typ: TypeDPoP,
		Alg: AlgEdDSA,
		Kid: "km_abc123",
	}

	data, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}

	t.Logf("Header JSON: %s", string(data))

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}

	if decoded["typ"] != "dpop+jwt" {
		t.Errorf("typ = %v, want dpop+jwt", decoded["typ"])
	}
	if decoded["alg"] != "EdDSA" {
		t.Errorf("alg = %v, want EdDSA", decoded["alg"])
	}
	if decoded["kid"] != "km_abc123" {
		t.Errorf("kid = %v, want km_abc123", decoded["kid"])
	}
	if _, ok := decoded["jwk"]; ok {
		t.Error("jwk should be omitted when nil")
	}
}

func TestHeaderWithJWK(t *testing.T) {
	t.Parallel()
	t.Log("Marshaling DPoP header with embedded JWK (enrollment)")
	jwk := &JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   "base64url-encoded-public-key",
	}
	h := Header{
		Typ: TypeDPoP,
		Alg: AlgEdDSA,
		JWK: jwk,
	}

	data, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}

	t.Logf("Header JSON: %s", string(data))

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}

	if _, ok := decoded["kid"]; ok {
		t.Error("kid should be omitted when empty")
	}

	jwkMap, ok := decoded["jwk"].(map[string]interface{})
	if !ok {
		t.Fatal("jwk should be present as object")
	}
	if jwkMap["kty"] != "OKP" {
		t.Errorf("jwk.kty = %v, want OKP", jwkMap["kty"])
	}
	if jwkMap["crv"] != "Ed25519" {
		t.Errorf("jwk.crv = %v, want Ed25519", jwkMap["crv"])
	}
}

func TestClaimsJSONMarshal(t *testing.T) {
	t.Parallel()
	t.Log("Marshaling DPoP claims payload")
	c := Claims{
		JTI: "550e8400-e29b-41d4-a716-446655440000",
		HTM: "POST",
		HTU: "https://nexus.example.com/api/v1/push",
		IAT: 1706540400,
	}

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	t.Logf("Claims JSON: %s", string(data))

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal claims: %v", err)
	}

	if decoded["jti"] != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("jti = %v, want UUID", decoded["jti"])
	}
	if decoded["htm"] != "POST" {
		t.Errorf("htm = %v, want POST", decoded["htm"])
	}
	if decoded["htu"] != "https://nexus.example.com/api/v1/push" {
		t.Errorf("htu = %v, want full URI", decoded["htu"])
	}
	// JSON numbers are float64
	if iat, ok := decoded["iat"].(float64); !ok || int64(iat) != 1706540400 {
		t.Errorf("iat = %v, want 1706540400", decoded["iat"])
	}
}

func TestClaimsRoundTrip(t *testing.T) {
	t.Parallel()
	t.Log("Testing claims round-trip serialization")
	original := Claims{
		JTI: "test-jti-12345",
		HTM: "GET",
		HTU: "https://example.com/resource",
		IAT: 1234567890,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Claims
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.JTI != original.JTI {
		t.Errorf("JTI = %q, want %q", decoded.JTI, original.JTI)
	}
	if decoded.HTM != original.HTM {
		t.Errorf("HTM = %q, want %q", decoded.HTM, original.HTM)
	}
	if decoded.HTU != original.HTU {
		t.Errorf("HTU = %q, want %q", decoded.HTU, original.HTU)
	}
	if decoded.IAT != original.IAT {
		t.Errorf("IAT = %d, want %d", decoded.IAT, original.IAT)
	}
}

func TestJWKRoundTrip(t *testing.T) {
	t.Parallel()
	t.Log("Testing JWK round-trip serialization")
	original := JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   "abcdefghijklmnopqrstuvwxyz123456789012345678901234",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	t.Logf("JWK JSON: %s", string(data))

	var decoded JWK
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Kty != original.Kty {
		t.Errorf("Kty = %q, want %q", decoded.Kty, original.Kty)
	}
	if decoded.Crv != original.Crv {
		t.Errorf("Crv = %q, want %q", decoded.Crv, original.Crv)
	}
	if decoded.X != original.X {
		t.Errorf("X = %q, want %q", decoded.X, original.X)
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()
	t.Log("Verifying DPoP type and algorithm constants")
	if TypeDPoP != "dpop+jwt" {
		t.Errorf("TypeDPoP = %q, want dpop+jwt", TypeDPoP)
	}
	if AlgEdDSA != "EdDSA" {
		t.Errorf("AlgEdDSA = %q, want EdDSA", AlgEdDSA)
	}
}
