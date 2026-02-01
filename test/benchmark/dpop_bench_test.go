//go:build benchmark

package benchmark

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nmelo/secure-infra/pkg/dpop"
)

// BenchmarkValidateProof measures the performance of DPoP proof validation.
func BenchmarkValidateProof(b *testing.B) {
	// Setup: generate key pair and create a valid proof
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate key pair: %v", err)
	}
	kid := "bench-key-123"

	header := dpop.Header{
		Typ: dpop.TypeDPoP,
		Alg: dpop.AlgEdDSA,
		Kid: kid,
	}
	claims := dpop.Claims{
		JTI: "bench-jti-12345",
		HTM: "POST",
		HTU: "https://example.com/api/push",
		IAT: time.Now().Unix(),
	}
	proof := makeProof(header, claims, priv)

	keyLookup := func(k string) ed25519.PublicKey {
		if k == kid {
			return pub
		}
		return nil
	}

	v := dpop.NewValidator(dpop.DefaultValidatorConfig())

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = v.ValidateProof(proof, "POST", "https://example.com/api/push", keyLookup)
	}
}

// BenchmarkValidatorUnderAttack_MalformedProofs measures processing of malformed proofs.
func BenchmarkValidatorUnderAttack_MalformedProofs(b *testing.B) {
	v := dpop.NewValidator(dpop.DefaultValidatorConfig())
	keyLookup := func(k string) ed25519.PublicKey { return nil }

	malformedProofs := []string{
		"",                         // Empty
		"single",                   // One part
		"two.parts",                // Two parts
		"a.b.c.d",                  // Four parts
		strings.Repeat("a", 10000), // Large single string
		"!!!.@@@.###",              // Invalid base64
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof := malformedProofs[i%len(malformedProofs)]
		_, _ = v.ValidateProof(proof, "POST", "https://example.com/api", keyLookup)
	}
}

// BenchmarkJTICacheRecord measures O(1) lookup performance of JTI cache.
func BenchmarkJTICacheRecord(b *testing.B) {
	cache := dpop.NewMemoryJTICache(
		dpop.WithMaxEntries(b.N+1000),
		dpop.WithCleanupInterval(time.Hour),
	)
	defer cache.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Record(fmt.Sprintf("bench-jti-%d", i))
	}
}

// BenchmarkJTICacheRecordParallel measures parallel JTI cache recording.
func BenchmarkJTICacheRecordParallel(b *testing.B) {
	cache := dpop.NewMemoryJTICache(
		dpop.WithMaxEntries(b.N*10+1000),
		dpop.WithCleanupInterval(time.Hour),
	)
	defer cache.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.Record(fmt.Sprintf("bench-parallel-%d", i))
			i++
		}
	})
}

// makeProof creates a DPoP proof for benchmarking (helper function).
func makeProof(header dpop.Header, claims dpop.Claims, priv ed25519.PrivateKey) string {
	gen := dpop.NewEd25519Generator(priv)
	proof, _ := gen.Generate(claims.HTM, claims.HTU, header.Kid)
	return proof
}
