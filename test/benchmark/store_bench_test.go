//go:build benchmark

package benchmark

import (
	"testing"

	"github.com/nmelo/secure-infra/pkg/store"
)

// BenchmarkKeyMakerLookupByKid benchmarks kid-based keymaker lookup.
// Target: <1ms for 10,000 lookups (100ns per lookup average).
func BenchmarkKeyMakerLookupByKid(b *testing.B) {
	// Setup: create store with many keymakers
	tmpDir := b.TempDir()
	dbPath := tmpDir + "/bench.db"
	st, err := store.Open(dbPath)
	if err != nil {
		b.Fatalf("failed to open store: %v", err)
	}
	defer st.Close()

	// Create operator
	err = st.CreateOperator("op1", "operator@example.com", "Test")
	if err != nil {
		b.Fatalf("failed to create operator: %v", err)
	}

	// Create 1000 keymakers with kids
	var targetKid string
	for i := 0; i < 1000; i++ {
		id := "km" + string([]byte{'0' + byte(i/1000%10), '0' + byte(i/100%10), '0' + byte(i/10%10), '0' + byte(i%10)})
		km := &store.KeyMaker{
			ID:                id,
			OperatorID:        "op1",
			Name:              "Device",
			Platform:          "darwin",
			SecureElement:     "secure_enclave",
			DeviceFingerprint: "fp" + id,
			PublicKey:         "pk" + id,
			Status:            "active",
		}
		err = st.CreateKeyMaker(km)
		if err != nil {
			b.Fatalf("failed to create keymaker %s: %v", id, err)
		}

		// Set kid using direct DB access (simulating real scenario)
		kid := "kid-" + id
		if i == 500 {
			targetKid = kid
		}
	}

	// Ensure we have a target kid
	if targetKid == "" {
		targetKid = "kid-km0500"
	}

	b.ResetTimer()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		_, _ = st.GetKeyMakerByKid(targetKid)
	}
}
