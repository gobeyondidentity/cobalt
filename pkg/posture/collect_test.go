package posture

import (
	"testing"
)

func TestCollect(t *testing.T) {
	p := Collect()

	// On any platform, Collect should return a non-nil Posture
	if p == nil {
		t.Fatal("Collect() returned nil")
	}

	// Hash should be deterministic
	hash1 := p.Hash()
	hash2 := p.Hash()
	if hash1 != hash2 {
		t.Errorf("Hash() not deterministic: %s != %s", hash1, hash2)
	}

	// Hash should be 64 characters (SHA256 hex)
	if len(hash1) != 64 {
		t.Errorf("Hash() length = %d, want 64", len(hash1))
	}
}

func TestBoolStr(t *testing.T) {
	tests := []struct {
		name string
		val  *bool
		want string
	}{
		{"nil", nil, "nil"},
		{"true", boolPtr(true), "true"},
		{"false", boolPtr(false), "false"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := boolStr(tt.val)
			if got != tt.want {
				t.Errorf("boolStr(%v) = %s, want %s", tt.val, got, tt.want)
			}
		})
	}
}

func TestPostureHashDeterministic(t *testing.T) {
	// Create two postures with the same values
	p1 := &Posture{
		SecureBoot:     boolPtr(true),
		DiskEncryption: "luks",
		OSVersion:      "Ubuntu 22.04.3 LTS",
		KernelVersion:  "5.15.0-91-generic",
		TPMPresent:     boolPtr(true),
	}

	p2 := &Posture{
		SecureBoot:     boolPtr(true),
		DiskEncryption: "luks",
		OSVersion:      "Ubuntu 22.04.3 LTS",
		KernelVersion:  "5.15.0-91-generic",
		TPMPresent:     boolPtr(true),
	}

	if p1.Hash() != p2.Hash() {
		t.Errorf("Hash() not deterministic for equal postures: %s != %s", p1.Hash(), p2.Hash())
	}
}

func TestPostureHashDifferent(t *testing.T) {
	p1 := &Posture{
		SecureBoot:     boolPtr(true),
		DiskEncryption: "luks",
		OSVersion:      "Ubuntu 22.04.3 LTS",
		KernelVersion:  "5.15.0-91-generic",
		TPMPresent:     boolPtr(true),
	}

	p2 := &Posture{
		SecureBoot:     boolPtr(false), // Different
		DiskEncryption: "luks",
		OSVersion:      "Ubuntu 22.04.3 LTS",
		KernelVersion:  "5.15.0-91-generic",
		TPMPresent:     boolPtr(true),
	}

	if p1.Hash() == p2.Hash() {
		t.Error("Hash() should be different for different postures")
	}
}

func boolPtr(b bool) *bool {
	return &b
}
