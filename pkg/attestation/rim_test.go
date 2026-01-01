package attestation

import (
	"context"
	"testing"
	"time"
)

func TestRIMClient_ListRIMIDs(t *testing.T) {
	client := NewRIMClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ids, err := client.ListRIMIDs(ctx)
	if err != nil {
		t.Fatalf("ListRIMIDs failed: %v", err)
	}

	if len(ids) == 0 {
		t.Error("Expected non-empty RIM ID list")
	}

	t.Logf("Found %d RIM IDs", len(ids))

	// Check for expected patterns (GPUs should be present)
	hasGPU := false
	for _, id := range ids {
		if len(id) > 10 && (id[0:2] == "GH" || id[0:2] == "GB") {
			hasGPU = true
			break
		}
	}
	if !hasGPU {
		t.Log("Warning: No GPU RIMs found (expected GH100, GB100, etc.)")
	}
}

func TestRIMClient_FindRIMForFirmware_NotFound(t *testing.T) {
	client := NewRIMClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// BlueField-3 firmware that won't be found (not available until April 2025)
	_, err := client.FindRIMForFirmware(ctx, "32.47.1088")
	if err == nil {
		t.Log("Unexpectedly found RIM for BF3 firmware - this may mean BF3 CoRIMs are now available")
	} else {
		t.Logf("Expected error for BF3 firmware: %v", err)
	}
}

func TestVerifyRIMIntegrity(t *testing.T) {
	// Test with nil entry
	valid, err := VerifyRIMIntegrity(nil)
	if err == nil {
		t.Error("Expected error for nil entry")
	}
	if valid {
		t.Error("Expected invalid for nil entry")
	}

	// Test with empty entry
	entry := &RIMEntry{}
	valid, err = VerifyRIMIntegrity(entry)
	if err == nil {
		t.Error("Expected error for empty entry")
	}
	if valid {
		t.Error("Expected invalid for empty entry")
	}
}
