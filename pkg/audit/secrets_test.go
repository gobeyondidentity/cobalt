package audit

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestNoSecretsInAuditOutput verifies that no secret material appears in
// formatted syslog audit output across all 10 event types. This is a
// security regression test protecting against credential exposure in logs
// forwarded to external SIEM systems.
//
// Strategy:
//   - Pattern-based checks (eyJ, -----BEGIN) catch ANY JWT or PEM in output
//   - Sentinel values catch specific hex-encoded secrets
//   - Tests run against a mock unixgram socket (no syslog daemon required)
func TestNoSecretsInAuditOutput(t *testing.T) {
	t.Log("Verifying no secret material appears in audit log output for all 10 event types")

	// Secrets that exist in the system but must never appear in audit logs.
	// These represent realistic credential material that callers handle
	// but event constructors must not propagate.
	type secret struct {
		name  string
		value string
	}
	secrets := []secret{
		// DPoP proof (JWT): base64url-encoded header.payload.signature
		{"dpop_proof", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9uZXh1cy5sb2NhbC9hcGkvdjEvcHVzaCIsImlhdCI6MTcwNjAwMDAwMH0.c2lnbmF0dXJlYnl0ZXM"},
		// Ed25519 private key (PEM-encoded)
		{"private_key", "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHPsGBnSGhVqFAhpFGPiayGLMghIPYflqCVFdfAA+1Lh\n-----END PRIVATE KEY-----"},
		// Invite code (32-char hex from CSPRNG)
		{"invite_code", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
		// Claim token (32-char hex from CSPRNG)
		{"claim_token", "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6"},
		// Ed25519 private seed (64-char hex)
		{"ed25519_seed", "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef"},
	}

	// Substrings that must NEVER appear in audit output regardless of context.
	// "eyJ" = base64("{\") which starts every JWT header. No legitimate audit
	// field produces this sequence.
	// "-----BEGIN" = PEM envelope header. No legitimate audit field contains this.
	forbiddenPatterns := []struct {
		name    string
		pattern string
	}{
		{"JWT prefix", "eyJ"},
		{"PEM header", "-----BEGIN"},
	}

	// kid (key identifier) SHOULD appear. Key IDs are public identifiers
	// used for correlation, not secret material.
	const testKID = "km_abc123def456"

	// Mock syslog receiver: unixgram socket, no real syslog daemon needed.
	socketPath := testSocketPath("secrets")
	t.Cleanup(func() { os.Remove(socketPath) })

	addr := net.UnixAddr{Name: socketPath, Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", &addr)
	if err != nil {
		t.Fatalf("failed to create mock syslog listener: %v", err)
	}
	defer listener.Close()

	writer, err := NewSyslogWriter(SyslogConfig{
		SocketPath: socketPath,
		Hostname:   "test.local",
		AppName:    "nexus",
	})
	if err != nil {
		t.Fatalf("NewSyslogWriter failed: %v", err)
	}
	defer writer.Close()

	ts := time.Date(2026, 2, 4, 15, 30, 0, 0, time.UTC)

	// All 10 event types with realistic data. Secrets are defined above
	// but intentionally NOT passed to constructors. If a future change
	// adds a constructor parameter that accepts secret data, the output
	// assertions below catch the regression.
	events := []struct {
		name  string
		event Event
	}{
		{"auth.success",
			NewAuthSuccess(testKID, "192.168.1.100", "POST", "/api/v1/push", "req-001", 42)},
		{"auth.failure",
			NewAuthFailure(testKID, "192.168.1.100", "invalid DPoP signature", "POST", "/api/v1/push", "req-002")},
		{"enroll.complete",
			NewEnrollComplete(testKID, "192.168.1.100", "km", testKID, "req-003")},
		{"enroll.failure",
			NewEnrollFailure("192.168.1.100", "expired invite code", "km", "req-004")},
		{"lifecycle.revoke",
			NewLifecycleRevoke(testKID, "192.168.1.100", "km_revoked789", "compromised", "req-005")},
		{"lifecycle.suspend",
			NewLifecycleSuspend(testKID, "192.168.1.100", "op_suspended456", "policy violation", "req-006")},
		{"lifecycle.unsuspend",
			NewLifecycleUnsuspend(testKID, "192.168.1.100", "op_suspended456", "investigation complete", "req-007")},
		{"lifecycle.decommission",
			NewLifecycleDecommission(testKID, "192.168.1.100", "dpu_decom123", "hardware failure", "req-008")},
		{"attestation.bypass",
			NewAttestationBypass(testKID, "192.168.1.100", "dpu_bypass456", "emergency maintenance", "stale", "req-009")},
		{"bootstrap.complete",
			NewBootstrapComplete(testKID, "192.168.1.100", testKID, "req-010")},
	}

	// Regression guard: fail if a new event type is added without test coverage.
	if len(events) != len(AllEventTypes()) {
		t.Fatalf("test covers %d event types but %d are defined; update this test", len(events), len(AllEventTypes()))
	}

	for i := range events {
		events[i].event.Timestamp = ts
	}

	var allOutput strings.Builder
	buf := make([]byte, 8192)

	for _, tc := range events {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Emitting %s event and checking for secret leakage", tc.name)

			if err := writer.Emit(tc.event); err != nil {
				t.Fatalf("Emit failed: %v", err)
			}

			listener.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := listener.Read(buf)
			if err != nil {
				t.Fatalf("failed to read from mock socket: %v", err)
			}

			output := string(buf[:n])
			t.Logf("Captured output (%d bytes): %s", n, output)
			allOutput.WriteString(output)
			allOutput.WriteByte('\n')

			// Check forbidden substrings: catches ANY JWT or PEM leak, not just test values.
			for _, fp := range forbiddenPatterns {
				if strings.Contains(output, fp.pattern) {
					t.Errorf("SECURITY: forbidden pattern %q (%s) found in %s output:\n%s", fp.pattern, fp.name, tc.name, output)
				}
			}

			// Check sentinel secret values.
			for _, s := range secrets {
				if strings.Contains(output, s.value) {
					t.Errorf("SECURITY: secret %q leaked in %s output:\n%s", s.name, tc.name, output)
				}
			}
		})
	}

	// kid MUST appear in output: it's a public identifier used for audit correlation.
	t.Run("kid_present_in_output", func(t *testing.T) {
		combined := allOutput.String()
		if !strings.Contains(combined, testKID) {
			t.Error("kid (key identifier) should appear in audit output but was not found")
		}
		t.Logf("Confirmed kid %q present in audit output (expected: kid is public, not secret)", testKID)
	})
}
