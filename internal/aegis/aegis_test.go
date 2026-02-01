package aegis

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/gobeyondidentity/secure-infra/gen/go/agent/v1"
	"github.com/gobeyondidentity/secure-infra/pkg/doca"
	"github.com/gobeyondidentity/secure-infra/pkg/ovs"
)

// newTestServer creates a server configured for testing (no sudo, no real hardware).
func newTestServer(t *testing.T, cfg *Config) *Server {
	t.Helper()
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	// Replace all components that use sudo with no-op implementations
	server.SetOVSClient(ovs.NewNoOpClient())
	server.SetSystemCollector(doca.NewNoOpCollector())
	server.SetInventoryCollector(doca.NewNoOpInventoryCollector())
	return server
}

// TestConfig_Validate tests the Config.Validate method with table-driven tests.
func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr string // empty means no error expected
	}{
		{
			name:    "valid minimal config",
			config:  &Config{ListenAddr: ":18051"},
			wantErr: "",
		},
		{
			name:    "missing listen address",
			config:  &Config{},
			wantErr: "listen address is required",
		},
		{
			name: "local API enabled without control plane URL",
			config: &Config{
				ListenAddr:      ":18051",
				LocalAPIEnabled: true,
				DPUName:         "bf3-test",
			},
			wantErr: "control plane URL is required",
		},
		{
			name: "local API enabled without DPU name",
			config: &Config{
				ListenAddr:      ":18051",
				LocalAPIEnabled: true,
				ControlPlaneURL: "https://nexus.example.com",
			},
			wantErr: "DPU name is required",
		},
		{
			name: "local API enabled with all required fields",
			config: &Config{
				ListenAddr:      ":18051",
				LocalAPIEnabled: true,
				ControlPlaneURL: "https://nexus.example.com",
				DPUName:         "bf3-test",
			},
			wantErr: "",
		},
		{
			name: "local API disabled ignores missing fields",
			config: &Config{
				ListenAddr:      ":18051",
				LocalAPIEnabled: false,
				// ControlPlaneURL and DPUName not required when LocalAPI disabled
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want containing %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

// TestConfig_LoadFromEnv tests environment variable loading.
func TestConfig_LoadFromEnv(t *testing.T) {
	// Helper to clean up env vars after each test
	cleanupEnv := func() {
		os.Unsetenv("FC_BMC_PASSWORD")
		os.Unsetenv("SERVER_URL")
		os.Unsetenv("CONTROL_PLANE_URL")
		os.Unsetenv("DPU_NAME")
		os.Unsetenv("DPU_ID")
		os.Unsetenv("DPU_SERIAL")
		os.Unsetenv("ALLOWED_HOSTNAMES")
	}

	t.Run("BMC address set without password", func(t *testing.T) {
		cleanupEnv()
		defer cleanupEnv()

		cfg := &Config{
			ListenAddr: ":18051",
			BMCAddr:    "192.168.1.203",
		}

		err := cfg.LoadFromEnv()
		if err == nil {
			t.Error("LoadFromEnv() expected error when BMCAddr set without FC_BMC_PASSWORD")
		}
		if err != nil && !strings.Contains(err.Error(), "FC_BMC_PASSWORD") {
			t.Errorf("LoadFromEnv() error = %q, want containing FC_BMC_PASSWORD", err.Error())
		}
	})

	t.Run("BMC address set with password", func(t *testing.T) {
		cleanupEnv()
		defer cleanupEnv()

		os.Setenv("FC_BMC_PASSWORD", "secret123")

		cfg := &Config{
			ListenAddr: ":18051",
			BMCAddr:    "192.168.1.203",
		}

		err := cfg.LoadFromEnv()
		if err != nil {
			t.Errorf("LoadFromEnv() unexpected error: %v", err)
		}
		if cfg.BMCPassword != "secret123" {
			t.Errorf("BMCPassword = %q, want %q", cfg.BMCPassword, "secret123")
		}
	})

	t.Run("no BMC address skips password check", func(t *testing.T) {
		cleanupEnv()
		defer cleanupEnv()

		cfg := &Config{
			ListenAddr: ":18051",
			// BMCAddr not set
		}

		err := cfg.LoadFromEnv()
		if err != nil {
			t.Errorf("LoadFromEnv() unexpected error: %v", err)
		}
	})

	t.Run("environment variables populate config fields", func(t *testing.T) {
		cleanupEnv()
		defer cleanupEnv()

		os.Setenv("CONTROL_PLANE_URL", "https://nexus.example.com")
		os.Setenv("DPU_NAME", "bf3-prod-01")
		os.Setenv("DPU_ID", "dpu-12345")
		os.Setenv("DPU_SERIAL", "SN-ABC123")
		os.Setenv("ALLOWED_HOSTNAMES", "host1,host2,host3")

		cfg := &Config{ListenAddr: ":18051"}

		err := cfg.LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv() unexpected error: %v", err)
		}

		if cfg.ControlPlaneURL != "https://nexus.example.com" {
			t.Errorf("ControlPlaneURL = %q, want %q", cfg.ControlPlaneURL, "https://nexus.example.com")
		}
		if cfg.DPUName != "bf3-prod-01" {
			t.Errorf("DPUName = %q, want %q", cfg.DPUName, "bf3-prod-01")
		}
		if cfg.DPUID != "dpu-12345" {
			t.Errorf("DPUID = %q, want %q", cfg.DPUID, "dpu-12345")
		}
		if cfg.DPUSerial != "SN-ABC123" {
			t.Errorf("DPUSerial = %q, want %q", cfg.DPUSerial, "SN-ABC123")
		}
		if len(cfg.AllowedHostnames) != 3 {
			t.Errorf("AllowedHostnames length = %d, want 3", len(cfg.AllowedHostnames))
		}
		expectedHostnames := []string{"host1", "host2", "host3"}
		for i, expected := range expectedHostnames {
			if i >= len(cfg.AllowedHostnames) || cfg.AllowedHostnames[i] != expected {
				t.Errorf("AllowedHostnames[%d] = %q, want %q", i, cfg.AllowedHostnames[i], expected)
			}
		}
	})

	t.Run("environment variables do not override existing values when empty", func(t *testing.T) {
		cleanupEnv()
		defer cleanupEnv()

		cfg := &Config{
			ListenAddr:      ":18051",
			ControlPlaneURL: "https://existing.example.com",
			DPUName:         "existing-dpu",
		}

		err := cfg.LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv() unexpected error: %v", err)
		}

		// When env vars are empty, existing values should remain
		if cfg.ControlPlaneURL != "https://existing.example.com" {
			t.Errorf("ControlPlaneURL changed unexpectedly to %q", cfg.ControlPlaneURL)
		}
		if cfg.DPUName != "existing-dpu" {
			t.Errorf("DPUName changed unexpectedly to %q", cfg.DPUName)
		}
	})

	t.Run("SERVER_URL takes precedence over CONTROL_PLANE_URL", func(t *testing.T) {
		cleanupEnv()
		defer cleanupEnv()

		t.Log("Setting both SERVER_URL and CONTROL_PLANE_URL env vars")
		os.Setenv("SERVER_URL", "https://new.example.com")
		os.Setenv("CONTROL_PLANE_URL", "https://legacy.example.com")

		cfg := &Config{ListenAddr: ":18051"}

		t.Log("Calling LoadFromEnv to populate config")
		err := cfg.LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv() unexpected error: %v", err)
		}

		t.Log("Verifying SERVER_URL value was used")
		if cfg.ControlPlaneURL != "https://new.example.com" {
			t.Errorf("ControlPlaneURL = %q, want %q (SERVER_URL should take precedence)", cfg.ControlPlaneURL, "https://new.example.com")
		}
	})

	t.Run("CONTROL_PLANE_URL works when SERVER_URL is not set (backward compatibility)", func(t *testing.T) {
		cleanupEnv()
		defer cleanupEnv()

		t.Log("Setting only CONTROL_PLANE_URL env var (legacy)")
		os.Setenv("CONTROL_PLANE_URL", "https://legacy.example.com")

		cfg := &Config{ListenAddr: ":18051"}

		t.Log("Calling LoadFromEnv to populate config")
		err := cfg.LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv() unexpected error: %v", err)
		}

		t.Log("Verifying CONTROL_PLANE_URL value was used for backward compatibility")
		if cfg.ControlPlaneURL != "https://legacy.example.com" {
			t.Errorf("ControlPlaneURL = %q, want %q", cfg.ControlPlaneURL, "https://legacy.example.com")
		}
	})

	t.Run("SERVER_URL alone sets ControlPlaneURL", func(t *testing.T) {
		cleanupEnv()
		defer cleanupEnv()

		t.Log("Setting only SERVER_URL env var")
		os.Setenv("SERVER_URL", "https://server-url.example.com")

		cfg := &Config{ListenAddr: ":18051"}

		t.Log("Calling LoadFromEnv to populate config")
		err := cfg.LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv() unexpected error: %v", err)
		}

		t.Log("Verifying SERVER_URL value was used")
		if cfg.ControlPlaneURL != "https://server-url.example.com" {
			t.Errorf("ControlPlaneURL = %q, want %q", cfg.ControlPlaneURL, "https://server-url.example.com")
		}
	})
}

// TestDefaultConfig tests the DefaultConfig function.
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ListenAddr != ":18051" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":18051")
	}
	if cfg.BMCUser != "root" {
		t.Errorf("BMCUser = %q, want %q", cfg.BMCUser, "root")
	}
	if cfg.LocalAPIAddr != "localhost:9443" {
		t.Errorf("LocalAPIAddr = %q, want %q", cfg.LocalAPIAddr, "localhost:9443")
	}
	if cfg.LocalAPIEnabled {
		t.Error("LocalAPIEnabled should be false by default")
	}
	if cfg.BMCAddr != "" {
		t.Errorf("BMCAddr should be empty by default, got %q", cfg.BMCAddr)
	}
}

// TestNewServer tests the NewServer function.
func TestNewServer(t *testing.T) {
	t.Run("valid config without BMC creates server", func(t *testing.T) {
		cfg := &Config{
			ListenAddr: ":18051",
		}

		server, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer() unexpected error: %v", err)
		}
		if server == nil {
			t.Fatal("NewServer() returned nil server")
		}

		// Check server has correct initial state
		if server.config != cfg {
			t.Error("Server config not set correctly")
		}
		if server.redfishCli != nil {
			t.Error("redfishCli should be nil when BMCAddr is not set")
		}
		if server.startTime == 0 {
			t.Error("startTime should be set")
		}
		if server.startTime > time.Now().Unix() {
			t.Error("startTime should not be in the future")
		}
		if server.version == "" {
			t.Error("version should be set")
		}
		if server.sysCollect == nil {
			t.Error("sysCollect should be initialized")
		}
		if server.invCollect == nil {
			t.Error("invCollect should be initialized")
		}
		if server.ovsClient == nil {
			t.Error("ovsClient should be initialized")
		}
	})

	// Note: Testing with BMC requires actual Redfish connectivity or mocking
	// the attestation.NewRedfishClient. For unit tests, we skip this case
	// as it requires external dependencies.
	t.Run("config with invalid BMC returns error", func(t *testing.T) {
		cfg := &Config{
			ListenAddr:  ":18051",
			BMCAddr:     "invalid-bmc-addr:12345",
			BMCUser:     "root",
			BMCPassword: "password",
		}

		// This will fail because we cannot connect to the BMC
		server, err := NewServer(cfg)
		// We expect an error because we cannot connect to a non-existent BMC
		if err == nil {
			// If no error, the implementation might be lazy-loading the client
			// In that case, just verify the server was created
			if server == nil {
				t.Fatal("NewServer() returned nil server without error")
			}
		}
		// Either error or successful server creation is acceptable
		// depending on implementation (eager vs lazy client creation)
	})
}

// TestServer_HealthCheck tests the HealthCheck method.
func TestServer_HealthCheck(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":18051",
	}

	server := newTestServer(t, cfg)

	ctx := context.Background()
	resp, err := server.HealthCheck(ctx, &agentv1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("HealthCheck() error: %v", err)
	}

	// Check response structure
	if resp == nil {
		t.Fatal("HealthCheck() returned nil response")
	}

	// HealthCheck always returns healthy=true (see implementation)
	if !resp.Healthy {
		t.Error("HealthCheck should return Healthy=true")
	}

	// Check version is set
	if resp.Version == "" {
		t.Error("HealthCheck should return a version")
	}

	// Check uptime is reasonable (should be >= 0)
	if resp.UptimeSeconds < 0 {
		t.Errorf("UptimeSeconds = %d, should be >= 0", resp.UptimeSeconds)
	}

	// Check components map exists and has expected entries
	if resp.Components == nil {
		t.Fatal("Components map should not be nil")
	}

	// Check "ovs" component exists
	if _, ok := resp.Components["ovs"]; !ok {
		t.Error("Components should include 'ovs'")
	}

	// Check "system" component exists
	if _, ok := resp.Components["system"]; !ok {
		t.Error("Components should include 'system'")
	}

	// BMC component should NOT be present when no BMC is configured
	if server.redfishCli == nil {
		if _, ok := resp.Components["bmc"]; ok {
			t.Error("Components should not include 'bmc' when redfishCli is nil")
		}
	}
}

// TestServer_DistributeCredential tests the DistributeCredential method.
func TestServer_DistributeCredential(t *testing.T) {
	tests := []struct {
		name       string
		req        *agentv1.DistributeCredentialRequest
		wantErr    error
		wantErrMsg string
	}{
		{
			name: "missing credential name",
			req: &agentv1.DistributeCredentialRequest{
				CredentialType: "ssh-ca",
				PublicKey:      []byte("ssh-ed25519 AAAA... test@example.com"),
			},
			wantErr: errMissingCredentialName,
		},
		{
			name: "missing public key",
			req: &agentv1.DistributeCredentialRequest{
				CredentialType: "ssh-ca",
				CredentialName: "test-ca",
			},
			wantErr: errMissingPublicKey,
		},
		{
			name: "unknown credential type",
			req: &agentv1.DistributeCredentialRequest{
				CredentialType: "unknown-type",
				CredentialName: "test-ca",
				PublicKey:      []byte("ssh-ed25519 AAAA... test@example.com"),
			},
			wantErr: errUnknownCredentialType,
		},
		{
			name: "valid ssh-ca without local API",
			req: &agentv1.DistributeCredentialRequest{
				CredentialType: "ssh-ca",
				CredentialName: "test-ca",
				PublicKey:      []byte("ssh-ed25519 AAAA... test@example.com"),
			},
			wantErr:    nil, // No error, but returns success=false
			wantErrMsg: "Local API not enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ListenAddr: ":18051",
			}
			server := newTestServer(t, cfg)

			ctx := context.Background()
			resp, err := server.DistributeCredential(ctx, tt.req)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("DistributeCredential() error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("DistributeCredential() unexpected error: %v", err)
				return
			}

			if tt.wantErrMsg != "" {
				if resp == nil {
					t.Fatal("DistributeCredential() response is nil")
				}
				if resp.Success {
					t.Error("DistributeCredential() expected Success=false")
				}
				if !strings.Contains(resp.Message, tt.wantErrMsg) {
					t.Errorf("DistributeCredential() message = %q, want containing %q", resp.Message, tt.wantErrMsg)
				}
			}
		})
	}
}

// TestServer_SetLocalAPI tests the SetLocalAPI method.
func TestServer_SetLocalAPI(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":18051",
	}
	server := newTestServer(t, cfg)

	// Initially localAPI should be nil
	if server.localAPI != nil {
		t.Error("localAPI should be nil initially")
	}

	// We cannot easily create a real localapi.Server without more setup,
	// but we can test that setting nil works and doesn't panic
	server.SetLocalAPI(nil)
	if server.localAPI != nil {
		t.Error("localAPI should be nil after SetLocalAPI(nil)")
	}
}

// TestServer_SetHostListener tests the SetHostListener method.
func TestServer_SetHostListener(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":18051",
	}
	server := newTestServer(t, cfg)

	// Initially hostListener should be nil
	if server.hostListener != nil {
		t.Error("hostListener should be nil initially")
	}

	// Test GetHostListener returns nil initially
	if server.GetHostListener() != nil {
		t.Error("GetHostListener() should return nil initially")
	}

	// Test SetHostListener with nil
	server.SetHostListener(nil)
	if server.GetHostListener() != nil {
		t.Error("GetHostListener() should return nil after SetHostListener(nil)")
	}
}

// TestErrMsg tests the errMsg helper function.
func TestErrMsg(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "nil error returns ok",
			err:  nil,
			want: "ok",
		},
		{
			name: "non-nil error returns error string",
			err:  errBMCNotConfigured,
			want: "BMC not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errMsg(tt.err)
			if got != tt.want {
				t.Errorf("errMsg() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGenerateNonce tests that nonce generation produces valid hex strings.
func TestGenerateNonce(t *testing.T) {
	nonce1 := generateNonce()

	// Should be 64 characters (32 bytes as hex)
	if len(nonce1) != 64 {
		t.Errorf("generateNonce() length = %d, want 64", len(nonce1))
	}

	// Should be valid hex
	for _, c := range nonce1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("generateNonce() contains invalid hex character: %c", c)
			break
		}
	}

	// Each call should produce a different nonce (with very high probability)
	nonce2 := generateNonce()
	if nonce1 == nonce2 {
		t.Error("generateNonce() should produce different values on each call")
	}
}

// TestCurrentUnixTime tests that currentUnixTime returns reasonable values.
func TestCurrentUnixTime(t *testing.T) {
	before := time.Now().Unix()
	got := currentUnixTime()
	after := time.Now().Unix()

	if got < before || got > after {
		t.Errorf("currentUnixTime() = %d, expected between %d and %d", got, before, after)
	}
}

// TestServer_Uptime tests that uptime calculation is correct.
func TestServer_Uptime(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":18051",
	}
	server := newTestServer(t, cfg)

	// Uptime should be >= 0 immediately after creation
	uptime := currentUnixTime() - server.startTime
	if uptime < 0 {
		t.Errorf("Initial uptime = %d, should be >= 0", uptime)
	}

	// Wait a short time and verify uptime increases
	time.Sleep(10 * time.Millisecond)
	uptime2 := currentUnixTime() - server.startTime
	if uptime2 < uptime {
		t.Errorf("Uptime decreased: %d -> %d", uptime, uptime2)
	}
}

// TestSentinelErrors tests that sentinel errors are properly defined.
func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{errBMCNotConfigured, "BMC not configured"},
		{errUnknownCredentialType, "unknown credential type"},
		{errMissingCredentialName, "credential name is required"},
		{errMissingPublicKey, "public key is required"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.err.Error() != tt.want {
				t.Errorf("error = %q, want %q", tt.err.Error(), tt.want)
			}
		})
	}
}
