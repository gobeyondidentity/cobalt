package netutil

import (
	"errors"
	"testing"
)

func TestValidateEndpointStrict_Loopback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
	}{
		{"localhost", "localhost"},
		{"localhost with port", "localhost:8080"},
		{"localhost URL", "http://localhost:8080/path"},
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1 with port", "127.0.0.1:8080"},
		{"127.0.0.1 URL", "http://127.0.0.1:8080/path"},
		{"127.x.x.x range", "127.0.0.254"},
		{"IPv6 loopback", "::1"},
		{"IPv6 loopback URL", "http://[::1]:8080/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpointStrict(tt.endpoint)
			if !errors.Is(err, ErrLoopbackAddress) {
				t.Errorf("ValidateEndpointStrict(%q) = %v, want ErrLoopbackAddress", tt.endpoint, err)
			}
		})
	}
}

func TestValidateEndpointStrict_LinkLocal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
	}{
		{"AWS metadata", "169.254.169.254"},
		{"AWS metadata with port", "169.254.169.254:80"},
		{"AWS metadata URL", "http://169.254.169.254/latest/meta-data/"},
		{"link-local start", "169.254.0.1"},
		{"link-local end", "169.254.255.254"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpointStrict(tt.endpoint)
			if !errors.Is(err, ErrLinkLocalAddress) {
				t.Errorf("ValidateEndpointStrict(%q) = %v, want ErrLinkLocalAddress", tt.endpoint, err)
			}
		})
	}
}

func TestValidateEndpointStrict_PrivateRanges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
	}{
		{"10.0.0.0/8 start", "10.0.0.1"},
		{"10.0.0.0/8 middle", "10.255.255.1"},
		{"10.0.0.0/8 with port", "10.0.0.1:8080"},
		{"10.0.0.0/8 URL", "http://10.0.0.1:8080/path"},
		{"172.16.0.0/12 start", "172.16.0.1"},
		{"172.16.0.0/12 middle", "172.20.0.1"},
		{"172.16.0.0/12 end", "172.31.255.254"},
		{"192.168.0.0/16 start", "192.168.0.1"},
		{"192.168.0.0/16 middle", "192.168.1.1"},
		{"192.168.0.0/16 end", "192.168.255.254"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpointStrict(tt.endpoint)
			if !errors.Is(err, ErrPrivateAddress) {
				t.Errorf("ValidateEndpointStrict(%q) = %v, want ErrPrivateAddress", tt.endpoint, err)
			}
		})
	}
}

func TestValidateEndpoint_AllowsPrivateRanges(t *testing.T) {
	t.Parallel()
	// ValidateEndpoint (non-strict) should allow private ranges for BMC addresses
	tests := []struct {
		name     string
		endpoint string
	}{
		{"10.0.0.0/8", "10.0.0.1"},
		{"172.16.0.0/12", "172.16.0.1"},
		{"192.168.0.0/16", "192.168.1.1"},
		{"BMC address", "192.168.1.203"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpoint(tt.endpoint)
			if err != nil {
				t.Errorf("ValidateEndpoint(%q) = %v, want nil (private ranges allowed)", tt.endpoint, err)
			}
		})
	}
}

func TestValidateEndpoint_BlocksLoopbackAndLinkLocal(t *testing.T) {
	t.Parallel()
	// ValidateEndpoint should still block loopback and link-local
	tests := []struct {
		name     string
		endpoint string
		wantErr  error
	}{
		{"localhost", "localhost", ErrLoopbackAddress},
		{"127.0.0.1", "127.0.0.1", ErrLoopbackAddress},
		{"AWS metadata", "169.254.169.254", ErrLinkLocalAddress},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpoint(tt.endpoint)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateEndpoint(%q) = %v, want %v", tt.endpoint, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEndpoint_InvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
	}{
		{"empty string", ""},
		{"just scheme", "http://"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpoint(tt.endpoint)
			if err == nil {
				t.Errorf("ValidateEndpoint(%q) = nil, want error", tt.endpoint)
			}
		})
	}
}

func TestValidateEndpointStrict_InvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
	}{
		{"empty string", ""},
		{"just scheme", "http://"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpointStrict(tt.endpoint)
			if err == nil {
				t.Errorf("ValidateEndpointStrict(%q) = nil, want error", tt.endpoint)
			}
		})
	}
}

// TestValidateEndpoint_PublicAddresses tests that public addresses are allowed
// These tests require DNS resolution and may be skipped in short mode
func TestValidateEndpoint_PublicAddresses(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping DNS resolution test in short mode")
	}

	tests := []struct {
		name     string
		endpoint string
	}{
		{"public IP", "8.8.8.8"},
		{"public IP with port", "8.8.8.8:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpoint(tt.endpoint)
			if err != nil {
				t.Errorf("ValidateEndpoint(%q) = %v, want nil", tt.endpoint, err)
			}
		})
	}
}

func TestValidateEndpointStrict_PublicAddresses(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping DNS resolution test in short mode")
	}

	tests := []struct {
		name     string
		endpoint string
	}{
		{"public IP", "8.8.8.8"},
		{"public IP with port", "8.8.8.8:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEndpointStrict(tt.endpoint)
			if err != nil {
				t.Errorf("ValidateEndpointStrict(%q) = %v, want nil", tt.endpoint, err)
			}
		})
	}
}

// TestExtractHost tests the internal host extraction logic
func TestExtractHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
		wantHost string
	}{
		{"bare host", "example.com", "example.com"},
		{"host:port", "example.com:8080", "example.com"},
		{"URL", "http://example.com:8080/path", "example.com"},
		{"URL with path", "https://example.com/path/to/resource", "example.com"},
		{"IPv4", "192.168.1.1", "192.168.1.1"},
		{"IPv4:port", "192.168.1.1:8080", "192.168.1.1"},
		{"IPv4 URL", "http://192.168.1.1:8080", "192.168.1.1"},
		{"IPv6 brackets", "[::1]", "::1"},
		{"IPv6 brackets port", "[::1]:8080", "::1"},
		{"IPv6 URL", "http://[::1]:8080/path", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHost(tt.endpoint)
			if got != tt.wantHost {
				t.Errorf("extractHost(%q) = %q, want %q", tt.endpoint, got, tt.wantHost)
			}
		})
	}
}
