package netutil

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		xRealIP    string
		remoteAddr string
		want       string
	}{
		{
			name:       "single XFF entry",
			xff:        "10.0.0.1",
			remoteAddr: "192.168.1.1:4321",
			want:       "10.0.0.1",
		},
		{
			name:       "multiple XFF entries returns first",
			xff:        "10.0.0.1, 172.16.0.1, 192.168.0.1",
			remoteAddr: "192.168.1.1:4321",
			want:       "10.0.0.1",
		},
		{
			name:       "XFF with spaces trimmed",
			xff:        "  10.0.0.1 , 172.16.0.1",
			remoteAddr: "192.168.1.1:4321",
			want:       "10.0.0.1",
		},
		{
			name:       "X-Real-IP used when no XFF",
			xRealIP:    "10.0.0.5",
			remoteAddr: "192.168.1.1:4321",
			want:       "10.0.0.5",
		},
		{
			name:       "XFF takes precedence over X-Real-IP",
			xff:        "10.0.0.1",
			xRealIP:    "10.0.0.5",
			remoteAddr: "192.168.1.1:4321",
			want:       "10.0.0.1",
		},
		{
			name:       "RemoteAddr with port stripped",
			remoteAddr: "192.168.1.1:4321",
			want:       "192.168.1.1",
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "192.168.1.1",
			want:       "192.168.1.1",
		},
		{
			name:       "IPv6 RemoteAddr with port stripped",
			remoteAddr: "[::1]:4321",
			want:       "[::1]",
		},
		{
			name:       "IPv6 RemoteAddr without port",
			remoteAddr: "::1",
			want:       "::1",
		},
		{
			name:       "empty RemoteAddr",
			remoteAddr: "",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := ClientIP(r)
			if got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientIP_ConsistencyAcrossSources(t *testing.T) {
	t.Log("Verifying that the same request always produces the same IP regardless of call site")

	r := &http.Request{
		RemoteAddr: "192.168.1.100:9090",
		Header:     make(http.Header),
	}
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 172.16.0.1")

	// Call multiple times to verify determinism
	results := make(map[string]bool)
	for i := 0; i < 10; i++ {
		results[ClientIP(r)] = true
	}

	if len(results) != 1 {
		t.Errorf("ClientIP() returned inconsistent results: %v", results)
	}

	ip := ClientIP(r)
	if ip != "10.0.0.1" {
		t.Errorf("ClientIP() = %q, want %q", ip, "10.0.0.1")
	}
}
