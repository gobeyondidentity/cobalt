package netutil

import (
	"net/http"
	"strings"
)

// ClientIP extracts the client IP address from an HTTP request.
// It checks X-Forwarded-For first (taking only the first entry in the chain),
// then X-Real-IP, and falls back to RemoteAddr with port stripped.
//
// Trust model: This function trusts X-Forwarded-For as set by the reverse proxy
// infrastructure. It is used for audit logging only, not access control decisions.
// Deployments must ensure XFF is set by a trusted proxy (and not spoofable by
// clients) for the audit trail to be meaningful.
func ClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (may contain multiple comma-separated IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr, stripping port if present
	return stripPort(r.RemoteAddr)
}

// stripPort removes the port portion from an address string.
// Handles IPv4 ("1.2.3.4:8080"), bracketed IPv6 ("[::1]:8080"),
// and bare IPv6 ("::1") without mangling.
func stripPort(addr string) string {
	idx := strings.LastIndex(addr, ":")
	if idx == -1 {
		return addr
	}

	// IPv6 with brackets: [::1]:port
	if strings.Contains(addr, "[") {
		if closeIdx := strings.LastIndex(addr, "]"); closeIdx != -1 && closeIdx < idx {
			return addr[:idx]
		}
		return addr
	}

	// Bare IPv6 (multiple colons, no brackets): return as-is
	if strings.Count(addr, ":") > 1 {
		return addr
	}

	// IPv4: 1.2.3.4:port
	return addr[:idx]
}
