package transport

import (
	"crypto/tls"
	"errors"
)

// NewNetworkTransport creates a transport using mTLS over TCP.
// This is a stub; the real implementation is in network.go (si-n8y).
func NewNetworkTransport(addr, inviteCode string, tlsConfig *tls.Config) (Transport, error) {
	return nil, errors.New("NetworkTransport not yet implemented")
}
