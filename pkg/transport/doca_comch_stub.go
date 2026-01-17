//go:build !doca

package transport

import "errors"

// docaComchAvailable returns false on systems without DOCA SDK.
func docaComchAvailable() bool {
	return false
}

// NewDOCAComchTransport returns an error on systems without DOCA SDK.
// The real implementation requires BlueField hardware and DOCA libraries.
func NewDOCAComchTransport() (Transport, error) {
	return nil, errors.New("DOCA Comch requires BlueField hardware and DOCA SDK")
}
