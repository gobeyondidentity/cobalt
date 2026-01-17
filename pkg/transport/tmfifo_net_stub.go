package transport

import "errors"

// NewTmfifoNetTransport creates a transport using the tmfifo_net0 device.
// This is a stub; the real implementation is in tmfifo_net.go (si-czr).
func NewTmfifoNetTransport(devicePath string) (Transport, error) {
	return nil, errors.New("TmfifoNetTransport not yet implemented")
}
