//go:build doca

// DOCA ComCh transport implementation. Requires DOCA SDK and BlueField hardware.
package transport

/*
#cgo LDFLAGS: -ldoca_comch -ldoca_argp -ldoca_common -libverbs -lmlx5 -lrdmacm -lcrypto -lnl-3 -lnl-genl-3 -lstdc++ -lm -lpthread -ldl

#include <doca_comch.h>
#include <doca_comch_consumer.h>
#include <doca_comch_producer.h>
#include <doca_error.h>
#include <doca_ctx.h>
#include <doca_pe.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// docaComchAvailable returns true when built with DOCA SDK.
func docaComchAvailable() bool {
	return true
}

// DOCAComchTransport implements Transport using NVIDIA DOCA Comch API.
// This is the production transport for BlueField DPU communication.
type DOCAComchTransport struct {
	mu       sync.Mutex
	conn     unsafe.Pointer // doca_comch_connection*
	producer unsafe.Pointer // doca_comch_producer*
	consumer unsafe.Pointer // doca_comch_consumer*
	pe       unsafe.Pointer // doca_pe*
	closed   bool
	isServer bool
	name     string
}

// DOCAComchConfig holds configuration for DOCA Comch transport.
type DOCAComchConfig struct {
	// DeviceName is the DOCA device name (e.g., "mlx5_0").
	DeviceName string
	// ServerName is the Comch server name for connection.
	ServerName string
	// IsServer indicates whether this is the DPU (server) side.
	IsServer bool
	// MaxMsgSize is the maximum message size in bytes.
	MaxMsgSize uint32
}

// NewDOCAComchTransport creates a new DOCA Comch transport using default settings.
// This is the selector-compatible constructor. For advanced configuration,
// use NewDOCAComchTransportWithConfig.
func NewDOCAComchTransport() (Transport, error) {
	return NewDOCAComchTransportWithConfig(DOCAComchConfig{
		DeviceName: "mlx5_0",
		ServerName: "secureinfra",
	})
}

// NewDOCAComchTransportWithConfig creates a DOCA Comch transport with explicit configuration.
// Call Connect() to establish the connection.
func NewDOCAComchTransportWithConfig(cfg DOCAComchConfig) (*DOCAComchTransport, error) {
	if cfg.DeviceName == "" {
		return nil, errors.New("DOCA device name required")
	}
	if cfg.ServerName == "" {
		return nil, errors.New("DOCA Comch server name required")
	}

	return &DOCAComchTransport{
		isServer: cfg.IsServer,
		name:     cfg.ServerName,
	}, nil
}

// Connect establishes the DOCA Comch connection.
// For server (DPU) side, this creates a Comch server and waits for connection.
// For client (Host) side, this connects to the DPU's Comch server.
func (t *DOCAComchTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("transport closed")
	}

	// TODO: Implement DOCA Comch connection setup
	// This will call:
	// - doca_comch_server_create() for DPU side
	// - doca_comch_client_create() for Host side
	// - Set up producer/consumer for bidirectional messaging
	// - Start the DOCA progress engine

	return fmt.Errorf("DOCA Comch Connect not yet implemented")
}

// Send transmits a message over the DOCA Comch channel.
func (t *DOCAComchTransport) Send(msg *Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("transport closed")
	}

	// TODO: Implement using doca_comch_producer_send()
	// - Serialize message to wire format
	// - Submit to producer
	// - Drive progress engine until completion

	return fmt.Errorf("DOCA Comch Send not yet implemented")
}

// Recv receives a message from the DOCA Comch channel.
func (t *DOCAComchTransport) Recv() (*Message, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, errors.New("transport closed")
	}

	// TODO: Implement using doca_comch_consumer_recv()
	// - Drive progress engine until message arrives
	// - Deserialize from wire format

	return nil, fmt.Errorf("DOCA Comch Recv not yet implemented")
}

// Close terminates the DOCA Comch connection.
func (t *DOCAComchTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	// TODO: Implement cleanup
	// - Stop progress engine
	// - Destroy producer/consumer
	// - Destroy connection/server

	return nil
}

// Type returns the transport type identifier.
func (t *DOCAComchTransport) Type() TransportType {
	return TransportDOCAComch
}

// DOCAComchListener implements TransportListener for DOCA Comch.
// Used by the DPU Agent to accept incoming Host Agent connections.
type DOCAComchListener struct {
	mu     sync.Mutex
	server unsafe.Pointer // doca_comch_server*
	pe     unsafe.Pointer // doca_pe*
	closed bool
	name   string
}

// NewDOCAComchListener creates a new DOCA Comch listener.
func NewDOCAComchListener(cfg DOCAComchConfig) (*DOCAComchListener, error) {
	if cfg.DeviceName == "" {
		return nil, errors.New("DOCA device name required")
	}
	if cfg.ServerName == "" {
		return nil, errors.New("DOCA Comch server name required")
	}

	// TODO: Implement server creation using doca_comch_server_create()

	return &DOCAComchListener{
		name: cfg.ServerName,
	}, nil
}

// Accept blocks until a new connection is received.
func (l *DOCAComchListener) Accept() (Transport, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil, errors.New("listener closed")
	}

	// TODO: Implement using doca_comch_server connection callbacks
	// - Drive progress engine until connection event
	// - Wrap connection in DOCAComchTransport

	return nil, fmt.Errorf("DOCA Comch Accept not yet implemented")
}

// Close stops the listener.
func (l *DOCAComchListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true

	// TODO: Implement cleanup
	// - Stop progress engine
	// - Destroy server

	return nil
}

// Type returns the transport type.
func (l *DOCAComchListener) Type() TransportType {
	return TransportDOCAComch
}
