//go:build doca

// Server-side (DPU) DOCA ComCh listener. Requires DOCA SDK and BlueField hardware.
package transport

/*
#cgo CFLAGS: -I/opt/mellanox/doca/include -I${SRCDIR}/csrc
#cgo linux,arm64 LDFLAGS: -L/opt/mellanox/doca/lib/aarch64-linux-gnu -ldoca_comch -ldoca_common -ldoca_argp -lstdc++
#cgo linux,amd64 LDFLAGS: -L/opt/mellanox/doca/lib/x86_64-linux-gnu -ldoca_comch -ldoca_common -ldoca_argp -lstdc++

#include <stdlib.h>
#include "comch_shim.h"
*/
import "C"
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// DOCAComchServerConfig holds configuration for DOCA ComCh server.
type DOCAComchServerConfig struct {
	// PCIAddr is the PCI address of the DOCA device on the DPU (e.g., "03:00.0").
	PCIAddr string

	// RepPCIAddr is the representor PCI address for the host device (e.g., "01:00.0").
	RepPCIAddr string

	// ServerName is the ComCh server name that clients connect to.
	ServerName string

	// MaxMsgSize is the maximum message size in bytes (0 for default).
	MaxMsgSize uint32

	// RecvBufferSize is the channel buffer size for received messages per connection.
	// Default is 16 if not specified.
	RecvBufferSize int

	// MaxClients is the maximum number of concurrent client connections.
	// Default is 64 if not specified.
	MaxClients int
}

// DOCAComchServer implements TransportListener using NVIDIA DOCA ComCh API.
// This is the DPU-side server that accepts connections from host clients.
type DOCAComchServer struct {
	mu sync.Mutex

	// Configuration
	pciAddr    string
	repPCIAddr string
	serverName string
	maxMsgSize uint32
	bufferSize int

	// Connection tracking
	connections map[uint64]*DOCAComchServerConn
	pendingChan chan uint64 // Pending connection IDs for Accept()

	// Epoll state
	epollFd int
	eventFd int

	// Lifecycle
	done      chan struct{}
	closeOnce sync.Once
	closed    bool
	running   bool
}

// DOCAComchServerConn represents a single client connection on the server.
// Implements the Transport interface for per-connection communication.
type DOCAComchServerConn struct {
	mu sync.Mutex

	// Connection identity
	connID uint64
	server *DOCAComchServer

	// Message channels
	recvChan chan []byte
	errChan  chan error

	// Lifecycle
	done      chan struct{}
	closeOnce sync.Once
	closed    bool
}

// validateServerConfig validates the server configuration.
func validateServerConfig(cfg DOCAComchServerConfig) error {
	if cfg.PCIAddr == "" {
		return errors.New("doca comch server: PCI address required")
	}
	if cfg.RepPCIAddr == "" {
		return errors.New("doca comch server: representor PCI address required")
	}
	if cfg.ServerName == "" {
		return errors.New("doca comch server: server name required")
	}
	return nil
}

// NewDOCAComchServer creates a new DOCA ComCh server transport listener.
// The server starts listening immediately upon creation.
func NewDOCAComchServer(cfg DOCAComchServerConfig) (*DOCAComchServer, error) {
	if err := validateServerConfig(cfg); err != nil {
		return nil, err
	}

	bufSize := cfg.RecvBufferSize
	if bufSize <= 0 {
		bufSize = 16
	}

	s := &DOCAComchServer{
		pciAddr:     cfg.PCIAddr,
		repPCIAddr:  cfg.RepPCIAddr,
		serverName:  cfg.ServerName,
		maxMsgSize:  cfg.MaxMsgSize,
		bufferSize:  bufSize,
		connections: make(map[uint64]*DOCAComchServerConn),
		pendingChan: make(chan uint64, 32),
		done:        make(chan struct{}),
		epollFd:     -1,
		eventFd:     -1,
	}

	// Initialize DOCA ComCh server via C shim
	cPCI := C.CString(cfg.PCIAddr)
	cRepPCI := C.CString(cfg.RepPCIAddr)
	cName := C.CString(cfg.ServerName)
	defer C.free(unsafe.Pointer(cPCI))
	defer C.free(unsafe.Pointer(cRepPCI))
	defer C.free(unsafe.Pointer(cName))

	ret := C.shim_init_server(cPCI, cRepPCI, cName, C.uint32_t(cfg.MaxMsgSize))
	if ret != C.SHIM_OK {
		return nil, fmt.Errorf("doca comch server: init failed with code %d", ret)
	}

	// Get event fd for epoll integration
	s.eventFd = int(C.shim_server_get_event_fd())
	if s.eventFd < 0 {
		C.shim_server_cleanup()
		return nil, errors.New("doca comch server: failed to get event fd")
	}

	// Set up epoll
	var err error
	s.epollFd, err = syscall.EpollCreate1(0)
	if err != nil {
		C.shim_server_cleanup()
		return nil, fmt.Errorf("doca comch server: epoll create failed: %w", err)
	}

	event := syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(s.eventFd)}
	if err := syscall.EpollCtl(s.epollFd, syscall.EPOLL_CTL_ADD, s.eventFd, &event); err != nil {
		syscall.Close(s.epollFd)
		C.shim_server_cleanup()
		return nil, fmt.Errorf("doca comch server: epoll ctl failed: %w", err)
	}

	// Register server callbacks
	registerServerCallbacks(s)

	// Update max message size from negotiated value
	s.maxMsgSize = uint32(C.shim_server_get_max_msg_size())
	s.running = true

	// Start event loop
	go s.eventLoop()

	return s, nil
}

// eventLoop runs the epoll-based event processing loop for the server.
func (s *DOCAComchServer) eventLoop() {
	events := make([]syscall.EpollEvent, 1)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		// Arm DOCA notification before blocking
		C.shim_server_request_notification()

		// Block on epoll
		n, err := syscall.EpollWait(s.epollFd, events, 1000)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return
		}

		if n > 0 {
			// Clear notification and process DOCA events
			C.shim_server_clear_notification()

			// Process all pending events
			for C.shim_server_progress() != 0 {
				// Callbacks fire here
			}
		}

		// Check server state
		state := C.shim_server_get_state()
		if state == C.SHIM_STATE_ERROR {
			return
		}
	}
}

// Accept blocks until a new client connection is received.
// Returns a Transport for communicating with the connected client.
func (s *DOCAComchServer) Accept() (Transport, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("doca comch server: server closed")
	}
	s.mu.Unlock()

	select {
	case connID := <-s.pendingChan:
		s.mu.Lock()
		conn, ok := s.connections[connID]
		s.mu.Unlock()

		if !ok {
			return nil, errors.New("doca comch server: connection not found")
		}
		return conn, nil

	case <-s.done:
		return nil, errors.New("doca comch server: server closed")
	}
}

// Close stops the server and releases all resources.
func (s *DOCAComchServer) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.running = false

		// Close all active connections
		for _, conn := range s.connections {
			conn.Close()
		}
		s.connections = make(map[uint64]*DOCAComchServerConn)

		s.mu.Unlock()

		close(s.done)

		if s.epollFd >= 0 {
			syscall.Close(s.epollFd)
			s.epollFd = -1
		}

		C.shim_server_cleanup()
		unregisterServerCallbacks()
	})
	return nil
}

// Type returns the transport type identifier.
func (s *DOCAComchServer) Type() TransportType {
	return TransportDOCAComch
}

// onConnectionEvent handles connection status changes from the C layer.
func (s *DOCAComchServer) onConnectionEvent(connID uint64, event int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	if event == int(C.SHIM_CONN_EVENT_CONNECTED) {
		// Create new connection wrapper
		conn := &DOCAComchServerConn{
			connID:   connID,
			server:   s,
			recvChan: make(chan []byte, s.bufferSize),
			errChan:  make(chan error, 1),
			done:     make(chan struct{}),
		}
		s.connections[connID] = conn

		// Queue for Accept()
		select {
		case s.pendingChan <- connID:
		default:
			// Queue full, connection will be cleaned up
		}
	} else if event == int(C.SHIM_CONN_EVENT_DISCONNECTED) {
		if conn, ok := s.connections[connID]; ok {
			conn.Close()
			delete(s.connections, connID)
		}
	}
}

// onMessageReceived handles incoming messages from the C layer.
func (s *DOCAComchServer) onMessageReceived(connID uint64, data []byte) {
	s.mu.Lock()
	conn, ok := s.connections[connID]
	s.mu.Unlock()

	if !ok {
		return
	}

	select {
	case conn.recvChan <- data:
	default:
		// Channel full, message dropped
	}
}

// DOCAComchServerConn methods

// Connect is a no-op for server connections (already connected).
func (c *DOCAComchServerConn) Connect(ctx context.Context) error {
	// Server connections are already connected when returned from Accept()
	return nil
}

// Send transmits a message to the connected client.
func (c *DOCAComchServerConn) Send(msg *Message) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("doca comch: connection closed")
	}
	c.mu.Unlock()

	// Serialize message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("doca comch: marshal failed: %w", err)
	}

	// Check message size
	maxSize := c.server.maxMsgSize
	if maxSize > 0 && uint32(len(data)) > maxSize {
		return fmt.Errorf("doca comch: message too large (%d > %d)", len(data), maxSize)
	}

	// Send via C shim
	cData := C.CBytes(data)
	defer C.free(cData)

	ret := C.shim_server_send(C.shim_conn_id_t(c.connID), (*C.uint8_t)(cData), C.uint32_t(len(data)))
	if ret != C.SHIM_OK {
		switch ret {
		case C.SHIM_ERR_CONN_NOT_FOUND:
			return errors.New("doca comch: connection not found")
		case C.SHIM_ERR_QUEUE_FULL:
			return errors.New("doca comch: send queue full, try again")
		default:
			return fmt.Errorf("doca comch: send failed with code %d", ret)
		}
	}

	// Drive progress to actually send the message
	C.shim_server_progress()

	return nil
}

// Recv receives a message from the connected client.
// Blocks until a message is available or the connection is closed.
func (c *DOCAComchServerConn) Recv() (*Message, error) {
	select {
	case data, ok := <-c.recvChan:
		if !ok {
			return nil, errors.New("doca comch: connection closed")
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			return nil, fmt.Errorf("doca comch: unmarshal failed: %w", err)
		}
		return &msg, nil

	case err := <-c.errChan:
		return nil, err

	case <-c.done:
		return nil, errors.New("doca comch: connection closed")
	}
}

// Close terminates the connection.
func (c *DOCAComchServerConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()

		close(c.done)

		// Close the connection in C layer
		C.shim_server_close_connection(C.shim_conn_id_t(c.connID))
	})
	return nil
}

// Type returns the transport type identifier.
func (c *DOCAComchServerConn) Type() TransportType {
	return TransportDOCAComch
}

// State returns the current connection state.
func (c *DOCAComchServerConn) State() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return "disconnected"
	}
	return "connected"
}

// MaxMessageSize returns the negotiated maximum message size.
func (c *DOCAComchServerConn) MaxMessageSize() uint32 {
	if c.server != nil {
		return c.server.maxMsgSize
	}
	return 0
}
