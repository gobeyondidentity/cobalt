//go:build doca

// Client-side (host) DOCA ComCh implementation. Requires DOCA SDK.
package transport

/*
#cgo CFLAGS: -I/opt/mellanox/doca/include -I${SRCDIR}/csrc
#cgo linux,arm64 LDFLAGS: -L/opt/mellanox/doca/lib/aarch64-linux-gnu -ldoca_comch -ldoca_common -ldoca_argp -lstdc++
#cgo linux,amd64 LDFLAGS: -L/opt/mellanox/doca/lib/x86_64-linux-gnu -ldoca_comch -ldoca_common -ldoca_argp -lstdc++

#include <stdlib.h>
#include "comch_shim.h"
#include "comch_shim.c"
*/
import "C"
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// DOCAComchClient implements Transport using NVIDIA DOCA ComCh API.
// This is the host-side client that connects to a DPU running a ComCh server.
// It uses an epoll-based event loop for efficient I/O (no busy polling).
type DOCAComchClient struct {
	mu sync.Mutex

	// Configuration
	pciAddr    string
	serverName string
	maxMsgSize uint32

	// Channels for message passing
	recvChan chan []byte
	errChan  chan error

	// Epoll state
	epollFd int
	eventFd int

	// Lifecycle
	done      chan struct{}
	closeOnce sync.Once
	closed    bool
	connected bool
}

// DOCAComchClientConfig holds configuration for DOCA ComCh client.
type DOCAComchClientConfig struct {
	// PCIAddr is the PCI address of the BlueField device (e.g., "01:00.0").
	PCIAddr string

	// ServerName is the ComCh server name to connect to.
	ServerName string

	// MaxMsgSize is the maximum message size in bytes (0 for default).
	MaxMsgSize uint32

	// RecvBufferSize is the channel buffer size for received messages.
	// Default is 16 if not specified.
	RecvBufferSize int
}

// NewDOCAComchClient creates a new DOCA ComCh client transport.
// Call Connect() to establish the connection to the DPU.
func NewDOCAComchClient(cfg DOCAComchClientConfig) (*DOCAComchClient, error) {
	if cfg.PCIAddr == "" {
		return nil, errors.New("doca comch: PCI address required")
	}
	if cfg.ServerName == "" {
		return nil, errors.New("doca comch: server name required")
	}

	bufSize := cfg.RecvBufferSize
	if bufSize <= 0 {
		bufSize = 16
	}

	return &DOCAComchClient{
		pciAddr:    cfg.PCIAddr,
		serverName: cfg.ServerName,
		maxMsgSize: cfg.MaxMsgSize,
		recvChan:   make(chan []byte, bufSize),
		errChan:    make(chan error, 1),
		done:       make(chan struct{}),
		epollFd:    -1,
		eventFd:    -1,
	}, nil
}

// Connect establishes the DOCA ComCh connection to the DPU server.
// This initializes the DOCA resources and starts the event loop goroutine.
func (c *DOCAComchClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return errors.New("doca comch: transport closed")
	}
	if c.connected {
		return errors.New("doca comch: already connected")
	}

	// Initialize DOCA ComCh client via C shim
	cPCI := C.CString(c.pciAddr)
	cName := C.CString(c.serverName)
	defer C.free(unsafe.Pointer(cPCI))
	defer C.free(unsafe.Pointer(cName))

	ret := C.shim_init_client(cPCI, cName, C.uint32_t(c.maxMsgSize))
	if ret != C.SHIM_OK {
		return fmt.Errorf("doca comch: init failed with code %d", ret)
	}

	// Get event fd for epoll integration
	c.eventFd = int(C.shim_get_event_fd())
	if c.eventFd < 0 {
		C.shim_cleanup()
		return errors.New("doca comch: failed to get event fd")
	}

	// Set up epoll
	var err error
	c.epollFd, err = syscall.EpollCreate1(0)
	if err != nil {
		C.shim_cleanup()
		return fmt.Errorf("doca comch: epoll create failed: %w", err)
	}

	event := syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(c.eventFd)}
	if err := syscall.EpollCtl(c.epollFd, syscall.EPOLL_CTL_ADD, c.eventFd, &event); err != nil {
		syscall.Close(c.epollFd)
		C.shim_cleanup()
		return fmt.Errorf("doca comch: epoll ctl failed: %w", err)
	}

	// Register the receive channel for callbacks
	registerComchRecvChan(c.recvChan)

	// Wait for connection to establish (STARTING -> RUNNING)
	connectTimeout := 30 * time.Second
	deadline := time.Now().Add(connectTimeout)
	for {
		select {
		case <-ctx.Done():
			c.cleanupLocked()
			return ctx.Err()
		default:
		}

		state := C.shim_get_state()
		if state == C.SHIM_STATE_CONNECTED {
			break
		}
		if state == C.SHIM_STATE_ERROR {
			c.cleanupLocked()
			return errors.New("doca comch: connection failed")
		}

		if time.Now().After(deadline) {
			c.cleanupLocked()
			return errors.New("doca comch: connection timeout")
		}

		// Progress to process state changes
		C.shim_progress()
		time.Sleep(10 * time.Millisecond)
	}

	c.connected = true

	// Update max message size from negotiated value
	c.maxMsgSize = uint32(C.shim_get_max_msg_size())

	// Start event loop
	go c.eventLoop()

	return nil
}

// MaxMsgSize returns the negotiated maximum message size.
// This is the actual limit negotiated with DOCA hardware, which may be less
// than the requested MaxMsgSize in the config.
func (c *DOCAComchClient) MaxMsgSize() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxMsgSize
}

// eventLoop runs the epoll-based event processing loop.
// It blocks on epoll_wait and processes DOCA events when they arrive.
func (c *DOCAComchClient) eventLoop() {
	events := make([]syscall.EpollEvent, 1)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		// Arm DOCA notification before blocking
		C.shim_request_notification()

		// Block on epoll (Go syscall, not CGO - cheap!)
		n, err := syscall.EpollWait(c.epollFd, events, 1000) // 1 second timeout
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			// Report error and exit
			select {
			case c.errChan <- fmt.Errorf("doca comch: epoll wait failed: %w", err):
			default:
			}
			return
		}

		if n > 0 {
			// Clear notification and process DOCA events
			C.shim_clear_notification()

			// Process all pending events
			for C.shim_progress() != 0 {
				// Callbacks fire here, delivering messages to recvChan
			}
		}

		// Check connection state
		state := C.shim_get_state()
		if state == C.SHIM_STATE_DISCONNECTED || state == C.SHIM_STATE_ERROR {
			select {
			case c.errChan <- errors.New("doca comch: connection lost"):
			default:
			}
			return
		}
	}
}

// Send transmits a message over the DOCA ComCh channel.
func (c *DOCAComchClient) Send(msg *Message) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("doca comch: transport closed")
	}
	if !c.connected {
		c.mu.Unlock()
		return errors.New("doca comch: not connected")
	}
	c.mu.Unlock()

	// Serialize message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("doca comch: marshal failed: %w", err)
	}

	// Check message size
	if c.maxMsgSize > 0 && uint32(len(data)) > c.maxMsgSize {
		return fmt.Errorf("doca comch: message too large (%d > %d)", len(data), c.maxMsgSize)
	}

	// Send via C shim
	cData := C.CBytes(data)
	defer C.free(cData)

	ret := C.shim_send((*C.uint8_t)(cData), C.uint32_t(len(data)))
	if ret != C.SHIM_OK {
		switch ret {
		case C.SHIM_ERR_NOT_CONNECTED:
			return errors.New("doca comch: not connected")
		case C.SHIM_ERR_QUEUE_FULL:
			return errors.New("doca comch: send queue full, try again")
		default:
			return fmt.Errorf("doca comch: send failed with code %d", ret)
		}
	}

	// Drive progress to actually send the message
	C.shim_progress()

	return nil
}

// Recv receives a message from the DOCA ComCh channel.
// Blocks until a message is available or the transport is closed.
func (c *DOCAComchClient) Recv() (*Message, error) {
	select {
	case data, ok := <-c.recvChan:
		if !ok {
			return nil, errors.New("doca comch: transport closed")
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			return nil, fmt.Errorf("doca comch: unmarshal failed: %w", err)
		}
		return &msg, nil

	case err := <-c.errChan:
		return nil, err

	case <-c.done:
		return nil, errors.New("doca comch: transport closed")
	}
}

// Close terminates the DOCA ComCh connection and releases resources.
func (c *DOCAComchClient) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.closed = true
		close(c.done)
		c.cleanupLocked()
	})
	return nil
}

// cleanupLocked releases DOCA and epoll resources.
// Must be called with mu held.
func (c *DOCAComchClient) cleanupLocked() {
	if c.epollFd >= 0 {
		syscall.Close(c.epollFd)
		c.epollFd = -1
	}
	C.shim_cleanup()
	c.connected = false
	unregisterComchRecvChan()
}

// Type returns the transport type identifier.
func (c *DOCAComchClient) Type() TransportType {
	return TransportDOCAComch
}

// State returns the current connection state as a string.
func (c *DOCAComchClient) State() string {
	state := C.shim_get_state()
	switch state {
	case C.SHIM_STATE_DISCONNECTED:
		return "disconnected"
	case C.SHIM_STATE_CONNECTING:
		return "connecting"
	case C.SHIM_STATE_CONNECTED:
		return "connected"
	case C.SHIM_STATE_ERROR:
		return "error"
	default:
		return "unknown"
	}
}

// MaxMessageSize returns the negotiated maximum message size.
func (c *DOCAComchClient) MaxMessageSize() uint32 {
	return c.maxMsgSize
}
