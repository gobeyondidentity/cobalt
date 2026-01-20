package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

const (
	// maxMessageSize limits the size of incoming messages over tmfifo.
	maxMessageSize = 64 * 1024 // 64KB
)

var (
	// ErrTmfifoDeviceNotFound indicates the tmfifo device does not exist.
	ErrTmfifoDeviceNotFound = errors.New("tmfifo device not found")

	// ErrTmfifoAlreadyConnected indicates the device already has an active connection.
	ErrTmfifoAlreadyConnected = errors.New("tmfifo device already has active connection")
)

// TmfifoNetTransport implements Transport using the tmfifo_net0 device.
// This transport wraps the BlueField tmfifo character device for
// bidirectional communication between DPU and host.
type TmfifoNetTransport struct {
	device     *os.File
	devicePath string
	reader     *bufio.Reader

	connected bool
	closed    bool
	mu        sync.Mutex
}

// newTmfifoNetTransportFromDevice creates a transport wrapping an already-opened device.
// Used internally by TmfifoNetListener.Accept().
func newTmfifoNetTransportFromDevice(device *os.File, devicePath string) *TmfifoNetTransport {
	return &TmfifoNetTransport{
		device:     device,
		devicePath: devicePath,
		reader:     bufio.NewReaderSize(device, maxMessageSize),
		connected:  true, // Already connected when created by listener
	}
}

// NewTmfifoNetTransport creates a client-side transport using the tmfifo_net0 device.
// Call Connect() to open the device before use.
func NewTmfifoNetTransport(devicePath string) (Transport, error) {
	if devicePath == "" {
		devicePath = DefaultTmfifoPath
	}

	// Verify device exists
	if _, err := os.Stat(devicePath); os.IsNotExist(err) {
		return nil, ErrTmfifoDeviceNotFound
	}

	return &TmfifoNetTransport{
		devicePath: devicePath,
	}, nil
}

// Connect opens the tmfifo device for communication.
// For server-side transports returned by Accept(), this is a no-op.
// For client-side transports, this opens the device.
func (t *TmfifoNetTransport) Connect(_ context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("transport closed")
	}
	if t.connected {
		return nil // Already connected
	}

	// Client-side: open the device
	device, err := os.OpenFile(t.devicePath, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open tmfifo device: %w", err)
	}
	t.device = device
	t.reader = bufio.NewReaderSize(device, maxMessageSize)
	t.connected = true

	log.Printf("tmfifo: connected to %s", t.devicePath)
	return nil
}

// Send transmits a message over the tmfifo device.
// Messages are JSON-encoded and newline-delimited.
func (t *TmfifoNetTransport) Send(msg *Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("transport closed")
	}
	if !t.connected {
		return errors.New("transport not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Write message with newline delimiter
	data = append(data, '\n')
	if _, err := t.device.Write(data); err != nil {
		return fmt.Errorf("write to tmfifo: %w", err)
	}

	log.Printf("tmfifo: sent %s message (nonce=%s)", msg.Type, msg.ID)
	return nil
}

// Recv blocks until a message is received from the tmfifo device.
// Returns io.EOF if the device is closed.
func (t *TmfifoNetTransport) Recv() (*Message, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, io.EOF
	}
	if !t.connected {
		t.mu.Unlock()
		return nil, errors.New("transport not connected")
	}
	reader := t.reader
	t.mu.Unlock()

	// Read until newline (message delimiter)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		if err == io.EOF || errors.Is(err, os.ErrClosed) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read from tmfifo: %w", err)
	}

	if len(line) == 0 {
		return nil, errors.New("empty message received")
	}

	var msg Message
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}

	log.Printf("tmfifo: received %s message (nonce=%s)", msg.Type, msg.ID)
	return &msg, nil
}

// Close terminates the transport and releases the device.
func (t *TmfifoNetTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	t.connected = false

	if t.device != nil {
		if err := t.device.Close(); err != nil {
			return fmt.Errorf("close tmfifo device: %w", err)
		}
	}

	log.Printf("tmfifo: transport closed")
	return nil
}

// Type returns TransportTmfifoNet.
func (t *TmfifoNetTransport) Type() TransportType {
	return TransportTmfifoNet
}

// TmfifoNetListener implements TransportListener for the tmfifo_net0 device.
// Since tmfifo is a single bidirectional device (not connection-oriented),
// Accept() returns a transport wrapping the device and blocks subsequent
// Accept calls until the current transport is closed.
type TmfifoNetListener struct {
	devicePath string

	currentTransport *TmfifoNetTransport
	closed           bool
	mu               sync.Mutex

	// acceptCh allows Accept() to wait for the previous transport to close
	acceptCh chan struct{}
}

// NewTmfifoNetListener creates a listener for the tmfifo_net0 device.
// The device path defaults to /dev/tmfifo_net0 if empty.
func NewTmfifoNetListener(devicePath string) (*TmfifoNetListener, error) {
	if devicePath == "" {
		devicePath = DefaultTmfifoPath
	}

	// Verify device exists
	if _, err := os.Stat(devicePath); os.IsNotExist(err) {
		return nil, ErrTmfifoDeviceNotFound
	}

	l := &TmfifoNetListener{
		devicePath: devicePath,
		acceptCh:   make(chan struct{}, 1),
	}

	// Signal that Accept can proceed initially
	l.acceptCh <- struct{}{}

	return l, nil
}

// Accept opens the tmfifo device and returns a Transport for communication.
// Since tmfifo is a single device, only one transport can be active at a time.
// Accept blocks if a transport is already active, until it is closed.
func (l *TmfifoNetListener) Accept() (Transport, error) {
	// Wait for permission to accept (i.e., no active transport)
	<-l.acceptCh

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, errors.New("listener closed")
	}
	devicePath := l.devicePath
	l.mu.Unlock()

	// Open device for read/write
	device, err := os.OpenFile(devicePath, os.O_RDWR, 0600)
	if err != nil {
		// Put the accept token back so future Accept calls can try
		l.acceptCh <- struct{}{}
		return nil, fmt.Errorf("open tmfifo device: %w", err)
	}

	transport := newTmfifoNetTransportFromDevice(device, devicePath)

	l.mu.Lock()
	l.currentTransport = transport
	l.mu.Unlock()

	log.Printf("tmfifo: accepted connection on %s", devicePath)

	// Start goroutine to watch for transport close and release accept token
	go l.watchTransportClose(transport)

	return transport, nil
}

// watchTransportClose monitors a transport and releases the accept token when closed.
func (l *TmfifoNetListener) watchTransportClose(t *TmfifoNetTransport) {
	// Poll for transport closure
	for {
		t.mu.Lock()
		closed := t.closed
		t.mu.Unlock()

		if closed {
			break
		}

		// Check listener closure
		l.mu.Lock()
		listenerClosed := l.closed
		l.mu.Unlock()

		if listenerClosed {
			return
		}

		// Small sleep to avoid busy loop
		time.Sleep(100 * time.Millisecond)
	}

	l.mu.Lock()
	l.currentTransport = nil
	// Release accept token if listener not closed
	if !l.closed {
		select {
		case l.acceptCh <- struct{}{}:
		default:
		}
	}
	l.mu.Unlock()
}

// Close stops the listener and closes any active transport.
func (l *TmfifoNetListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true

	// Close any active transport
	if l.currentTransport != nil {
		l.currentTransport.Close()
		l.currentTransport = nil
	}

	close(l.acceptCh)

	log.Printf("tmfifo: listener closed")
	return nil
}

// Type returns TransportTmfifoNet.
func (l *TmfifoNetListener) Type() TransportType {
	return TransportTmfifoNet
}
