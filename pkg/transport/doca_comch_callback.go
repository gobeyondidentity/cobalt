//go:build doca

package transport

/*
#include <stdint.h>
*/
import "C"
import (
	"sync"
	"unsafe"
)

// globalComchRecvChan is the channel where received messages are delivered.
// Set by registerComchRecvChan when a client connects.
var (
	globalComchRecvChan chan []byte
	globalComchMu       sync.Mutex
)

// registerComchRecvChan sets the channel for message delivery.
// Called during Connect() to link the C callbacks to the Go client.
func registerComchRecvChan(ch chan []byte) {
	globalComchMu.Lock()
	globalComchRecvChan = ch
	globalComchMu.Unlock()
}

// unregisterComchRecvChan clears the message delivery channel.
// Called during Close() to prevent callbacks to closed channels.
func unregisterComchRecvChan() {
	globalComchMu.Lock()
	globalComchRecvChan = nil
	globalComchMu.Unlock()
}

// goOnMessageReceived is called from C when a message is received.
// It copies the data from C memory (which will be reused) to a Go-owned
// byte slice and delivers it to the registered channel.
//
//export goOnMessageReceived
func goOnMessageReceived(data *C.uint8_t, length C.uint32_t) {
	globalComchMu.Lock()
	ch := globalComchRecvChan
	globalComchMu.Unlock()

	if ch == nil {
		// No receiver registered, drop the message
		return
	}

	// Copy data from C memory to Go-owned slice
	// The C buffer is reused by DOCA, so we must copy
	msg := C.GoBytes(unsafe.Pointer(data), C.int(length))

	// Non-blocking send to avoid deadlock if channel is full
	// In high-throughput scenarios, the application should drain quickly
	select {
	case ch <- msg:
		// Message delivered
	default:
		// Channel full, message dropped
		// This shouldn't happen with normal message rates
		// TODO: Add metrics counter for dropped messages
	}
}
