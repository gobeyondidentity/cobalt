//go:build doca

package transport

/*
#include <stdint.h>
#include "cgo/comch_shim.h"
*/
import "C"
import (
	"sync"
	"unsafe"
)

// globalServerInstance holds the active server instance for callbacks.
var (
	globalServerInstance *DOCAComchServer
	globalServerMu       sync.Mutex
)

// registerServerCallbacks registers the server instance for C callbacks.
func registerServerCallbacks(s *DOCAComchServer) {
	globalServerMu.Lock()
	globalServerInstance = s
	globalServerMu.Unlock()
}

// unregisterServerCallbacks clears the server instance.
func unregisterServerCallbacks() {
	globalServerMu.Lock()
	globalServerInstance = nil
	globalServerMu.Unlock()
}

// goOnServerMessageReceived is called from C when a message is received on a connection.
// It copies the data from C memory and delivers it to the appropriate connection.
//
//export goOnServerMessageReceived
func goOnServerMessageReceived(connID C.shim_conn_id_t, data *C.uint8_t, length C.uint32_t) {
	globalServerMu.Lock()
	server := globalServerInstance
	globalServerMu.Unlock()

	if server == nil {
		return
	}

	// Copy data from C memory to Go-owned slice
	msg := C.GoBytes(unsafe.Pointer(data), C.int(length))

	// Deliver to the server
	server.onMessageReceived(uint64(connID), msg)
}

// goOnServerConnectionEvent is called from C when a connection status changes.
//
//export goOnServerConnectionEvent
func goOnServerConnectionEvent(connID C.shim_conn_id_t, event C.int) {
	globalServerMu.Lock()
	server := globalServerInstance
	globalServerMu.Unlock()

	if server == nil {
		return
	}

	server.onConnectionEvent(uint64(connID), int(event))
}
