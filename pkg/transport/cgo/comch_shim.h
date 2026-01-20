//go:build doca

// comch_shim.h - C shim layer for DOCA ComCh Go integration
// This provides thin wrappers around DOCA ComCh client and server functions for CGO.
// See ADR-007 for architecture details.

#ifndef COMCH_SHIM_H
#define COMCH_SHIM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Connection state values returned by shim_get_state() and shim_server_get_state()
typedef enum {
    SHIM_STATE_DISCONNECTED = 0,
    SHIM_STATE_CONNECTING = 1,
    SHIM_STATE_CONNECTED = 2,
    SHIM_STATE_ERROR = 3
} shim_state_t;

// Connection event types for server callbacks
typedef enum {
    SHIM_CONN_EVENT_CONNECTED = 0,
    SHIM_CONN_EVENT_DISCONNECTED = 1
} shim_conn_event_t;

// Error codes returned by shim functions
typedef enum {
    SHIM_OK = 0,
    SHIM_ERR_INVALID_ARG = -1,
    SHIM_ERR_DEVICE_OPEN = -2,
    SHIM_ERR_PE_CREATE = -3,
    SHIM_ERR_CLIENT_CREATE = -4,
    SHIM_ERR_PE_CONNECT = -5,
    SHIM_ERR_NOTIFICATION = -6,
    SHIM_ERR_START = -7,
    SHIM_ERR_NOT_CONNECTED = -8,
    SHIM_ERR_SEND_ALLOC = -9,
    SHIM_ERR_SEND_SUBMIT = -10,
    SHIM_ERR_QUEUE_FULL = -11,
    SHIM_ERR_ALREADY_INIT = -12,
    SHIM_ERR_NOT_INIT = -13,
    SHIM_ERR_SERVER_CREATE = -14,
    SHIM_ERR_REP_DEVICE_OPEN = -15,
    SHIM_ERR_NO_CONNECTION = -16,
    SHIM_ERR_CONN_NOT_FOUND = -17
} shim_error_t;

// Opaque connection handle for server-side connections
typedef uint64_t shim_conn_id_t;

// shim_init_client initializes a DOCA ComCh client connection.
// Arguments:
//   pci_addr: PCI address of the DOCA device (e.g., "01:00.0")
//   server_name: Name of the ComCh server to connect to
//   max_msg_size: Maximum message size in bytes (0 for default)
// Returns: SHIM_OK on success, error code on failure
int shim_init_client(const char *pci_addr, const char *server_name, uint32_t max_msg_size);

// shim_send sends a message to the connected server.
// Arguments:
//   data: Pointer to message data
//   len: Length of message data in bytes
// Returns: SHIM_OK on success, error code on failure
int shim_send(const uint8_t *data, uint32_t len);

// shim_get_event_fd returns the file descriptor for epoll integration.
// This fd becomes readable when there are events to process.
// Returns: File descriptor on success, -1 on error
int shim_get_event_fd(void);

// shim_request_notification arms the notification mechanism.
// Must be called before blocking on the event fd.
void shim_request_notification(void);

// shim_clear_notification clears the notification after epoll wakes up.
// Must be called before processing events.
void shim_clear_notification(void);

// shim_progress drives the DOCA progress engine.
// Processes pending events and invokes callbacks.
// Returns: Number of events processed (0 means no work)
int shim_progress(void);

// shim_get_state returns the current connection state.
// Returns: shim_state_t value
int shim_get_state(void);

// shim_cleanup releases all DOCA resources.
// Safe to call multiple times or if init was not called.
void shim_cleanup(void);

// shim_get_max_msg_size returns the negotiated maximum message size.
// Returns: Maximum message size in bytes, or 0 if not connected
uint32_t shim_get_max_msg_size(void);

// ============================================================================
// Server API (DPU side)
// ============================================================================

// shim_init_server initializes a DOCA ComCh server.
// Arguments:
//   pci_addr: PCI address of the DOCA device (e.g., "03:00.0")
//   rep_pci_addr: Representor PCI address for host device (e.g., "01:00.0")
//   server_name: Name of the ComCh server for client discovery
//   max_msg_size: Maximum message size in bytes (0 for default)
// Returns: SHIM_OK on success, error code on failure
int shim_init_server(const char *pci_addr, const char *rep_pci_addr,
                     const char *server_name, uint32_t max_msg_size);

// shim_server_get_event_fd returns the file descriptor for epoll integration.
// Returns: File descriptor on success, -1 on error
int shim_server_get_event_fd(void);

// shim_server_request_notification arms the notification mechanism.
void shim_server_request_notification(void);

// shim_server_clear_notification clears the notification after epoll wakes up.
void shim_server_clear_notification(void);

// shim_server_progress drives the DOCA progress engine for server.
// Returns: Number of events processed (0 means no work)
int shim_server_progress(void);

// shim_server_get_state returns the current server state.
// Returns: shim_state_t value
int shim_server_get_state(void);

// shim_server_accept_connection pops the next pending connection from the queue.
// Arguments:
//   conn_id: Output parameter for the connection ID
// Returns: SHIM_OK if connection available, SHIM_ERR_NO_CONNECTION if none pending
int shim_server_accept_connection(shim_conn_id_t *conn_id);

// shim_server_send sends a message on a specific connection.
// Arguments:
//   conn_id: Connection ID from shim_server_accept_connection
//   data: Pointer to message data
//   len: Length of message data in bytes
// Returns: SHIM_OK on success, error code on failure
int shim_server_send(shim_conn_id_t conn_id, const uint8_t *data, uint32_t len);

// shim_server_close_connection closes a specific client connection.
// Arguments:
//   conn_id: Connection ID to close
// Returns: SHIM_OK on success, SHIM_ERR_CONN_NOT_FOUND if connection not found
int shim_server_close_connection(shim_conn_id_t conn_id);

// shim_server_cleanup releases all server DOCA resources.
void shim_server_cleanup(void);

// shim_server_get_max_msg_size returns the server's maximum message size.
// Returns: Maximum message size in bytes, or 0 if not initialized
uint32_t shim_server_get_max_msg_size(void);

#ifdef __cplusplus
}
#endif

#endif // COMCH_SHIM_H
