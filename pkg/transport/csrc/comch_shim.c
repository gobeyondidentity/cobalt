// comch_shim.c - C shim layer for DOCA ComCh Go integration
// Provides thin wrappers around DOCA ComCh client API for CGO.
// See ADR-007 for architecture details.

#include <stdlib.h>
#include <string.h>
#include <doca_comch.h>
#include <doca_pe.h>
#include <doca_dev.h>
#include <doca_ctx.h>
#include <doca_error.h>
#include <doca_log.h>

#include "comch_shim.h"

// Forward declarations for Go-exported callback functions.
// These are implemented by CGO from //export directives in Go code.
// We declare them here instead of including _cgo_export.h because this
// file is #include'd inline by Go files before _cgo_export.h is generated.
extern void goOnMessageReceived(uint8_t *data, uint32_t len);
extern void goOnServerMessageReceived(uint64_t conn_id, uint8_t *data, uint32_t len);
extern void goOnServerConnectionEvent(uint64_t conn_id, int event);

DOCA_LOG_REGISTER(COMCH_SHIM);

// Global state - single client instance per process
static struct doca_comch_client *g_client = NULL;
static struct doca_pe *g_pe = NULL;
static struct doca_dev *g_dev = NULL;
static struct doca_comch_connection *g_conn = NULL;
static doca_notification_handle_t g_notification_handle;
static shim_state_t g_state = SHIM_STATE_DISCONNECTED;
static uint32_t g_max_msg_size = 0;

// Forward declarations for callbacks
static void msg_recv_cb(struct doca_comch_event_msg_recv *event,
                        uint8_t *recv_buffer, uint32_t msg_len,
                        struct doca_comch_connection *conn);
static void send_complete_cb(struct doca_comch_task_send *task,
                             union doca_data task_user_data,
                             union doca_data ctx_user_data);
static void send_error_cb(struct doca_comch_task_send *task,
                          union doca_data task_user_data,
                          union doca_data ctx_user_data);
static void state_changed_cb(const union doca_data user_data,
                             struct doca_ctx *ctx,
                             enum doca_ctx_states prev_state,
                             enum doca_ctx_states next_state);

// Helper: open DOCA device by PCI address
static doca_error_t open_device_by_pci(const char *pci_addr, struct doca_dev **dev) {
    struct doca_devinfo **dev_list = NULL;
    uint32_t nb_devs = 0;
    doca_error_t result;
    char pci_buf[DOCA_DEVINFO_PCI_ADDR_SIZE];

    result = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create device list: %s", doca_error_get_descr(result));
        return result;
    }

    *dev = NULL;
    for (uint32_t i = 0; i < nb_devs; i++) {
        result = doca_devinfo_get_pci_addr_str(dev_list[i], pci_buf);
        if (result != DOCA_SUCCESS)
            continue;

        if (strcmp(pci_buf, pci_addr) == 0) {
            result = doca_dev_open(dev_list[i], dev);
            if (result == DOCA_SUCCESS) {
                doca_devinfo_destroy_list(dev_list);
                return DOCA_SUCCESS;
            }
        }
    }

    doca_devinfo_destroy_list(dev_list);
    DOCA_LOG_ERR("Device with PCI address %s not found", pci_addr);
    return DOCA_ERROR_NOT_FOUND;
}

// Callback: message received from server
static void msg_recv_cb(struct doca_comch_event_msg_recv *event,
                        uint8_t *recv_buffer, uint32_t msg_len,
                        struct doca_comch_connection *conn) {
    (void)event;
    (void)conn;

    DOCA_LOG_DBG("Message received: %u bytes", msg_len);

    // Call back into Go with the received message
    goOnMessageReceived(recv_buffer, msg_len);
}

// Callback: send task completed successfully
static void send_complete_cb(struct doca_comch_task_send *task,
                             union doca_data task_user_data,
                             union doca_data ctx_user_data) {
    (void)task_user_data;
    (void)ctx_user_data;

    DOCA_LOG_DBG("Send task completed");
    doca_task_free(doca_comch_task_send_as_task(task));
}

// Callback: send task failed
static void send_error_cb(struct doca_comch_task_send *task,
                          union doca_data task_user_data,
                          union doca_data ctx_user_data) {
    (void)task_user_data;
    (void)ctx_user_data;

    DOCA_LOG_ERR("Send task failed");
    doca_task_free(doca_comch_task_send_as_task(task));
}

// Callback: context state changed
static void state_changed_cb(const union doca_data user_data,
                             struct doca_ctx *ctx,
                             enum doca_ctx_states prev_state,
                             enum doca_ctx_states next_state) {
    (void)user_data;
    (void)ctx;

    DOCA_LOG_DBG("State changed: %d -> %d", prev_state, next_state);

    switch (next_state) {
    case DOCA_CTX_STATE_IDLE:
        g_state = SHIM_STATE_DISCONNECTED;
        g_conn = NULL;
        break;
    case DOCA_CTX_STATE_STARTING:
        g_state = SHIM_STATE_CONNECTING;
        break;
    case DOCA_CTX_STATE_RUNNING:
        g_state = SHIM_STATE_CONNECTED;
        // Get the connection handle now that we're connected
        doca_comch_client_get_connection(g_client, &g_conn);
        break;
    case DOCA_CTX_STATE_STOPPING:
        g_state = SHIM_STATE_DISCONNECTED;
        break;
    default:
        break;
    }
}

int shim_init_client(const char *pci_addr, const char *server_name, uint32_t max_msg_size) {
    doca_error_t result;

    if (pci_addr == NULL || server_name == NULL) {
        return SHIM_ERR_INVALID_ARG;
    }

    if (g_client != NULL) {
        return SHIM_ERR_ALREADY_INIT;
    }

    // Open device
    result = open_device_by_pci(pci_addr, &g_dev);
    if (result != DOCA_SUCCESS) {
        return SHIM_ERR_DEVICE_OPEN;
    }

    // Create progress engine
    result = doca_pe_create(&g_pe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create PE: %s", doca_error_get_descr(result));
        goto err_pe;
    }

    // Create ComCh client
    result = doca_comch_client_create(g_dev, server_name, &g_client);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create client: %s", doca_error_get_descr(result));
        goto err_client;
    }

    // Set max message size if specified
    if (max_msg_size > 0) {
        result = doca_comch_client_set_max_msg_size(g_client, max_msg_size);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_WARN("Failed to set max msg size: %s", doca_error_get_descr(result));
        }
    }

    // Get the context for configuration
    struct doca_ctx *ctx = doca_comch_client_as_ctx(g_client);

    // Register state change callback
    union doca_data user_data = {0};
    result = doca_ctx_set_state_changed_cb(ctx, state_changed_cb);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_WARN("Failed to set state changed callback: %s", doca_error_get_descr(result));
    }

    // Connect PE to context
    result = doca_pe_connect_ctx(g_pe, ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to connect PE: %s", doca_error_get_descr(result));
        goto err_connect;
    }

    // Configure send task callbacks
    result = doca_comch_client_task_send_set_conf(g_client, send_complete_cb, send_error_cb, 64);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set send conf: %s", doca_error_get_descr(result));
        goto err_connect;
    }

    // Register message receive callback
    result = doca_comch_client_event_msg_recv_register(g_client, msg_recv_cb);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register msg recv: %s", doca_error_get_descr(result));
        goto err_connect;
    }

    // Get notification handle for epoll integration
    result = doca_pe_get_notification_handle(g_pe, &g_notification_handle);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to get notification handle: %s", doca_error_get_descr(result));
        goto err_connect;
    }

    // Start the context (will transition IDLE -> STARTING -> RUNNING)
    g_state = SHIM_STATE_CONNECTING;
    result = doca_ctx_start(ctx);
    if (result != DOCA_ERROR_IN_PROGRESS && result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to start context: %s", doca_error_get_descr(result));
        g_state = SHIM_STATE_ERROR;
        goto err_connect;
    }

    // Get max message size after initialization
    result = doca_comch_client_get_max_msg_size(g_client, &g_max_msg_size);
    if (result != DOCA_SUCCESS) {
        g_max_msg_size = 4096;  // Default fallback
    }

    DOCA_LOG_INFO("Client initialized, connecting to server '%s'", server_name);
    return SHIM_OK;

err_connect:
    doca_comch_client_destroy(g_client);
    g_client = NULL;
err_client:
    doca_pe_destroy(g_pe);
    g_pe = NULL;
err_pe:
    doca_dev_close(g_dev);
    g_dev = NULL;
    return SHIM_ERR_CLIENT_CREATE;
}

int shim_send(const uint8_t *data, uint32_t len) {
    if (g_client == NULL) {
        return SHIM_ERR_NOT_INIT;
    }

    if (g_conn == NULL || g_state != SHIM_STATE_CONNECTED) {
        return SHIM_ERR_NOT_CONNECTED;
    }

    if (data == NULL || len == 0) {
        return SHIM_ERR_INVALID_ARG;
    }

    struct doca_comch_task_send *task = NULL;
    doca_error_t result = doca_comch_client_task_send_alloc_init(
        g_client, g_conn, data, len, &task);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to alloc send task: %s", doca_error_get_descr(result));
        return SHIM_ERR_SEND_ALLOC;
    }

    result = doca_task_submit(doca_comch_task_send_as_task(task));
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to submit send task: %s", doca_error_get_descr(result));
        doca_task_free(doca_comch_task_send_as_task(task));
        if (result == DOCA_ERROR_AGAIN) {
            return SHIM_ERR_QUEUE_FULL;
        }
        return SHIM_ERR_SEND_SUBMIT;
    }

    return SHIM_OK;
}

int shim_get_event_fd(void) {
    if (g_pe == NULL) {
        return -1;
    }
    // On Linux, doca_notification_handle_t is a file descriptor (int)
    return (int)g_notification_handle;
}

void shim_request_notification(void) {
    if (g_pe != NULL) {
        doca_pe_request_notification(g_pe);
    }
}

void shim_clear_notification(void) {
    if (g_pe != NULL) {
        doca_pe_clear_notification(g_pe, g_notification_handle);
    }
}

int shim_progress(void) {
    if (g_pe == NULL) {
        return 0;
    }
    return doca_pe_progress(g_pe);
}

int shim_get_state(void) {
    return (int)g_state;
}

void shim_cleanup(void) {
    if (g_client != NULL) {
        struct doca_ctx *ctx = doca_comch_client_as_ctx(g_client);
        doca_ctx_stop(ctx);

        // Progress until idle
        while (g_state != SHIM_STATE_DISCONNECTED && g_pe != NULL) {
            doca_pe_progress(g_pe);
        }

        doca_comch_client_destroy(g_client);
        g_client = NULL;
    }

    if (g_pe != NULL) {
        doca_pe_destroy(g_pe);
        g_pe = NULL;
    }

    if (g_dev != NULL) {
        doca_dev_close(g_dev);
        g_dev = NULL;
    }

    g_conn = NULL;
    g_state = SHIM_STATE_DISCONNECTED;
    g_max_msg_size = 0;

    DOCA_LOG_INFO("Client cleanup complete");
}

uint32_t shim_get_max_msg_size(void) {
    return g_max_msg_size;
}

// ============================================================================
// Server Implementation (DPU side)
// ============================================================================

// Maximum number of concurrent client connections
#define MAX_SERVER_CONNECTIONS 64

// Connection tracking for server
typedef struct {
    struct doca_comch_connection *conn;
    shim_conn_id_t id;
    int active;
} server_conn_entry_t;

// Server global state
static struct doca_comch_server *g_server = NULL;
static struct doca_pe *g_server_pe = NULL;
static struct doca_dev *g_server_dev = NULL;
static struct doca_dev_rep *g_server_rep = NULL;
static doca_notification_handle_t g_server_notification_handle;
static shim_state_t g_server_state = SHIM_STATE_DISCONNECTED;
static uint32_t g_server_max_msg_size = 0;

// Connection tracking
static server_conn_entry_t g_server_conns[MAX_SERVER_CONNECTIONS];
static shim_conn_id_t g_next_conn_id = 1;

// Queue for newly accepted connections (pending Accept() calls from Go)
#define PENDING_CONN_QUEUE_SIZE 32
static shim_conn_id_t g_pending_conns[PENDING_CONN_QUEUE_SIZE];
static int g_pending_head = 0;
static int g_pending_tail = 0;

// Forward declarations for server callbacks
static void server_msg_recv_cb(struct doca_comch_event_msg_recv *event,
                               uint8_t *recv_buffer, uint32_t msg_len,
                               struct doca_comch_connection *conn);
static void server_send_complete_cb(struct doca_comch_task_send *task,
                                    union doca_data task_user_data,
                                    union doca_data ctx_user_data);
static void server_send_error_cb(struct doca_comch_task_send *task,
                                 union doca_data task_user_data,
                                 union doca_data ctx_user_data);
static void server_state_changed_cb(const union doca_data user_data,
                                    struct doca_ctx *ctx,
                                    enum doca_ctx_states prev_state,
                                    enum doca_ctx_states next_state);
static void server_connect_cb(struct doca_comch_event_connection_status_changed *event,
                              struct doca_comch_connection *conn);
static void server_disconnect_cb(struct doca_comch_event_connection_status_changed *event,
                                 struct doca_comch_connection *conn);

// Helper: find connection entry by DOCA connection pointer
static server_conn_entry_t* find_conn_by_doca(struct doca_comch_connection *conn) {
    for (int i = 0; i < MAX_SERVER_CONNECTIONS; i++) {
        if (g_server_conns[i].active && g_server_conns[i].conn == conn) {
            return &g_server_conns[i];
        }
    }
    return NULL;
}

// Helper: find connection entry by ID
static server_conn_entry_t* find_conn_by_id(shim_conn_id_t id) {
    for (int i = 0; i < MAX_SERVER_CONNECTIONS; i++) {
        if (g_server_conns[i].active && g_server_conns[i].id == id) {
            return &g_server_conns[i];
        }
    }
    return NULL;
}

// Helper: add connection to tracking
static shim_conn_id_t add_connection(struct doca_comch_connection *conn) {
    for (int i = 0; i < MAX_SERVER_CONNECTIONS; i++) {
        if (!g_server_conns[i].active) {
            g_server_conns[i].conn = conn;
            g_server_conns[i].id = g_next_conn_id++;
            g_server_conns[i].active = 1;
            return g_server_conns[i].id;
        }
    }
    return 0;  // No slots available
}

// Helper: remove connection from tracking
static void remove_connection(struct doca_comch_connection *conn) {
    server_conn_entry_t *entry = find_conn_by_doca(conn);
    if (entry != NULL) {
        entry->active = 0;
        entry->conn = NULL;
        entry->id = 0;
    }
}

// Helper: queue pending connection
static int queue_pending_conn(shim_conn_id_t id) {
    int next_tail = (g_pending_tail + 1) % PENDING_CONN_QUEUE_SIZE;
    if (next_tail == g_pending_head) {
        return -1;  // Queue full
    }
    g_pending_conns[g_pending_tail] = id;
    g_pending_tail = next_tail;
    return 0;
}

// Helper: dequeue pending connection
static int dequeue_pending_conn(shim_conn_id_t *id) {
    if (g_pending_head == g_pending_tail) {
        return -1;  // Queue empty
    }
    *id = g_pending_conns[g_pending_head];
    g_pending_head = (g_pending_head + 1) % PENDING_CONN_QUEUE_SIZE;
    return 0;
}

// Helper: open representor device
static doca_error_t open_rep_device_by_pci(struct doca_dev *dev, const char *rep_pci_addr,
                                           struct doca_dev_rep **rep) {
    struct doca_devinfo_rep **rep_list = NULL;
    uint32_t nb_reps = 0;
    doca_error_t result;
    char pci_buf[DOCA_DEVINFO_PCI_ADDR_SIZE];

    result = doca_devinfo_rep_create_list(dev, DOCA_DEVINFO_REP_FILTER_NET, &rep_list, &nb_reps);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create rep list: %s", doca_error_get_descr(result));
        return result;
    }

    *rep = NULL;
    for (uint32_t i = 0; i < nb_reps; i++) {
        result = doca_devinfo_rep_get_pci_addr_str(rep_list[i], pci_buf);
        if (result != DOCA_SUCCESS)
            continue;

        if (strcmp(pci_buf, rep_pci_addr) == 0) {
            result = doca_dev_rep_open(rep_list[i], rep);
            if (result == DOCA_SUCCESS) {
                doca_devinfo_rep_destroy_list(rep_list);
                return DOCA_SUCCESS;
            }
        }
    }

    doca_devinfo_rep_destroy_list(rep_list);
    DOCA_LOG_ERR("Representor with PCI address %s not found", rep_pci_addr);
    return DOCA_ERROR_NOT_FOUND;
}

// Callback: message received from client
static void server_msg_recv_cb(struct doca_comch_event_msg_recv *event,
                               uint8_t *recv_buffer, uint32_t msg_len,
                               struct doca_comch_connection *conn) {
    (void)event;

    DOCA_LOG_DBG("Server received message: %u bytes", msg_len);

    // Find the connection ID
    server_conn_entry_t *entry = find_conn_by_doca(conn);
    if (entry == NULL) {
        DOCA_LOG_WARN("Received message from unknown connection");
        return;
    }

    // Call back into Go with connection ID and message
    goOnServerMessageReceived(entry->id, recv_buffer, msg_len);
}

// Callback: send task completed successfully
static void server_send_complete_cb(struct doca_comch_task_send *task,
                                    union doca_data task_user_data,
                                    union doca_data ctx_user_data) {
    (void)task_user_data;
    (void)ctx_user_data;

    DOCA_LOG_DBG("Server send task completed");
    doca_task_free(doca_comch_task_send_as_task(task));
}

// Callback: send task failed
static void server_send_error_cb(struct doca_comch_task_send *task,
                                 union doca_data task_user_data,
                                 union doca_data ctx_user_data) {
    (void)task_user_data;
    (void)ctx_user_data;

    DOCA_LOG_ERR("Server send task failed");
    doca_task_free(doca_comch_task_send_as_task(task));
}

// Callback: server context state changed
static void server_state_changed_cb(const union doca_data user_data,
                                    struct doca_ctx *ctx,
                                    enum doca_ctx_states prev_state,
                                    enum doca_ctx_states next_state) {
    (void)user_data;
    (void)ctx;

    DOCA_LOG_DBG("Server state changed: %d -> %d", prev_state, next_state);

    switch (next_state) {
    case DOCA_CTX_STATE_IDLE:
        g_server_state = SHIM_STATE_DISCONNECTED;
        break;
    case DOCA_CTX_STATE_STARTING:
        g_server_state = SHIM_STATE_CONNECTING;
        break;
    case DOCA_CTX_STATE_RUNNING:
        g_server_state = SHIM_STATE_CONNECTED;
        break;
    case DOCA_CTX_STATE_STOPPING:
        g_server_state = SHIM_STATE_DISCONNECTED;
        break;
    default:
        break;
    }
}

// Callback: client connected (DOCA 3.2.x API uses separate connect/disconnect callbacks)
static void server_connect_cb(struct doca_comch_event_connection_status_changed *event,
                              struct doca_comch_connection *conn) {
    (void)event;

    DOCA_LOG_INFO("New client connected");

    // Add to connection tracking
    shim_conn_id_t id = add_connection(conn);
    if (id == 0) {
        DOCA_LOG_ERR("Maximum connections reached, cannot accept new client");
        return;
    }

    // Queue for Accept()
    if (queue_pending_conn(id) < 0) {
        DOCA_LOG_ERR("Pending connection queue full");
        remove_connection(conn);
        return;
    }

    // Notify Go of connection event
    goOnServerConnectionEvent(id, SHIM_CONN_EVENT_CONNECTED);
}

// Callback: client disconnected (DOCA 3.2.x API)
static void server_disconnect_cb(struct doca_comch_event_connection_status_changed *event,
                                 struct doca_comch_connection *conn) {
    (void)event;

    DOCA_LOG_INFO("Client disconnected");

    server_conn_entry_t *entry = find_conn_by_doca(conn);
    if (entry != NULL) {
        shim_conn_id_t id = entry->id;
        remove_connection(conn);

        // Notify Go of disconnection
        goOnServerConnectionEvent(id, SHIM_CONN_EVENT_DISCONNECTED);
    }
}

int shim_init_server(const char *pci_addr, const char *rep_pci_addr,
                     const char *server_name, uint32_t max_msg_size) {
    doca_error_t result;

    if (pci_addr == NULL || rep_pci_addr == NULL || server_name == NULL) {
        return SHIM_ERR_INVALID_ARG;
    }

    if (g_server != NULL) {
        return SHIM_ERR_ALREADY_INIT;
    }

    // Initialize connection tracking
    memset(g_server_conns, 0, sizeof(g_server_conns));
    g_next_conn_id = 1;
    g_pending_head = 0;
    g_pending_tail = 0;

    // Open device
    result = open_device_by_pci(pci_addr, &g_server_dev);
    if (result != DOCA_SUCCESS) {
        return SHIM_ERR_DEVICE_OPEN;
    }

    // Open representor device
    result = open_rep_device_by_pci(g_server_dev, rep_pci_addr, &g_server_rep);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to open rep device: %s", doca_error_get_descr(result));
        goto err_rep;
    }

    // Create progress engine
    result = doca_pe_create(&g_server_pe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create PE: %s", doca_error_get_descr(result));
        goto err_pe;
    }

    // Create ComCh server
    result = doca_comch_server_create(g_server_dev, g_server_rep, server_name, &g_server);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create server: %s", doca_error_get_descr(result));
        goto err_server;
    }

    // Set max message size if specified
    if (max_msg_size > 0) {
        result = doca_comch_server_set_max_msg_size(g_server, max_msg_size);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_WARN("Failed to set max msg size: %s", doca_error_get_descr(result));
        }
    }

    // Get the context for configuration
    struct doca_ctx *ctx = doca_comch_server_as_ctx(g_server);

    // Register state change callback
    result = doca_ctx_set_state_changed_cb(ctx, server_state_changed_cb);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_WARN("Failed to set state changed callback: %s", doca_error_get_descr(result));
    }

    // Connect PE to context
    result = doca_pe_connect_ctx(g_server_pe, ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to connect PE: %s", doca_error_get_descr(result));
        goto err_connect;
    }

    // Configure send task callbacks
    result = doca_comch_server_task_send_set_conf(g_server, server_send_complete_cb,
                                                   server_send_error_cb, 64);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set send conf: %s", doca_error_get_descr(result));
        goto err_connect;
    }

    // Register message receive callback
    result = doca_comch_server_event_msg_recv_register(g_server, server_msg_recv_cb);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register msg recv: %s", doca_error_get_descr(result));
        goto err_connect;
    }

    // Register connection status callbacks (DOCA 3.2.x API: separate connect/disconnect)
    result = doca_comch_server_event_connection_status_changed_register(
        g_server, server_connect_cb, server_disconnect_cb);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register connection callback: %s", doca_error_get_descr(result));
        goto err_connect;
    }

    // Get notification handle for epoll integration
    result = doca_pe_get_notification_handle(g_server_pe, &g_server_notification_handle);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to get notification handle: %s", doca_error_get_descr(result));
        goto err_connect;
    }

    // Start the context (server goes to RUNNING immediately)
    g_server_state = SHIM_STATE_CONNECTING;
    result = doca_ctx_start(ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to start context: %s", doca_error_get_descr(result));
        g_server_state = SHIM_STATE_ERROR;
        goto err_connect;
    }

    // Get max message size after initialization
    result = doca_comch_server_get_max_msg_size(g_server, &g_server_max_msg_size);
    if (result != DOCA_SUCCESS) {
        g_server_max_msg_size = 4096;  // Default fallback
    }

    g_server_state = SHIM_STATE_CONNECTED;
    DOCA_LOG_INFO("Server initialized, listening as '%s'", server_name);
    return SHIM_OK;

err_connect:
    doca_comch_server_destroy(g_server);
    g_server = NULL;
err_server:
    doca_pe_destroy(g_server_pe);
    g_server_pe = NULL;
err_pe:
    doca_dev_rep_close(g_server_rep);
    g_server_rep = NULL;
err_rep:
    doca_dev_close(g_server_dev);
    g_server_dev = NULL;
    return SHIM_ERR_SERVER_CREATE;
}

int shim_server_get_event_fd(void) {
    if (g_server_pe == NULL) {
        return -1;
    }
    return (int)g_server_notification_handle;
}

void shim_server_request_notification(void) {
    if (g_server_pe != NULL) {
        doca_pe_request_notification(g_server_pe);
    }
}

void shim_server_clear_notification(void) {
    if (g_server_pe != NULL) {
        doca_pe_clear_notification(g_server_pe, g_server_notification_handle);
    }
}

int shim_server_progress(void) {
    if (g_server_pe == NULL) {
        return 0;
    }
    return doca_pe_progress(g_server_pe);
}

int shim_server_get_state(void) {
    return (int)g_server_state;
}

int shim_server_accept_connection(shim_conn_id_t *conn_id) {
    if (conn_id == NULL) {
        return SHIM_ERR_INVALID_ARG;
    }

    if (dequeue_pending_conn(conn_id) < 0) {
        return SHIM_ERR_NO_CONNECTION;
    }

    return SHIM_OK;
}

int shim_server_send(shim_conn_id_t conn_id, const uint8_t *data, uint32_t len) {
    if (g_server == NULL) {
        return SHIM_ERR_NOT_INIT;
    }

    if (data == NULL || len == 0) {
        return SHIM_ERR_INVALID_ARG;
    }

    server_conn_entry_t *entry = find_conn_by_id(conn_id);
    if (entry == NULL) {
        return SHIM_ERR_CONN_NOT_FOUND;
    }

    struct doca_comch_task_send *task = NULL;
    doca_error_t result = doca_comch_server_task_send_alloc_init(
        g_server, entry->conn, data, len, &task);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to alloc send task: %s", doca_error_get_descr(result));
        return SHIM_ERR_SEND_ALLOC;
    }

    result = doca_task_submit(doca_comch_task_send_as_task(task));
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to submit send task: %s", doca_error_get_descr(result));
        doca_task_free(doca_comch_task_send_as_task(task));
        if (result == DOCA_ERROR_AGAIN) {
            return SHIM_ERR_QUEUE_FULL;
        }
        return SHIM_ERR_SEND_SUBMIT;
    }

    return SHIM_OK;
}

int shim_server_close_connection(shim_conn_id_t conn_id) {
    server_conn_entry_t *entry = find_conn_by_id(conn_id);
    if (entry == NULL) {
        return SHIM_ERR_CONN_NOT_FOUND;
    }

    // Mark as inactive (actual DOCA connection cleanup happens in disconnect callback)
    entry->active = 0;
    entry->conn = NULL;
    entry->id = 0;

    return SHIM_OK;
}

void shim_server_cleanup(void) {
    if (g_server != NULL) {
        struct doca_ctx *ctx = doca_comch_server_as_ctx(g_server);
        doca_ctx_stop(ctx);

        // Progress until idle
        while (g_server_state != SHIM_STATE_DISCONNECTED && g_server_pe != NULL) {
            doca_pe_progress(g_server_pe);
        }

        doca_comch_server_destroy(g_server);
        g_server = NULL;
    }

    if (g_server_pe != NULL) {
        doca_pe_destroy(g_server_pe);
        g_server_pe = NULL;
    }

    if (g_server_rep != NULL) {
        doca_dev_rep_close(g_server_rep);
        g_server_rep = NULL;
    }

    if (g_server_dev != NULL) {
        doca_dev_close(g_server_dev);
        g_server_dev = NULL;
    }

    // Clear connection tracking
    memset(g_server_conns, 0, sizeof(g_server_conns));
    g_pending_head = 0;
    g_pending_tail = 0;

    g_server_state = SHIM_STATE_DISCONNECTED;
    g_server_max_msg_size = 0;

    DOCA_LOG_INFO("Server cleanup complete");
}

uint32_t shim_server_get_max_msg_size(void) {
    return g_server_max_msg_size;
}
