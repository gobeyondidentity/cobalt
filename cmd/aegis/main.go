// Fabric Console DPU Agent
// Runs on BlueField DPU ARM cores, exposes system info, OVS, and attestation APIs

package main

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	agentv1 "github.com/gobeyondidentity/secure-infra/gen/go/agent/v1"
	"github.com/gobeyondidentity/secure-infra/internal/aegis"
	"github.com/gobeyondidentity/secure-infra/internal/aegis/localapi"
	"github.com/gobeyondidentity/secure-infra/internal/version"
	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
	"github.com/gobeyondidentity/secure-infra/pkg/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

var (
	listenAddr   = flag.String("listen", ":18051", "gRPC listen address")
	healthListen = flag.String("health-listen", ":18052", "HTTP health endpoint listen address")
	bmcAddr      = flag.String("bmc-addr", "", "BMC address for Redfish API (optional)")
	bmcUser      = flag.String("bmc-user", "root", "BMC username")
	localListen  = flag.String("local-listen", "localhost:9443", "Local API listen address")
	allowTmfifoNet = flag.Bool("allow-tmfifo-net", false, "Allow connections from tmfifo_net subnet (192.168.100.0/30)")
	server         = flag.String("server", "", "Nexus server URL (required with --dpu-name for host communication)")
	dpuName        = flag.String("dpu-name", "", "DPU name for registration (required with --server for host communication)")
	noComch        = flag.Bool("no-comch", false, "Disable ComCh transport listener")
	keystorePath   = flag.String("keystore", "/var/lib/secureinfra/known_hosts.json", "Path to TOFU keystore for host authentication")

	// DOCA ComCh configuration
	docaPCIAddr    = flag.String("doca-pci-addr", "", "PCI address of DOCA device on DPU (e.g., \"03:00.0\")")
	docaRepPCIAddr = flag.String("doca-rep-pci-addr", "", "Representor PCI address for host connection")
	docaServerName = flag.String("doca-server-name", "secure-infra", "ComCh server name for host communication")

	// State persistence
	dbPath = flag.String("db-path", "/var/lib/aegis/aegis.db", "Path to SQLite database for state persistence")

	// Enrollment flags
	enrollMode      = flag.Bool("enroll", false, "Run enrollment to register this DPU with the control plane")
	serial          = flag.String("serial", "", "DPU serial number (required for --enroll)")
	skipAttestation = flag.Bool("skip-attestation", false, "Skip SPDM attestation (development mode only)")

	// Version flag
	showVersion = flag.Bool("version", false, "Show version and exit")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("aegis version %s\n", version.Version)
		os.Exit(0)
	}

	// Handle enrollment mode
	if *enrollMode {
		log.Printf("Fabric Console Agent v%s - Enrollment Mode", version.Version)
		if err := EnrollCommand(*serial, *server, *skipAttestation); err != nil {
			log.Fatalf("Enrollment failed: %v", err)
		}
		return
	}

	log.Printf("Fabric Console Agent v%s starting...", version.Version)

	// Start HTTP health endpoint (always available for monitoring)
	httpHealthServer := startHealthServer(*healthListen)

	// Build configuration
	cfg := aegis.DefaultConfig()
	cfg.ListenAddr = *listenAddr
	cfg.BMCAddr = *bmcAddr
	cfg.BMCUser = *bmcUser
	cfg.LocalAPIAddr = *localListen
	cfg.ServerURL = *server
	cfg.DPUName = *dpuName

	// Load sensitive config from environment
	if err := cfg.LoadFromEnv(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()
	agentServer, err := aegis.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create agent server: %v", err)
	}
	agentv1.RegisterDPUAgentServiceServer(grpcServer, agentServer)

	// Register standard gRPC health service for grpc-health-probe and Kubernetes health checks
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Enable reflection for grpcurl
	reflection.Register(grpcServer)

	// Start listening
	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
	}

	log.Printf("gRPC server listening on %s", cfg.ListenAddr)

	// Handle shutdown gracefully
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Auto-enable local API + ComCh when server + dpu-name configured
	var localServer *localapi.Server
	var hostListener transport.TransportListener
	var transportCtx context.Context
	var transportCancel context.CancelFunc

	if cfg.ServerURL != "" && cfg.DPUName != "" {
		// Start local API
		localServer, err = startLocalAPI(ctx, cfg, agentServer)
		if err != nil {
			log.Fatalf("Failed to start local API: %v", err)
		}
		agentServer.SetLocalAPI(localServer)

		// Start ComCh transport (unless disabled)
		if !*noComch {
			hostListener = tryStartTransportListener(*docaPCIAddr, *docaRepPCIAddr, *docaServerName)
			if hostListener != nil {
				localServer.SetHostListener(hostListener)
				agentServer.SetHostListener(hostListener)

				// Create keystore for TOFU authentication
				keystore, err := transport.NewKeyStore(*keystorePath)
				if err != nil {
					log.Fatalf("Failed to create keystore: %v", err)
				}
				log.Printf("transport: keystore initialized at %s", *keystorePath)

				// Create auth server for transport connections
				authServer := transport.NewAuthServer(keystore, 1) // maxConns=1 for single host

				// Start message handling loop with authentication
				transportCtx, transportCancel = context.WithCancel(ctx)
				go runTransportLoop(transportCtx, hostListener, localServer, authServer)
			}
		}
	}

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)

		// Shutdown transport listener first
		if transportCancel != nil {
			transportCancel()
		}
		if hostListener != nil {
			if err := hostListener.Close(); err != nil {
				log.Printf("transport listener shutdown error: %v", err)
			}
		}

		// Shutdown local API server
		if localServer != nil {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := localServer.Stop(shutdownCtx); err != nil {
				log.Printf("Local API shutdown error: %v", err)
			}
		}

		// Shutdown HTTP health server
		if httpHealthServer != nil {
			healthCtx, healthCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer healthCancel()
			if err := httpHealthServer.Shutdown(healthCtx); err != nil {
				log.Printf("HTTP health server shutdown error: %v", err)
			}
		}

		grpcServer.GracefulStop()
		cancel()
	}()

	// Serve gRPC
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("gRPC server error: %v", err)
	}

	<-ctx.Done()
	log.Println("Agent stopped")
}

// aegisLogger implements dpop.Logger for logging DPoP warnings.
type aegisLogger struct{}

func (l *aegisLogger) Warn(msg string) {
	log.Printf("WARNING: %s", msg)
}

// startLocalAPI initializes and starts the local HTTP API server.
func startLocalAPI(ctx context.Context, cfg *aegis.Config, agentServer *aegis.Server) (*localapi.Server, error) {
	log.Printf("Starting local API for Host Agent communication...")

	// Initialize DPoP client for authenticated nexus API requests
	dpopClient, err := initDPoPClient(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("DPoP initialization failed: %w", err)
	}

	// Initialize state persistence store
	// When local-api is enabled, the store is mandatory for state persistence
	stateStore, err := store.Open(*dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open state store at %s: %w", *dbPath, err)
	}
	log.Printf("State persistence enabled: %s", *dbPath)

	localCfg := &localapi.Config{
		ListenAddr:       cfg.LocalAPIAddr,
		ServerURL:        cfg.ServerURL,
		DPUName:          cfg.DPUName,
		DPUID:            cfg.DPUID,
		DPUSerial:        cfg.DPUSerial,
		AllowedHostnames: cfg.AllowedHostnames,
		AllowTmfifoNet:   *allowTmfifoNet,
		Store:            stateStore,
		DPoPClient:       dpopClient,
		AttestationFetcher: func(ctx context.Context) (*localapi.AttestationInfo, error) {
			return fetchAttestation(ctx, agentServer)
		},
	}

	server, err := localapi.NewServer(localCfg)
	if err != nil {
		stateStore.Close()
		return nil, err
	}

	if err := server.Start(); err != nil {
		stateStore.Close()
		return nil, err
	}

	log.Printf("Local API enabled: %s", cfg.LocalAPIAddr)
	log.Printf("Server: %s", cfg.ServerURL)
	log.Printf("DPU Name: %s", cfg.DPUName)

	return server, nil
}

// initDPoPClient initializes the DPoP client for authenticated nexus API requests.
// Returns an error if aegis is not enrolled (key/kid files don't exist).
func initDPoPClient(controlPlaneURL string) (*dpop.Client, error) {
	// Check if aegis is enrolled by verifying key and kid exist
	keyPath, kidPath := dpop.DefaultKeyPaths("aegis")
	keyStore := dpop.NewFileKeyStore(keyPath)
	kidStore := dpop.NewFileKIDStore(kidPath)

	idCfg := dpop.IdentityConfig{
		KeyStore:  keyStore,
		KIDStore:  kidStore,
		ServerURL: controlPlaneURL,
	}

	if !dpop.IsEnrolled(idCfg) {
		return nil, fmt.Errorf("aegis is not enrolled. Key file (%s) or kid file (%s) not found. "+
			"Please run the enrollment process first", keyPath, kidPath)
	}

	log.Printf("DPoP: loading identity from %s", keyPath)

	// Create DPoP client from configuration
	dpopCfg := dpop.ClientConfig{
		ClientType: "aegis",
		ServerURL:  controlPlaneURL,
		Logger:     &aegisLogger{},
	}

	client, _, kid, err := dpop.NewClientFromConfig(dpopCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create DPoP client: %w", err)
	}

	log.Printf("DPoP: identity loaded successfully (kid=%s)", kid)
	return client, nil
}

// startHealthServer starts a minimal HTTP server serving only the /health endpoint.
// Used for liveness probes and monitoring integration.
func startHealthServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": version.Version,
		})
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		log.Printf("Health endpoint listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Health server error: %v", err)
		}
	}()

	return server
}

// tryStartTransportListener attempts to create a transport listener for Host Agent communication.
// Selection priority: ComCh (if DOCA available) -> Tmfifo -> Network
// Returns nil if no transport is available.
func tryStartTransportListener(pciAddr, repPCIAddr, serverName string) transport.TransportListener {
	// Build config from CLI flags
	cfg := &transport.Config{
		DOCAPCIAddr:    pciAddr,
		DOCARepPCIAddr: repPCIAddr,
		DOCAServerName: serverName,
		// TmfifoPath uses default if empty
	}

	// Try ComCh first (priority 1)
	if transport.DOCAComchAvailable() {
		log.Printf("transport: DOCA ComCh available, creating ComCh listener")
		if pciAddr != "" {
			log.Printf("transport: using PCI address %s, rep %s, server name %s", pciAddr, repPCIAddr, serverName)
		}
		listener, err := transport.NewDPUTransportListener(cfg)
		if err != nil {
			log.Printf("transport: ComCh listener creation failed (%v), falling back", err)
		} else {
			log.Printf("transport: ComCh listener created")
			return listener
		}
	}

	// Try Tmfifo second (priority 2)
	tmfifoListener, err := transport.NewTmfifoNetListener("")
	if err == nil {
		log.Printf("transport: tmfifo listener created")
		return tmfifoListener
	}
	log.Printf("transport: tmfifo device not available (%v)", err)

	// Network fallback is not attempted here since the DPU agent
	// already has a gRPC server for network communication.
	// The transport listener is specifically for hardware channels.
	log.Printf("transport: no hardware transport available, using HTTP API only")
	return nil
}

// runTransportLoop accepts connections and handles messages from Host Agents.
func runTransportLoop(ctx context.Context, listener transport.TransportListener, localServer *localapi.Server, authServer *transport.AuthServer) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Accept a connection
		t, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("transport: accept error: %v", err)
				continue
			}
		}

		log.Printf("transport: accepted %s connection", t.Type())

		// Authenticate the connection before processing application messages
		authCtx, authCancel := context.WithTimeout(ctx, 30*time.Second)
		hostKey, err := authServer.Authenticate(authCtx, t)
		authCancel()
		if err != nil {
			log.Printf("transport: authentication failed: %v", err)
			t.Close()
			continue
		}
		log.Printf("transport: authenticated host (key fingerprint: %s)", transport.Fingerprint(hostKey)[:16])

		// Set the active transport on the local server for credential push
		localServer.SetActiveTransport(t)

		// Handle messages from this connection
		go handleTransportConnection(ctx, t, localServer)
	}
}

// handleTransportConnection reads and handles messages from a transport connection.
func handleTransportConnection(ctx context.Context, t transport.Transport, localServer *localapi.Server) {
	defer func() {
		t.Close()
		localServer.ClearActiveTransport(t)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := t.Recv()
		if err != nil {
			if err == io.EOF {
				log.Printf("transport: connection closed")
				return
			}
			log.Printf("transport: recv error: %v", err)
			return
		}

		// Handle the message
		resp := handleTransportMessage(ctx, msg, localServer)
		if resp != nil {
			if err := t.Send(resp); err != nil {
				log.Printf("transport: send error: %v", err)
			}
		}
	}
}

// handleTransportMessage dispatches a message to the appropriate handler.
func handleTransportMessage(ctx context.Context, msg *transport.Message, localServer *localapi.Server) *transport.Message {
	switch msg.Type {
	case transport.MessageEnrollRequest:
		return handleEnrollRequest(ctx, msg, localServer)
	case transport.MessagePostureReport:
		return handlePostureReport(ctx, msg)
	case transport.MessageCredentialAck:
		handleCredentialAck(msg, localServer)
		return nil
	default:
		log.Printf("transport: unknown message type: %s", msg.Type)
		return nil
	}
}

// handleEnrollRequest processes ENROLL_REQUEST messages from the Host Agent.
func handleEnrollRequest(ctx context.Context, msg *transport.Message, localServer *localapi.Server) *transport.Message {
	var payload struct {
		Hostname string          `json:"hostname"`
		Posture  json.RawMessage `json:"posture,omitempty"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		log.Printf("transport: invalid enroll request payload: %v", err)
		return nil
	}

	log.Printf("transport: enroll request from host '%s'", payload.Hostname)

	// Parse posture if provided
	var posture *localapi.PosturePayload
	if len(payload.Posture) > 0 {
		posture = &localapi.PosturePayload{}
		if err := json.Unmarshal(payload.Posture, posture); err != nil {
			log.Printf("transport: invalid posture payload: %v", err)
			// Continue without posture rather than failing
			posture = nil
		}
	}

	// Bridge to control plane registration via local API server
	resp, err := localServer.RegisterViaTransport(ctx, payload.Hostname, posture)
	if err != nil {
		log.Printf("transport: registration failed: %v", err)
		respPayload, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return &transport.Message{
			Type:    transport.MessageEnrollResponse,
			Payload: respPayload,
			ID:      generateMessageNonce(),
		}
	}

	respPayload, _ := json.Marshal(map[string]interface{}{
		"success":  true,
		"host_id":  resp.HostID,
		"dpu_name": resp.DPUName,
	})

	return &transport.Message{
		Type:    transport.MessageEnrollResponse,
		Payload: respPayload,
		ID:      generateMessageNonce(),
	}
}

// handlePostureReport processes POSTURE_REPORT messages from the Host Agent.
func handlePostureReport(ctx context.Context, msg *transport.Message) *transport.Message {
	var payload struct {
		Hostname string          `json:"hostname"`
		Posture  json.RawMessage `json:"posture"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		log.Printf("transport: invalid posture report payload: %v", err)
		return nil
	}

	// TODO: Bridge to local API posture update
	log.Printf("transport: posture report from host '%s'", payload.Hostname)

	respPayload, _ := json.Marshal(map[string]interface{}{
		"accepted": true,
	})

	return &transport.Message{
		Type:    transport.MessagePostureAck,
		Payload: respPayload,
		ID:      generateMessageNonce(),
	}
}

// handleCredentialAck processes CREDENTIAL_ACK messages from the Host Agent.
func handleCredentialAck(msg *transport.Message, localServer *localapi.Server) {
	var payload struct {
		Success       bool   `json:"success"`
		InstalledPath string `json:"installed_path,omitempty"`
		Error         string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		log.Printf("transport: invalid credential ack payload: %v", err)
		return
	}

	// Deliver ack to waiting credential pusher
	localServer.HandleCredentialAck(msg.ID, payload.Success, payload.InstalledPath, payload.Error)

	if payload.Success {
		log.Printf("transport: credential installed at %s", payload.InstalledPath)
	} else {
		log.Printf("transport: credential installation failed: %s", payload.Error)
	}
}

// generateMessageNonce creates a random nonce for messages.
func generateMessageNonce() string {
	b := make([]byte, 16)
	// Note: using time-based fallback if crypto/rand fails (shouldn't happen)
	if _, err := cryptoRand.Read(b); err != nil {
		return time.Now().Format("20060102150405.000000")
	}
	return string(b)
}

// fetchAttestation retrieves the current DPU attestation status.
func fetchAttestation(ctx context.Context, agentServer *aegis.Server) (*localapi.AttestationInfo, error) {
	resp, err := agentServer.GetAttestation(ctx, &agentv1.GetAttestationRequest{
		Target: "irot", // Use internal Root of Trust
	})
	if err != nil {
		return &localapi.AttestationInfo{
			Status:      "unavailable",
			LastChecked: time.Now(),
		}, nil
	}

	var status string
	switch resp.Status {
	case agentv1.AttestationStatus_ATTESTATION_STATUS_VALID:
		status = "valid"
	case agentv1.AttestationStatus_ATTESTATION_STATUS_INVALID:
		status = "invalid"
	default:
		status = "unavailable"
	}

	var measurements []string
	for _, cert := range resp.Certificates {
		if cert.FingerprintSha256 != "" {
			measurements = append(measurements, cert.FingerprintSha256)
		}
	}

	return &localapi.AttestationInfo{
		Status:       status,
		Measurements: measurements,
		LastChecked:  time.Now(),
	}, nil
}
