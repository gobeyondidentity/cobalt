// Fabric Console API Server
// HTTP API that wraps gRPC client for web dashboard access
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gobeyondidentity/secure-infra/internal/api"
	"github.com/gobeyondidentity/secure-infra/internal/version"
	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
)

var (
	listenAddr = flag.String("listen", ":18080", "HTTP listen address")
	dbPath     = flag.String("db", "", "Database path (default: ~/.local/share/bluectl/dpus.db)")
)

func main() {
	flag.CommandLine.SetOutput(os.Stdout)
	flag.Parse()

	log.Printf("Fabric Console API v%s starting...", version.Version)

	// Open database
	path := *dbPath
	if path == "" {
		path = store.DefaultPath()
	}

	db, err := store.Open(path)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Initialize bootstrap window
	cancelCountdown, err := initBootstrapWindow(db)
	if err != nil {
		log.Fatalf("Failed to initialize bootstrap: %v", err)
	}

	// Create API server
	server := api.NewServer(db)

	// Set up HTTP server
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// Initialize DPoP authentication middleware
	jtiCache := dpop.NewMemoryJTICache(
		dpop.WithTTL(5*time.Minute),
		dpop.WithMaxEntries(100000),
	)
	defer jtiCache.Close()

	validator := dpop.NewValidator(dpop.DefaultValidatorConfig())
	proofValidator := api.NewStoreProofValidator(validator, db)
	identityLookup := api.NewStoreIdentityLookup(db)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	authMiddleware := dpop.NewAuthMiddleware(proofValidator, identityLookup, jtiCache, dpop.WithLogger(logger))

	// Apply middleware: logging -> CORS -> auth -> routes
	// CORS wraps auth so that CORS headers (including DPoP) are set even on auth failures
	// and OPTIONS preflight requests bypass authentication
	httpServer := &http.Server{
		Addr:    *listenAddr,
		Handler: loggingMiddleware(corsMiddleware(authMiddleware.Wrap(mux))),
	}

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		if cancelCountdown != nil {
			cancelCountdown()
		}
		httpServer.Close()
	}()

	log.Printf("HTTP server listening on %s", *listenAddr)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}

	log.Println("API server stopped")
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, DPoP")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusResponseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s %d %dms", r.Method, r.URL.Path, sw.statusCode, time.Since(start).Milliseconds())
	})
}

// BootstrapWindowDuration is the duration for which the bootstrap window remains open.
const BootstrapWindowDuration = 10 * time.Minute

// initBootstrapWindow initializes the bootstrap window for first-admin enrollment.
// Returns a cancel function to stop the countdown goroutine, or nil if bootstrap is complete.
func initBootstrapWindow(db *store.Store) (context.CancelFunc, error) {
	// Check if first admin already exists
	hasAdmin, err := db.HasFirstAdmin()
	if err != nil {
		return nil, fmt.Errorf("failed to check first admin: %w", err)
	}

	if hasAdmin {
		// Bootstrap is complete, get admin ID for logging
		state, err := db.GetBootstrapState()
		if err != nil {
			return nil, fmt.Errorf("failed to get bootstrap state: %w", err)
		}
		if state != nil && state.FirstAdminID != nil {
			log.Printf("Bootstrap complete. First admin: %s", *state.FirstAdminID)
		} else {
			log.Printf("Bootstrap complete.")
		}
		return nil, nil
	}

	// No admin exists, check bootstrap state
	state, err := db.GetBootstrapState()
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap state: %w", err)
	}

	if state != nil {
		// Bootstrap window exists, check if expired
		expiresAt := state.WindowOpenedAt.Add(BootstrapWindowDuration)
		if time.Now().After(expiresAt) {
			// Window expired, reset and reinitialize (restart-reset behavior)
			log.Printf("Bootstrap window expired. Resetting for fresh 10-minute window.")
			if err := db.ResetBootstrapWindow(); err != nil {
				return nil, fmt.Errorf("failed to reset bootstrap window: %w", err)
			}

			// Audit log: window reset
			db.InsertAuditEntry(&store.AuditEntry{
				Timestamp: time.Now(),
				Action:    "bootstrap.window_reset",
				Target:    "bootstrap_state",
				Decision:  "reset",
				Details: map[string]string{
					"reason": "window_expired_on_restart",
				},
			})

			if err := db.InitBootstrapWindow(); err != nil {
				return nil, fmt.Errorf("failed to initialize bootstrap window: %w", err)
			}

			// Re-fetch state after init
			state, err = db.GetBootstrapState()
			if err != nil {
				return nil, fmt.Errorf("failed to get bootstrap state after init: %w", err)
			}
		}
	} else {
		// No bootstrap state exists, initialize fresh window
		if err := db.InitBootstrapWindow(); err != nil {
			return nil, fmt.Errorf("failed to initialize bootstrap window: %w", err)
		}

		// Fetch the newly created state
		state, err = db.GetBootstrapState()
		if err != nil {
			return nil, fmt.Errorf("failed to get bootstrap state after init: %w", err)
		}
	}

	// Audit log: window opened
	db.InsertAuditEntry(&store.AuditEntry{
		Timestamp: time.Now(),
		Action:    "bootstrap.window_opened",
		Target:    "bootstrap_state",
		Decision:  "open",
		Details: map[string]string{
			"window_opened_at": state.WindowOpenedAt.Format(time.RFC3339),
		},
	})

	// Calculate expiration time
	expiresAt := state.WindowOpenedAt.Add(BootstrapWindowDuration)

	// Print bootstrap banner
	fmt.Println("============================================================")
	fmt.Println("BOOTSTRAP MODE: First admin enrollment required")
	fmt.Println("Run `bluectl init` within 10 minutes to enroll.")
	fmt.Printf("Window expires at: %s\n", expiresAt.Format(time.RFC3339))
	fmt.Println("============================================================")

	// Start countdown goroutine
	ctx, cancel := context.WithCancel(context.Background())
	go runBootstrapCountdown(ctx, db, expiresAt)

	return cancel, nil
}

// runBootstrapCountdown logs countdown messages every minute until window expires.
func runBootstrapCountdown(ctx context.Context, db *store.Store, expiresAt time.Time) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check if admin has enrolled
			hasAdmin, err := db.HasFirstAdmin()
			if err != nil {
				log.Printf("Error checking admin status: %v", err)
				continue
			}
			if hasAdmin {
				// Admin enrolled, stop countdown
				return
			}

			// Check remaining time
			remaining := time.Until(expiresAt)
			if remaining <= 0 {
				log.Println("Bootstrap window expired. Restart server to get fresh 10-minute window.")
				return
			}

			// Log remaining time (rounded to minutes)
			minutes := int(remaining.Minutes())
			if minutes > 0 {
				log.Printf("Bootstrap window: %d minutes remaining", minutes)
			}
		}
	}
}
