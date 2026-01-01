// Fabric Console API Server
// HTTP API that wraps gRPC client for web dashboard access
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/beyondidentity/fabric-console/internal/api"
	"github.com/beyondidentity/fabric-console/pkg/store"
)

var (
	version = "0.1.0"

	listenAddr = flag.String("listen", ":8080", "HTTP listen address")
	dbPath     = flag.String("db", "", "Database path (default: ~/.local/share/bluectl/dpus.db)")
)

func main() {
	flag.Parse()

	log.Printf("Fabric Console API v%s starting...", version)

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

	// Create API server
	server := api.NewServer(db)

	// Set up HTTP server
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	httpServer := &http.Server{
		Addr:    *listenAddr,
		Handler: corsMiddleware(mux),
	}

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
