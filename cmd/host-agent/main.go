// Fabric Console Host Agent
// Lightweight agent that runs on Linux hosts, collects security posture,
// and reports to the control plane.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/beyondidentity/fabric-console/pkg/posture"
)

var version = "0.1.0"

func main() {
	controlPlane := flag.String("control-plane", "http://localhost:8080", "Control plane URL")
	dpuName := flag.String("dpu", "", "DPU name to pair with (required)")
	interval := flag.Duration("interval", 5*time.Minute, "Posture refresh interval")
	oneshot := flag.Bool("oneshot", false, "Collect and report once, then exit")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("host-agent v%s\n", version)
		os.Exit(0)
	}

	if *dpuName == "" {
		log.Fatal("--dpu flag is required")
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	log.Printf("Host Agent v%s starting...", version)
	log.Printf("Control plane: %s", *controlPlane)
	log.Printf("Hostname: %s", hostname)
	log.Printf("DPU: %s", *dpuName)

	// Collect initial posture
	p := posture.Collect()
	log.Printf("Initial posture collected: hash=%s", p.Hash())

	// Register with control plane
	hostID, err := register(*controlPlane, *dpuName, hostname, p)
	if err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	log.Printf("Registered as host %s, paired with DPU %s", hostID, *dpuName)

	// If oneshot mode, we're done
	if *oneshot {
		log.Println("Oneshot mode: exiting after successful registration")
		return
	}

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Create ticker for periodic posture collection
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	log.Printf("Starting posture collection loop (interval: %s)", *interval)

	for {
		select {
		case <-ticker.C:
			p := posture.Collect()
			if err := reportPosture(*controlPlane, hostID, p); err != nil {
				log.Printf("Warning: posture report failed: %v", err)
			} else {
				log.Printf("Posture reported: hash=%s", p.Hash())
			}

		case sig := <-sigCh:
			log.Printf("Received signal %v, shutting down...", sig)
			return
		}
	}
}

// registerRequest is the JSON body for POST /api/v1/hosts/register
type registerRequest struct {
	DPUName  string          `json:"dpu_name"`
	Hostname string          `json:"hostname"`
	Posture  *posturePayload `json:"posture,omitempty"`
}

// registerResponse is the JSON response from POST /api/v1/hosts/register
type registerResponse struct {
	HostID          string `json:"host_id"`
	RefreshInterval string `json:"refresh_interval"`
}

// posturePayload is the JSON structure for posture data
type posturePayload struct {
	SecureBoot     *bool  `json:"secure_boot"`
	DiskEncryption string `json:"disk_encryption"`
	OSVersion      string `json:"os_version"`
	KernelVersion  string `json:"kernel_version"`
	TPMPresent     *bool  `json:"tpm_present"`
}

// errorResponse is the JSON structure for API errors
type errorResponse struct {
	Error string `json:"error"`
}

// register sends a registration request to the control plane.
// Returns the assigned host ID on success.
func register(controlPlane, dpuName, hostname string, p *posture.Posture) (string, error) {
	url := controlPlane + "/api/v1/hosts/register"

	req := registerRequest{
		DPUName:  dpuName,
		Hostname: hostname,
		Posture:  postureToPayload(p),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp errorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return "", fmt.Errorf("registration failed: %s", errResp.Error)
		}
		return "", fmt.Errorf("registration failed: HTTP %d", resp.StatusCode)
	}

	var regResp registerResponse
	if err := json.Unmarshal(respBody, &regResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return regResp.HostID, nil
}

// reportPosture sends a posture update to the control plane.
func reportPosture(controlPlane, hostID string, p *posture.Posture) error {
	url := fmt.Sprintf("%s/api/v1/hosts/%s/posture", controlPlane, hostID)

	payload := postureToPayload(p)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal posture: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp errorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("posture update failed: %s", errResp.Error)
		}
		return fmt.Errorf("posture update failed: HTTP %d", resp.StatusCode)
	}

	return nil
}

// postureToPayload converts a posture.Posture to the API payload format.
func postureToPayload(p *posture.Posture) *posturePayload {
	return &posturePayload{
		SecureBoot:     p.SecureBoot,
		DiskEncryption: p.DiskEncryption,
		OSVersion:      p.OSVersion,
		KernelVersion:  p.KernelVersion,
		TPMPresent:     p.TPMPresent,
	}
}
