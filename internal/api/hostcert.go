// This file contains the host certificate issuance endpoint.
package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gobeyondidentity/secure-infra/pkg/sshca"
	"github.com/gobeyondidentity/secure-infra/pkg/store"
	"golang.org/x/crypto/ssh"
)

// Default validity duration for host certificates (30 days).
const defaultHostCertValidity = 30 * 24 * time.Hour

// ----- Host Certificate Types -----

// HostCertRequest is the request body for host certificate issuance.
// Called by DPU Agent on behalf of Host Agent.
type HostCertRequest struct {
	PublicKey   string   `json:"public_key"`    // Host's SSH public key (OpenSSH format)
	Principals  []string `json:"principals"`    // Hostnames/IPs for cert
	DPUName     string   `json:"dpu_name"`      // Calling DPU's name
	DPUAttested bool     `json:"dpu_attested"`  // DPU's attestation status
}

// HostCertResponse is the response for host certificate issuance.
type HostCertResponse struct {
	Certificate string `json:"certificate"`     // SSH host certificate
	Serial      uint64 `json:"serial"`
	ValidAfter  string `json:"valid_after"`
	ValidBefore string `json:"valid_before"`
	CAPublicKey string `json:"ca_public_key"`
}

// ----- Host Certificate Handler -----

// handleHostCertRequest handles POST /api/v1/hosts/{hostname}/cert
// This endpoint is called by the DPU Agent on behalf of the Host Agent.
func (s *Server) handleHostCertRequest(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeError(w, r, http.StatusBadRequest, "hostname is required in path")
		return
	}

	var req HostCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if req.PublicKey == "" {
		writeError(w, r, http.StatusBadRequest, "public_key is required")
		return
	}
	if req.DPUName == "" {
		writeError(w, r, http.StatusBadRequest, "dpu_name is required")
		return
	}
	if len(req.Principals) == 0 {
		writeError(w, r, http.StatusBadRequest, "at least one principal is required")
		return
	}

	// Step 1: Verify the DPU exists
	dpu, err := s.store.Get(req.DPUName)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "DPU not found: "+req.DPUName)
		return
	}

	// Step 2: Verify DPU attestation status
	// The request includes dpu_attested from the DPU agent, but we verify against our stored attestation
	attestation, err := s.store.GetAttestation(dpu.Name)
	if err != nil {
		// No attestation record found
		writeError(w, r, http.StatusForbidden, "DPU attestation not found; attestation required before issuing host certificates")
		return
	}
	if attestation.Status != store.AttestationStatusVerified {
		writeError(w, r, http.StatusForbidden, fmt.Sprintf("DPU attestation status is '%s'; must be 'verified' to issue host certificates", attestation.Status))
		return
	}

	// Step 3: Verify the host is paired with this DPU (lookup in agent_hosts table)
	agentHost, err := s.store.GetAgentHostByHostname(hostname)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "Host not registered: "+hostname)
		return
	}
	if agentHost.DPUName != dpu.Name {
		writeError(w, r, http.StatusForbidden, fmt.Sprintf("Host '%s' is not paired with DPU '%s'", hostname, dpu.Name))
		return
	}

	// Step 4: Determine tenant and get SSH CA
	var tenantID string
	if dpu.TenantID != nil {
		tenantID = *dpu.TenantID
	}

	// Get SSH CA for this tenant (or global if no tenant-specific CA)
	var sshCA *store.SSHCA
	if tenantID != "" {
		// Try tenant-specific CA first
		cas, err := s.store.GetSSHCAsByTenant(tenantID)
		if err == nil && len(cas) > 0 {
			// Use the first CA with a private key (need to fetch full CA with private key)
			sshCA, err = s.store.GetSSHCAByID(cas[0].ID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "Failed to retrieve SSH CA: "+err.Error())
				return
			}
		}
	}

	// If no tenant CA, try to get a global CA
	if sshCA == nil {
		cas, err := s.store.ListSSHCAs()
		if err != nil || len(cas) == 0 {
			writeError(w, r, http.StatusInternalServerError, "No SSH CA available for signing")
			return
		}
		// Find a CA without tenant assignment (global) or use the first available
		for _, ca := range cas {
			if ca.TenantID == nil {
				sshCA, err = s.store.GetSSHCAByID(ca.ID)
				if err == nil {
					break
				}
			}
		}
		// Fall back to first CA if no global found
		if sshCA == nil {
			sshCA, err = s.store.GetSSHCAByID(cas[0].ID)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, "Failed to retrieve SSH CA: "+err.Error())
				return
			}
		}
	}

	// Step 5: Sign the host certificate
	validAfter := time.Now()
	validBefore := validAfter.Add(defaultHostCertValidity)

	cert, serial, err := signHostCertificate(sshCA, req.PublicKey, req.Principals, hostname, validAfter, validBefore)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "Failed to sign certificate: "+err.Error())
		return
	}

	// Get CA public key in OpenSSH format
	caPublicKey, err := getCAPublicKeyString(sshCA)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "Failed to encode CA public key: "+err.Error())
		return
	}

	// Return the signed certificate
	writeJSON(w, http.StatusOK, HostCertResponse{
		Certificate: cert,
		Serial:      serial,
		ValidAfter:  validAfter.Format(time.RFC3339),
		ValidBefore: validBefore.Format(time.RFC3339),
		CAPublicKey: caPublicKey,
	})
}

// signHostCertificate signs a host's public key, returning an SSH host certificate.
// hostPubKey is in OpenSSH authorized_keys format (e.g., "ssh-ed25519 AAAAC3...").
// Returns the certificate in OpenSSH format and the serial number.
func signHostCertificate(ca *store.SSHCA, hostPubKey string, principals []string, keyID string, validAfter, validBefore time.Time) (string, uint64, error) {
	// Parse the host's public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostPubKey))
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse host public key: %w", err)
	}

	// Generate random serial
	serial, err := randomSerial()
	if err != nil {
		return "", 0, fmt.Errorf("failed to generate serial: %w", err)
	}

	// Create the host certificate
	// Note: Host certificates use ssh.HostCert and do not have extensions
	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          serial,
		CertType:        ssh.HostCert,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions:     ssh.Permissions{}, // Host certs don't use extensions
	}

	// Create signer from CA private key
	signer, err := ssh.NewSignerFromKey(ed25519.PrivateKey(ca.PrivateKey))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create CA signer: %w", err)
	}

	// Sign the certificate
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return "", 0, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Marshal to authorized_keys format (includes trailing newline)
	certBytes := ssh.MarshalAuthorizedKey(cert)
	return string(certBytes[:len(certBytes)-1]), serial, nil
}

// randomSerial generates a random uint64 for certificate serial numbers.
func randomSerial() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

// getCAPublicKeyString returns the CA public key in OpenSSH authorized_keys format.
func getCAPublicKeyString(ca *store.SSHCA) (string, error) {
	// Create a sshca.CA to use its PublicKeyString method
	sshcaCA := &sshca.CA{
		ID:         ca.ID,
		Name:       ca.Name,
		KeyType:    ca.KeyType,
		PublicKey:  ca.PublicKey,
		PrivateKey: ca.PrivateKey,
		CreatedAt:  ca.CreatedAt,
	}
	return sshcaCA.PublicKeyString()
}
