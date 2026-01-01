package sshca

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// CertOptions configures certificate signing.
type CertOptions struct {
	Principal   string        // Required: username/identity
	ValidAfter  time.Time     // Start of validity (default: now)
	ValidBefore time.Time     // End of validity (required)
	Extensions  []string      // SSH extensions (default: permit-pty, permit-user-rc, permit-port-forwarding)
	KeyID       string        // Optional: override auto-generated key ID
}

// DefaultExtensions returns the default set of SSH certificate extensions.
func DefaultExtensions() []string {
	return []string{
		"permit-pty",
		"permit-user-rc",
		"permit-port-forwarding",
	}
}

// SignCertificate signs a user's public key, returning an SSH certificate.
// userPubKey is in OpenSSH authorized_keys format (e.g., "ssh-ed25519 AAAAC3...").
// Returns the certificate in OpenSSH format suitable for ~/.ssh/id_ed25519-cert.pub.
func (ca *CA) SignCertificate(userPubKey string, opts CertOptions) (string, error) {
	if opts.Principal == "" {
		return "", fmt.Errorf("principal is required")
	}

	if opts.ValidBefore.IsZero() {
		return "", fmt.Errorf("validity period (ValidBefore) is required")
	}

	// Parse the user's public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(userPubKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse user public key: %w", err)
	}

	// Set defaults
	validAfter := opts.ValidAfter
	if validAfter.IsZero() {
		validAfter = time.Now()
	}

	extensions := opts.Extensions
	if len(extensions) == 0 {
		extensions = DefaultExtensions()
	}

	keyID := opts.KeyID
	if keyID == "" {
		keyID = fmt.Sprintf("%s-%d", opts.Principal, time.Now().Unix())
	}

	// Generate random serial
	serial, err := randomSerial()
	if err != nil {
		return "", fmt.Errorf("failed to generate serial: %w", err)
	}

	// Build extensions map (extensions have empty string values in SSH certs)
	extMap := make(map[string]string)
	for _, ext := range extensions {
		extMap[ext] = ""
	}

	// Create the certificate
	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: []string{opts.Principal},
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(opts.ValidBefore.Unix()),
		Permissions: ssh.Permissions{
			Extensions: extMap,
		},
	}

	// Get the CA signer
	signer, err := ca.Signer()
	if err != nil {
		return "", fmt.Errorf("failed to get CA signer: %w", err)
	}

	// Sign the certificate
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return "", fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Marshal to authorized_keys format (includes trailing newline)
	certBytes := ssh.MarshalAuthorizedKey(cert)
	return string(certBytes[:len(certBytes)-1]), nil
}

// ParseDuration parses validity duration strings like "8h", "24h", "7d".
// The "d" suffix is parsed as 24h multiplier.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	// Handle day suffix
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := strconv.ParseFloat(daysStr, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid day duration: %s", s)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}

	// Use standard library for other durations
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}
	return d, nil
}

// randomSerial generates a random uint64 for certificate serial numbers.
func randomSerial() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}
