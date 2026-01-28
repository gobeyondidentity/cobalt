// Package localapi provides a local HTTP API for Host Agent communication.
// The Host Agent calls this API instead of talking directly to the Control Plane.
// The DPU Agent proxies requests, adding its identity and attestation status.
package localapi

import "time"

// RegisterRequest is the JSON body for POST /local/v1/register.
type RegisterRequest struct {
	Hostname string          `json:"hostname"`
	Posture  *PosturePayload `json:"posture,omitempty"`
}

// RegisterResponse is the JSON response from POST /local/v1/register.
type RegisterResponse struct {
	HostID  string `json:"host_id"`
	DPUName string `json:"dpu_name"`
}

// PostureRequest is the JSON body for POST /local/v1/posture.
type PostureRequest struct {
	Hostname string          `json:"hostname"`
	Posture  *PosturePayload `json:"posture"`
}

// PostureResponse is the JSON response from POST /local/v1/posture.
type PostureResponse struct {
	Accepted bool `json:"accepted"`
}

// CertRequest is the JSON body for POST /local/v1/cert.
type CertRequest struct {
	Hostname   string   `json:"hostname"`
	PublicKey  string   `json:"public_key"`
	Principals []string `json:"principals"`
}

// CertResponse is the JSON response from POST /local/v1/cert.
type CertResponse struct {
	Certificate string `json:"certificate"`
	Serial      uint64 `json:"serial"`
	ValidBefore string `json:"valid_before"` // RFC3339 timestamp
}

// PosturePayload represents host security posture data.
type PosturePayload struct {
	SecureBoot     *bool  `json:"secure_boot"`
	DiskEncryption string `json:"disk_encryption"` // luks, filevault, bitlocker, none
	OSVersion      string `json:"os_version"`
	KernelVersion  string `json:"kernel_version"`
	TPMPresent     *bool  `json:"tpm_present"`
}

// ErrorResponse is the JSON structure for API errors.
type ErrorResponse struct {
	Error string `json:"error"`
}

// HealthResponse is the JSON response from GET /local/v1/health.
type HealthResponse struct {
	Status            string `json:"status"` // healthy, degraded, unhealthy
	DPUName           string `json:"dpu_name"`
	AttestationStatus string `json:"attestation_status"` // valid, invalid, unavailable
	ControlPlane      string `json:"control_plane"`      // connected, disconnected
}

// AttestationInfo holds the DPU's current attestation status for proxying.
type AttestationInfo struct {
	Status       string    // valid, invalid, unavailable
	Measurements []string  // List of measurement digests
	LastChecked  time.Time // When attestation was last verified
}

// ProxiedCertRequest is sent to the Control Plane with DPU attestation info.
type ProxiedCertRequest struct {
	// Host information (from Host Agent)
	Hostname   string   `json:"hostname"`
	PublicKey  string   `json:"public_key"`
	Principals []string `json:"principals"`

	// DPU information (added by DPU Agent)
	DPUName           string   `json:"dpu_name"`
	DPUSerial         string   `json:"dpu_serial"`
	AttestationStatus string   `json:"attestation_status"`
	Measurements      []string `json:"measurements,omitempty"`

	// Host posture (if available)
	HostID      string          `json:"host_id,omitempty"`
	HostPosture *PosturePayload `json:"host_posture,omitempty"`
}

// ProxiedCertResponse is received from the Control Plane.
type ProxiedCertResponse struct {
	Certificate string `json:"certificate"`
	Serial      uint64 `json:"serial"`
	ValidBefore string `json:"valid_before"`
}

// ProxiedRegisterRequest is sent to the Control Plane for host registration.
type ProxiedRegisterRequest struct {
	// Host information (from Host Agent)
	Hostname string          `json:"hostname"`
	Posture  *PosturePayload `json:"posture,omitempty"`

	// DPU information (added by DPU Agent)
	DPUName           string `json:"dpu_name"`
	DPUID             string `json:"dpu_id"`
	DPUSerial         string `json:"dpu_serial"`
	AttestationStatus string `json:"attestation_status"`
}

// ProxiedRegisterResponse is received from the Control Plane.
type ProxiedRegisterResponse struct {
	HostID          string `json:"host_id"`
	RefreshInterval string `json:"refresh_interval,omitempty"`
}

// ProxiedPostureRequest is sent to the Control Plane for posture updates.
type ProxiedPostureRequest struct {
	HostID            string          `json:"host_id"`
	Posture           *PosturePayload `json:"posture"`
	DPUName           string          `json:"dpu_name"`
	AttestationStatus string          `json:"attestation_status"`
}

// CredentialPushRequest is the JSON body for POST /local/v1/credential.
// Called by the DPU Agent gRPC handler when km distribute triggers.
type CredentialPushRequest struct {
	CredentialType string `json:"credential_type"` // "ssh-ca", "tls-cert", etc.
	CredentialName string `json:"credential_name"`
	Data           []byte `json:"data"` // Public key or certificate
}

// CredentialPushResponse is the JSON response from POST /local/v1/credential.
type CredentialPushResponse struct {
	Success       bool   `json:"success"`
	InstalledPath string `json:"installed_path,omitempty"`
	Error         string `json:"error,omitempty"`
}

// CredentialPushResult contains the result of pushing a credential to the Host Agent.
// Used by the DPU Agent's gRPC handler to return results.
type CredentialPushResult struct {
	Success       bool
	Message       string
	InstalledPath string
	SshdReloaded  bool
}

// QueuedCredential represents a credential waiting to be retrieved by the Host Agent.
type QueuedCredential struct {
	CredType string `json:"type"`
	CredName string `json:"name"`
	Data     []byte `json:"data"`
}

// CredentialsPendingResponse is the JSON response from GET /local/v1/credentials/pending.
type CredentialsPendingResponse struct {
	Credentials []*QueuedCredential `json:"credentials"`
}
