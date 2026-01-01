// Package fixture handles loading and templating of DPU fixture data.
package fixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"text/template"

	agentv1 "github.com/beyondidentity/fabric-console/gen/go/agent/v1"
)

// Fixture holds all the data needed to emulate a DPU.
type Fixture struct {
	SystemInfo  *agentv1.GetSystemInfoResponse `json:"system_info"`
	Bridges     []*agentv1.Bridge              `json:"bridges"`
	Flows       map[string][]*agentv1.Flow     `json:"flows"`
	Attestation *AttestationData               `json:"attestation"`
	Health      *HealthData                    `json:"health"`
	Metadata    map[string]string              `json:"_metadata,omitempty"`
	Defaults    map[string]string              `json:"_defaults,omitempty"`
}

// AttestationData holds attestation response data.
type AttestationData struct {
	Status       string            `json:"status"`
	Certificates []*CertData       `json:"certificates"`
	Measurements map[string]string `json:"measurements"`
}

// CertData holds certificate data.
type CertData struct {
	Level             int32  `json:"level"`
	Subject           string `json:"subject"`
	Issuer            string `json:"issuer"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	Algorithm         string `json:"algorithm"`
	PEM               string `json:"pem"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

// HealthData holds health response data.
type HealthData struct {
	Healthy       bool                          `json:"healthy"`
	Version       string                        `json:"version"`
	UptimeSeconds int64                         `json:"uptime_seconds"`
	Components    map[string]*ComponentHealthData `json:"components"`
}

// ComponentHealthData holds component health data.
type ComponentHealthData struct {
	Healthy bool   `json:"healthy"`
	Message string `json:"message"`
}

// TemplateVars holds template variables for fixture templating.
type TemplateVars struct {
	InstanceID   string
	Hostname     string
	SerialNumber string
}

// Load reads a fixture file and applies optional templating.
func Load(path string, vars *TemplateVars) (*Fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading fixture file: %w", err)
	}

	// If we have template variables, apply templating
	if vars != nil {
		data, err = applyTemplate(data, vars)
		if err != nil {
			return nil, fmt.Errorf("applying template: %w", err)
		}
	}

	var fixture Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		return nil, fmt.Errorf("parsing fixture JSON: %w", err)
	}

	return &fixture, nil
}

// applyTemplate processes Go template syntax in the fixture data.
func applyTemplate(data []byte, vars *TemplateVars) ([]byte, error) {
	tmpl, err := template.New("fixture").Parse(string(data))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ToSystemInfoResponse converts fixture data to a GetSystemInfoResponse.
func (f *Fixture) ToSystemInfoResponse() *agentv1.GetSystemInfoResponse {
	return f.SystemInfo
}

// ToListBridgesResponse converts fixture data to a ListBridgesResponse.
func (f *Fixture) ToListBridgesResponse() *agentv1.ListBridgesResponse {
	return &agentv1.ListBridgesResponse{
		Bridges: f.Bridges,
	}
}

// ToGetFlowsResponse converts fixture data to a GetFlowsResponse for a bridge.
// If bridge is empty, returns flows from all bridges.
func (f *Fixture) ToGetFlowsResponse(bridge string) *agentv1.GetFlowsResponse {
	if bridge == "" {
		// Return all flows from all bridges
		var allFlows []*agentv1.Flow
		for _, flows := range f.Flows {
			allFlows = append(allFlows, flows...)
		}
		return &agentv1.GetFlowsResponse{Flows: allFlows}
	}
	flows, ok := f.Flows[bridge]
	if !ok {
		return &agentv1.GetFlowsResponse{Flows: nil}
	}
	return &agentv1.GetFlowsResponse{Flows: flows}
}

// ToGetAttestationResponse converts fixture data to a GetAttestationResponse.
func (f *Fixture) ToGetAttestationResponse() *agentv1.GetAttestationResponse {
	if f.Attestation == nil {
		return &agentv1.GetAttestationResponse{
			Status: agentv1.AttestationStatus_ATTESTATION_STATUS_UNAVAILABLE,
		}
	}

	var certs []*agentv1.Certificate
	for _, c := range f.Attestation.Certificates {
		certs = append(certs, &agentv1.Certificate{
			Level:             c.Level,
			Subject:           c.Subject,
			Issuer:            c.Issuer,
			NotBefore:         c.NotBefore,
			NotAfter:          c.NotAfter,
			Algorithm:         c.Algorithm,
			Pem:               c.PEM,
			FingerprintSha256: c.FingerprintSHA256,
		})
	}

	status := parseAttestationStatus(f.Attestation.Status)

	return &agentv1.GetAttestationResponse{
		Certificates: certs,
		Measurements: f.Attestation.Measurements,
		Status:       status,
	}
}

// ToHealthCheckResponse converts fixture data to a HealthCheckResponse.
func (f *Fixture) ToHealthCheckResponse() *agentv1.HealthCheckResponse {
	if f.Health == nil {
		return &agentv1.HealthCheckResponse{
			Healthy: true,
			Version: "0.1.0",
		}
	}

	components := make(map[string]*agentv1.ComponentHealth)
	for name, c := range f.Health.Components {
		components[name] = &agentv1.ComponentHealth{
			Healthy: c.Healthy,
			Message: c.Message,
		}
	}

	return &agentv1.HealthCheckResponse{
		Healthy:       f.Health.Healthy,
		Version:       f.Health.Version,
		UptimeSeconds: f.Health.UptimeSeconds,
		Components:    components,
	}
}

func parseAttestationStatus(s string) agentv1.AttestationStatus {
	switch s {
	case "ATTESTATION_STATUS_VALID":
		return agentv1.AttestationStatus_ATTESTATION_STATUS_VALID
	case "ATTESTATION_STATUS_INVALID":
		return agentv1.AttestationStatus_ATTESTATION_STATUS_INVALID
	case "ATTESTATION_STATUS_UNAVAILABLE":
		return agentv1.AttestationStatus_ATTESTATION_STATUS_UNAVAILABLE
	default:
		return agentv1.AttestationStatus_ATTESTATION_STATUS_UNSPECIFIED
	}
}
