// Package grpcclient provides a shared gRPC client for DPU agent communication.
package grpcclient

import (
	"context"
	"fmt"

	agentv1 "github.com/gobeyondidentity/cobalt/gen/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client wraps the DPUAgentService gRPC client.
type Client struct {
	conn   *grpc.ClientConn
	client agentv1.DPUAgentServiceClient
}

// NewClient creates a new gRPC client connected to the specified address.
// Connection is lazy; errors surface on first RPC call.
func NewClient(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for %s: %w", addr, err)
	}

	return &Client{
		conn:   conn,
		client: agentv1.NewDPUAgentServiceClient(conn),
	}, nil
}

// NewClientWithService creates a client with injected dependencies for testing.
func NewClientWithService(conn *grpc.ClientConn, client agentv1.DPUAgentServiceClient) *Client {
	return &Client{
		conn:   conn,
		client: client,
	}
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// HealthCheck checks agent health.
func (c *Client) HealthCheck(ctx context.Context) (*agentv1.HealthCheckResponse, error) {
	return c.client.HealthCheck(ctx, &agentv1.HealthCheckRequest{})
}

// GetSystemInfo retrieves DPU system information.
func (c *Client) GetSystemInfo(ctx context.Context) (*agentv1.GetSystemInfoResponse, error) {
	return c.client.GetSystemInfo(ctx, &agentv1.GetSystemInfoRequest{})
}

// ListBridges retrieves OVS bridges.
func (c *Client) ListBridges(ctx context.Context) (*agentv1.ListBridgesResponse, error) {
	return c.client.ListBridges(ctx, &agentv1.ListBridgesRequest{})
}

// GetFlows retrieves OVS flows for a bridge.
func (c *Client) GetFlows(ctx context.Context, bridge string) (*agentv1.GetFlowsResponse, error) {
	return c.client.GetFlows(ctx, &agentv1.GetFlowsRequest{Bridge: bridge})
}

// GetAttestation retrieves attestation certificates for the specified target (IRoT or ERoT).
func (c *Client) GetAttestation(ctx context.Context, target string) (*agentv1.GetAttestationResponse, error) {
	return c.client.GetAttestation(ctx, &agentv1.GetAttestationRequest{Target: target})
}

// GetDPUInventory retrieves detailed firmware and software inventory.
func (c *Client) GetDPUInventory(ctx context.Context) (*agentv1.GetDPUInventoryResponse, error) {
	return c.client.GetDPUInventory(ctx, &agentv1.GetDPUInventoryRequest{})
}

// GetSignedMeasurements retrieves SPDM signed measurements.
func (c *Client) GetSignedMeasurements(ctx context.Context, nonce string, indices []int32, target string) (*agentv1.GetSignedMeasurementsResponse, error) {
	return c.client.GetSignedMeasurements(ctx, &agentv1.GetSignedMeasurementsRequest{
		Nonce:   nonce,
		Indices: indices,
		Target:  target,
	})
}

// DistributeCredential sends a credential to the DPU agent for installation.
func (c *Client) DistributeCredential(ctx context.Context, credType, credName string, publicKey []byte) (*agentv1.DistributeCredentialResponse, error) {
	return c.client.DistributeCredential(ctx, &agentv1.DistributeCredentialRequest{
		CredentialType: credType,
		CredentialName: credName,
		PublicKey:      publicKey,
	})
}
