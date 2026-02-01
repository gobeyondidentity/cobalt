// Package hostclient provides a gRPC client for the Host Agent.
package hostclient

import (
	"context"
	"fmt"
	"time"

	hostv1 "github.com/gobeyondidentity/secure-infra/gen/go/host/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client wraps the Host Agent gRPC client.
type Client struct {
	conn   *grpc.ClientConn
	client hostv1.HostAgentServiceClient
}

// NewClient creates a new Host Agent client.
func NewClient(addr string) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to host agent at %s: %w", addr, err)
	}

	return &Client{
		conn:   conn,
		client: hostv1.NewHostAgentServiceClient(conn),
	}, nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// GetHostInfo returns basic information about the host machine.
func (c *Client) GetHostInfo(ctx context.Context) (*hostv1.GetHostInfoResponse, error) {
	return c.client.GetHostInfo(ctx, &hostv1.GetHostInfoRequest{})
}

// GetGPUInfo returns information about GPUs installed on the host.
func (c *Client) GetGPUInfo(ctx context.Context) (*hostv1.GetGPUInfoResponse, error) {
	return c.client.GetGPUInfo(ctx, &hostv1.GetGPUInfoRequest{})
}

// GetSecurityInfo returns security posture of the host.
func (c *Client) GetSecurityInfo(ctx context.Context) (*hostv1.GetSecurityInfoResponse, error) {
	return c.client.GetSecurityInfo(ctx, &hostv1.GetSecurityInfoRequest{})
}

// GetDPUConnections returns info about DPUs connected to the host.
func (c *Client) GetDPUConnections(ctx context.Context) (*hostv1.GetDPUConnectionsResponse, error) {
	return c.client.GetDPUConnections(ctx, &hostv1.GetDPUConnectionsRequest{})
}

// HealthCheck verifies the host agent is running and responsive.
func (c *Client) HealthCheck(ctx context.Context) (*hostv1.HealthCheckResponse, error) {
	return c.client.HealthCheck(ctx, &hostv1.HealthCheckRequest{})
}
