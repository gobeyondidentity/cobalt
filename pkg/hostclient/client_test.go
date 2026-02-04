package hostclient

import (
	"context"
	"errors"
	"net"
	"testing"

	hostv1 "github.com/gobeyondidentity/cobalt/gen/go/host/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// mockHostAgentServiceClient implements hostv1.HostAgentServiceClient for testing.
type mockHostAgentServiceClient struct {
	getHostInfoFunc       func(ctx context.Context, req *hostv1.GetHostInfoRequest, opts ...grpc.CallOption) (*hostv1.GetHostInfoResponse, error)
	getGPUInfoFunc        func(ctx context.Context, req *hostv1.GetGPUInfoRequest, opts ...grpc.CallOption) (*hostv1.GetGPUInfoResponse, error)
	getSecurityInfoFunc   func(ctx context.Context, req *hostv1.GetSecurityInfoRequest, opts ...grpc.CallOption) (*hostv1.GetSecurityInfoResponse, error)
	getDPUConnectionsFunc func(ctx context.Context, req *hostv1.GetDPUConnectionsRequest, opts ...grpc.CallOption) (*hostv1.GetDPUConnectionsResponse, error)
	healthCheckFunc       func(ctx context.Context, req *hostv1.HealthCheckRequest, opts ...grpc.CallOption) (*hostv1.HealthCheckResponse, error)
	scanSSHKeysFunc       func(ctx context.Context, req *hostv1.ScanSSHKeysRequest, opts ...grpc.CallOption) (*hostv1.ScanSSHKeysResponse, error)
}

func (m *mockHostAgentServiceClient) GetHostInfo(ctx context.Context, req *hostv1.GetHostInfoRequest, opts ...grpc.CallOption) (*hostv1.GetHostInfoResponse, error) {
	if m.getHostInfoFunc != nil {
		return m.getHostInfoFunc(ctx, req, opts...)
	}
	return &hostv1.GetHostInfoResponse{Hostname: "test-host"}, nil
}

func (m *mockHostAgentServiceClient) GetGPUInfo(ctx context.Context, req *hostv1.GetGPUInfoRequest, opts ...grpc.CallOption) (*hostv1.GetGPUInfoResponse, error) {
	if m.getGPUInfoFunc != nil {
		return m.getGPUInfoFunc(ctx, req, opts...)
	}
	return &hostv1.GetGPUInfoResponse{}, nil
}

func (m *mockHostAgentServiceClient) GetSecurityInfo(ctx context.Context, req *hostv1.GetSecurityInfoRequest, opts ...grpc.CallOption) (*hostv1.GetSecurityInfoResponse, error) {
	if m.getSecurityInfoFunc != nil {
		return m.getSecurityInfoFunc(ctx, req, opts...)
	}
	return &hostv1.GetSecurityInfoResponse{}, nil
}

func (m *mockHostAgentServiceClient) GetDPUConnections(ctx context.Context, req *hostv1.GetDPUConnectionsRequest, opts ...grpc.CallOption) (*hostv1.GetDPUConnectionsResponse, error) {
	if m.getDPUConnectionsFunc != nil {
		return m.getDPUConnectionsFunc(ctx, req, opts...)
	}
	return &hostv1.GetDPUConnectionsResponse{}, nil
}

func (m *mockHostAgentServiceClient) HealthCheck(ctx context.Context, req *hostv1.HealthCheckRequest, opts ...grpc.CallOption) (*hostv1.HealthCheckResponse, error) {
	if m.healthCheckFunc != nil {
		return m.healthCheckFunc(ctx, req, opts...)
	}
	return &hostv1.HealthCheckResponse{Healthy: true}, nil
}

func (m *mockHostAgentServiceClient) ScanSSHKeys(ctx context.Context, req *hostv1.ScanSSHKeysRequest, opts ...grpc.CallOption) (*hostv1.ScanSSHKeysResponse, error) {
	if m.scanSSHKeysFunc != nil {
		return m.scanSSHKeysFunc(ctx, req, opts...)
	}
	return &hostv1.ScanSSHKeysResponse{}, nil
}

func TestClient_Close_NilConnection(t *testing.T) {
	t.Log("Testing Close() with nil connection returns no error")
	c := &Client{conn: nil}
	err := c.Close()
	if err != nil {
		t.Errorf("Close() with nil conn: got error %v, want nil", err)
	}
}

func TestClient_GetHostInfo(t *testing.T) {
	t.Log("Testing GetHostInfo passes through to service client")
	mock := &mockHostAgentServiceClient{
		getHostInfoFunc: func(ctx context.Context, req *hostv1.GetHostInfoRequest, opts ...grpc.CallOption) (*hostv1.GetHostInfoResponse, error) {
			return &hostv1.GetHostInfoResponse{
				Hostname:      "workbench",
				OsName:        "Ubuntu",
				OsVersion:     "24.04",
				KernelVersion: "6.8.0",
				Architecture:  "x86_64",
				CpuCores:      32,
				MemoryGb:      128,
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	resp, err := c.GetHostInfo(context.Background())

	if err != nil {
		t.Fatalf("GetHostInfo() error = %v", err)
	}
	if resp.Hostname != "workbench" {
		t.Errorf("GetHostInfo() hostname = %q, want %q", resp.Hostname, "workbench")
	}
	if resp.OsName != "Ubuntu" {
		t.Errorf("GetHostInfo() os_name = %q, want %q", resp.OsName, "Ubuntu")
	}
	if resp.CpuCores != 32 {
		t.Errorf("GetHostInfo() cpu_cores = %d, want %d", resp.CpuCores, 32)
	}
}

func TestClient_GetHostInfo_Error(t *testing.T) {
	t.Log("Testing GetHostInfo returns error from service client")
	expectedErr := errors.New("connection lost")
	mock := &mockHostAgentServiceClient{
		getHostInfoFunc: func(ctx context.Context, req *hostv1.GetHostInfoRequest, opts ...grpc.CallOption) (*hostv1.GetHostInfoResponse, error) {
			return nil, expectedErr
		},
	}

	c := NewClientWithService(nil, mock)
	_, err := c.GetHostInfo(context.Background())

	if err != expectedErr {
		t.Errorf("GetHostInfo() error = %v, want %v", err, expectedErr)
	}
}

func TestClient_GetGPUInfo(t *testing.T) {
	t.Log("Testing GetGPUInfo passes through to service client")
	mock := &mockHostAgentServiceClient{
		getGPUInfoFunc: func(ctx context.Context, req *hostv1.GetGPUInfoRequest, opts ...grpc.CallOption) (*hostv1.GetGPUInfoResponse, error) {
			return &hostv1.GetGPUInfoResponse{
				Gpus: []*hostv1.GPU{
					{
						Index:         0,
						Name:          "NVIDIA RTX 5080",
						Uuid:          "GPU-12345",
						DriverVersion: "565.00",
						MemoryMb:      16384,
					},
				},
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	resp, err := c.GetGPUInfo(context.Background())

	if err != nil {
		t.Fatalf("GetGPUInfo() error = %v", err)
	}
	if len(resp.Gpus) != 1 {
		t.Fatalf("GetGPUInfo() gpu count = %d, want %d", len(resp.Gpus), 1)
	}
	if resp.Gpus[0].Name != "NVIDIA RTX 5080" {
		t.Errorf("GetGPUInfo() gpu name = %q, want %q", resp.Gpus[0].Name, "NVIDIA RTX 5080")
	}
}

func TestClient_GetSecurityInfo(t *testing.T) {
	t.Log("Testing GetSecurityInfo passes through to service client")
	mock := &mockHostAgentServiceClient{
		getSecurityInfoFunc: func(ctx context.Context, req *hostv1.GetSecurityInfoRequest, opts ...grpc.CallOption) (*hostv1.GetSecurityInfoResponse, error) {
			return &hostv1.GetSecurityInfoResponse{
				SecureBootEnabled: true,
				TpmPresent:        true,
				TpmVersion:        "2.0",
				UefiMode:          true,
				FirewallStatus:    "active",
				SelinuxStatus:     "n/a",
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	resp, err := c.GetSecurityInfo(context.Background())

	if err != nil {
		t.Fatalf("GetSecurityInfo() error = %v", err)
	}
	if !resp.SecureBootEnabled {
		t.Error("GetSecurityInfo() secure_boot_enabled = false, want true")
	}
	if !resp.TpmPresent {
		t.Error("GetSecurityInfo() tpm_present = false, want true")
	}
	if resp.TpmVersion != "2.0" {
		t.Errorf("GetSecurityInfo() tpm_version = %q, want %q", resp.TpmVersion, "2.0")
	}
	if resp.FirewallStatus != "active" {
		t.Errorf("GetSecurityInfo() firewall_status = %q, want %q", resp.FirewallStatus, "active")
	}
}

func TestClient_GetDPUConnections(t *testing.T) {
	t.Log("Testing GetDPUConnections passes through to service client")
	mock := &mockHostAgentServiceClient{
		getDPUConnectionsFunc: func(ctx context.Context, req *hostv1.GetDPUConnectionsRequest, opts ...grpc.CallOption) (*hostv1.GetDPUConnectionsResponse, error) {
			return &hostv1.GetDPUConnectionsResponse{
				Dpus: []*hostv1.DPUConnection{
					{
						Name:        "rshim0",
						PciAddress:  "0000:03:00.0",
						RshimDevice: "/dev/rshim0",
						Connected:   true,
					},
				},
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	resp, err := c.GetDPUConnections(context.Background())

	if err != nil {
		t.Fatalf("GetDPUConnections() error = %v", err)
	}
	if len(resp.Dpus) != 1 {
		t.Fatalf("GetDPUConnections() dpu count = %d, want %d", len(resp.Dpus), 1)
	}
	if resp.Dpus[0].Name != "rshim0" {
		t.Errorf("GetDPUConnections() dpu name = %q, want %q", resp.Dpus[0].Name, "rshim0")
	}
	if !resp.Dpus[0].Connected {
		t.Error("GetDPUConnections() connected = false, want true")
	}
}

func TestClient_HealthCheck(t *testing.T) {
	t.Log("Testing HealthCheck passes through to service client")
	mock := &mockHostAgentServiceClient{
		healthCheckFunc: func(ctx context.Context, req *hostv1.HealthCheckRequest, opts ...grpc.CallOption) (*hostv1.HealthCheckResponse, error) {
			return &hostv1.HealthCheckResponse{
				Healthy:       true,
				Version:       "1.0.0",
				UptimeSeconds: 3600,
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	resp, err := c.HealthCheck(context.Background())

	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}
	if !resp.Healthy {
		t.Error("HealthCheck() healthy = false, want true")
	}
	if resp.Version != "1.0.0" {
		t.Errorf("HealthCheck() version = %q, want %q", resp.Version, "1.0.0")
	}
	if resp.UptimeSeconds != 3600 {
		t.Errorf("HealthCheck() uptime = %d, want %d", resp.UptimeSeconds, 3600)
	}
}

func TestClient_HealthCheck_Error(t *testing.T) {
	t.Log("Testing HealthCheck returns error from service client")
	expectedErr := errors.New("agent unreachable")
	mock := &mockHostAgentServiceClient{
		healthCheckFunc: func(ctx context.Context, req *hostv1.HealthCheckRequest, opts ...grpc.CallOption) (*hostv1.HealthCheckResponse, error) {
			return nil, expectedErr
		},
	}

	c := NewClientWithService(nil, mock)
	_, err := c.HealthCheck(context.Background())

	if err != expectedErr {
		t.Errorf("HealthCheck() error = %v, want %v", err, expectedErr)
	}
}

func TestNewClientWithService(t *testing.T) {
	t.Log("Testing NewClientWithService creates client with injected dependencies")
	mock := &mockHostAgentServiceClient{}

	c := NewClientWithService(nil, mock)

	if c == nil {
		t.Fatal("NewClientWithService() returned nil")
	}
	if c.client == nil {
		t.Error("NewClientWithService() client field is nil")
	}
}

// mockHostAgentServer implements hostv1.HostAgentServiceServer for bufconn testing.
type mockHostAgentServer struct {
	hostv1.UnimplementedHostAgentServiceServer
}

func (s *mockHostAgentServer) HealthCheck(ctx context.Context, req *hostv1.HealthCheckRequest) (*hostv1.HealthCheckResponse, error) {
	return &hostv1.HealthCheckResponse{Healthy: true}, nil
}

func TestClient_Close_WithConnection(t *testing.T) {
	t.Log("Testing Close() with non-nil connection calls conn.Close()")

	// Create an in-memory gRPC server using bufconn
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)

	server := grpc.NewServer()
	hostv1.RegisterHostAgentServiceServer(server, &mockHostAgentServer{})
	go func() {
		if err := server.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Logf("Server error: %v", err)
		}
	}()
	defer server.Stop()

	// Create a connection to the bufconn server
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}

	// Create client with the real connection
	c := &Client{conn: conn, client: hostv1.NewHostAgentServiceClient(conn)}

	// Close should work
	err = c.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestNewClient_ConnectionRefused(t *testing.T) {
	t.Log("Testing NewClient with unreachable address returns error")

	// Try to connect to a port that's definitely not listening
	_, err := NewClient("localhost:1")

	if err == nil {
		t.Error("NewClient() with bad address should return error")
	}
}
