package grpcclient

import (
	"context"
	"errors"
	"net"
	"testing"

	agentv1 "github.com/gobeyondidentity/cobalt/gen/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// mockDPUAgentServiceClient implements agentv1.DPUAgentServiceClient for testing.
type mockDPUAgentServiceClient struct {
	healthCheckFunc           func(ctx context.Context, req *agentv1.HealthCheckRequest, opts ...grpc.CallOption) (*agentv1.HealthCheckResponse, error)
	getSystemInfoFunc         func(ctx context.Context, req *agentv1.GetSystemInfoRequest, opts ...grpc.CallOption) (*agentv1.GetSystemInfoResponse, error)
	listBridgesFunc           func(ctx context.Context, req *agentv1.ListBridgesRequest, opts ...grpc.CallOption) (*agentv1.ListBridgesResponse, error)
	getFlowsFunc              func(ctx context.Context, req *agentv1.GetFlowsRequest, opts ...grpc.CallOption) (*agentv1.GetFlowsResponse, error)
	getAttestationFunc        func(ctx context.Context, req *agentv1.GetAttestationRequest, opts ...grpc.CallOption) (*agentv1.GetAttestationResponse, error)
	getDPUInventoryFunc       func(ctx context.Context, req *agentv1.GetDPUInventoryRequest, opts ...grpc.CallOption) (*agentv1.GetDPUInventoryResponse, error)
	getSignedMeasurementsFunc func(ctx context.Context, req *agentv1.GetSignedMeasurementsRequest, opts ...grpc.CallOption) (*agentv1.GetSignedMeasurementsResponse, error)
	distributeCredentialFunc  func(ctx context.Context, req *agentv1.DistributeCredentialRequest, opts ...grpc.CallOption) (*agentv1.DistributeCredentialResponse, error)
}

func (m *mockDPUAgentServiceClient) HealthCheck(ctx context.Context, req *agentv1.HealthCheckRequest, opts ...grpc.CallOption) (*agentv1.HealthCheckResponse, error) {
	if m.healthCheckFunc != nil {
		return m.healthCheckFunc(ctx, req, opts...)
	}
	return &agentv1.HealthCheckResponse{Healthy: true}, nil
}

func (m *mockDPUAgentServiceClient) GetSystemInfo(ctx context.Context, req *agentv1.GetSystemInfoRequest, opts ...grpc.CallOption) (*agentv1.GetSystemInfoResponse, error) {
	if m.getSystemInfoFunc != nil {
		return m.getSystemInfoFunc(ctx, req, opts...)
	}
	return &agentv1.GetSystemInfoResponse{Hostname: "test-dpu"}, nil
}

func (m *mockDPUAgentServiceClient) ListBridges(ctx context.Context, req *agentv1.ListBridgesRequest, opts ...grpc.CallOption) (*agentv1.ListBridgesResponse, error) {
	if m.listBridgesFunc != nil {
		return m.listBridgesFunc(ctx, req, opts...)
	}
	return &agentv1.ListBridgesResponse{Bridges: []*agentv1.Bridge{{Name: "br0"}}}, nil
}

func (m *mockDPUAgentServiceClient) GetFlows(ctx context.Context, req *agentv1.GetFlowsRequest, opts ...grpc.CallOption) (*agentv1.GetFlowsResponse, error) {
	if m.getFlowsFunc != nil {
		return m.getFlowsFunc(ctx, req, opts...)
	}
	return &agentv1.GetFlowsResponse{}, nil
}

func (m *mockDPUAgentServiceClient) GetAttestation(ctx context.Context, req *agentv1.GetAttestationRequest, opts ...grpc.CallOption) (*agentv1.GetAttestationResponse, error) {
	if m.getAttestationFunc != nil {
		return m.getAttestationFunc(ctx, req, opts...)
	}
	return &agentv1.GetAttestationResponse{}, nil
}

func (m *mockDPUAgentServiceClient) GetDPUInventory(ctx context.Context, req *agentv1.GetDPUInventoryRequest, opts ...grpc.CallOption) (*agentv1.GetDPUInventoryResponse, error) {
	if m.getDPUInventoryFunc != nil {
		return m.getDPUInventoryFunc(ctx, req, opts...)
	}
	return &agentv1.GetDPUInventoryResponse{}, nil
}

func (m *mockDPUAgentServiceClient) GetSignedMeasurements(ctx context.Context, req *agentv1.GetSignedMeasurementsRequest, opts ...grpc.CallOption) (*agentv1.GetSignedMeasurementsResponse, error) {
	if m.getSignedMeasurementsFunc != nil {
		return m.getSignedMeasurementsFunc(ctx, req, opts...)
	}
	return &agentv1.GetSignedMeasurementsResponse{}, nil
}

func (m *mockDPUAgentServiceClient) DistributeCredential(ctx context.Context, req *agentv1.DistributeCredentialRequest, opts ...grpc.CallOption) (*agentv1.DistributeCredentialResponse, error) {
	if m.distributeCredentialFunc != nil {
		return m.distributeCredentialFunc(ctx, req, opts...)
	}
	return &agentv1.DistributeCredentialResponse{Success: true}, nil
}

func TestClient_Close_NilConnection(t *testing.T) {
	t.Log("Testing Close() with nil connection returns no error")
	c := &Client{conn: nil}
	err := c.Close()
	if err != nil {
		t.Errorf("Close() with nil conn: got error %v, want nil", err)
	}
}

func TestClient_HealthCheck(t *testing.T) {
	t.Log("Testing HealthCheck passes through to service client")
	mock := &mockDPUAgentServiceClient{
		healthCheckFunc: func(ctx context.Context, req *agentv1.HealthCheckRequest, opts ...grpc.CallOption) (*agentv1.HealthCheckResponse, error) {
			return &agentv1.HealthCheckResponse{Healthy: true, Version: "1.0.0"}, nil
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
}

func TestClient_HealthCheck_Error(t *testing.T) {
	t.Log("Testing HealthCheck returns error from service client")
	expectedErr := errors.New("connection refused")
	mock := &mockDPUAgentServiceClient{
		healthCheckFunc: func(ctx context.Context, req *agentv1.HealthCheckRequest, opts ...grpc.CallOption) (*agentv1.HealthCheckResponse, error) {
			return nil, expectedErr
		},
	}

	c := NewClientWithService(nil, mock)
	_, err := c.HealthCheck(context.Background())

	if err != expectedErr {
		t.Errorf("HealthCheck() error = %v, want %v", err, expectedErr)
	}
}

func TestClient_GetSystemInfo(t *testing.T) {
	t.Log("Testing GetSystemInfo passes through to service client")
	mock := &mockDPUAgentServiceClient{
		getSystemInfoFunc: func(ctx context.Context, req *agentv1.GetSystemInfoRequest, opts ...grpc.CallOption) (*agentv1.GetSystemInfoResponse, error) {
			return &agentv1.GetSystemInfoResponse{
				Hostname:      "bf3-dpu",
				Model:         "BlueField-3",
				KernelVersion: "5.15.0",
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	resp, err := c.GetSystemInfo(context.Background())

	if err != nil {
		t.Fatalf("GetSystemInfo() error = %v", err)
	}
	if resp.Hostname != "bf3-dpu" {
		t.Errorf("GetSystemInfo() hostname = %q, want %q", resp.Hostname, "bf3-dpu")
	}
	if resp.Model != "BlueField-3" {
		t.Errorf("GetSystemInfo() model = %q, want %q", resp.Model, "BlueField-3")
	}
}

func TestClient_ListBridges(t *testing.T) {
	t.Log("Testing ListBridges passes through to service client")
	mock := &mockDPUAgentServiceClient{
		listBridgesFunc: func(ctx context.Context, req *agentv1.ListBridgesRequest, opts ...grpc.CallOption) (*agentv1.ListBridgesResponse, error) {
			return &agentv1.ListBridgesResponse{
				Bridges: []*agentv1.Bridge{
					{Name: "br0"},
					{Name: "br-int"},
				},
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	resp, err := c.ListBridges(context.Background())

	if err != nil {
		t.Fatalf("ListBridges() error = %v", err)
	}
	if len(resp.Bridges) != 2 {
		t.Errorf("ListBridges() bridge count = %d, want %d", len(resp.Bridges), 2)
	}
	if resp.Bridges[0].Name != "br0" {
		t.Errorf("ListBridges() first bridge = %q, want %q", resp.Bridges[0].Name, "br0")
	}
}

func TestClient_GetFlows(t *testing.T) {
	t.Log("Testing GetFlows passes bridge parameter to service client")
	var capturedBridge string
	mock := &mockDPUAgentServiceClient{
		getFlowsFunc: func(ctx context.Context, req *agentv1.GetFlowsRequest, opts ...grpc.CallOption) (*agentv1.GetFlowsResponse, error) {
			capturedBridge = req.Bridge
			return &agentv1.GetFlowsResponse{
				Flows: []*agentv1.Flow{{Cookie: "0x1234"}},
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	resp, err := c.GetFlows(context.Background(), "br-int")

	if err != nil {
		t.Fatalf("GetFlows() error = %v", err)
	}
	if capturedBridge != "br-int" {
		t.Errorf("GetFlows() bridge parameter = %q, want %q", capturedBridge, "br-int")
	}
	if len(resp.Flows) != 1 {
		t.Errorf("GetFlows() flow count = %d, want %d", len(resp.Flows), 1)
	}
}

func TestClient_GetAttestation(t *testing.T) {
	t.Log("Testing GetAttestation passes target parameter to service client")
	var capturedTarget string
	mock := &mockDPUAgentServiceClient{
		getAttestationFunc: func(ctx context.Context, req *agentv1.GetAttestationRequest, opts ...grpc.CallOption) (*agentv1.GetAttestationResponse, error) {
			capturedTarget = req.Target
			return &agentv1.GetAttestationResponse{
				Status: agentv1.AttestationStatus_ATTESTATION_STATUS_VALID,
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	resp, err := c.GetAttestation(context.Background(), "IRoT")

	if err != nil {
		t.Fatalf("GetAttestation() error = %v", err)
	}
	if capturedTarget != "IRoT" {
		t.Errorf("GetAttestation() target parameter = %q, want %q", capturedTarget, "IRoT")
	}
	if resp.Status != agentv1.AttestationStatus_ATTESTATION_STATUS_VALID {
		t.Errorf("GetAttestation() response status = %v, want VERIFIED", resp.Status)
	}
}

func TestClient_GetDPUInventory(t *testing.T) {
	t.Log("Testing GetDPUInventory passes through to service client")
	mock := &mockDPUAgentServiceClient{
		getDPUInventoryFunc: func(ctx context.Context, req *agentv1.GetDPUInventoryRequest, opts ...grpc.CallOption) (*agentv1.GetDPUInventoryResponse, error) {
			return &agentv1.GetDPUInventoryResponse{
				OperationMode: "embedded",
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	resp, err := c.GetDPUInventory(context.Background())

	if err != nil {
		t.Fatalf("GetDPUInventory() error = %v", err)
	}
	if resp.OperationMode != "embedded" {
		t.Errorf("GetDPUInventory() operation mode = %q, want %q", resp.OperationMode, "embedded")
	}
}

func TestClient_GetSignedMeasurements(t *testing.T) {
	t.Log("Testing GetSignedMeasurements passes all parameters to service client")
	var capturedNonce string
	var capturedIndices []int32
	var capturedTarget string

	mock := &mockDPUAgentServiceClient{
		getSignedMeasurementsFunc: func(ctx context.Context, req *agentv1.GetSignedMeasurementsRequest, opts ...grpc.CallOption) (*agentv1.GetSignedMeasurementsResponse, error) {
			capturedNonce = req.Nonce
			capturedIndices = req.Indices
			capturedTarget = req.Target
			return &agentv1.GetSignedMeasurementsResponse{
				HashingAlgorithm: "SHA-512",
				SpdmVersion:      "1.1.0",
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	indices := []int32{1, 2, 3}
	resp, err := c.GetSignedMeasurements(context.Background(), "test-nonce", indices, "ERoT")

	if err != nil {
		t.Fatalf("GetSignedMeasurements() error = %v", err)
	}
	if capturedNonce != "test-nonce" {
		t.Errorf("GetSignedMeasurements() nonce = %q, want %q", capturedNonce, "test-nonce")
	}
	if len(capturedIndices) != 3 {
		t.Errorf("GetSignedMeasurements() indices count = %d, want %d", len(capturedIndices), 3)
	}
	if capturedTarget != "ERoT" {
		t.Errorf("GetSignedMeasurements() target = %q, want %q", capturedTarget, "ERoT")
	}
	if resp.HashingAlgorithm != "SHA-512" {
		t.Errorf("GetSignedMeasurements() response hashing algorithm = %q, want %q", resp.HashingAlgorithm, "SHA-512")
	}
}

func TestClient_DistributeCredential(t *testing.T) {
	t.Log("Testing DistributeCredential passes all parameters to service client")
	var capturedType, capturedName string
	var capturedKey []byte

	mock := &mockDPUAgentServiceClient{
		distributeCredentialFunc: func(ctx context.Context, req *agentv1.DistributeCredentialRequest, opts ...grpc.CallOption) (*agentv1.DistributeCredentialResponse, error) {
			capturedType = req.CredentialType
			capturedName = req.CredentialName
			capturedKey = req.PublicKey
			return &agentv1.DistributeCredentialResponse{
				Success: true,
				Message: "installed",
			}, nil
		},
	}

	c := NewClientWithService(nil, mock)
	pubKey := []byte("ssh-ed25519 AAAAC3...")
	resp, err := c.DistributeCredential(context.Background(), "ssh_ca", "my-ca", pubKey)

	if err != nil {
		t.Fatalf("DistributeCredential() error = %v", err)
	}
	if capturedType != "ssh_ca" {
		t.Errorf("DistributeCredential() type = %q, want %q", capturedType, "ssh_ca")
	}
	if capturedName != "my-ca" {
		t.Errorf("DistributeCredential() name = %q, want %q", capturedName, "my-ca")
	}
	if string(capturedKey) != string(pubKey) {
		t.Errorf("DistributeCredential() key mismatch")
	}
	if !resp.Success {
		t.Error("DistributeCredential() success = false, want true")
	}
	if resp.Message != "installed" {
		t.Errorf("DistributeCredential() message = %q, want %q", resp.Message, "installed")
	}
}

func TestClient_DistributeCredential_Error(t *testing.T) {
	t.Log("Testing DistributeCredential returns error from service client")
	expectedErr := errors.New("permission denied")
	mock := &mockDPUAgentServiceClient{
		distributeCredentialFunc: func(ctx context.Context, req *agentv1.DistributeCredentialRequest, opts ...grpc.CallOption) (*agentv1.DistributeCredentialResponse, error) {
			return nil, expectedErr
		},
	}

	c := NewClientWithService(nil, mock)
	_, err := c.DistributeCredential(context.Background(), "ssh_ca", "my-ca", []byte("key"))

	if err != expectedErr {
		t.Errorf("DistributeCredential() error = %v, want %v", err, expectedErr)
	}
}

func TestNewClientWithService(t *testing.T) {
	t.Log("Testing NewClientWithService creates client with injected dependencies")
	mock := &mockDPUAgentServiceClient{}

	c := NewClientWithService(nil, mock)

	if c == nil {
		t.Fatal("NewClientWithService() returned nil")
	}
	if c.client == nil {
		t.Error("NewClientWithService() client field is nil")
	}
}

func TestClient_Close_WithConnection(t *testing.T) {
	t.Log("Testing Close() with non-nil connection calls conn.Close()")

	// Create an in-memory gRPC server using bufconn
	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)

	server := grpc.NewServer()
	agentv1.RegisterDPUAgentServiceServer(server, &mockAgentServer{})
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
	c := &Client{conn: conn, client: agentv1.NewDPUAgentServiceClient(conn)}

	// Close should work
	err = c.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

// mockAgentServer implements agentv1.DPUAgentServiceServer for bufconn testing.
type mockAgentServer struct {
	agentv1.UnimplementedDPUAgentServiceServer
}

func (s *mockAgentServer) HealthCheck(ctx context.Context, req *agentv1.HealthCheckRequest) (*agentv1.HealthCheckResponse, error) {
	return &agentv1.HealthCheckResponse{Healthy: true}, nil
}

func TestNewClient_LazyConnection(t *testing.T) {
	t.Log("Testing NewClient succeeds (lazy connection), RPC fails on unreachable address")

	// grpc.NewClient uses lazy connection, so NewClient succeeds even for bad addresses
	c, err := NewClient("localhost:1")
	if err != nil {
		t.Fatalf("NewClient() error = %v, want nil (lazy connection)", err)
	}
	defer c.Close()

	// The error surfaces when we make an RPC call
	ctx := context.Background()
	_, err = c.HealthCheck(ctx)
	if err == nil {
		t.Error("HealthCheck() on unreachable address should return error")
	}
}
