package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gobeyondidentity/cobalt/pkg/attestation"
	"github.com/gobeyondidentity/cobalt/pkg/authz"
	"github.com/gobeyondidentity/cobalt/pkg/dpop"
	"github.com/gobeyondidentity/cobalt/pkg/store"
)

// StorePrincipalLookup resolves DPoP identities to authorization principals using the store.
type StorePrincipalLookup struct {
	store *store.Store
}

// NewStorePrincipalLookup creates a principal lookup backed by the store.
func NewStorePrincipalLookup(s *store.Store) *StorePrincipalLookup {
	return &StorePrincipalLookup{store: s}
}

// LookupPrincipal resolves an authenticated identity to a principal with role and tenants.
func (l *StorePrincipalLookup) LookupPrincipal(ctx context.Context, identity *dpop.Identity) (*authz.Principal, error) {
	if identity == nil {
		return nil, fmt.Errorf("identity is nil")
	}

	switch identity.CallerType {
	case dpop.CallerTypeKeyMaker, dpop.CallerTypeAdmin:
		return l.lookupOperatorPrincipal(ctx, identity)
	case dpop.CallerTypeDPU:
		return l.lookupDPUPrincipal(ctx, identity)
	default:
		return nil, fmt.Errorf("unknown caller type: %s", identity.CallerType)
	}
}

// lookupOperatorPrincipal resolves a keymaker or admin identity to a principal.
func (l *StorePrincipalLookup) lookupOperatorPrincipal(ctx context.Context, identity *dpop.Identity) (*authz.Principal, error) {
	operatorID := identity.OperatorID
	if operatorID == "" {
		return nil, fmt.Errorf("operator ID is empty for identity %s", identity.KID)
	}

	// Get tenant memberships and roles
	tenants, err := l.store.GetOperatorTenants(operatorID)
	if err != nil {
		return nil, fmt.Errorf("failed to get operator tenants: %w", err)
	}

	// Determine highest role and collect tenant IDs
	var tenantIDs []string
	highestRole := authz.RoleOperator // Default to lowest role

	for _, t := range tenants {
		tenantIDs = append(tenantIDs, t.TenantID)

		// Map store role to authz role and track highest
		var role authz.Role
		switch t.Role {
		case "super:admin":
			role = authz.RoleSuperAdmin
		case "tenant:admin", "admin":
			role = authz.RoleTenantAdmin
		default:
			role = authz.RoleOperator
		}

		if roleRank(role) > roleRank(highestRole) {
			highestRole = role
		}
	}

	// Check if operator has super:admin in any tenant
	isSuperAdmin, err := l.store.IsSuperAdmin(operatorID)
	if err != nil {
		return nil, fmt.Errorf("failed to check super admin status: %w", err)
	}
	if isSuperAdmin {
		highestRole = authz.RoleSuperAdmin
	}

	return &authz.Principal{
		UID:       identity.KID,
		Type:      authz.PrincipalOperator,
		Role:      highestRole,
		TenantIDs: tenantIDs,
	}, nil
}

// lookupDPUPrincipal resolves a DPU identity to a principal.
func (l *StorePrincipalLookup) lookupDPUPrincipal(ctx context.Context, identity *dpop.Identity) (*authz.Principal, error) {
	var tenantIDs []string
	if identity.TenantID != "" {
		tenantIDs = []string{identity.TenantID}
	}

	return &authz.Principal{
		UID:       identity.KID,
		Type:      authz.PrincipalDPU,
		Role:      authz.RoleOperator, // DPUs don't have admin roles
		TenantIDs: tenantIDs,
	}, nil
}

// roleRank returns a numeric rank for role comparison.
// Higher rank = more permissions.
func roleRank(role authz.Role) int {
	switch role {
	case authz.RoleSuperAdmin:
		return 3
	case authz.RoleTenantAdmin:
		return 2
	case authz.RoleOperator:
		return 1
	default:
		return 0
	}
}

// StoreResourceExtractor extracts resource information from HTTP requests.
type StoreResourceExtractor struct {
	store *store.Store
}

// NewStoreResourceExtractor creates a resource extractor backed by the store.
func NewStoreResourceExtractor(s *store.Store) *StoreResourceExtractor {
	return &StoreResourceExtractor{store: s}
}

// ExtractResource determines the target resource from the request.
func (e *StoreResourceExtractor) ExtractResource(r *http.Request, action authz.Action, principal *authz.Principal) (*authz.Resource, error) {
	// Determine resource type from action
	resourceType := actionToResourceType(string(action))

	// Try to get resource ID from path parameter
	resourceID := r.PathValue("id")

	// Handle self-referential endpoints
	if resourceID == "me" || resourceID == "" {
		if isSelfAction(string(action)) {
			resourceID = principal.UID
		}
	}

	// For POST/PUT, try to extract resource info from body if needed
	if resourceID == "" && (r.Method == "POST" || r.Method == "PUT") {
		bodyID, _ := extractIDFromBody(r)
		if bodyID != "" {
			resourceID = bodyID
		}
	}

	// Get tenant ID for the resource
	tenantID := e.getResourceTenantID(resourceID, resourceType, principal)

	return &authz.Resource{
		UID:      resourceID,
		Type:     resourceType,
		TenantID: tenantID,
	}, nil
}

// actionToResourceType maps Cedar actions to resource types.
func actionToResourceType(action string) string {
	switch {
	case strings.HasPrefix(action, "operator:"):
		return "Operator"
	case strings.HasPrefix(action, "role:"):
		return "Operator"
	case strings.HasPrefix(action, "dpu:"):
		return "DPU"
	case strings.HasPrefix(action, "credential:"):
		return "DPU"
	case strings.HasPrefix(action, "distribution:"):
		return "Distribution"
	case strings.HasPrefix(action, "authorization:"):
		return "Authorization"
	case strings.HasPrefix(action, "tenant:"):
		return "Tenant"
	case strings.HasPrefix(action, "audit:"):
		return "Audit"
	case strings.HasPrefix(action, "host:"):
		return "DPU"
	case strings.HasPrefix(action, "trust:"):
		return "TrustRelationship"
	case strings.HasPrefix(action, "ssh-ca:"):
		return "SSHCA"
	default:
		return "Unknown"
	}
}

// isSelfAction returns true if the action is self-referential.
func isSelfAction(action string) bool {
	return action == authz.ActionOperatorReadSelf || action == authz.ActionDPUReadOwnConfig || action == authz.ActionHostRegister
}

// extractIDFromBody tries to extract a resource ID from the request body.
// Returns empty string if not found or on error.
// IMPORTANT: This function restores the body so handlers can read it.
func extractIDFromBody(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	// Read body (limit to prevent memory exhaustion)
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return "", err
	}

	// Restore the body for downstream handlers
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Try to parse as JSON
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", nil
	}

	// Look for common ID fields (DPU fields first for push requests)
	for _, field := range []string{"id", "target_dpu", "dpu_id", "dpuId", "device_id", "operator_id", "tenant_id"} {
		if v, ok := data[field]; ok {
			if s, ok := v.(string); ok {
				return s, nil
			}
		}
	}

	return "", nil
}

// getResourceTenantID determines the tenant ID for a resource.
func (e *StoreResourceExtractor) getResourceTenantID(resourceID, resourceType string, principal *authz.Principal) string {
	// If resource ID is empty, use principal's tenant if they have one
	if resourceID == "" && len(principal.TenantIDs) > 0 {
		return principal.TenantIDs[0]
	}

	// Try to look up resource tenant from store based on type
	if resourceID != "" {
		switch resourceType {
		case "DPU":
			if dpu, err := e.store.Get(resourceID); err == nil && dpu != nil && dpu.TenantID != nil {
				return *dpu.TenantID
			}
		case "Operator":
			// Operators can belong to multiple tenants; use first if available
			if tenants, err := e.store.GetOperatorTenants(resourceID); err == nil && len(tenants) > 0 {
				return tenants[0].TenantID
			}
		}
	}

	// Fall back to principal's first tenant
	if len(principal.TenantIDs) > 0 {
		return principal.TenantIDs[0]
	}

	return ""
}

// StoreAuthorizationLookup checks operator authorization grants using the store.
type StoreAuthorizationLookup struct {
	store *store.Store
}

// NewStoreAuthorizationLookup creates an authorization lookup backed by the store.
func NewStoreAuthorizationLookup(s *store.Store) *StoreAuthorizationLookup {
	return &StoreAuthorizationLookup{store: s}
}

// HasAuthorization returns true if the operator has any active authorization grants.
func (l *StoreAuthorizationLookup) HasAuthorization(ctx context.Context, operatorID string) (bool, error) {
	return l.store.HasAnyAuthorization(operatorID)
}

// StoreAttestationLookup retrieves attestation status from the store.
type StoreAttestationLookup struct {
	store *store.Store
}

// NewStoreAttestationLookup creates an attestation lookup backed by the store.
func NewStoreAttestationLookup(s *store.Store) *StoreAttestationLookup {
	return &StoreAttestationLookup{store: s}
}

// GetAttestationStatus returns the current attestation status for a DPU.
func (l *StoreAttestationLookup) GetAttestationStatus(ctx context.Context, dpuID string) (authz.AttestationStatus, error) {
	// Extract DPU name from ID (strip prefix if present)
	dpuName := dpuID
	if strings.HasPrefix(dpuID, "dpu_") {
		// Need to look up the DPU to get its name
		dpu, err := l.store.Get(dpuID)
		if err != nil || dpu == nil {
			return authz.AttestationUnavailable, nil
		}
		dpuName = dpu.Name
	}

	// Get attestation record
	att, err := l.store.GetAttestation(dpuName)
	if err != nil {
		return authz.AttestationUnavailable, nil
	}
	if att == nil {
		return authz.AttestationUnavailable, nil
	}

	// Map store attestation status to authz attestation status
	switch att.Status {
	case store.AttestationStatusVerified:
		return authz.AttestationVerified, nil
	case store.AttestationStatusStale:
		return authz.AttestationStale, nil
	case store.AttestationStatusFailed:
		return authz.AttestationFailed, nil
	case store.AttestationStatusUnavailable, store.AttestationStatusPending:
		return authz.AttestationUnavailable, nil
	default:
		return authz.AttestationUnavailable, nil
	}
}

// AutoRefreshAttestationLookup retrieves attestation status with automatic refresh.
// When status is unavailable or stale, it attempts to refresh attestation from the DPU
// before returning the status. This solves the chicken-and-egg problem where new DPUs
// have no attestation data, causing Cedar policy to block credential:push before the
// handler can trigger a refresh.
type AutoRefreshAttestationLookup struct {
	store  *store.Store
	gate   *attestation.Gate
	logger *slog.Logger
}

// NewAutoRefreshAttestationLookup creates an attestation lookup that auto-refreshes.
func NewAutoRefreshAttestationLookup(s *store.Store, g *attestation.Gate) *AutoRefreshAttestationLookup {
	return &AutoRefreshAttestationLookup{
		store:  s,
		gate:   g,
		logger: slog.Default(),
	}
}

// WithLogger sets a custom logger for the auto-refresh lookup.
func (l *AutoRefreshAttestationLookup) WithLogger(logger *slog.Logger) *AutoRefreshAttestationLookup {
	l.logger = logger
	return l
}

// GetAttestationStatus returns the current attestation status for a DPU.
// If the status is unavailable or stale, it attempts to refresh attestation
// from the DPU before returning the result.
func (l *AutoRefreshAttestationLookup) GetAttestationStatus(ctx context.Context, dpuID string) (authz.AttestationStatus, error) {
	// Look up the DPU to get its full details
	dpu, err := l.store.Get(dpuID)
	if err != nil || dpu == nil {
		// DPU not found, can't refresh
		return authz.AttestationUnavailable, nil
	}

	// Get current attestation status from store
	att, err := l.store.GetAttestation(dpu.Name)
	if err != nil {
		att = nil // Treat as unavailable
	}

	// Determine current status
	var currentStatus authz.AttestationStatus
	if att == nil {
		currentStatus = authz.AttestationUnavailable
	} else {
		switch att.Status {
		case store.AttestationStatusVerified:
			// Check freshness
			if att.Age() <= l.gate.FreshnessWindow {
				return authz.AttestationVerified, nil
			}
			currentStatus = authz.AttestationStale
		case store.AttestationStatusStale:
			currentStatus = authz.AttestationStale
		case store.AttestationStatusFailed:
			// Failed attestation cannot be auto-refreshed
			return authz.AttestationFailed, nil
		default:
			currentStatus = authz.AttestationUnavailable
		}
	}

	// If status is unavailable or stale, attempt auto-refresh
	if currentStatus == authz.AttestationUnavailable || currentStatus == authz.AttestationStale {
		l.logger.Info("auto-refreshing attestation for policy check",
			"dpu_id", dpuID,
			"dpu_name", dpu.Name,
			"current_status", string(currentStatus),
		)

		decision, refreshed, err := l.gate.CanDistributeWithAutoRefresh(
			ctx,
			dpu,
			"authz:middleware", // Trigger source
			"system",           // Triggered by (middleware doesn't know the operator yet)
		)
		if err != nil {
			l.logger.Error("attestation auto-refresh failed",
				"dpu_id", dpuID,
				"error", err,
			)
			return authz.AttestationUnavailable, nil
		}

		if refreshed {
			l.logger.Info("attestation auto-refresh completed",
				"dpu_id", dpuID,
				"dpu_name", dpu.Name,
				"allowed", decision.Allowed,
				"reason", decision.Reason,
			)
		}

		// Map the decision to attestation status
		if decision.Allowed {
			return authz.AttestationVerified, nil
		}

		// Check the reason to determine the actual status
		if decision.IsAttestationFailed() {
			return authz.AttestationFailed, nil
		}

		// Refresh attempted but still not verified
		if decision.Attestation != nil {
			switch decision.Attestation.Status {
			case store.AttestationStatusVerified:
				return authz.AttestationVerified, nil
			case store.AttestationStatusStale:
				return authz.AttestationStale, nil
			case store.AttestationStatusFailed:
				return authz.AttestationFailed, nil
			}
		}

		return authz.AttestationUnavailable, nil
	}

	return currentStatus, nil
}
