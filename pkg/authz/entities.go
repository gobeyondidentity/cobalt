package authz

import "github.com/cedar-policy/cedar-go"

// buildEntities constructs the Cedar EntityMap from principal and resource.
// This creates the entity graph that Cedar uses to evaluate policies.
func buildEntities(principal Principal, resource Resource) cedar.EntityMap {
	entities := cedar.EntityMap{}

	// Build principal entity
	principalUID := cedar.NewEntityUID(cedar.EntityType(principal.Type), cedar.String(principal.UID))

	// Build tenant parents for principal (supports multi-tenant operators)
	var principalParents cedar.EntityUIDSet
	if len(principal.TenantIDs) > 0 {
		tenantUIDs := make([]cedar.EntityUID, 0, len(principal.TenantIDs))
		for _, tid := range principal.TenantIDs {
			tenantUID := cedar.NewEntityUID("Tenant", cedar.String(tid))
			tenantUIDs = append(tenantUIDs, tenantUID)
			// Ensure tenant entity exists in the map
			if _, exists := entities[tenantUID]; !exists {
				entities[tenantUID] = cedar.Entity{
					UID:        tenantUID,
					Parents:    cedar.NewEntityUIDSet(),
					Attributes: cedar.NewRecord(cedar.RecordMap{}),
				}
			}
		}
		principalParents = cedar.NewEntityUIDSet(tenantUIDs...)
	} else {
		principalParents = cedar.NewEntityUIDSet()
	}

	// Build tenant_ids set for the principal (used by tenant:admin policies)
	tenantIDsSet := make([]cedar.Value, 0, len(principal.TenantIDs))
	for _, tid := range principal.TenantIDs {
		tenantIDsSet = append(tenantIDsSet, cedar.String(tid))
	}

	entities[principalUID] = cedar.Entity{
		UID:     principalUID,
		Parents: principalParents,
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"role":       cedar.String(string(principal.Role)),
			"tenant_ids": cedar.NewSet(tenantIDsSet...),
		}),
	}

	// Build resource entity
	resourceUID := cedar.NewEntityUID(cedar.EntityType(resource.Type), cedar.String(resource.UID))

	var resourceParents cedar.EntityUIDSet
	if resource.TenantID != "" {
		tenantUID := cedar.NewEntityUID("Tenant", cedar.String(resource.TenantID))
		resourceParents = cedar.NewEntityUIDSet(tenantUID)
		// Ensure tenant entity exists in the map
		if _, exists := entities[tenantUID]; !exists {
			entities[tenantUID] = cedar.Entity{
				UID:        tenantUID,
				Parents:    cedar.NewEntityUIDSet(),
				Attributes: cedar.NewRecord(cedar.RecordMap{}),
			}
		}
	} else {
		resourceParents = cedar.NewEntityUIDSet()
	}

	entities[resourceUID] = cedar.Entity{
		UID:     resourceUID,
		Parents: resourceParents,
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"tenant": cedar.String(resource.TenantID),
		}),
	}

	return entities
}

// buildCedarRequest constructs the Cedar request from an AuthzRequest.
// This maps the application-level request to Cedar's evaluation format.
func buildCedarRequest(req AuthzRequest) cedar.Request {
	// Build context record from the request context map
	contextMap := cedar.RecordMap{}

	// Add attestation status if present
	if status, ok := req.Context["attestation_status"].(AttestationStatus); ok {
		contextMap["attestation_status"] = cedar.String(string(status))
	} else if statusStr, ok := req.Context["attestation_status"].(string); ok {
		contextMap["attestation_status"] = cedar.String(statusStr)
	}

	// Add operator_authorized if present (for authorization-based access)
	if authorized, ok := req.Context["operator_authorized"].(bool); ok {
		contextMap["operator_authorized"] = cedar.Boolean(authorized)
	}

	// Add force_bypass_requested if present
	if bypass, ok := req.Context["force_bypass_requested"].(bool); ok {
		contextMap["force_bypass_requested"] = cedar.Boolean(bypass)
	}

	return cedar.Request{
		Principal: cedar.NewEntityUID(cedar.EntityType(req.Principal.Type), cedar.String(req.Principal.UID)),
		Action:    cedar.NewEntityUID("Action", cedar.String(req.Action)),
		Resource:  cedar.NewEntityUID(cedar.EntityType(req.Resource.Type), cedar.String(req.Resource.UID)),
		Context:   cedar.NewRecord(contextMap),
	}
}
