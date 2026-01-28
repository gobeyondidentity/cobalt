package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(tenantCmd)
	tenantCmd.AddCommand(tenantListCmd)
	tenantCmd.AddCommand(tenantAddCmd)
	tenantCmd.AddCommand(tenantRemoveCmd)
	tenantCmd.AddCommand(tenantShowCmd)
	tenantCmd.AddCommand(tenantUpdateCmd)
	tenantCmd.AddCommand(tenantAssignCmd)
	tenantCmd.AddCommand(tenantUnassignCmd)

	// Add flags for tenant add
	tenantAddCmd.Flags().StringP("description", "d", "", "Tenant description")
	tenantAddCmd.Flags().StringP("contact", "c", "", "Contact email")
	tenantAddCmd.Flags().StringSliceP("tags", "t", nil, "Tags (comma-separated)")

	// Add flags for tenant update
	tenantUpdateCmd.Flags().StringP("name", "n", "", "New name")
	tenantUpdateCmd.Flags().StringP("description", "d", "", "New description")
	tenantUpdateCmd.Flags().StringP("contact", "c", "", "New contact email")
	tenantUpdateCmd.Flags().StringSliceP("tags", "t", nil, "New tags (comma-separated)")
}

var tenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Manage tenants",
	Long:  `Commands to list, add, remove, and manage tenant groupings for DPUs.`,
}

var tenantListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tenants",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Use remote Nexus server if configured
		if serverURL := GetServer(); serverURL != "" {
			return listTenantsRemote(cmd.Context(), serverURL)
		}

		tenants, err := dpuStore.ListTenants()
		if err != nil {
			return err
		}

		if outputFormat != "table" {
			return formatOutput(tenants)
		}

		if len(tenants) == 0 {
			fmt.Println("No tenants found. Use 'bluectl tenant add' to create one.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tDESCRIPTION\tCONTACT\tDPUs\tTAGS")
		for _, t := range tenants {
			count, _ := dpuStore.GetTenantDPUCount(t.ID)
			tags := strings.Join(t.Tags, ", ")
			if tags == "" {
				tags = "-"
			}
			desc := t.Description
			if desc == "" {
				desc = "-"
			} else if len(desc) > 40 {
				desc = desc[:37] + "..."
			}
			contact := t.Contact
			if contact == "" {
				contact = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
				t.Name, desc, contact, count, tags)
		}
		w.Flush()
		return nil
	},
}

func listTenantsRemote(ctx context.Context, serverURL string) error {
	client := NewNexusClient(serverURL)
	tenants, err := client.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("failed to list tenants from server: %w", err)
	}

	if outputFormat != "table" {
		if len(tenants) == 0 {
			fmt.Println("[]")
			return nil
		}
		return formatOutput(tenants)
	}

	if len(tenants) == 0 {
		fmt.Println("No tenants found. Use 'bluectl tenant add' to create one.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDESCRIPTION\tCONTACT\tDPUs\tTAGS")
	for _, t := range tenants {
		tags := strings.Join(t.Tags, ", ")
		if tags == "" {
			tags = "-"
		}
		desc := t.Description
		if desc == "" {
			desc = "-"
		} else if len(desc) > 40 {
			desc = desc[:37] + "..."
		}
		contact := t.Contact
		if contact == "" {
			contact = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
			t.Name, desc, contact, t.DPUCount, tags)
	}
	w.Flush()
	return nil
}

var tenantAddCmd = &cobra.Command{
	Use:     "add <name>",
	Aliases: []string{"create"},
	Short:   "Create a new tenant",
	Long: `Create a new tenant to group DPUs.

Examples:
  bluectl tenant add "Acme Corp"
  bluectl tenant add "Production" -d "Production environment" -c "ops@example.com"
  bluectl tenant add "Dev Team" -t staging,dev`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		description, _ := cmd.Flags().GetString("description")
		contact, _ := cmd.Flags().GetString("contact")
		tags, _ := cmd.Flags().GetStringSlice("tags")

		// Use remote Nexus server if configured
		if serverURL := GetServer(); serverURL != "" {
			return addTenantRemote(cmd.Context(), serverURL, name, description, contact, tags)
		}

		id := "tnt_" + uuid.New().String()[:8]

		if err := dpuStore.AddTenant(id, name, description, contact, tags); err != nil {
			return fmt.Errorf("failed to add tenant: %w", err)
		}

		fmt.Printf("Created tenant '%s'.\n", name)
		return nil
	},
}

func addTenantRemote(ctx context.Context, serverURL, name, description, contact string, tags []string) error {
	client := NewNexusClient(serverURL)
	tenant, err := client.CreateTenant(ctx, name, description, contact, tags)
	if err != nil {
		return fmt.Errorf("failed to create tenant on server: %w", err)
	}

	if outputFormat == "json" || outputFormat == "yaml" {
		return formatOutput(map[string]any{
			"status": "created",
			"tenant": tenant,
		})
	}

	fmt.Printf("Created tenant '%s'.\n", tenant.Name)
	return nil
}

var tenantRemoveCmd = &cobra.Command{
	Use:     "remove <name-or-id>",
	Aliases: []string{"delete"},
	Short:   "Remove a tenant",
	Long: `Remove a tenant. The tenant must not have any dependencies (DPUs, operators, CAs, or trust relationships).

Examples:
  bluectl tenant remove "Acme Corp"
  bluectl tenant remove abc12345`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Use remote Nexus server if configured
		if serverURL := GetServer(); serverURL != "" {
			return removeTenantRemote(cmd.Context(), serverURL, args[0])
		}

		tenant, err := dpuStore.GetTenant(args[0])
		if err != nil {
			return fmt.Errorf("tenant not found: %s", args[0])
		}

		deps, err := dpuStore.GetTenantDependencies(tenant.ID)
		if err != nil {
			return fmt.Errorf("failed to check dependencies: %w", err)
		}

		if deps.HasAny() {
			fmt.Fprintf(os.Stderr, "Cannot remove tenant '%s'. The following depend on it:\n", tenant.Name)
			if len(deps.DPUs) > 0 {
				fmt.Fprintf(os.Stderr, "  DPUs (%d): %s\n", len(deps.DPUs), strings.Join(deps.DPUs, ", "))
			}
			if len(deps.Operators) > 0 {
				fmt.Fprintf(os.Stderr, "  Operators (%d): %s\n", len(deps.Operators), strings.Join(deps.Operators, ", "))
			}
			if len(deps.CAs) > 0 {
				fmt.Fprintf(os.Stderr, "  SSH CAs (%d): %s\n", len(deps.CAs), strings.Join(deps.CAs, ", "))
			}
			if deps.TrustRelationships > 0 {
				fmt.Fprintf(os.Stderr, "  Trust relationships: %d\n", deps.TrustRelationships)
			}
			fmt.Fprintf(os.Stderr, "\nTo see details: bluectl tenant show %s\n", tenant.Name)
			return fmt.Errorf("tenant has dependencies that must be removed first")
		}

		if err := dpuStore.RemoveTenant(tenant.ID); err != nil {
			return err
		}
		fmt.Printf("Removed tenant '%s'\n", tenant.Name)
		return nil
	},
}

func removeTenantRemote(ctx context.Context, serverURL, nameOrID string) error {
	client := NewNexusClient(serverURL)

	// Resolve tenant name to ID
	tenants, err := client.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	var tenantID, tenantName string
	for _, t := range tenants {
		if t.Name == nameOrID || t.ID == nameOrID {
			tenantID = t.ID
			tenantName = t.Name
			break
		}
	}
	if tenantID == "" {
		return fmt.Errorf("tenant not found: %s", nameOrID)
	}

	if err := client.DeleteTenant(ctx, tenantID); err != nil {
		return fmt.Errorf("failed to remove tenant from server: %w", err)
	}
	fmt.Printf("Removed tenant '%s'\n", tenantName)
	return nil
}

var tenantShowCmd = &cobra.Command{
	Use:     "show <name-or-id>",
	Aliases: []string{"describe"},
	Short:   "Show tenant details",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tenant, err := dpuStore.GetTenant(args[0])
		if err != nil {
			return fmt.Errorf("tenant not found: %s", args[0])
		}

		dpus, _ := dpuStore.ListDPUsByTenant(tenant.ID)

		if outputFormat != "table" {
			return formatOutput(map[string]interface{}{
				"tenant": tenant,
				"dpus":   dpus,
			})
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "Name:\t%s\n", tenant.Name)
		fmt.Fprintf(w, "Description:\t%s\n", tenant.Description)
		fmt.Fprintf(w, "Contact:\t%s\n", tenant.Contact)
		if len(tenant.Tags) > 0 {
			fmt.Fprintf(w, "Tags:\t%s\n", strings.Join(tenant.Tags, ", "))
		}
		fmt.Fprintf(w, "Created:\t%s\n", tenant.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(w, "Updated:\t%s\n", tenant.UpdatedAt.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(w, "DPU Count:\t%d\n", len(dpus))
		w.Flush()

		if len(dpus) > 0 {
			fmt.Println("\nAssigned DPUs:")
			w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  NAME\tHOST\tSTATUS")
			for _, dpu := range dpus {
				fmt.Fprintf(w, "  %s\t%s\t%s\n", dpu.Name, dpu.Host, dpu.Status)
			}
			w.Flush()
		}

		return nil
	},
}

var tenantUpdateCmd = &cobra.Command{
	Use:   "update <name-or-id>",
	Short: "Update tenant details",
	Long: `Update tenant name, description, contact, or tags.

Examples:
  bluectl tenant update "Acme Corp" -n "Acme Inc"
  bluectl tenant update "Production" -d "Updated description"
  bluectl tenant update "Dev Team" -t dev,staging,test`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tenant, err := dpuStore.GetTenant(args[0])
		if err != nil {
			return fmt.Errorf("tenant not found: %s", args[0])
		}

		// Get new values or use existing
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			name = tenant.Name
		}

		description, _ := cmd.Flags().GetString("description")
		if !cmd.Flags().Changed("description") {
			description = tenant.Description
		}

		contact, _ := cmd.Flags().GetString("contact")
		if !cmd.Flags().Changed("contact") {
			contact = tenant.Contact
		}

		tags, _ := cmd.Flags().GetStringSlice("tags")
		if !cmd.Flags().Changed("tags") {
			tags = tenant.Tags
		}

		if err := dpuStore.UpdateTenant(tenant.ID, name, description, contact, tags); err != nil {
			return fmt.Errorf("failed to update tenant: %w", err)
		}

		fmt.Printf("Updated tenant '%s'\n", name)
		return nil
	},
}

var tenantAssignCmd = &cobra.Command{
	Use:   "assign <tenant-name-or-id> <dpu-name-or-id>",
	Short: "Assign a DPU to a tenant",
	Long: `Assign a DPU to a tenant for grouping and access control.

Examples:
  bluectl tenant assign "Production" bf3-lab
  bluectl tenant assign acme123 dpu456`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Use remote Nexus server if configured
		if serverURL := GetServer(); serverURL != "" {
			return assignDPURemote(cmd.Context(), serverURL, args[0], args[1])
		}

		tenant, err := dpuStore.GetTenant(args[0])
		if err != nil {
			return fmt.Errorf("tenant not found: %s", args[0])
		}

		dpu, err := dpuStore.Get(args[1])
		if err != nil {
			return fmt.Errorf("DPU not found: %s", args[1])
		}

		if err := dpuStore.AssignDPUToTenant(dpu.ID, tenant.ID); err != nil {
			return fmt.Errorf("failed to assign DPU: %w", err)
		}

		fmt.Printf("Assigned DPU '%s' to tenant '%s'\n", dpu.Name, tenant.Name)
		return nil
	},
}

func assignDPURemote(ctx context.Context, serverURL, tenantNameOrID, dpuNameOrID string) error {
	client := NewNexusClient(serverURL)

	// Resolve tenant name to ID
	tenants, err := client.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	var tenantID string
	for _, t := range tenants {
		if t.Name == tenantNameOrID || t.ID == tenantNameOrID {
			tenantID = t.ID
			break
		}
	}
	if tenantID == "" {
		return fmt.Errorf("tenant not found: %s", tenantNameOrID)
	}

	// Resolve DPU name to ID
	dpus, err := client.ListDPUs(ctx)
	if err != nil {
		return fmt.Errorf("failed to list DPUs: %w", err)
	}

	var dpuID, dpuName string
	for _, d := range dpus {
		if d.Name == dpuNameOrID || d.ID == dpuNameOrID {
			dpuID = d.ID
			dpuName = d.Name
			break
		}
	}
	if dpuID == "" {
		return fmt.Errorf("DPU not found: %s", dpuNameOrID)
	}

	if err := client.AssignDPUToTenant(ctx, tenantID, dpuID); err != nil {
		return fmt.Errorf("failed to assign DPU: %w", err)
	}

	fmt.Printf("Assigned DPU '%s' to tenant '%s'\n", dpuName, tenantNameOrID)
	return nil
}

var tenantUnassignCmd = &cobra.Command{
	Use:   "unassign <dpu-name-or-id>",
	Short: "Unassign a DPU from its tenant",
	Long: `Remove a DPU from its current tenant assignment.

Examples:
  bluectl tenant unassign bf3-lab
  bluectl tenant unassign dpu456`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Use remote Nexus server if configured
		if serverURL := GetServer(); serverURL != "" {
			return unassignDPURemote(cmd.Context(), serverURL, args[0])
		}

		dpu, err := dpuStore.Get(args[0])
		if err != nil {
			return fmt.Errorf("DPU not found: %s", args[0])
		}

		if dpu.TenantID == nil {
			return fmt.Errorf("DPU '%s' is not assigned to any tenant", dpu.Name)
		}

		tenant, _ := dpuStore.GetTenant(*dpu.TenantID)
		tenantName := *dpu.TenantID
		if tenant != nil {
			tenantName = tenant.Name
		}

		if err := dpuStore.UnassignDPUFromTenant(dpu.ID); err != nil {
			return fmt.Errorf("failed to unassign DPU: %w", err)
		}

		fmt.Printf("Unassigned DPU '%s' from tenant '%s'\n", dpu.Name, tenantName)
		return nil
	},
}

func unassignDPURemote(ctx context.Context, serverURL, dpuNameOrID string) error {
	client := NewNexusClient(serverURL)

	// Get DPU list to find the DPU and its tenant
	dpus, err := client.ListDPUs(ctx)
	if err != nil {
		return fmt.Errorf("failed to list DPUs: %w", err)
	}

	var targetDPU *dpuResponse
	for i := range dpus {
		if dpus[i].Name == dpuNameOrID || dpus[i].ID == dpuNameOrID {
			targetDPU = &dpus[i]
			break
		}
	}

	if targetDPU == nil {
		return fmt.Errorf("DPU not found: %s", dpuNameOrID)
	}

	if targetDPU.TenantID == nil {
		return fmt.Errorf("DPU '%s' is not assigned to any tenant", targetDPU.Name)
	}

	if err := client.UnassignDPUFromTenant(ctx, *targetDPU.TenantID, targetDPU.ID); err != nil {
		return fmt.Errorf("failed to unassign DPU: %w", err)
	}

	fmt.Printf("Unassigned DPU '%s' from tenant\n", targetDPU.Name)
	return nil
}
