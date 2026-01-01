"use client"

import * as React from "react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { CreateTenantModal } from "@/components/create-tenant-modal"
import { HelpTooltip, HelpText } from "@/components/help-tooltip"
import { mockTenants, type Tenant } from "@/lib/mock-data"
import { Plus, Building2, Mail, Calendar } from "lucide-react"

export default function TenantsPage() {
  const [modalOpen, setModalOpen] = React.useState(false)
  const [editingTenant, setEditingTenant] = React.useState<Tenant | null>(null)

  const handleCreateTenant = () => {
    setEditingTenant(null)
    setModalOpen(true)
  }

  const EmptyState = () => (
    <Card className="border-dashed col-span-full">
      <CardContent className="flex flex-col items-center justify-center py-16">
        <div className="rounded-full bg-muted p-4 mb-4">
          <Building2 className="h-8 w-8 text-muted-foreground" />
        </div>
        <h3 className="text-lg font-semibold mb-2">No tenants created</h3>
        <p className="text-muted-foreground text-center mb-4">
          Create your first <HelpText term="tenant">tenant</HelpText> to organize <HelpText term="dpu">DPUs</HelpText>
        </p>
        <Button className="bg-pine-green hover:bg-pine-green/90 text-white" onClick={handleCreateTenant}>
          <Plus className="h-4 w-4 mr-2" />
          Create Tenant
        </Button>
      </CardContent>
    </Card>
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="font-heading text-3xl font-medium tracking-tight">
            <HelpTooltip term="tenant" iconSize="md">
              Tenants
            </HelpTooltip>
          </h1>
          <p className="text-muted-foreground mt-1">
            Organize <HelpText term="dpu">DPUs</HelpText> by customer or environment
          </p>
        </div>
        <Button className="bg-pine-green hover:bg-pine-green/90 text-white" onClick={handleCreateTenant}>
          <Plus className="h-4 w-4 mr-2" />
          Create Tenant
        </Button>
      </div>

      {/* Tenant Cards Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {mockTenants.length === 0 ? (
          <EmptyState />
        ) : (
          mockTenants.map((tenant) => (
            <Link key={tenant.id} href={`/tenants/${tenant.id}`}>
              <Card className="h-full hover:border-primary/50 transition-colors cursor-pointer">
                <CardContent className="p-5">
                  <h3 className="text-lg font-semibold mb-1">{tenant.name}</h3>
                  <p className="text-sm text-muted-foreground line-clamp-2 mb-4">{tenant.description}</p>

                  {/* Stats */}
                  <div className="flex items-center gap-4 text-sm mb-4">
                    <span className="font-medium">{tenant.dpuCount} DPUs</span>
                    <span className="text-muted-foreground">
                      {tenant.healthyCount} Healthy
                      {tenant.warningCount > 0 && `, ${tenant.warningCount} Warning`}
                    </span>
                  </div>

                  {/* Tags */}
                  {tenant.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {tenant.tags.map((tag) => (
                        <Badge key={tag} variant="secondary" className="text-xs font-normal">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  )}
                </CardContent>
                <CardFooter className="px-5 py-3 border-t border-border bg-muted/30">
                  <div className="flex items-center justify-between w-full text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" />
                      {new Date(tenant.createdAt).toLocaleDateString()}
                    </span>
                    <span className="flex items-center gap-1">
                      <Mail className="h-3 w-3" />
                      {tenant.contactEmail}
                    </span>
                  </div>
                </CardFooter>
              </Card>
            </Link>
          ))
        )}
      </div>

      <CreateTenantModal open={modalOpen} onOpenChange={setModalOpen} tenant={editingTenant} />
    </div>
  )
}
