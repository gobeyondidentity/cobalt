"use client"

import * as React from "react"
import { use } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { DataTable } from "@/components/data-table"
import { StatusBadge } from "@/components/status-badge"
import { CreateTenantModal } from "@/components/create-tenant-modal"
import { HelpTooltip, HelpText } from "@/components/help-tooltip"
import { mockTenants, mockDPUs, type DPU } from "@/lib/mock-data"
import { ArrowLeft, Edit, Trash2, Plus, Mail, Calendar, Tag, Server } from "lucide-react"

export default function TenantDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const router = useRouter()
  const resolvedParams = use(params)
  const [editModalOpen, setEditModalOpen] = React.useState(false)

  const tenant = mockTenants.find((t) => t.id === resolvedParams.id)
  const assignedDPUs = mockDPUs.filter((d) => d.tenantId === resolvedParams.id)

  if (!tenant) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <h2 className="text-xl font-semibold mb-2">Tenant Not Found</h2>
        <p className="text-muted-foreground mb-4">The requested tenant could not be found.</p>
        <Button onClick={() => router.push("/tenants")}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Tenants
        </Button>
      </div>
    )
  }

  const columns = [
    {
      key: "status",
      header: "Status",
      headerTooltip: "healthy",
      render: (dpu: DPU) => <StatusBadge status={dpu.status} />,
      className: "w-16",
    },
    {
      key: "name",
      header: "Name",
      sortable: true,
      render: (dpu: DPU) => (
        <Link
          href={`/fleet/${dpu.id}`}
          className="font-medium text-foreground hover:text-primary hover:underline"
          onClick={(e) => e.stopPropagation()}
        >
          {dpu.name}
        </Link>
      ),
    },
    {
      key: "ipAddress",
      header: "IP Address",
      headerTooltip: "ip-address",
      render: (dpu: DPU) => <code className="font-mono text-sm">{dpu.ipAddress}</code>,
    },
    {
      key: "model",
      header: "Model",
      sortable: true,
    },
    {
      key: "firmware",
      header: "Firmware",
      headerTooltip: "firmware",
      render: (dpu: DPU) => <code className="font-mono text-sm">{dpu.firmware}</code>,
    },
    {
      key: "lastSeen",
      header: "Last Seen",
      sortable: true,
    },
    {
      key: "actions",
      header: "",
      render: () => (
        <Button
          variant="ghost"
          size="sm"
          className="text-muted-foreground hover:text-destructive"
          onClick={(e) => e.stopPropagation()}
        >
          Remove
        </Button>
      ),
      className: "w-24",
    },
  ]

  const EmptyDPUs = () => (
    <Card className="border-dashed">
      <CardContent className="flex flex-col items-center justify-center py-12">
        <div className="rounded-full bg-muted p-3 mb-3">
          <Server className="h-6 w-6 text-muted-foreground" />
        </div>
        <h3 className="font-semibold mb-1">No DPUs assigned</h3>
        <p className="text-sm text-muted-foreground text-center mb-3">
          Assign <HelpText term="dpu">DPUs</HelpText> to this <HelpText term="tenant">tenant</HelpText> to manage them
          together
        </p>
        <Button variant="outline" size="sm">
          <Plus className="h-4 w-4 mr-2" />
          Assign DPU
        </Button>
      </CardContent>
    </Card>
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <Link
            href="/tenants"
            className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground mb-2"
          >
            <ArrowLeft className="h-4 w-4 mr-1" />
            Tenants
          </Link>
          <h1 className="font-heading text-3xl font-medium tracking-tight">{tenant.name}</h1>
          <p className="text-muted-foreground mt-1">{tenant.description}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setEditModalOpen(true)}>
            <Edit className="h-4 w-4 mr-2" />
            Edit
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="text-destructive hover:bg-destructive hover:text-white bg-transparent"
          >
            <Trash2 className="h-4 w-4 mr-2" />
            Delete
          </Button>
        </div>
      </div>

      {/* Metadata Card */}
      <Card>
        <CardContent className="p-5">
          <div className="grid gap-6 md:grid-cols-4">
            <div className="flex items-start gap-3">
              <Mail className="h-5 w-5 text-muted-foreground mt-0.5" />
              <div>
                <p className="text-sm text-muted-foreground">Contact</p>
                <p className="font-medium">{tenant.contactEmail}</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <Tag className="h-5 w-5 text-muted-foreground mt-0.5" />
              <div>
                <p className="text-sm text-muted-foreground">
                  <HelpTooltip term="tags">Tags</HelpTooltip>
                </p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {tenant.tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <Calendar className="h-5 w-5 text-muted-foreground mt-0.5" />
              <div>
                <p className="text-sm text-muted-foreground">Created</p>
                <p className="font-medium">{new Date(tenant.createdAt).toLocaleDateString()}</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <Server className="h-5 w-5 text-muted-foreground mt-0.5" />
              <div>
                <p className="text-sm text-muted-foreground">
                  <HelpTooltip term="dpu">DPU Count</HelpTooltip>
                </p>
                <p className="font-medium">{assignedDPUs.length}</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Assigned DPUs */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-4">
          <CardTitle className="text-lg">
            Assigned <HelpText term="dpu">DPUs</HelpText>
          </CardTitle>
          <Button variant="outline" size="sm">
            <Plus className="h-4 w-4 mr-2" />
            Assign DPU
          </Button>
        </CardHeader>
        <CardContent>
          {assignedDPUs.length === 0 ? (
            <EmptyDPUs />
          ) : (
            <DataTable
              data={assignedDPUs}
              columns={columns}
              pageSize={10}
              onRowClick={(dpu) => (window.location.href = `/fleet/${dpu.id}`)}
            />
          )}
        </CardContent>
      </Card>

      <CreateTenantModal open={editModalOpen} onOpenChange={setEditModalOpen} tenant={tenant} />
    </div>
  )
}
