"use client"

import * as React from "react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { DataTable } from "@/components/data-table"
import { StatusBadge } from "@/components/status-badge"
import { HelpTooltip, HelpText } from "@/components/help-tooltip"
import { mockDPUs, mockTenants, type DPU } from "@/lib/mock-data"
import { Plus, RefreshCw, LayoutGrid, List, Server } from "lucide-react"

type ViewMode = "table" | "cards"
type StatusFilter = "all" | "healthy" | "warning" | "error"

export default function FleetPage() {
  const [searchQuery, setSearchQuery] = React.useState("")
  const [tenantFilter, setTenantFilter] = React.useState("all")
  const [statusFilter, setStatusFilter] = React.useState<StatusFilter>("all")
  const [viewMode, setViewMode] = React.useState<ViewMode>("table")

  const filteredDPUs = React.useMemo(() => {
    return mockDPUs.filter((dpu) => {
      const matchesSearch =
        dpu.name.toLowerCase().includes(searchQuery.toLowerCase()) || dpu.ipAddress.includes(searchQuery)
      const matchesTenant = tenantFilter === "all" || dpu.tenantId === tenantFilter
      const matchesStatus = statusFilter === "all" || dpu.status === statusFilter
      return matchesSearch && matchesTenant && matchesStatus
    })
  }, [searchQuery, tenantFilter, statusFilter])

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
      key: "tenant",
      header: "Tenant",
      headerTooltip: "tenant",
      render: (dpu: DPU) => (
        <Badge variant="secondary" className="font-normal">
          {dpu.tenant}
        </Badge>
      ),
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
      key: "host",
      header: "Host",
      headerTooltip: "host",
      render: (dpu: DPU) => <span className={dpu.host ? "" : "text-muted-foreground"}>{dpu.host || "—"}</span>,
    },
    {
      key: "lastSeen",
      header: "Last Seen",
      sortable: true,
    },
  ]

  const tenantCount = new Set(mockDPUs.map((d) => d.tenantId)).size

  const EmptyState = () => (
    <Card className="border-dashed">
      <CardContent className="flex flex-col items-center justify-center py-16">
        <div className="rounded-full bg-muted p-4 mb-4">
          <Server className="h-8 w-8 text-muted-foreground" />
        </div>
        <h3 className="text-lg font-semibold mb-2">No DPUs registered</h3>
        <p className="text-muted-foreground text-center mb-4">
          Add your first <HelpText term="dpu">DPU</HelpText> to get started
        </p>
        <Button className="bg-pine-green hover:bg-pine-green/90 text-white">
          <Plus className="h-4 w-4 mr-2" />
          Add DPU
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
            <HelpTooltip term="dpu" iconSize="md">
              Fleet Overview
            </HelpTooltip>
          </h1>
          <p className="text-muted-foreground mt-1">
            {mockDPUs.length} <HelpText term="dpu">DPUs</HelpText> across {tenantCount}{" "}
            <HelpText term="tenant">tenants</HelpText>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button className="bg-pine-green hover:bg-pine-green/90 text-white" size="sm">
            <Plus className="h-4 w-4 mr-2" />
            Add DPU
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center">
        <div className="flex-1 max-w-sm">
          <Input
            placeholder="Search by name or IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-10"
          />
        </div>
        <Select value={tenantFilter} onValueChange={setTenantFilter}>
          <SelectTrigger className="w-40 h-10">
            <SelectValue placeholder="All Tenants" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Tenants</SelectItem>
            {mockTenants.map((tenant) => (
              <SelectItem key={tenant.id} value={tenant.id}>
                {tenant.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="flex items-center gap-1 rounded-md border border-input p-1">
          {(["all", "healthy", "warning", "error"] as const).map((status) => (
            <Button
              key={status}
              variant={statusFilter === status ? "secondary" : "ghost"}
              size="sm"
              className="h-8 px-3 capitalize"
              onClick={() => setStatusFilter(status)}
            >
              {status}
            </Button>
          ))}
        </div>
        <div className="flex items-center gap-1 rounded-md border border-input p-1">
          <Button
            variant={viewMode === "table" ? "secondary" : "ghost"}
            size="icon"
            className="h-8 w-8"
            onClick={() => setViewMode("table")}
          >
            <List className="h-4 w-4" />
          </Button>
          <Button
            variant={viewMode === "cards" ? "secondary" : "ghost"}
            size="icon"
            className="h-8 w-8"
            onClick={() => setViewMode("cards")}
          >
            <LayoutGrid className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Content */}
      {viewMode === "table" ? (
        <DataTable
          data={filteredDPUs}
          columns={columns}
          selectable
          pageSize={10}
          onRowClick={(dpu) => (window.location.href = `/fleet/${dpu.id}`)}
          emptyState={<EmptyState />}
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filteredDPUs.map((dpu) => (
            <Link key={dpu.id} href={`/fleet/${dpu.id}`}>
              <Card className="hover:border-primary/50 transition-colors cursor-pointer">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <h3 className="font-semibold">{dpu.name}</h3>
                      <code className="text-sm text-muted-foreground font-mono">{dpu.ipAddress}</code>
                    </div>
                    <StatusBadge status={dpu.status} showLabel />
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Tenant</span>
                      <Badge variant="secondary">{dpu.tenant}</Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Model</span>
                      <span>{dpu.model}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Host</span>
                      <span>{dpu.host || "—"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Last Seen</span>
                      <span>{dpu.lastSeen}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
