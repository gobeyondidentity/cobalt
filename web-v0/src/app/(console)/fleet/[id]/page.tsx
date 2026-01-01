"use client"

import * as React from "react"
import Link from "next/link"
import { useRouter, useParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { StatusBadge } from "@/components/status-badge"
import { HelpTooltip, HelpText } from "@/components/help-tooltip"
import {
  mockDPUs,
  mockNetworkInterfaces,
  mockFirmwareComponents,
  mockPackages,
  type NetworkInterface,
} from "@/lib/mock-data"
import {
  ArrowLeft,
  RefreshCw,
  Trash2,
  CheckCircle,
  AlertTriangle,
  XCircle,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Cpu,
  HardDrive,
  Clock,
  Shield,
  Monitor,
} from "lucide-react"
import { cn } from "@/lib/utils"

// DICE Chain certificate data
const diceChainIRoT = [
  { level: "L0", cn: "NVIDIA Device Identity Root CA", valid: true },
  { level: "L1", cn: "NVIDIA Device Identity CA", valid: true },
  { level: "L2", cn: "NVIDIA DPU IRoT CA", valid: true },
  { level: "L3", cn: "BF3-IRoT-DeviceID", valid: true },
  { level: "L4", cn: "BF3-IRoT-Alias", valid: true },
  { level: "L5", cn: "BF3-IRoT-ECA", valid: true },
]

const diceChainERoT = [
  { level: "L0", cn: "NVIDIA Device Identity Root CA", valid: true },
  { level: "L1", cn: "NVIDIA Device Identity CA", valid: true },
  { level: "L2", cn: "NVIDIA DPU ERoT CA", valid: true },
  { level: "L3", cn: "BF3-ERoT-DeviceID", valid: true },
  { level: "L4", cn: "BF3-ERoT-Alias", valid: true },
  { level: "L5", cn: "BF3-ERoT-ECA", valid: true },
]

const measurements = [
  { index: 0, purpose: "Boot ROM", purposeKey: "boot-rom", reference: "a3b2c1...", live: "a3b2c1...", match: true },
  { index: 1, purpose: "ATF BL2", purposeKey: "atf-bl2", reference: "d4e5f6...", live: "d4e5f6...", match: true },
  { index: 2, purpose: "ATF BL31", purposeKey: "atf-bl31", reference: "g7h8i9...", live: "g7h8i9...", match: true },
  { index: 3, purpose: "UEFI", purposeKey: "uefi", reference: "j0k1l2...", live: "j0k1l2...", match: true },
]

function OverviewTab({ dpu }: { dpu: (typeof mockDPUs)[0] }) {
  return (
    <div className="grid gap-6 md:grid-cols-2">
      {/* System Information */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-lg">
            <Cpu className="h-5 w-5 text-muted-foreground" />
            System Information
          </CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="space-y-3">
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Hostname</dt>
              <dd className="font-medium">{dpu.name}</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Model</dt>
              <dd className="font-medium">{dpu.model}</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">
                <HelpTooltip term="serial-number">Serial Number</HelpTooltip>
              </dt>
              <dd className="font-mono text-sm">{dpu.serialNumber}</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">
                <HelpTooltip term="arm-cores">ARM Cores</HelpTooltip>
              </dt>
              <dd className="font-medium">{dpu.armCores}</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Memory</dt>
              <dd className="font-medium">{dpu.memory}</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Storage</dt>
              <dd className="font-medium">{dpu.storage}</dd>
            </div>
            <div className="flex justify-between py-2">
              <dt className="text-muted-foreground flex items-center gap-1">
                <Clock className="h-4 w-4" />
                <HelpTooltip term="uptime">Uptime</HelpTooltip>
              </dt>
              <dd className="font-medium">{dpu.uptime}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      {/* Software Versions */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-lg">
            <HardDrive className="h-5 w-5 text-muted-foreground" />
            Software Versions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="space-y-3">
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">
                <HelpTooltip term="doca-sdk">DOCA SDK</HelpTooltip>
              </dt>
              <dd className="font-mono text-sm">{dpu.docaSdk}</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">
                <HelpTooltip term="kernel">Kernel</HelpTooltip>
              </dt>
              <dd className="font-mono text-sm">{dpu.kernel}</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">
                <HelpTooltip term="ovs">OVS</HelpTooltip>
              </dt>
              <dd className="font-mono text-sm">{dpu.ovs}</dd>
            </div>
            <div className="flex justify-between py-2">
              <dt className="text-muted-foreground">
                <HelpTooltip term="firmware">Firmware</HelpTooltip>
              </dt>
              <dd className="font-mono text-sm">{dpu.firmware}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      {/* Network Interfaces */}
      <Card className="md:col-span-2">
        <CardHeader className="pb-3">
          <CardTitle className="text-lg">
            <HelpTooltip term="network-interface">Network Interfaces</HelpTooltip>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="bg-grey-20 dark:bg-secondary hover:bg-grey-20">
                <TableHead className="eyebrow">Interface</TableHead>
                <TableHead className="eyebrow">
                  <HelpTooltip term="mac-address">MAC Address</HelpTooltip>
                </TableHead>
                <TableHead className="eyebrow">Status</TableHead>
                <TableHead className="eyebrow">Speed</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mockNetworkInterfaces.map((iface: NetworkInterface) => (
                <TableRow key={iface.name}>
                  <TableCell className="font-mono text-sm">{iface.name}</TableCell>
                  <TableCell className="font-mono text-sm">{iface.mac}</TableCell>
                  <TableCell>
                    <Badge variant={iface.status === "up" ? "default" : "secondary"} className="capitalize">
                      {iface.status}
                    </Badge>
                  </TableCell>
                  <TableCell>{iface.speed}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}

function InventoryTab({ dpu }: { dpu: (typeof mockDPUs)[0] }) {
  return (
    <div className="grid gap-6 md:grid-cols-2">
      {/* Firmware Components */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-lg">
            <HelpTooltip term="firmware">Firmware Components</HelpTooltip>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="bg-grey-20 dark:bg-secondary hover:bg-grey-20">
                <TableHead className="eyebrow">Component</TableHead>
                <TableHead className="eyebrow">Version</TableHead>
                <TableHead className="eyebrow">Build Date</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mockFirmwareComponents.map((component) => (
                <TableRow key={component.component}>
                  <TableCell>{component.component}</TableCell>
                  <TableCell className="font-mono text-sm">{component.version}</TableCell>
                  <TableCell>{component.buildDate}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Boot Configuration */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-lg">Boot Configuration</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="space-y-3">
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Mode</dt>
              <dd className="font-medium">
                <HelpText term="uefi">UEFI</HelpText>
              </dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">
                <HelpTooltip term="secure-boot">Secure Boot</HelpTooltip>
              </dt>
              <dd>
                <Badge variant={dpu.secureBootEnabled ? "default" : "secondary"}>
                  {dpu.secureBootEnabled ? "Enabled" : "Disabled"}
                </Badge>
              </dd>
            </div>
            <div className="flex justify-between py-2">
              <dt className="text-muted-foreground">Boot Device</dt>
              <dd className="font-medium">
                <HelpText term="nvme">NVMe</HelpText>
              </dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      {/* Packages */}
      <Card className="md:col-span-2">
        <CardHeader className="pb-3">
          <CardTitle className="text-lg">Installed Packages</CardTitle>
          <p className="text-sm text-muted-foreground">
            {mockPackages.length} <HelpText term="doca-sdk">DOCA</HelpText>/MLNX packages installed
          </p>
        </CardHeader>
        <CardContent>
          <div className="max-h-64 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow className="bg-grey-20 dark:bg-secondary hover:bg-grey-20">
                  <TableHead className="eyebrow">Package</TableHead>
                  <TableHead className="eyebrow">Version</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mockPackages.map((pkg) => (
                  <TableRow key={pkg.name}>
                    <TableCell className="font-mono text-sm">{pkg.name}</TableCell>
                    <TableCell className="font-mono text-sm">{pkg.version}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function OVSFlowsTab() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        <div className="rounded-full bg-muted p-4 mb-4">
          <HardDrive className="h-8 w-8 text-muted-foreground" />
        </div>
        <h3 className="text-lg font-semibold mb-2">
          <HelpTooltip term="ovs-flows" iconSize="md">
            OVS Flows
          </HelpTooltip>
        </h3>
        <p className="text-muted-foreground text-center mb-4 max-w-md">
          <HelpText term="ovs">Open vSwitch</HelpText> flow table inspection and management. View, filter, and analyze
          flow rules across all bridges.
        </p>
        <Button variant="outline">
          <RefreshCw className="h-4 w-4 mr-2" />
          Load Flows
        </Button>
      </CardContent>
    </Card>
  )
}

function DICEChainVisualization({
  chain,
  title,
  tooltipTerm,
}: {
  chain: typeof diceChainIRoT
  title: string
  tooltipTerm: string
}) {
  const [expanded, setExpanded] = React.useState<string | null>(null)

  return (
    <div className="space-y-3">
      <h4 className="font-semibold text-sm">
        <HelpTooltip term={tooltipTerm}>{title}</HelpTooltip>
      </h4>
      <div className="space-y-2">
        {chain.map((cert, index) => (
          <div key={cert.level}>
            <button
              onClick={() => setExpanded(expanded === cert.level ? null : cert.level)}
              className="w-full text-left"
            >
              <div
                className={cn(
                  "flex items-center gap-3 p-3 rounded-lg border transition-colors",
                  "hover:bg-muted/50",
                  expanded === cert.level && "bg-muted/50",
                )}
                style={{ marginLeft: `${index * 12}px` }}
              >
                <Badge variant="outline" className="font-mono text-xs">
                  {cert.level}
                </Badge>
                {cert.valid ? (
                  <CheckCircle className="h-4 w-4 text-status-healthy flex-shrink-0" />
                ) : (
                  <XCircle className="h-4 w-4 text-status-error flex-shrink-0" />
                )}
                <span className="text-sm truncate flex-1">{cert.cn}</span>
                {expanded === cert.level ? (
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                )}
              </div>
            </button>
            {expanded === cert.level && (
              <div
                className="mt-2 p-4 bg-muted/30 rounded-lg text-sm space-y-2"
                style={{ marginLeft: `${index * 12 + 16}px` }}
              >
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <dt className="text-muted-foreground text-xs uppercase tracking-wider">Subject</dt>
                    <dd className="font-mono text-xs mt-1 break-all">CN={cert.cn}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground text-xs uppercase tracking-wider">Issuer</dt>
                    <dd className="font-mono text-xs mt-1 break-all">
                      CN={index > 0 ? chain[index - 1].cn : "Self-Signed"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground text-xs uppercase tracking-wider">Valid From</dt>
                    <dd className="font-mono text-xs mt-1">2024-01-01 00:00:00 UTC</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground text-xs uppercase tracking-wider">Valid Until</dt>
                    <dd className="font-mono text-xs mt-1">2034-01-01 00:00:00 UTC</dd>
                  </div>
                  <div className="col-span-2">
                    <dt className="text-muted-foreground text-xs uppercase tracking-wider">Algorithm</dt>
                    <dd className="font-mono text-xs mt-1">ECDSA P-384</dd>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function AttestationTab({ dpu }: { dpu: (typeof mockDPUs)[0] }) {
  return (
    <div className="space-y-6">
      {/* Status Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-full bg-status-healthy/10 p-2">
                <CheckCircle className="h-5 w-5 text-status-healthy" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">
                  <HelpTooltip term="certificate-chain">Certificate Chains</HelpTooltip>
                </p>
                <p className="font-semibold">
                  <HelpText term="irot">IRoT</HelpText> Valid, <HelpText term="erot">ERoT</HelpText> Valid
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-full bg-status-healthy/10 p-2">
                <Shield className="h-5 w-5 text-status-healthy" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">
                  <HelpTooltip term="measurements">Measurements</HelpTooltip>
                </p>
                <p className="font-semibold">4 of 4 signed</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-full bg-status-warning/10 p-2">
                <AlertTriangle className="h-5 w-5 text-status-warning" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Validation</p>
                <p className="font-semibold">
                  <HelpText term="corim">CoRIM</HelpText> Not Available
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* DICE Chain Visualization */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-lg">
            <HelpTooltip term="dice-chain">DICE Certificate Chains</HelpTooltip>
          </CardTitle>
          <div className="flex items-center gap-2 mt-2 p-2 bg-tailwind-accent/20 dark:bg-tailwind-accent/10 rounded-md">
            <Shield className="h-4 w-4 text-pine-green dark:text-tailwind-accent" />
            <span className="text-sm text-pine-green dark:text-tailwind-accent">
              Both chains share NVIDIA Device Identity CA as their <HelpText term="root-ca">root of trust</HelpText>
            </span>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-8 md:grid-cols-2">
            <DICEChainVisualization
              chain={diceChainIRoT}
              title="IRoT Chain (Immutable Root of Trust)"
              tooltipTerm="irot"
            />
            <DICEChainVisualization
              chain={diceChainERoT}
              title="ERoT Chain (External Root of Trust)"
              tooltipTerm="erot"
            />
          </div>
        </CardContent>
      </Card>

      {/* Measurements Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-lg">
            <HelpTooltip term="measurements">Platform Measurements</HelpTooltip>
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Comparison of <HelpText term="reference-measurement">reference measurements</HelpText> against{" "}
            <HelpText term="live-measurement">live measurements</HelpText> from the device
          </p>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="bg-grey-20 dark:bg-secondary hover:bg-grey-20">
                <TableHead className="eyebrow w-16">Index</TableHead>
                <TableHead className="eyebrow">Purpose</TableHead>
                <TableHead className="eyebrow">
                  <HelpTooltip term="reference-measurement">Reference</HelpTooltip>
                </TableHead>
                <TableHead className="eyebrow">
                  <HelpTooltip term="live-measurement">Live</HelpTooltip>
                </TableHead>
                <TableHead className="eyebrow w-24">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {measurements.map((m) => (
                <TableRow key={m.index}>
                  <TableCell className="font-mono text-sm">{m.index}</TableCell>
                  <TableCell>
                    <HelpText term={m.purposeKey}>{m.purpose}</HelpText>
                  </TableCell>
                  <TableCell className="font-mono text-sm">{m.reference}</TableCell>
                  <TableCell className="font-mono text-sm">{m.live}</TableCell>
                  <TableCell>
                    <Badge variant={m.match ? "default" : "destructive"} className="gap-1">
                      {m.match ? (
                        <>
                          <CheckCircle className="h-3 w-3" /> Match
                        </>
                      ) : (
                        <>
                          <XCircle className="h-3 w-3" /> Mismatch
                        </>
                      )}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}

function HostTab({ dpu }: { dpu: (typeof mockDPUs)[0] }) {
  const hasHostAgent = dpu.host !== null

  if (!hasHostAgent) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-16">
          <div className="rounded-full bg-muted p-4 mb-4">
            <Monitor className="h-8 w-8 text-muted-foreground" />
          </div>
          <h3 className="text-lg font-semibold mb-2">
            <HelpTooltip term="host-agent" iconSize="md">
              Host Agent Not Installed
            </HelpTooltip>
          </h3>
          <p className="text-muted-foreground text-center mb-4 max-w-md">
            Install the <HelpText term="host-agent">host agent</HelpText> on the server connected to this{" "}
            <HelpText term="dpu">DPU</HelpText> to view hardware details, <HelpText term="gpu">GPU</HelpText>{" "}
            information, and connection status.
          </p>
          <Button variant="outline">
            <ExternalLink className="h-4 w-4 mr-2" />
            View Installation Guide
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="grid gap-6 md:grid-cols-2">
      {/* Host Information */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-lg">
            <Monitor className="h-5 w-5 text-muted-foreground" />
            <HelpTooltip term="host">Host Information</HelpTooltip>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="space-y-3">
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Hostname</dt>
              <dd className="font-medium">{dpu.host}</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Model</dt>
              <dd className="font-medium">Dell PowerEdge R750</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">
                <HelpTooltip term="serial-number">Serial</HelpTooltip>
              </dt>
              <dd className="font-mono text-sm">SVCTAG123456</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">CPU</dt>
              <dd className="font-medium">2x Intel Xeon Gold 6338</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Memory</dt>
              <dd className="font-medium">512 GB DDR4</dd>
            </div>
            <div className="flex justify-between py-2">
              <dt className="text-muted-foreground">OS</dt>
              <dd className="font-medium">Ubuntu 22.04 LTS</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      {/* GPU Information */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-lg">
            <Cpu className="h-5 w-5 text-muted-foreground" />
            <HelpTooltip term="gpu">GPU Information</HelpTooltip>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="space-y-3">
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Model</dt>
              <dd className="font-medium">NVIDIA A100 80GB</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Count</dt>
              <dd className="font-medium">8</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Driver</dt>
              <dd className="font-mono text-sm">535.104.05</dd>
            </div>
            <div className="flex justify-between py-2">
              <dt className="text-muted-foreground">CUDA</dt>
              <dd className="font-mono text-sm">12.2</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      {/* Connection Status */}
      <Card className="md:col-span-2">
        <CardHeader className="pb-3">
          <CardTitle className="text-lg">Connection Status</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="h-3 w-3 rounded-full bg-status-healthy animate-pulse" />
              <span className="font-medium">Connected</span>
            </div>
            <span className="text-muted-foreground">PCIe Gen4 x16</span>
            <span className="text-muted-foreground">•</span>
            <span className="text-muted-foreground">Last heartbeat: 2 seconds ago</span>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

export default function DPUDetailPage() {
  const router = useRouter()
  const params = useParams()
  const id = params.id as string

  const dpu = mockDPUs.find((d) => d.id === id)

  if (!dpu) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <h2 className="text-xl font-semibold mb-2">DPU Not Found</h2>
        <p className="text-muted-foreground mb-4">The requested DPU could not be found.</p>
        <Button onClick={() => router.push("/fleet")}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Fleet
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <Link
            href="/fleet"
            className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground mb-2"
          >
            <ArrowLeft className="h-4 w-4 mr-1" />
            Fleet
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="font-heading text-3xl font-medium tracking-tight">{dpu.name}</h1>
            <StatusBadge status={dpu.status} showLabel />
          </div>
          <div className="flex items-center gap-4 mt-2 text-sm text-muted-foreground">
            <code className="font-mono">{dpu.ipAddress}</code>
            <span>•</span>
            <span>{dpu.model}</span>
            <span>•</span>
            <Badge variant="secondary">
              <HelpText term="tenant">{dpu.tenant}</HelpText>
            </Badge>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="text-destructive hover:bg-destructive hover:text-white bg-transparent"
          >
            <Trash2 className="h-4 w-4 mr-2" />
            Remove
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="inventory">Inventory</TabsTrigger>
          <TabsTrigger value="ovs">
            <HelpText term="ovs-flows">OVS Flows</HelpText>
          </TabsTrigger>
          <TabsTrigger value="attestation">
            <HelpText term="attestation">Attestation</HelpText>
          </TabsTrigger>
          <TabsTrigger value="host">
            <HelpText term="host">Host</HelpText>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab dpu={dpu} />
        </TabsContent>
        <TabsContent value="inventory">
          <InventoryTab dpu={dpu} />
        </TabsContent>
        <TabsContent value="ovs">
          <OVSFlowsTab />
        </TabsContent>
        <TabsContent value="attestation">
          <AttestationTab dpu={dpu} />
        </TabsContent>
        <TabsContent value="host">
          <HostTab dpu={dpu} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
