import { notFound } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getDPU, getSystemInfo, getFlows, getAttestation, getAttestationChains, getInventory, validateCoRIM } from "@/lib/actions";
import { DiceChain } from "@/components/dice-chain";

export const dynamic = "force-dynamic";

interface DPUDetailPageProps {
  params: Promise<{ id: string }>;
}

export default async function DPUDetailPage({ params }: DPUDetailPageProps) {
  const { id } = await params;

  const { dpu, error: dpuError } = await getDPU(id);
  if (dpuError || !dpu) {
    notFound();
  }

  const [systemResult, flowsResult, attestationResult, chainsResult, inventoryResult, validationResult] = await Promise.all([
    getSystemInfo(id),
    getFlows(id),
    getAttestation(id),
    getAttestationChains(id).catch(() => ({ chains: undefined, error: "Certificate chains not available" })),
    getInventory(id),
    validateCoRIM(id).catch(() => ({ validation: undefined, error: "CoRIM validation not available" })),
  ]);

  const systemInfo = systemResult.info;
  const flows = flowsResult.flows;
  const attestation = attestationResult.attestation;
  const chains = chainsResult.chains;
  const inventory = inventoryResult.inventory;
  const validation = validationResult.validation;

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h ${mins}m`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(1)} TB`;
    if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
    if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
    if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-zinc-100">
              {dpu.name}
            </h1>
            <Badge
              className={
                dpu.status === "healthy"
                  ? "bg-green-500"
                  : dpu.status === "unhealthy"
                  ? "bg-red-500"
                  : ""
              }
              variant={dpu.status === "healthy" || dpu.status === "unhealthy" ? "default" : "secondary"}
            >
              {dpu.status}
            </Badge>
          </div>
          <p className="text-zinc-600 dark:text-zinc-400 mt-1">
            {dpu.host}:{dpu.port}
          </p>
        </div>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="inventory">Inventory</TabsTrigger>
          <TabsTrigger value="flows">OVS Flows ({flows.length})</TabsTrigger>
          <TabsTrigger value="attestation">Attestation</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {systemResult.error ? (
            <Card>
              <CardContent className="pt-6">
                <div className="text-center text-muted-foreground">
                  Failed to load system info: {systemResult.error}
                </div>
              </CardContent>
            </Card>
          ) : systemInfo ? (
            <div className="grid gap-6 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>System Information</CardTitle>
                  <CardDescription>Hardware and software details</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <div className="text-muted-foreground">Hostname</div>
                      <div className="font-medium">{systemInfo.hostname}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Model</div>
                      <div className="font-medium">{systemInfo.model}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">ARM Cores</div>
                      <div className="font-medium">{systemInfo.armCores}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Memory</div>
                      <div className="font-medium">{systemInfo.memoryGb} GB</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Uptime</div>
                      <div className="font-medium">{formatUptime(systemInfo.uptimeSeconds)}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Software Versions</CardTitle>
                  <CardDescription>Installed components</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3 text-sm">
                    <div>
                      <div className="text-muted-foreground">DOCA Version</div>
                      <div className="font-mono text-xs">{systemInfo.docaVersion}</div>
                    </div>
                    <Separator />
                    <div>
                      <div className="text-muted-foreground">Kernel</div>
                      <div className="font-mono text-xs">{systemInfo.kernelVersion}</div>
                    </div>
                    <Separator />
                    <div>
                      <div className="text-muted-foreground">OVS Version</div>
                      <div className="font-mono text-xs">{systemInfo.ovsVersion}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          ) : null}
        </TabsContent>

        <TabsContent value="inventory" className="space-y-4">
          {inventoryResult.error ? (
            <Card>
              <CardContent className="pt-6">
                <div className="text-center text-muted-foreground">
                  Failed to load inventory: {inventoryResult.error}
                </div>
              </CardContent>
            </Card>
          ) : inventory ? (
            <div className="grid gap-6 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Firmware Versions</CardTitle>
                  <CardDescription>BMC, NIC, and component firmware</CardDescription>
                </CardHeader>
                <CardContent>
                  {inventory.firmwares.length === 0 ? (
                    <div className="text-muted-foreground">No firmware data available</div>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Component</TableHead>
                          <TableHead>Version</TableHead>
                          <TableHead>Build Date</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {inventory.firmwares.map((fw, i) => (
                          <TableRow key={i}>
                            <TableCell className="uppercase">{fw.name}</TableCell>
                            <TableCell className="font-mono text-xs">{fw.version}</TableCell>
                            <TableCell>{fw.buildDate || "-"}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Boot Configuration</CardTitle>
                  <CardDescription>Boot mode and security settings</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <div className="text-muted-foreground">UEFI Mode</div>
                      <div className="font-medium">{inventory.boot?.uefiMode ? "Yes" : "No"}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Secure Boot</div>
                      <div className="font-medium">
                        {inventory.boot?.secureBoot ? (
                          <Badge className="bg-green-500">Enabled</Badge>
                        ) : (
                          <Badge variant="secondary">Disabled</Badge>
                        )}
                      </div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Boot Device</div>
                      <div className="font-mono text-xs">{inventory.boot?.bootDevice || "-"}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Operation Mode</div>
                      <div className="font-medium capitalize">{inventory.operationMode}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Installed Packages ({inventory.packages.length})</CardTitle>
                  <CardDescription>DOCA, MLNX, and BlueField packages</CardDescription>
                </CardHeader>
                <CardContent>
                  {inventory.packages.length === 0 ? (
                    <div className="text-muted-foreground">No packages found</div>
                  ) : (
                    <div className="max-h-64 overflow-y-auto">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Name</TableHead>
                            <TableHead>Version</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {inventory.packages.map((pkg, i) => (
                            <TableRow key={i}>
                              <TableCell className="font-mono text-xs">{pkg.name}</TableCell>
                              <TableCell className="font-mono text-xs">{pkg.version}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Kernel Modules ({inventory.modules.length})</CardTitle>
                  <CardDescription>Mellanox, RDMA, and OVS modules</CardDescription>
                </CardHeader>
                <CardContent>
                  {inventory.modules.length === 0 ? (
                    <div className="text-muted-foreground">No modules found</div>
                  ) : (
                    <div className="max-h-64 overflow-y-auto">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Name</TableHead>
                            <TableHead>Size</TableHead>
                            <TableHead>Used By</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {inventory.modules.map((mod, i) => (
                            <TableRow key={i}>
                              <TableCell className="font-mono text-xs">{mod.name}</TableCell>
                              <TableCell>{mod.size}</TableCell>
                              <TableCell>{mod.usedBy}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          ) : null}
        </TabsContent>

        <TabsContent value="flows">
          <Card>
            <CardHeader>
              <CardTitle>OVS Flows</CardTitle>
              <CardDescription>OpenFlow rules on this DPU</CardDescription>
            </CardHeader>
            <CardContent>
              {flowsResult.error ? (
                <div className="text-center text-muted-foreground py-4">
                  Failed to load flows: {flowsResult.error}
                </div>
              ) : flows.length === 0 ? (
                <div className="text-center text-muted-foreground py-4">
                  No flows found
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Table</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Match</TableHead>
                      <TableHead>Actions</TableHead>
                      <TableHead className="text-right">Packets</TableHead>
                      <TableHead className="text-right">Bytes</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {flows.map((flow, i) => (
                      <TableRow key={i}>
                        <TableCell>{flow.table}</TableCell>
                        <TableCell>{flow.priority}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {flow.match || "*"}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {flow.actions}
                        </TableCell>
                        <TableCell className="text-right">
                          {flow.packets.toLocaleString()}
                        </TableCell>
                        <TableCell className="text-right">
                          {formatBytes(flow.bytes)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="attestation" className="space-y-4">
          {/* CoRIM Validation Status */}
          {!validation && validationResult.error && (
            <Card>
              <CardHeader>
                <CardTitle>CoRIM Validation</CardTitle>
                <CardDescription>
                  Comparison of live SPDM measurements against NVIDIA golden references
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-start gap-3 p-4 bg-muted/50 rounded-lg">
                  <div className="text-yellow-500 mt-0.5">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10"/>
                      <line x1="12" y1="8" x2="12" y2="12"/>
                      <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                  </div>
                  <div className="space-y-1">
                    <p className="text-sm font-medium">CoRIM Not Available</p>
                    <p className="text-sm text-muted-foreground">
                      {validationResult.error.includes("No CoRIM found")
                        ? "NVIDIA has not yet published CoRIM reference measurements for BlueField-3 firmware to their RIM service. DICE certificate chains and SPDM measurements are still available below."
                        : validationResult.error}
                    </p>
                    <p className="text-xs text-muted-foreground mt-2">
                      When available, CoRIM validation will compare live firmware hashes against NVIDIA-signed golden values.
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Validation Summary */}
          {validation && (
            <div className="grid gap-4 md:grid-cols-3">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Validation Status</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-2">
                    {validation.valid ? (
                      <Badge className="bg-green-500">VALID</Badge>
                    ) : (
                      <Badge variant="destructive">INVALID</Badge>
                    )}
                    <span className="text-sm text-muted-foreground">
                      {validation.matched}/{validation.totalChecked} matched
                    </span>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">Firmware Version</CardTitle>
                </CardHeader>
                <CardContent>
                  <span className="font-mono text-sm">{validation.firmwareVersion}</span>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">CoRIM ID</CardTitle>
                </CardHeader>
                <CardContent>
                  <span className="font-mono text-xs truncate block">{validation.corimId || "N/A"}</span>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Measurement Validation Table */}
          {validation && validation.results.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Measurement Validation</CardTitle>
                <CardDescription>Comparison of live SPDM measurements against CoRIM reference values</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-16">Index</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead>Reference</TableHead>
                      <TableHead>Live</TableHead>
                      <TableHead className="w-24">Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {validation.results.map((r, i) => (
                      <TableRow key={i}>
                        <TableCell>{r.index}</TableCell>
                        <TableCell>{r.description}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {r.referenceDigest ? `${r.referenceDigest.substring(0, 16)}...` : "-"}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {r.liveDigest ? `${r.liveDigest.substring(0, 16)}...` : "-"}
                        </TableCell>
                        <TableCell>
                          {r.status === "match" && <Badge className="bg-green-500">Match</Badge>}
                          {r.status === "mismatch" && <Badge variant="destructive">Mismatch</Badge>}
                          {r.status === "missing_reference" && <Badge variant="secondary">No Ref</Badge>}
                          {r.status === "missing_live" && <Badge variant="secondary">No Live</Badge>}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          {/* DICE Certificate Chains */}
          <Card>
            <CardHeader>
              <CardTitle>DICE Certificate Chains</CardTitle>
              <CardDescription>
                IRoT (Internal Root of Trust) and ERoT (External Root of Trust) certificate hierarchies
              </CardDescription>
            </CardHeader>
            <CardContent>
              {chainsResult.error ? (
                <div className="text-center text-muted-foreground py-4">
                  Failed to load certificate chains: {chainsResult.error}
                </div>
              ) : chains ? (
                <DiceChain chains={chains} />
              ) : (
                <div className="text-muted-foreground">
                  No certificate chains available. BMC may not be configured.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
