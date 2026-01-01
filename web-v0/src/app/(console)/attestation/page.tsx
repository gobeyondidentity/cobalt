import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ShieldCheck, CheckCircle, AlertTriangle, XCircle } from "lucide-react"
import { mockDPUs } from "@/lib/mock-data"
import Link from "next/link"
import { HelpTooltip, HelpText } from "@/components/help-tooltip"

export default function AttestationPage() {
  const healthyCount = mockDPUs.filter((d) => d.status === "healthy").length
  const warningCount = mockDPUs.filter((d) => d.status === "warning").length
  const errorCount = mockDPUs.filter((d) => d.status === "error").length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="font-heading text-3xl font-medium tracking-tight">
          <HelpTooltip term="attestation" iconSize="md">
            Attestation
          </HelpTooltip>
        </h1>
        <p className="text-muted-foreground mt-1">
          Monitor <HelpText term="dice-chain">DICE certificate</HelpText> status across your fleet
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-full bg-status-healthy/10 p-2">
                <CheckCircle className="h-5 w-5 text-status-healthy" />
              </div>
              <div>
                <p className="text-2xl font-semibold">{healthyCount}</p>
                <p className="text-sm text-muted-foreground">
                  <HelpTooltip term="fully-attested">Fully Attested</HelpTooltip>
                </p>
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
                <p className="text-2xl font-semibold">{warningCount}</p>
                <p className="text-sm text-muted-foreground">
                  <HelpTooltip term="partial-attestation">Partial Attestation</HelpTooltip>
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-full bg-status-error/10 p-2">
                <XCircle className="h-5 w-5 text-status-error" />
              </div>
              <div>
                <p className="text-2xl font-semibold">{errorCount}</p>
                <p className="text-sm text-muted-foreground">
                  <HelpTooltip term="attestation-failed">Attestation Failed</HelpTooltip>
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* DPU Attestation List */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">
            <HelpTooltip term="dpu">DPU</HelpTooltip> Attestation Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="divide-y divide-border">
            {mockDPUs.map((dpu) => (
              <Link
                key={dpu.id}
                href={`/fleet/${dpu.id}?tab=attestation`}
                className="flex items-center justify-between py-4 hover:bg-muted/50 -mx-4 px-4 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <ShieldCheck
                    className={`h-5 w-5 ${
                      dpu.status === "healthy"
                        ? "text-status-healthy"
                        : dpu.status === "warning"
                          ? "text-status-warning"
                          : "text-status-error"
                    }`}
                  />
                  <div>
                    <p className="font-medium">{dpu.name}</p>
                    <p className="text-sm text-muted-foreground">{dpu.model}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <Badge
                      variant={
                        dpu.status === "healthy" ? "default" : dpu.status === "warning" ? "secondary" : "destructive"
                      }
                    >
                      {dpu.status === "healthy" ? (
                        <HelpText term="certificate-chain">Chains Valid</HelpText>
                      ) : dpu.status === "warning" ? (
                        <HelpText term="corim">CoRIM Missing</HelpText>
                      ) : (
                        <HelpText term="certificate-chain">Chain Invalid</HelpText>
                      )}
                    </Badge>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
