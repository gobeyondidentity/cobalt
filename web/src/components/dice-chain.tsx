"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { ChainsResponse, Certificate } from "@/lib/api";
import { ChevronDown, ChevronRight, Shield, ShieldCheck, ShieldX, Link2 } from "lucide-react";

interface DiceChainProps {
  chains: ChainsResponse;
}

// Extract CN from a certificate subject/issuer DN
function extractCN(dn: string): string {
  const match = dn.match(/CN=([^,]+)/i);
  return match ? match[1] : dn;
}

// Check if a certificate is expired
function isExpired(notAfter: string): boolean {
  return new Date(notAfter) < new Date();
}

// Check if a certificate expires within 30 days
function expiresSoon(notAfter: string): boolean {
  const expiryDate = new Date(notAfter);
  const thirtyDaysFromNow = new Date();
  thirtyDaysFromNow.setDate(thirtyDaysFromNow.getDate() + 30);
  return expiryDate <= thirtyDaysFromNow && expiryDate > new Date();
}

interface CertNodeProps {
  cert: Certificate;
  isLast: boolean;
  isSharedRoot?: boolean;
}

function CertNode({ cert, isLast, isSharedRoot }: CertNodeProps) {
  const [expanded, setExpanded] = useState(false);
  const expired = isExpired(cert.notAfter);
  const soonExpiry = expiresSoon(cert.notAfter);

  const statusColor = expired
    ? "text-red-500"
    : soonExpiry
    ? "text-yellow-500"
    : "text-green-500";

  const StatusIcon = expired ? ShieldX : ShieldCheck;

  return (
    <div className="relative">
      {/* Connector line */}
      {!isLast && (
        <div className="absolute left-4 top-10 bottom-0 w-0.5 bg-muted-foreground/20" />
      )}

      <div
        className={`flex items-start gap-2 p-2 rounded-lg cursor-pointer hover:bg-muted/50 transition-colors ${
          isSharedRoot ? "bg-blue-500/10 border border-blue-500/30" : ""
        }`}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-1 min-w-[24px]">
          {expanded ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
        </div>

        <StatusIcon
          className={`h-5 w-5 mt-0.5 ${statusColor}`}
          data-testid={expired ? "cert-status-expired" : "cert-status-valid"}
        />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium truncate">{extractCN(cert.subject)}</span>
            <Badge variant="outline" className="text-xs">
              L{cert.level}
            </Badge>
            {isSharedRoot && (
              <Badge variant="secondary" className="text-xs">
                <Link2 className="h-3 w-3 mr-1" />
                Shared Root
              </Badge>
            )}
          </div>

          {expanded && (
            <div className="mt-2 text-sm text-muted-foreground space-y-1">
              <div>
                <span className="font-medium">Issuer:</span> {extractCN(cert.issuer)}
              </div>
              <div>
                <span className="font-medium">Algorithm:</span> {cert.algorithm}
              </div>
              <div>
                <span className="font-medium">Valid:</span>{" "}
                {new Date(cert.notBefore).toLocaleDateString()} to{" "}
                {new Date(cert.notAfter).toLocaleDateString()}
                {expired && (
                  <Badge variant="destructive" className="ml-2 text-xs">
                    Expired
                  </Badge>
                )}
                {soonExpiry && (
                  <Badge variant="outline" className="ml-2 text-xs border-yellow-500 text-yellow-500">
                    Expires Soon
                  </Badge>
                )}
              </div>
              {cert.fingerprint && (
                <div className="font-mono text-xs">
                  <span className="font-medium">Fingerprint:</span>{" "}
                  {cert.fingerprint.substring(0, 16)}...
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface ChainColumnProps {
  title: string;
  icon: React.ReactNode;
  certificates: Certificate[];
  error: string | null;
  sharedRootFingerprint?: string;
}

function ChainColumn({ title, icon, certificates, error, sharedRootFingerprint }: ChainColumnProps) {
  if (error) {
    return (
      <Card className="flex-1">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-base">
            {icon}
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-destructive text-sm">{error}</div>
        </CardContent>
      </Card>
    );
  }

  if (certificates.length === 0) {
    return (
      <Card className="flex-1">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-base">
            {icon}
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-muted-foreground text-sm">No certificates available</div>
        </CardContent>
      </Card>
    );
  }

  // Sort by level descending (root first)
  const sortedCerts = [...certificates].sort((a, b) => b.level - a.level);

  return (
    <Card className="flex-1">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-base">
          {icon}
          {title}
          <Badge variant="outline" className="ml-auto">
            {certificates.length} certs
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1">
        {sortedCerts.map((cert, idx) => (
          <CertNode
            key={cert.fingerprint || idx}
            cert={cert}
            isLast={idx === sortedCerts.length - 1}
            isSharedRoot={sharedRootFingerprint === cert.fingerprint}
          />
        ))}
      </CardContent>
    </Card>
  );
}

export function DiceChain({ chains }: DiceChainProps) {
  const sharedRootFingerprint = chains.sharedRoot?.fingerprint;
  const hasAnyCertificates =
    chains.irot.certificates.length > 0 || chains.erot.certificates.length > 0;

  if (!hasAnyCertificates && !chains.irot.error && !chains.erot.error) {
    return (
      <div className="text-muted-foreground text-sm py-4 text-center">
        No certificates available from the DPU
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {sharedRootFingerprint && (
        <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground bg-blue-500/5 py-2 rounded-lg border border-blue-500/20">
          <Link2 className="h-4 w-4 text-blue-500" />
          <span>Both chains share the same NVIDIA Device Identity CA root</span>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ChainColumn
          title="IRoT Chain"
          icon={<Shield className="h-4 w-4 text-green-500" />}
          certificates={chains.irot.certificates}
          error={chains.irot.error}
          sharedRootFingerprint={sharedRootFingerprint}
        />
        <ChainColumn
          title="ERoT Chain"
          icon={<Shield className="h-4 w-4 text-blue-500" />}
          certificates={chains.erot.certificates}
          error={chains.erot.error}
          sharedRootFingerprint={sharedRootFingerprint}
        />
      </div>
    </div>
  );
}
