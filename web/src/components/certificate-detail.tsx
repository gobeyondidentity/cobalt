"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { Certificate } from "@/lib/api";
import { ShieldCheck, ShieldX, AlertTriangle } from "lucide-react";

interface CertificateDetailProps {
  certificate: Certificate;
}

// Parse DN components from a certificate subject/issuer string
function parseDN(dn: string): Record<string, string> {
  const components: Record<string, string> = {};
  // Split by comma, but respect escaped commas
  const parts = dn.split(/,(?=\s*[A-Z]+=)/);
  for (const part of parts) {
    const match = part.trim().match(/^([A-Z]+)=(.+)$/i);
    if (match) {
      components[match[1].toUpperCase()] = match[2];
    }
  }
  return components;
}

// Extract CN from a DN string
function extractCN(dn: string): string {
  const components = parseDN(dn);
  return components.CN || dn;
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

// Format a date for display
function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function CertificateDetail({ certificate }: CertificateDetailProps) {
  const expired = isExpired(certificate.notAfter);
  const soonExpiry = expiresSoon(certificate.notAfter);
  const subjectDN = parseDN(certificate.subject);
  const issuerDN = parseDN(certificate.issuer);

  // Determine status
  let StatusIcon = ShieldCheck;
  let statusText = "Valid";
  let statusColor = "text-green-500";
  let badgeVariant: "default" | "destructive" | "outline" | "secondary" = "default";

  if (expired) {
    StatusIcon = ShieldX;
    statusText = "Expired";
    statusColor = "text-red-500";
    badgeVariant = "destructive";
  } else if (soonExpiry) {
    StatusIcon = AlertTriangle;
    statusText = "Expires Soon";
    statusColor = "text-yellow-500";
    badgeVariant = "outline";
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-lg">
          <StatusIcon className={`h-5 w-5 ${statusColor}`} />
          <span>{extractCN(certificate.subject)}</span>
          <Badge variant={badgeVariant} className="ml-auto">
            {statusText}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Subject Details */}
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-1">Subject</h4>
          <div className="text-sm space-y-0.5">
            <div className="font-medium">{subjectDN.CN || certificate.subject}</div>
            {subjectDN.O && <div className="text-muted-foreground">{subjectDN.O}</div>}
            {subjectDN.OU && <div className="text-muted-foreground text-xs">{subjectDN.OU}</div>}
          </div>
        </div>

        {/* Issuer */}
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-1">Issuer</h4>
          <div className="text-sm">
            <div>{extractCN(certificate.issuer)}</div>
            {issuerDN.O && <div className="text-muted-foreground text-xs">{issuerDN.O}</div>}
          </div>
        </div>

        {/* Level */}
        <div className="flex items-center gap-4">
          <div>
            <h4 className="text-sm font-medium text-muted-foreground mb-1">Level</h4>
            <Badge variant="outline">L{certificate.level}</Badge>
          </div>

          {/* Algorithm */}
          <div>
            <h4 className="text-sm font-medium text-muted-foreground mb-1">Algorithm</h4>
            <div className="text-sm font-mono">{certificate.algorithm}</div>
          </div>
        </div>

        {/* Validity */}
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-1">Validity</h4>
          <div className="text-sm">
            <span>{formatDate(certificate.notBefore)}</span>
            <span className="text-muted-foreground mx-2">to</span>
            <span>{formatDate(certificate.notAfter)}</span>
          </div>
        </div>

        {/* Fingerprint */}
        {certificate.fingerprint && (
          <div>
            <h4 className="text-sm font-medium text-muted-foreground mb-1">Fingerprint</h4>
            <div className="text-xs font-mono text-muted-foreground break-all">
              {certificate.fingerprint}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
