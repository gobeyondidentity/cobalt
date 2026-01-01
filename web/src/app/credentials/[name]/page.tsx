import { notFound } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { getSSHCA } from "@/lib/actions";

export const dynamic = "force-dynamic";

interface CADetailPageProps {
  params: Promise<{ name: string }>;
}

export default async function CADetailPage({ params }: CADetailPageProps) {
  const { name } = await params;
  const decodedName = decodeURIComponent(name);

  const { ca, error } = await getSSHCA(decodedName);
  if (error || !ca) {
    notFound();
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <a
              href="/credentials"
              className="text-sm text-muted-foreground hover:text-foreground"
            >
              Credentials
            </a>
            <span className="text-muted-foreground">/</span>
          </div>
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-zinc-100">
              {ca.name}
            </h1>
            <Badge variant="outline">{ca.keyType}</Badge>
          </div>
          <p className="text-zinc-600 dark:text-zinc-400 mt-1">
            SSH Certificate Authority
          </p>
        </div>
        <a href="/credentials">
          <Button variant="outline">Back to Credentials</Button>
        </a>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>CA Details</CardTitle>
            <CardDescription>Certificate Authority information</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <div className="text-muted-foreground">Name</div>
                <div className="font-medium">{ca.name}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Key Type</div>
                <div className="font-medium">{ca.keyType}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Created</div>
                <div className="font-medium">
                  {new Date(ca.createdAt).toLocaleString()}
                </div>
              </div>
              <div>
                <div className="text-muted-foreground">Distributions</div>
                <div className="font-medium">{ca.distributions}</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Public Key</CardTitle>
            <CardDescription>
              Add this to authorized_keys or TrustedUserCAKeys
            </CardDescription>
          </CardHeader>
          <CardContent>
            {ca.publicKey ? (
              <div className="relative">
                <pre className="p-4 bg-muted rounded-md overflow-x-auto text-xs font-mono whitespace-pre-wrap break-all">
                  {ca.publicKey}
                </pre>
                <p className="text-xs text-muted-foreground mt-2">
                  Base64-encoded public key
                </p>
              </div>
            ) : (
              <div className="text-muted-foreground">
                Public key not available
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
