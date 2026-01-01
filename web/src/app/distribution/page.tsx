import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { getDistributionHistory } from "@/lib/actions";
import { Distribution } from "@/lib/api";

export const dynamic = "force-dynamic";

interface DistributionPageProps {
  searchParams: Promise<{ target?: string; result?: string }>;
}

function getOutcomeBadge(outcome: Distribution["outcome"]) {
  switch (outcome) {
    case "success":
      return <Badge className="bg-green-500">Success</Badge>;
    case "blocked-stale":
      return <Badge className="bg-yellow-500">Blocked (Stale)</Badge>;
    case "blocked-failed":
      return <Badge className="bg-red-500">Blocked (Failed)</Badge>;
    case "forced":
      return <Badge className="bg-orange-500">Forced</Badge>;
    default:
      return <Badge variant="outline">{outcome}</Badge>;
  }
}

function formatAttestationAge(seconds?: number): string {
  if (seconds === undefined || seconds === null) return "N/A";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default async function DistributionPage({ searchParams }: DistributionPageProps) {
  const { target, result } = await searchParams;

  const { distributions, error } = await getDistributionHistory({
    target,
    result,
    limit: 100,
  });

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-zinc-900 dark:text-zinc-100">
            Distribution History
          </h1>
          <p className="text-zinc-600 dark:text-zinc-400 mt-1">
            Credential distribution events and attestation outcomes
          </p>
        </div>
      </div>

      {/* Filters */}
      <Card className="mb-6">
        <CardHeader className="pb-4">
          <CardTitle className="text-lg">Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="flex flex-wrap gap-4" method="GET">
            <div className="flex flex-col gap-1">
              <label htmlFor="target" className="text-sm text-muted-foreground">
                Target DPU
              </label>
              <input
                type="text"
                id="target"
                name="target"
                defaultValue={target}
                placeholder="Filter by DPU name"
                className="px-3 py-2 border rounded-md text-sm bg-background"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label htmlFor="result" className="text-sm text-muted-foreground">
                Outcome
              </label>
              <select
                id="result"
                name="result"
                defaultValue={result}
                className="px-3 py-2 border rounded-md text-sm bg-background"
              >
                <option value="">All outcomes</option>
                <option value="success">Success</option>
                <option value="blocked-stale">Blocked (Stale)</option>
                <option value="blocked-failed">Blocked (Failed)</option>
                <option value="forced">Forced</option>
              </select>
            </div>
            <div className="flex items-end">
              <button
                type="submit"
                className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90"
              >
                Apply
              </button>
            </div>
            {(target || result) && (
              <div className="flex items-end">
                <a
                  href="/distribution"
                  className="px-4 py-2 border rounded-md text-sm hover:bg-muted"
                >
                  Clear
                </a>
              </div>
            )}
          </form>
        </CardContent>
      </Card>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md text-red-700">
          Failed to load distribution history: {error}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Distribution Events</CardTitle>
          <CardDescription>
            {distributions.length === 0
              ? "No distribution events recorded"
              : `${distributions.length} event(s) found`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {distributions.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <p>No distribution events found.</p>
              <p className="text-sm mt-1">
                Events are recorded when credentials are distributed to DPUs.
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Credential</TableHead>
                  <TableHead>Target DPU</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead>Attestation</TableHead>
                  <TableHead>Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {distributions.map((dist) => (
                  <TableRow key={dist.id}>
                    <TableCell>
                      <div className="font-medium">{dist.credentialName}</div>
                      <div className="text-xs text-muted-foreground">
                        {dist.credentialType}
                      </div>
                    </TableCell>
                    <TableCell>{dist.dpuName}</TableCell>
                    <TableCell>
                      {getOutcomeBadge(dist.outcome)}
                      {dist.errorMessage && (
                        <div className="text-xs text-red-500 mt-1 max-w-xs truncate" title={dist.errorMessage}>
                          {dist.errorMessage}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="text-sm">
                        {dist.attestationStatus ? (
                          <Badge
                            variant={dist.attestationStatus === "valid" ? "default" : "secondary"}
                            className={dist.attestationStatus === "valid" ? "bg-green-500" : ""}
                          >
                            {dist.attestationStatus}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">N/A</span>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {formatAttestationAge(dist.attestationAgeSeconds)}
                      </div>
                    </TableCell>
                    <TableCell>
                      {new Date(dist.createdAt).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
