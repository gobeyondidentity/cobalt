import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { listSSHCAs } from "@/lib/actions";

export const dynamic = "force-dynamic";

export default async function CredentialsPage() {
  const { cas, error } = await listSSHCAs();

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-zinc-900 dark:text-zinc-100">
            Credentials
          </h1>
          <p className="text-zinc-600 dark:text-zinc-400 mt-1">
            SSH Certificate Authorities for DPU access
          </p>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md text-red-700">
          Failed to load credentials: {error}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>SSH Certificate Authorities</CardTitle>
          <CardDescription>
            {cas.length === 0
              ? "No SSH CAs configured"
              : `${cas.length} CA(s) available`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {cas.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <p>No SSH Certificate Authorities configured.</p>
              <p className="text-sm mt-1">
                SSH CAs are created when the Fabric Agent registers with the console.
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Key Type</TableHead>
                  <TableHead>Distributions</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {cas.map((ca) => (
                  <TableRow key={ca.id}>
                    <TableCell className="font-medium">
                      <a href={`/credentials/${encodeURIComponent(ca.name)}`} className="hover:underline">
                        {ca.name}
                      </a>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{ca.keyType}</Badge>
                    </TableCell>
                    <TableCell>{ca.distributions}</TableCell>
                    <TableCell>
                      {new Date(ca.createdAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <a href={`/credentials/${encodeURIComponent(ca.name)}`}>
                        <Button variant="outline" size="sm">
                          View
                        </Button>
                      </a>
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
