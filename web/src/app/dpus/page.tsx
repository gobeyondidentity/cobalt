import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { listDPUs } from "@/lib/actions";
import { AddDPUButton } from "@/components/add-dpu-button";
import { DeleteDPUButton } from "@/components/delete-dpu-button";

export const dynamic = "force-dynamic";

export default async function DPUsPage() {
  const { dpus, error } = await listDPUs();

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "healthy":
        return <Badge className="bg-green-500">Healthy</Badge>;
      case "unhealthy":
        return <Badge className="bg-red-500">Unhealthy</Badge>;
      case "offline":
        return <Badge variant="secondary">Offline</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-zinc-900 dark:text-zinc-100">
            DPUs
          </h1>
          <p className="text-zinc-600 dark:text-zinc-400 mt-1">
            Manage your registered BlueField DPUs
          </p>
        </div>
        <AddDPUButton />
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md text-red-700">
          Failed to load DPUs: {error}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Registered DPUs</CardTitle>
          <CardDescription>
            {dpus.length === 0
              ? "No DPUs registered yet"
              : `${dpus.length} DPU(s) registered`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {dpus.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <p>No DPUs registered.</p>
              <p className="text-sm mt-1">Click &quot;Add DPU&quot; to register your first device.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Address</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {dpus.map((dpu) => (
                  <TableRow key={dpu.id}>
                    <TableCell className="font-medium">
                      <a href={`/dpus/${dpu.id}`} className="hover:underline">
                        {dpu.name}
                      </a>
                    </TableCell>
                    <TableCell>{dpu.host}:{dpu.port}</TableCell>
                    <TableCell>{getStatusBadge(dpu.status)}</TableCell>
                    <TableCell>
                      {dpu.lastSeen
                        ? new Date(dpu.lastSeen).toLocaleString()
                        : "Never"}
                    </TableCell>
                    <TableCell className="text-right space-x-2">
                      <a href={`/dpus/${dpu.id}`}>
                        <Button variant="outline" size="sm">
                          View
                        </Button>
                      </a>
                      <DeleteDPUButton id={dpu.id} name={dpu.name} />
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
