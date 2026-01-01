import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { listDPUs } from "@/lib/actions";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const { dpus, error } = await listDPUs();

  const healthy = dpus.filter((d) => d.status === "healthy").length;
  const unhealthy = dpus.filter((d) => d.status === "unhealthy").length;
  const offline = dpus.filter((d) => d.status === "offline" || d.status === "unknown").length;

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-zinc-900 dark:text-zinc-100">
          Dashboard
        </h1>
        <p className="text-zinc-600 dark:text-zinc-400 mt-1">
          Overview of your DPU fleet
        </p>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md text-red-700">
          Failed to load DPUs: {error}
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total DPUs</CardDescription>
            <CardTitle className="text-4xl">{dpus.length}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">
              Registered devices
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Healthy</CardDescription>
            <CardTitle className="text-4xl text-green-600">{healthy}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">
              Responding normally
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Unhealthy</CardDescription>
            <CardTitle className="text-4xl text-red-600">{unhealthy}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">
              Require attention
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Offline</CardDescription>
            <CardTitle className="text-4xl text-zinc-400">{offline}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">
              Not reachable
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="mt-8">
        {dpus.length === 0 ? (
          <Card>
            <CardHeader>
              <CardTitle>Getting Started</CardTitle>
              <CardDescription>
                Register your first DPU to begin monitoring
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">
                No DPUs registered yet. Add a DPU to start monitoring your BlueField infrastructure.
              </p>
              <a
                href="/dpus"
                className="inline-flex items-center justify-center rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800"
              >
                Manage DPUs
              </a>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>Recent DPUs</CardTitle>
              <CardDescription>
                Quick access to your registered devices
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {dpus.slice(0, 5).map((dpu) => (
                  <a
                    key={dpu.id}
                    href={`/dpus/${dpu.id}`}
                    className="flex items-center justify-between p-3 rounded-md hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
                  >
                    <div>
                      <div className="font-medium">{dpu.name}</div>
                      <div className="text-sm text-muted-foreground">
                        {dpu.host}:{dpu.port}
                      </div>
                    </div>
                    <div
                      className={`px-2 py-1 text-xs font-medium rounded ${
                        dpu.status === "healthy"
                          ? "bg-green-100 text-green-700"
                          : dpu.status === "unhealthy"
                          ? "bg-red-100 text-red-700"
                          : "bg-zinc-100 text-zinc-700"
                      }`}
                    >
                      {dpu.status}
                    </div>
                  </a>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
