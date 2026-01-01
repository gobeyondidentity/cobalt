import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Monitor, Plus } from "lucide-react"
import { HelpTooltip, HelpText } from "@/components/help-tooltip"

export default function HostsPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="font-heading text-3xl font-medium tracking-tight">
            <HelpTooltip term="host" iconSize="md">
              Hosts
            </HelpTooltip>
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage <HelpText term="host">host machines</HelpText> running <HelpText term="dpu">DPUs</HelpText>
          </p>
        </div>
        <Button className="bg-pine-green hover:bg-pine-green/90 text-white">
          <Plus className="h-4 w-4 mr-2" />
          Add Host
        </Button>
      </div>

      {/* Empty State */}
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-16">
          <div className="rounded-full bg-muted p-4 mb-4">
            <Monitor className="h-8 w-8 text-muted-foreground" />
          </div>
          <h3 className="text-lg font-semibold mb-2">No hosts registered</h3>
          <p className="text-muted-foreground text-center mb-4 max-w-md">
            <HelpText term="host">Host machines</HelpText> are automatically discovered when the{" "}
            <HelpText term="host-agent">Fabric Host Agent</HelpText> is installed. Install the agent on your servers to
            begin monitoring.
          </p>
          <Button className="bg-pine-green hover:bg-pine-green/90 text-white">
            <Plus className="h-4 w-4 mr-2" />
            Add Host
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
