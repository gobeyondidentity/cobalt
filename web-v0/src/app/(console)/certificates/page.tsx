import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { KeyRound, Plus, Upload } from "lucide-react"
import { HelpTooltip, HelpText } from "@/components/help-tooltip"

export default function CertificatesPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="font-heading text-3xl font-medium tracking-tight">
            <HelpTooltip term="certificate" iconSize="md">
              Certificates
            </HelpTooltip>
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage trusted <HelpText term="certificate">certificates</HelpText> and{" "}
            <HelpText term="corim">CoRIM</HelpText> files
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline">
            <Upload className="h-4 w-4 mr-2" />
            <HelpText term="corim">Upload CoRIM</HelpText>
          </Button>
          <Button className="bg-pine-green hover:bg-pine-green/90 text-white">
            <Plus className="h-4 w-4 mr-2" />
            Add Certificate
          </Button>
        </div>
      </div>

      {/* Empty State */}
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-16">
          <div className="rounded-full bg-muted p-4 mb-4">
            <KeyRound className="h-8 w-8 text-muted-foreground" />
          </div>
          <h3 className="text-lg font-semibold mb-2">No certificates uploaded</h3>
          <p className="text-muted-foreground text-center mb-4 max-w-md">
            Upload <HelpText term="corim">CoRIM (Concise Reference Integrity Manifest)</HelpText> files to enable{" "}
            <HelpText term="measurements">measurement</HelpText> validation against known good{" "}
            <HelpText term="reference-measurement">reference values</HelpText>.
          </p>
          <div className="flex gap-2">
            <Button variant="outline">
              <Upload className="h-4 w-4 mr-2" />
              Upload CoRIM
            </Button>
            <Button className="bg-pine-green hover:bg-pine-green/90 text-white">
              <Plus className="h-4 w-4 mr-2" />
              Add Certificate
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
