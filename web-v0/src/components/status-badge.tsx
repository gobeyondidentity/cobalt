import { cn } from "@/lib/utils"
import { TooltipProvider, Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

type StatusType = "healthy" | "warning" | "error" | "offline"

interface StatusBadgeProps {
  status: StatusType
  showLabel?: boolean
  size?: "sm" | "md"
}

const statusConfig = {
  healthy: {
    label: "Healthy",
    dotClass: "bg-status-healthy",
    badgeClass: "bg-status-healthy/10 text-status-healthy border-status-healthy/20",
    description: "The DPU is operating normally with all security checks passing and no detected issues.",
  },
  warning: {
    label: "Warning",
    dotClass: "bg-status-warning",
    badgeClass: "bg-status-warning/10 text-status-warning border-status-warning/20",
    description: "The DPU has minor issues or missing information that should be addressed but isn't critical.",
  },
  error: {
    label: "Error",
    dotClass: "bg-status-error",
    badgeClass: "bg-status-error/10 text-status-error border-status-error/20",
    description: "The DPU has significant problems that require immediate attention, such as failed attestation.",
  },
  offline: {
    label: "Offline",
    dotClass: "bg-status-offline",
    badgeClass: "bg-status-offline/10 text-status-offline border-status-offline/20",
    description: "The DPU is not currently responding to management requests or has been powered off.",
  },
}

export function StatusBadge({ status, showLabel = false, size = "md" }: StatusBadgeProps) {
  const config = statusConfig[status]

  return (
    <TooltipProvider>
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>
          {showLabel ? (
            <span
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium cursor-help",
                config.badgeClass,
              )}
            >
              <span className={cn("h-1.5 w-1.5 rounded-full", config.dotClass)} />
              {config.label}
            </span>
          ) : (
            <span
              className={cn(
                "inline-block rounded-full cursor-help",
                config.dotClass,
                size === "sm" ? "h-2 w-2" : "h-2.5 w-2.5",
              )}
            />
          )}
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs">
          <p className={showLabel ? "font-medium mb-1" : ""}>{config.label}</p>
          <p className="text-xs text-muted-foreground">{config.description}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
