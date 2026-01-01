"use client"

import type * as React from "react"
import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from "@/components/ui/tooltip"
import { HelpCircle } from "lucide-react"
import { cn } from "@/lib/utils"

interface HelpTooltipProps {
  term: string
  children?: React.ReactNode
  className?: string
  iconSize?: "sm" | "md"
  side?: "top" | "bottom" | "left" | "right"
}

// Glossary of technical terms with explanations
export const glossary: Record<string, string> = {
  // DPU & Hardware
  dpu: "Data Processing Unit - A specialized processor that offloads and accelerates networking, storage, and security tasks from the main CPU.",
  "arm-cores": "The number of ARM-based CPU cores available on the DPU for running software and processing tasks.",
  "serial-number": "A unique identifier assigned to this specific DPU hardware unit by the manufacturer.",
  firmware:
    "Low-level software permanently programmed into the DPU that controls its basic functions and hardware interfaces.",
  uptime: "The amount of time since the DPU was last rebooted or powered on.",

  // Software
  "doca-sdk": "NVIDIA DOCA SDK - Software development kit for building applications that run on NVIDIA BlueField DPUs.",
  kernel: "The core operating system software running on the DPU's ARM processors.",
  ovs: "Open vSwitch - A production-quality, multilayer virtual switch used for network virtualization and SDN.",
  "ovs-flows":
    "Flow rules in Open vSwitch that define how network packets should be processed, forwarded, or modified.",

  // Security & Attestation
  attestation:
    "The process of cryptographically verifying that a DPU's hardware and software are in a known, trusted state.",
  "dice-chain":
    "Device Identifier Composition Engine - A standard for establishing device identity through a chain of certificates rooted in hardware.",
  irot: "Immutable Root of Trust - Hardware-based security foundation that cannot be modified, providing the ultimate trust anchor for the device.",
  erot: "External Root of Trust - A separate security processor that provides additional attestation capabilities and can be updated.",
  corim:
    "Concise Reference Integrity Manifest - A standardized format for describing known-good measurements of firmware and software components.",
  measurements:
    "Cryptographic hashes of firmware and software components used to verify the integrity of the boot chain.",
  "secure-boot":
    "A security feature that ensures only cryptographically signed and verified software can run during the boot process.",
  "reference-measurement":
    "The expected cryptographic hash of a firmware component, used to verify the device is running known-good code.",
  "live-measurement":
    "The actual cryptographic hash computed from the currently running firmware, compared against reference values.",

  // Certificates
  certificate:
    "A digital document that cryptographically binds a public key to an identity, used for authentication and secure communication.",
  "certificate-chain":
    "A sequence of certificates where each certificate validates the next, establishing a path to a trusted root.",
  "root-ca":
    "Root Certificate Authority - The top-level certificate in a chain that serves as the ultimate trust anchor.",

  // Network
  "network-interface": "A hardware or virtual connection point for network communication, identified by a MAC address.",
  "mac-address": "Media Access Control address - A unique hardware identifier assigned to each network interface.",
  "ip-address":
    "Internet Protocol address - A numerical label assigned to a device for network identification and communication.",

  // Organization
  tenant:
    "A logical grouping of DPUs, typically representing a customer, department, or environment (e.g., production vs. staging).",
  tags: "Labels attached to resources for organization, filtering, and grouping related items together.",

  // Host
  host: "The physical server machine that contains or is connected to a DPU.",
  "host-agent": "Software installed on the host server that enables monitoring and management of the DPU connection.",
  gpu: "Graphics Processing Unit - A specialized processor often present in host servers for parallel computing workloads.",

  // Status
  healthy: "The DPU is operating normally with all security checks passing and no detected issues.",
  warning: "The DPU has minor issues or missing information that should be addressed but isn't critical.",
  error: "The DPU has significant problems that require immediate attention, such as failed attestation.",
  offline: "The DPU is not currently responding to management requests or has been powered off.",
  "fully-attested":
    "All certificate chains are valid and all firmware measurements match their expected reference values.",
  "partial-attestation":
    "Some but not all attestation checks have passed - typically missing CoRIM data for measurement validation.",
  "attestation-failed":
    "Critical security verification has failed - the device may be running unauthorized or compromised software.",

  // Boot
  uefi: "Unified Extensible Firmware Interface - Modern firmware interface that initializes hardware and loads the operating system.",
  "boot-rom": "The first code executed when the DPU powers on, stored in read-only memory and cannot be modified.",
  "atf-bl2":
    "ARM Trusted Firmware BL2 - Early boot stage firmware responsible for initializing memory and loading the next boot stage.",
  "atf-bl31": "ARM Trusted Firmware BL31 - Secure runtime firmware that provides services to the operating system.",
  nvme: "Non-Volatile Memory Express - A high-speed storage interface protocol used for solid-state drives.",

  // API
  "api-url": "The endpoint address where the Fabric Console backend service is accessible for management operations.",
  "test-connection": "Verify that the console can successfully communicate with the backend API service.",
}

export function HelpTooltip({ term, children, className, iconSize = "sm", side = "top" }: HelpTooltipProps) {
  const description = glossary[term.toLowerCase()] || `Description for "${term}" - placeholder text.`

  return (
    <TooltipProvider>
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>
          <span className={cn("inline-flex items-center gap-1 cursor-help", className)}>
            {children}
            <HelpCircle
              className={cn(
                "text-muted-foreground/60 hover:text-muted-foreground transition-colors",
                iconSize === "sm" ? "h-3.5 w-3.5" : "h-4 w-4",
              )}
            />
          </span>
        </TooltipTrigger>
        <TooltipContent side={side} className="max-w-xs text-left">
          <p>{description}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

// Inline variant for use within text
export function HelpText({
  term,
  children,
  className,
}: {
  term: string
  children: React.ReactNode
  className?: string
}) {
  const description = glossary[term.toLowerCase()] || `Description for "${term}" - placeholder text.`

  return (
    <TooltipProvider>
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>
          <span className={cn("border-b border-dashed border-muted-foreground/40 cursor-help", className)}>
            {children}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs text-left">
          <p>{description}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
