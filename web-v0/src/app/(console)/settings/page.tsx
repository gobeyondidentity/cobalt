"use client"

import * as React from "react"
import { useTheme } from "next-themes"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { HelpTooltip } from "@/components/help-tooltip"
import { Sun, Moon, Monitor, ExternalLink, CheckCircle, Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"

type ThemeOption = "light" | "dark" | "system"

const themeOptions: { value: ThemeOption; label: string; icon: React.ElementType }[] = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
]

export default function SettingsPage() {
  const { theme, setTheme } = useTheme()
  const [connectionStatus, setConnectionStatus] = React.useState<"idle" | "testing" | "success" | "error">("idle")

  const handleTestConnection = () => {
    setConnectionStatus("testing")
    setTimeout(() => {
      setConnectionStatus("success")
      setTimeout(() => setConnectionStatus("idle"), 2000)
    }, 1500)
  }

  return (
    <div className="space-y-6 max-w-3xl">
      {/* Header */}
      <div>
        <h1 className="font-heading text-3xl font-medium tracking-tight">Settings</h1>
        <p className="text-muted-foreground mt-1">Manage your console preferences and configuration</p>
      </div>

      {/* Appearance */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Appearance</CardTitle>
          <CardDescription>Customize how the console looks on your device</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <Label>Theme</Label>
            <div className="flex gap-2">
              {themeOptions.map((option) => {
                const Icon = option.icon
                const isActive = theme === option.value
                return (
                  <Button
                    key={option.value}
                    variant="outline"
                    className={cn("flex-1 gap-2 h-12", isActive && "border-primary bg-primary/5 text-primary")}
                    onClick={() => setTheme(option.value)}
                  >
                    <Icon className="h-4 w-4" />
                    {option.label}
                  </Button>
                )
              })}
            </div>

            {/* Theme Preview */}
            <div className="mt-6 p-4 rounded-lg border border-border bg-muted/30">
              <p className="text-sm text-muted-foreground mb-3">Preview</p>
              <div className="grid gap-3 md:grid-cols-2">
                <div className="p-3 rounded-md bg-background border border-border">
                  <div className="h-2 w-20 rounded bg-foreground/20 mb-2" />
                  <div className="h-2 w-16 rounded bg-foreground/10" />
                </div>
                <div className="p-3 rounded-md bg-primary text-primary-foreground">
                  <div className="h-2 w-20 rounded bg-primary-foreground/30 mb-2" />
                  <div className="h-2 w-16 rounded bg-primary-foreground/20" />
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* API Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">API Configuration</CardTitle>
          <CardDescription>Configure the connection to your Fabric backend</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="api-url">
              <HelpTooltip term="api-url">API URL</HelpTooltip>
            </Label>
            <Input
              id="api-url"
              value="https://api.fabric.beyondidentity.com/v1"
              readOnly
              className="font-mono text-sm bg-muted"
            />
          </div>
          <Button variant="outline" onClick={handleTestConnection} disabled={connectionStatus === "testing"}>
            {connectionStatus === "testing" && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {connectionStatus === "success" && <CheckCircle className="h-4 w-4 mr-2 text-status-healthy" />}
            {connectionStatus === "idle" || connectionStatus === "error" ? (
              <HelpTooltip term="test-connection">Test Connection</HelpTooltip>
            ) : connectionStatus === "testing" ? (
              "Testing..."
            ) : (
              "Connected"
            )}
          </Button>
        </CardContent>
      </Card>

      {/* About */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">About</CardTitle>
          <CardDescription>Information about this Fabric Console installation</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="space-y-3">
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Version</dt>
              <dd className="font-mono text-sm">0.2.0</dd>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <dt className="text-muted-foreground">Build</dt>
              <dd className="font-mono text-sm">a1b2c3d</dd>
            </div>
            <div className="flex justify-between py-2">
              <dt className="text-muted-foreground">Documentation</dt>
              <dd>
                <a
                  href="https://docs.beyondidentity.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-primary hover:underline"
                >
                  View Docs
                  <ExternalLink className="h-3 w-3" />
                </a>
              </dd>
            </div>
          </dl>
        </CardContent>
      </Card>
    </div>
  )
}
