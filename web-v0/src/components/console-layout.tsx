"use client"

import * as React from "react"
import { usePathname } from "next/navigation"
import Link from "next/link"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useTheme } from "next-themes"
import {
  Server,
  Monitor,
  ShieldCheck,
  KeyRound,
  Building2,
  Settings,
  Search,
  Moon,
  Sun,
  Menu,
  X,
  ChevronRight,
  User,
} from "lucide-react"

const navigationGroups = [
  {
    label: "INFRASTRUCTURE",
    items: [
      { name: "Fleet", href: "/fleet", icon: Server },
      { name: "Hosts", href: "/hosts", icon: Monitor },
    ],
  },
  {
    label: "SECURITY",
    items: [
      { name: "Attestation", href: "/attestation", icon: ShieldCheck },
      { name: "Certificates", href: "/certificates", icon: KeyRound },
    ],
  },
  {
    label: "ADMIN",
    items: [
      { name: "Tenants", href: "/tenants", icon: Building2 },
      { name: "Settings", href: "/settings", icon: Settings },
    ],
  },
]

function Logo({ collapsed = false }: { collapsed?: boolean }) {
  return (
    <Link href="/fleet" className="flex items-center gap-2 px-2">
      <svg viewBox="0 0 32 32" className="h-8 w-8 text-sidebar-foreground" fill="currentColor">
        <path d="M16 2L4 8v16l12 6 12-6V8L16 2zm0 4l8 4-8 4-8-4 8-4zm-8 8l8 4 8-4v8l-8 4-8-4v-8z" />
      </svg>
      {!collapsed && (
        <div className="flex flex-col">
          <span className="text-sm font-semibold text-sidebar-foreground">Beyond Identity</span>
          <span className="text-xs text-sidebar-foreground/70">Fabric Console</span>
        </div>
      )}
    </Link>
  )
}

function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const pathname = usePathname()

  return (
    <aside
      className={cn(
        "fixed left-0 top-0 z-40 h-screen bg-sidebar border-r border-sidebar-border transition-all duration-300",
        collapsed ? "w-16" : "w-64",
      )}
    >
      <div className="flex h-full flex-col">
        {/* Logo */}
        <div className="flex h-16 items-center justify-between px-3 border-b border-sidebar-border">
          <Logo collapsed={collapsed} />
          <Button
            variant="ghost"
            size="icon"
            onClick={onToggle}
            className="h-8 w-8 text-sidebar-foreground hover:bg-sidebar-accent"
          >
            {collapsed ? <ChevronRight className="h-4 w-4" /> : <X className="h-4 w-4" />}
          </Button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-6">
          {navigationGroups.map((group) => (
            <div key={group.label}>
              {!collapsed && <span className="eyebrow text-sidebar-foreground/60 px-2 mb-2 block">{group.label}</span>}
              <ul className="space-y-1">
                {group.items.map((item) => {
                  const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`)
                  return (
                    <li key={item.name}>
                      <Link
                        href={item.href}
                        className={cn(
                          "flex items-center gap-3 rounded-md px-2 py-2 text-sm font-medium transition-colors",
                          isActive
                            ? "bg-sidebar-primary text-sidebar-primary-foreground"
                            : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                          collapsed && "justify-center",
                        )}
                        title={collapsed ? item.name : undefined}
                      >
                        <item.icon className="h-5 w-5 flex-shrink-0" />
                        {!collapsed && <span>{item.name}</span>}
                      </Link>
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </nav>
      </div>
    </aside>
  )
}

function MobileSidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const pathname = usePathname()

  if (!open) return null

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50" onClick={onClose} />
      <aside className="fixed left-0 top-0 z-50 h-screen w-64 bg-sidebar border-r border-sidebar-border">
        <div className="flex h-full flex-col">
          <div className="flex h-16 items-center justify-between px-3 border-b border-sidebar-border">
            <Logo />
            <Button
              variant="ghost"
              size="icon"
              onClick={onClose}
              className="h-8 w-8 text-sidebar-foreground hover:bg-sidebar-accent"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>

          <nav className="flex-1 overflow-y-auto p-3 space-y-6">
            {navigationGroups.map((group) => (
              <div key={group.label}>
                <span className="eyebrow text-sidebar-foreground/60 px-2 mb-2 block">{group.label}</span>
                <ul className="space-y-1">
                  {group.items.map((item) => {
                    const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`)
                    return (
                      <li key={item.name}>
                        <Link
                          href={item.href}
                          onClick={onClose}
                          className={cn(
                            "flex items-center gap-3 rounded-md px-2 py-2 text-sm font-medium transition-colors",
                            isActive
                              ? "bg-sidebar-primary text-sidebar-primary-foreground"
                              : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                          )}
                        >
                          <item.icon className="h-5 w-5" />
                          <span>{item.name}</span>
                        </Link>
                      </li>
                    )
                  })}
                </ul>
              </div>
            ))}
          </nav>
        </div>
      </aside>
    </>
  )
}

function Header({ onMenuClick }: { onMenuClick: () => void }) {
  const { theme, setTheme } = useTheme()
  const pathname = usePathname()

  const getBreadcrumbs = () => {
    const paths = pathname.split("/").filter(Boolean)
    return paths.map((path, index) => ({
      name: path.charAt(0).toUpperCase() + path.slice(1).replace(/-/g, " "),
      href: "/" + paths.slice(0, index + 1).join("/"),
      isLast: index === paths.length - 1,
    }))
  }

  const breadcrumbs = getBreadcrumbs()

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-4 border-b border-border bg-background px-4 md:px-8">
      <Button variant="ghost" size="icon" className="md:hidden" onClick={onMenuClick}>
        <Menu className="h-5 w-5" />
      </Button>

      {/* Breadcrumbs */}
      <nav className="hidden items-center gap-2 text-sm md:flex">
        <Link href="/fleet" className="text-muted-foreground hover:text-foreground">
          Home
        </Link>
        {breadcrumbs.map((crumb) => (
          <React.Fragment key={crumb.href}>
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
            {crumb.isLast ? (
              <span className="font-medium text-foreground">{crumb.name}</span>
            ) : (
              <Link href={crumb.href} className="text-muted-foreground hover:text-foreground">
                {crumb.name}
              </Link>
            )}
          </React.Fragment>
        ))}
      </nav>

      {/* Search */}
      <div className="flex-1 flex justify-center max-w-md mx-auto">
        <div className="relative w-full">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input type="search" placeholder="Search..." className="w-full pl-9 h-9" />
        </div>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="icon" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          <Sun className="h-5 w-5 rotate-0 scale-100 transition-transform dark:-rotate-90 dark:scale-0" />
          <Moon className="absolute h-5 w-5 rotate-90 scale-0 transition-transform dark:rotate-0 dark:scale-100" />
          <span className="sr-only">Toggle theme</span>
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="rounded-full">
              <User className="h-5 w-5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuLabel>My Account</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem>Profile</DropdownMenuItem>
            <DropdownMenuItem>Settings</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem>Log out</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}

export function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const [sidebarCollapsed, setSidebarCollapsed] = React.useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false)

  return (
    <div className="min-h-screen bg-background">
      {/* Desktop Sidebar */}
      <div className="hidden md:block">
        <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
      </div>

      {/* Mobile Sidebar */}
      <div className="md:hidden">
        <MobileSidebar open={mobileMenuOpen} onClose={() => setMobileMenuOpen(false)} />
      </div>

      {/* Main Content */}
      <div className={cn("transition-all duration-300", sidebarCollapsed ? "md:ml-16" : "md:ml-64")}>
        <Header onMenuClick={() => setMobileMenuOpen(true)} />
        <main className="p-4 md:p-8">{children}</main>
      </div>
    </div>
  )
}
