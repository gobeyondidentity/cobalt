"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { LayoutDashboard, Cpu, KeyRound, Send } from "lucide-react";

const navigation = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "DPUs", href: "/dpus", icon: Cpu },
  { name: "Credentials", href: "/credentials", icon: KeyRound },
  { name: "Distribution", href: "/distribution", icon: Send },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <div className="flex h-screen w-64 flex-col bg-zinc-900 text-zinc-100">
      <div className="flex h-16 items-center px-6 border-b border-zinc-800">
        <span className="text-xl font-semibold">Fabric Console</span>
      </div>
      <nav className="flex-1 px-4 py-4 space-y-1">
        {navigation.map((item) => {
          const isActive = pathname === item.href ||
            (item.href !== "/" && pathname.startsWith(item.href));
          const Icon = item.icon;
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                isActive
                  ? "bg-zinc-800 text-white"
                  : "text-zinc-400 hover:bg-zinc-800 hover:text-white"
              )}
            >
              <Icon className="h-4 w-4" />
              {item.name}
            </Link>
          );
        })}
      </nav>
      <div className="px-4 py-4 border-t border-zinc-800">
        <div className="text-xs text-zinc-500">Fabric Console v0.1.0</div>
      </div>
    </div>
  );
}
