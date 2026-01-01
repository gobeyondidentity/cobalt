import type React from "react"
import type { Metadata, Viewport } from "next"
import { Inter, Inter_Tight, JetBrains_Mono } from "next/font/google"
// import { Analytics } from "@vercel/analytics/next"
import { ThemeProvider } from "@/components/theme-provider"
import "./globals.css"

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
})

const interTight = Inter_Tight({
  subsets: ["latin"],
  variable: "--font-inter-tight",
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
})

export const metadata: Metadata = {
  title: "Fabric Console | Beyond Identity",
  description: "DPU Fleet Management Dashboard for Enterprise AI Infrastructure",
  generator: "v0.app",
}

export const viewport: Viewport = {
  themeColor: "#154545",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.variable} ${interTight.variable} ${jetbrainsMono.variable} font-sans antialiased`}>
        <ThemeProvider attribute="class" defaultTheme="light" enableSystem disableTransitionOnChange>
          {children}
        </ThemeProvider>
        {/* <Analytics /> */}
      </body>
    </html>
  )
}
