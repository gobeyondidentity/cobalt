export type DPUStatus = "healthy" | "warning" | "error" | "offline"

export interface DPU {
  id: string
  name: string
  ipAddress: string
  tenant: string
  tenantId: string
  model: string
  firmware: string
  host: string | null
  lastSeen: string
  status: DPUStatus
  serialNumber: string
  armCores: number
  memory: string
  storage: string
  uptime: string
  docaSdk: string
  kernel: string
  ovs: string
  secureBootEnabled: boolean
}

export interface Tenant {
  id: string
  name: string
  description: string
  contactEmail: string
  tags: string[]
  dpuCount: number
  healthyCount: number
  warningCount: number
  createdAt: string
}

export interface NetworkInterface {
  name: string
  mac: string
  status: "up" | "down"
  speed: string
}

export interface FirmwareComponent {
  component: string
  version: string
  buildDate: string
}

export interface Package {
  name: string
  version: string
}

export const mockDPUs: DPU[] = [
  {
    id: "1",
    name: "bf3-lab-01",
    ipAddress: "192.168.1.101",
    tenant: "Production",
    tenantId: "t1",
    model: "BlueField-3 B3210E",
    firmware: "32.47.1088",
    host: "gpu-server-01",
    lastSeen: "2m ago",
    status: "healthy",
    serialNumber: "MT2243X08762",
    armCores: 16,
    memory: "32 GB",
    storage: "256 GB NVMe",
    uptime: "14 days, 3 hours",
    docaSdk: "3.2.0",
    kernel: "5.15.0-doca",
    ovs: "2.17.0",
    secureBootEnabled: true,
  },
  {
    id: "2",
    name: "bf3-lab-02",
    ipAddress: "192.168.1.102",
    tenant: "Production",
    tenantId: "t1",
    model: "BlueField-3 B3210E",
    firmware: "32.47.1088",
    host: "gpu-server-02",
    lastSeen: "1m ago",
    status: "healthy",
    serialNumber: "MT2243X08763",
    armCores: 16,
    memory: "32 GB",
    storage: "256 GB NVMe",
    uptime: "7 days, 12 hours",
    docaSdk: "3.2.0",
    kernel: "5.15.0-doca",
    ovs: "2.17.0",
    secureBootEnabled: true,
  },
  {
    id: "3",
    name: "bf3-dev-01",
    ipAddress: "192.168.2.101",
    tenant: "Development",
    tenantId: "t2",
    model: "BlueField-2 B2220E",
    firmware: "24.35.2000",
    host: "dev-server-01",
    lastSeen: "5m ago",
    status: "warning",
    serialNumber: "MT2143X05421",
    armCores: 8,
    memory: "16 GB",
    storage: "128 GB NVMe",
    uptime: "2 days, 8 hours",
    docaSdk: "2.8.0",
    kernel: "5.4.0-doca",
    ovs: "2.14.0",
    secureBootEnabled: false,
  },
  {
    id: "4",
    name: "bf3-staging-01",
    ipAddress: "192.168.3.101",
    tenant: "Staging",
    tenantId: "t3",
    model: "BlueField-3 B3210E",
    firmware: "32.47.1086",
    host: null,
    lastSeen: "30m ago",
    status: "error",
    serialNumber: "MT2243X08764",
    armCores: 16,
    memory: "32 GB",
    storage: "256 GB NVMe",
    uptime: "0 days, 4 hours",
    docaSdk: "3.2.0",
    kernel: "5.15.0-doca",
    ovs: "2.17.0",
    secureBootEnabled: true,
  },
  {
    id: "5",
    name: "bf3-prod-03",
    ipAddress: "192.168.1.103",
    tenant: "Production",
    tenantId: "t1",
    model: "BlueField-3 B3210E",
    firmware: "32.47.1088",
    host: "gpu-server-03",
    lastSeen: "1m ago",
    status: "healthy",
    serialNumber: "MT2243X08765",
    armCores: 16,
    memory: "32 GB",
    storage: "256 GB NVMe",
    uptime: "21 days, 6 hours",
    docaSdk: "3.2.0",
    kernel: "5.15.0-doca",
    ovs: "2.17.0",
    secureBootEnabled: true,
  },
]

export const mockTenants: Tenant[] = [
  {
    id: "t1",
    name: "Production",
    description: "Production environment for customer-facing workloads",
    contactEmail: "ops@company.com",
    tags: ["Production", "US-East"],
    dpuCount: 3,
    healthyCount: 3,
    warningCount: 0,
    createdAt: "2024-01-15",
  },
  {
    id: "t2",
    name: "Development",
    description: "Development and testing environment",
    contactEmail: "dev@company.com",
    tags: ["Development", "Internal"],
    dpuCount: 1,
    healthyCount: 0,
    warningCount: 1,
    createdAt: "2024-02-20",
  },
  {
    id: "t3",
    name: "Staging",
    description: "Pre-production staging environment",
    contactEmail: "qa@company.com",
    tags: ["Staging", "US-West"],
    dpuCount: 1,
    healthyCount: 0,
    warningCount: 0,
    createdAt: "2024-03-10",
  },
]

export const mockNetworkInterfaces: NetworkInterface[] = [
  { name: "pf0", mac: "04:3f:72:b5:c2:10", status: "up", speed: "100 Gbps" },
  { name: "pf1", mac: "04:3f:72:b5:c2:11", status: "up", speed: "100 Gbps" },
  { name: "p0", mac: "04:3f:72:b5:c2:12", status: "up", speed: "25 Gbps" },
  { name: "p1", mac: "04:3f:72:b5:c2:13", status: "down", speed: "25 Gbps" },
]

export const mockFirmwareComponents: FirmwareComponent[] = [
  { component: "NIC Firmware", version: "32.47.1088", buildDate: "2024-10-15" },
  { component: "BMC Firmware", version: "3.9.5", buildDate: "2024-09-20" },
  { component: "UEFI", version: "14.32.15", buildDate: "2024-08-10" },
  { component: "ARM System Controller", version: "32.47.1088", buildDate: "2024-10-15" },
  { component: "Arm Trusted Firmware", version: "2.9.0", buildDate: "2024-07-01" },
]

export const mockPackages: Package[] = [
  { name: "doca-runtime", version: "3.2.0-1" },
  { name: "doca-devel", version: "3.2.0-1" },
  { name: "mlnx-ofed-kernel", version: "24.07-0.6.1.1" },
  { name: "openvswitch", version: "2.17.0-1" },
  { name: "dpdk", version: "22.11.0" },
  { name: "librte-mempool", version: "22.11.0" },
  { name: "doca-flow", version: "3.2.0-1" },
  { name: "doca-dpi", version: "3.2.0-1" },
]
