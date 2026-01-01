// API client for Fabric Console backend

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

export interface DPU {
  id: string;
  name: string;
  host: string;
  port: number;
  status: string;
  lastSeen: string | null;
}

export interface SystemInfo {
  hostname: string;
  model: string;
  serialNumber: string;
  firmwareVersion: string;
  docaVersion: string;
  ovsVersion: string;
  kernelVersion: string;
  armCores: number;
  memoryGb: number;
  uptimeSeconds: number;
}

export interface Flow {
  cookie: string;
  table: number;
  priority: number;
  match: string;
  actions: string;
  packets: number;
  bytes: number;
  age: string;
}

export interface HealthCheck {
  healthy: boolean;
  version: string;
  uptimeSeconds: number;
  components: Record<string, { healthy: boolean; message: string }>;
}

export interface Certificate {
  level: number;
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  algorithm: string;
  pem: string;
  fingerprint?: string;
}

export interface Attestation {
  status: string;
  certificates: Certificate[];
  measurements: Record<string, string>;
}

export interface ChainData {
  certificates: Certificate[];
  error: string | null;
}

export interface ChainsResponse {
  irot: ChainData;
  erot: ChainData;
  sharedRoot?: Certificate;
}

export interface Measurement {
  index: number;
  description: string;
  algorithm: string;
  digest: string;
}

export interface MeasurementsResponse {
  measurements: Measurement[];
  hashingAlgorithm: string;
  signingAlgorithm: string;
  spdmVersion: string;
}

export interface ValidationResult {
  index: number;
  description: string;
  referenceDigest: string;
  liveDigest: string;
  match: boolean;
  status: string;
}

export interface CoRIMValidation {
  valid: boolean;
  totalChecked: number;
  matched: number;
  mismatched: number;
  missingRef: number;
  missingLive: number;
  results: ValidationResult[];
  firmwareVersion: string;
  corimId: string;
}

export interface Inventory {
  firmwares: Array<{
    name: string;
    version: string;
    buildDate: string;
  }>;
  packages: Array<{
    name: string;
    version: string;
  }>;
  modules: Array<{
    name: string;
    size: string;
    usedBy: number;
  }>;
  boot: {
    uefiMode: boolean;
    secureBoot: boolean;
    bootDevice: string;
  } | null;
  operationMode: string;
}

// ----- SSH CA Types -----

export interface SSHCA {
  id: string;
  name: string;
  keyType: string;
  publicKey?: string; // Only in detail view
  createdAt: string;
  distributions: number;
}

// ----- Distribution Types -----

export interface Distribution {
  id: number;
  dpuName: string;
  credentialType: string;
  credentialName: string;
  outcome: "success" | "blocked-stale" | "blocked-failed" | "forced";
  attestationStatus?: string;
  attestationAgeSeconds?: number;
  installedPath?: string;
  errorMessage?: string;
  createdAt: string;
}

export interface DistributionFilters {
  target?: string;
  from?: string;
  to?: string;
  result?: string;
  limit?: number;
}

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE) {
    this.baseUrl = baseUrl;
  }

  private async fetch<T>(path: string, options?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
    });

    if (!res.ok) {
      const error = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(error.error || `API error: ${res.status}`);
    }

    return res.json();
  }

  async listDPUs(): Promise<DPU[]> {
    return this.fetch<DPU[]>("/api/dpus");
  }

  async getDPU(id: string): Promise<DPU> {
    return this.fetch<DPU>(`/api/dpus/${id}`);
  }

  async addDPU(name: string, host: string, port: number = 50051): Promise<DPU> {
    return this.fetch<DPU>("/api/dpus", {
      method: "POST",
      body: JSON.stringify({ name, host, port }),
    });
  }

  async deleteDPU(id: string): Promise<void> {
    await this.fetch(`/api/dpus/${id}`, { method: "DELETE" });
  }

  async getSystemInfo(id: string): Promise<SystemInfo> {
    return this.fetch<SystemInfo>(`/api/dpus/${id}/info`);
  }

  async getFlows(id: string, bridge?: string): Promise<{ flows: Flow[] }> {
    const params = bridge ? `?bridge=${bridge}` : "";
    return this.fetch<{ flows: Flow[] }>(`/api/dpus/${id}/flows${params}`);
  }

  async getAttestation(id: string, target?: string): Promise<Attestation> {
    const params = target ? `?target=${target}` : "";
    return this.fetch<Attestation>(`/api/dpus/${id}/attestation${params}`);
  }

  async getAttestationChains(id: string): Promise<ChainsResponse> {
    return this.fetch<ChainsResponse>(`/api/dpus/${id}/attestation/chains`);
  }

  async healthCheck(id: string): Promise<HealthCheck> {
    return this.fetch<HealthCheck>(`/api/dpus/${id}/health`);
  }

  async getInventory(id: string): Promise<Inventory> {
    return this.fetch<Inventory>(`/api/dpus/${id}/inventory`);
  }

  async getMeasurements(id: string, target?: string): Promise<MeasurementsResponse> {
    const params = target ? `?target=${target}` : "";
    return this.fetch<MeasurementsResponse>(`/api/dpus/${id}/measurements${params}`);
  }

  async validateCoRIM(id: string, target?: string): Promise<CoRIMValidation> {
    const params = target ? `?target=${target}` : "";
    return this.fetch<CoRIMValidation>(`/api/dpus/${id}/corim/validate${params}`);
  }

  // ----- SSH CA Methods -----

  async listSSHCAs(): Promise<SSHCA[]> {
    return this.fetch<SSHCA[]>("/api/credentials/ssh-cas");
  }

  async getSSHCA(name: string): Promise<SSHCA> {
    return this.fetch<SSHCA>(`/api/credentials/ssh-cas/${encodeURIComponent(name)}`);
  }

  // ----- Distribution Methods -----

  async getDistributionHistory(filters?: DistributionFilters): Promise<Distribution[]> {
    const params = new URLSearchParams();
    if (filters?.target) params.set("target", filters.target);
    if (filters?.from) params.set("from", filters.from);
    if (filters?.to) params.set("to", filters.to);
    if (filters?.result) params.set("result", filters.result);
    if (filters?.limit) params.set("limit", filters.limit.toString());

    const queryString = params.toString();
    return this.fetch<Distribution[]>(`/api/distribution/history${queryString ? `?${queryString}` : ""}`);
  }
}

export const api = new ApiClient();
