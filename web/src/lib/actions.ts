"use server";

import { api, DPU, SystemInfo, Flow, HealthCheck, Attestation, ChainsResponse, Inventory, MeasurementsResponse, CoRIMValidation } from "./api";
import { revalidatePath } from "next/cache";

export async function listDPUs(): Promise<{ dpus: DPU[]; error?: string }> {
  try {
    const dpus = await api.listDPUs();
    return { dpus };
  } catch (e) {
    return { dpus: [], error: (e as Error).message };
  }
}

export async function getDPU(id: string): Promise<{ dpu?: DPU; error?: string }> {
  try {
    const dpu = await api.getDPU(id);
    return { dpu };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function addDPU(
  name: string,
  host: string,
  port: number
): Promise<{ dpu?: DPU; error?: string }> {
  try {
    const dpu = await api.addDPU(name, host, port);
    revalidatePath("/dpus");
    revalidatePath("/");
    return { dpu };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function deleteDPU(id: string): Promise<{ error?: string }> {
  try {
    await api.deleteDPU(id);
    revalidatePath("/dpus");
    revalidatePath("/");
    return {};
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function getSystemInfo(
  id: string
): Promise<{ info?: SystemInfo; error?: string }> {
  try {
    const info = await api.getSystemInfo(id);
    return { info };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function getFlows(
  id: string,
  bridge?: string
): Promise<{ flows: Flow[]; error?: string }> {
  try {
    const result = await api.getFlows(id, bridge);
    return { flows: result.flows };
  } catch (e) {
    return { flows: [], error: (e as Error).message };
  }
}

export async function getAttestation(
  id: string,
  target?: string
): Promise<{ attestation?: Attestation; error?: string }> {
  try {
    const attestation = await api.getAttestation(id, target);
    return { attestation };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function getAttestationChains(
  id: string
): Promise<{ chains?: ChainsResponse; error?: string }> {
  try {
    const chains = await api.getAttestationChains(id);
    return { chains };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function healthCheck(
  id: string
): Promise<{ health?: HealthCheck; error?: string }> {
  try {
    const health = await api.healthCheck(id);
    return { health };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function getInventory(
  id: string
): Promise<{ inventory?: Inventory; error?: string }> {
  try {
    const inventory = await api.getInventory(id);
    return { inventory };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function getMeasurements(
  id: string,
  target?: string
): Promise<{ measurements?: MeasurementsResponse; error?: string }> {
  try {
    const measurements = await api.getMeasurements(id, target);
    return { measurements };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export async function validateCoRIM(
  id: string,
  target?: string
): Promise<{ validation?: CoRIMValidation; error?: string }> {
  try {
    const validation = await api.validateCoRIM(id, target);
    return { validation };
  } catch (e) {
    return { error: (e as Error).message };
  }
}
