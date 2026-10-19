import type { ApiClient } from "./api.ts";

export interface StorageStatus {
  api_version: "codexploit/v1";
  driver: "memory" | "sqlite" | "postgres";
  profile: "complete" | "catalog" | "knowledge" | "execution";
  readiness: "ready" | "unavailable";
  durable: boolean;
  schema_version: string;
  capabilities: Record<string, boolean>;
  locations: Record<string, string>;
}

export async function readStorageStatus(
  api: ApiClient,
  signal?: AbortSignal,
): Promise<StorageStatus> {
  const response = await api.response("/v1/storage/status", { signal }, [503]);
  return response.json() as Promise<StorageStatus>;
}
