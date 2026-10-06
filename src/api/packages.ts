import type { RawAuditFile } from "../lib/types";

export interface PackagesApi {
  loadSnapshot(): Promise<RawAuditFile>;
}

export function createStaticPackagesApi(baseUrl = import.meta.env.BASE_URL): PackagesApi {
  return {
    async loadSnapshot() {
      const response = await fetch(`${baseUrl}data/intune_apps_sample_30.json`);
      if (!response.ok) {
        throw new Error(`Unable to load package snapshot (${response.status})`);
      }
      return response.json() as Promise<RawAuditFile>;
    },
  };
}
