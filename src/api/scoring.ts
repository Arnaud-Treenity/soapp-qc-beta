import type { ScoringConfig } from "../lib/types";
import { readJson, writeJson } from "./storage";

const SCORING_STORAGE_KEY = "soapp-qc-scoring-config-v1";

export interface ScoringApi {
  load(): Promise<Partial<ScoringConfig> | null>;
  save(config: ScoringConfig): Promise<void>;
}

export function createScoringApi(): ScoringApi {
  return {
    async load() {
      return readJson<Partial<ScoringConfig>>(SCORING_STORAGE_KEY);
    },
    async save(config) {
      writeJson(SCORING_STORAGE_KEY, config);
    },
  };
}
