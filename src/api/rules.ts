import type { GuidelineRule, RuleCatalogFile } from "../lib/types";
import { readJson, removeKey, writeJson, writeText, readText } from "./storage";

const RULE_CATALOG_STORAGE_KEY = "soapp-qc-rule-catalog-v1";
const RULE_CATALOG_VERSION = "2026-10-phase2";
const RULE_CATALOG_VERSION_STORAGE_KEY = "soapp-qc-rule-catalog-version";

export interface RulesApi {
  loadBaseline(): Promise<GuidelineRule[]>;
  loadCatalog(): Promise<GuidelineRule[] | null>;
  saveCatalog(rules: GuidelineRule[]): Promise<void>;
}

export function createRulesApi(baseUrl = import.meta.env.BASE_URL): RulesApi {
  return {
    async loadBaseline() {
      const response = await fetch(`${baseUrl}data/guidelines_rules_v1.json`);
      if (!response.ok) {
        throw new Error(`Unable to load rules baseline (${response.status})`);
      }
      const file = await response.json() as RuleCatalogFile;
      return file.rules;
    },
    async loadCatalog() {
      const version = readText(RULE_CATALOG_VERSION_STORAGE_KEY);
      if (version !== RULE_CATALOG_VERSION) {
        removeKey(RULE_CATALOG_STORAGE_KEY);
        return null;
      }
      const stored = readJson<unknown>(RULE_CATALOG_STORAGE_KEY);
      return Array.isArray(stored) && stored.every(isGuidelineRule) ? stored : null;
    },
    async saveCatalog(rules) {
      writeJson(RULE_CATALOG_STORAGE_KEY, rules);
      writeText(RULE_CATALOG_VERSION_STORAGE_KEY, RULE_CATALOG_VERSION);
    },
  };
}

function isGuidelineRule(value: unknown): value is GuidelineRule {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<GuidelineRule>;
  return (
    typeof candidate.id === "string" &&
    typeof candidate.domain === "string" &&
    typeof candidate.phase === "string" &&
    typeof candidate.title === "string" &&
    typeof candidate.requirement === "string" &&
    typeof candidate.control_type === "string" &&
    typeof candidate.severity === "string" &&
    typeof candidate.weight_within_domain === "number" &&
    Array.isArray(candidate.evidence_sources) &&
    Array.isArray(candidate.applicability) &&
    typeof candidate.remediation === "string"
  );
}
