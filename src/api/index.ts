import { createFindingsApi, type FindingsApi } from "./findings";
import { createStaticPackagesApi, type PackagesApi } from "./packages";
import { createRulesApi, type RulesApi } from "./rules";
import { createScoringApi, type ScoringApi } from "./scoring";

/**
 * Storage boundary for SoApp QC.
 * The UI talks to these services only. The current adapter reads the Intune
 * snapshot and the rules baseline from static JSON, and keeps QC workflows,
 * the rule catalog and the scoring config in localStorage.
 * Replace `createLocalDataClient()` with an HTTP adapter (Node or .NET in
 * front of PostgreSQL) without changing the views.
 */
export type DataClient = {
  packages: PackagesApi;
  rules: RulesApi;
  findings: FindingsApi;
  scoring: ScoringApi;
};

export function createLocalDataClient(): DataClient {
  return {
    packages: createStaticPackagesApi(),
    rules: createRulesApi(),
    findings: createFindingsApi(),
    scoring: createScoringApi(),
  };
}

export const dataClient = createLocalDataClient();
