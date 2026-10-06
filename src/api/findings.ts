import type { QcWorkflowStore } from "../lib/qc";
import { readJson, writeJson } from "./storage";

const QC_WORKFLOW_STORAGE_KEY = "soapp-qc-workflows-v1";

export interface FindingsApi {
  loadWorkflows(): Promise<QcWorkflowStore>;
  saveWorkflows(workflows: QcWorkflowStore): Promise<void>;
}

export function createFindingsApi(): FindingsApi {
  return {
    async loadWorkflows() {
      const stored = readJson<unknown>(QC_WORKFLOW_STORAGE_KEY);
      return stored && typeof stored === "object" && !Array.isArray(stored) ? stored as QcWorkflowStore : {};
    },
    async saveWorkflows(workflows) {
      writeJson(QC_WORKFLOW_STORAGE_KEY, workflows);
    },
  };
}
