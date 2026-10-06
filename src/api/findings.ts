import type { QcFindingStatus, QcFindingWorkflow, QcGateDecision, QcWorkflowStore } from "../lib/qc";
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
      return stored && typeof stored === "object" && !Array.isArray(stored) ? sanitizeWorkflows(stored as Record<string, unknown>) : {};
    },
    async saveWorkflows(workflows) {
      writeJson(QC_WORKFLOW_STORAGE_KEY, workflows);
    },
  };
}

const GATE_DECISIONS: QcGateDecision[] = ["pending", "accepted", "rejected"];
const FINDING_STATUSES: QcFindingStatus[] = ["new", "assigned_supplier", "corrected"];

function sanitizeWorkflows(stored: Record<string, unknown>): QcWorkflowStore {
  const workflows: QcWorkflowStore = {};
  for (const [appId, raw] of Object.entries(stored)) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const workflow = raw as Partial<QcWorkflowStore[string]> & { gateDecision?: string };
    const findings: Record<string, QcFindingWorkflow> = {};
    for (const [ruleId, finding] of Object.entries(workflow.findings ?? {})) {
      if (!finding) continue;
      const status = FINDING_STATUSES.includes(finding.status) ? finding.status : "new";
      findings[ruleId] = {
        ruleId: finding.ruleId || ruleId,
        status,
        assignee: finding.assignee ?? "",
        comment: finding.comment ?? "",
        updatedAt: finding.updatedAt ?? new Date().toISOString(),
        history: Array.isArray(finding.history) ? finding.history : [],
      };
    }
    workflows[appId] = {
      appId: workflow.appId || appId,
      gateDecision: GATE_DECISIONS.includes(workflow.gateDecision as QcGateDecision) ? workflow.gateDecision as QcGateDecision : "pending",
      gateComment: workflow.gateComment ?? "",
      gateUpdatedAt: workflow.gateUpdatedAt,
      supplierSince: workflow.supplierSince,
      internalSince: workflow.internalSince,
      findings,
      history: Array.isArray(workflow.history) ? workflow.history : [],
    };
  }
  return workflows;
}
