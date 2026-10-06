import type { AuditApp, RuleResult, Severity } from "./types";

export type QcGateDecision = "pending" | "accepted" | "rejected" | "accepted_with_exception";
export type QcFindingStatus = "new" | "assigned_supplier" | "corrected" | "exception";
export type SlaStatus = "within" | "at_risk" | "breached";

export type QcTimelineEntry = {
  id: string;
  at: string;
  actor: string;
  action: string;
  detail: string;
};

export type QcException = {
  id: string;
  ruleId: string;
  reason: string;
  validator: string;
  ticketRef: string;
  expiresAt: string;
  createdAt: string;
};

export type QcFindingWorkflow = {
  ruleId: string;
  status: QcFindingStatus;
  assignee: string;
  comment: string;
  updatedAt: string;
  history: QcTimelineEntry[];
  exceptionId?: string;
};

export type QcAppWorkflow = {
  appId: string;
  gateDecision: QcGateDecision;
  gateComment: string;
  gateUpdatedAt?: string;
  supplierSince?: string;
  internalSince?: string;
  findings: Record<string, QcFindingWorkflow>;
  exceptions: QcException[];
  history: QcTimelineEntry[];
};

export type QcWorkflowStore = Record<string, QcAppWorkflow>;

export const SLA_BY_SEVERITY_DAYS: Record<Severity, number> = {
  critical: 2,
  high: 5,
  medium: 10,
  low: 15,
};

export function isOpenRule(rule: RuleResult) {
  return ["non_compliant", "to_clarify", "non_verifiable"].includes(rule.status);
}

export function ageInDays(value?: string) {
  const days = daysBetween(value);
  return days ?? 0;
}

export function daysBetween(start?: string, end?: string) {
  if (!start) return null;
  const from = new Date(start).getTime();
  const to = end ? new Date(end).getTime() : Date.now();
  if (Number.isNaN(from) || Number.isNaN(to)) return null;
  return Math.max(0, Math.floor((to - from) / 86_400_000));
}

export function slaForFinding(rule: RuleResult, finding?: QcFindingWorkflow): { status: SlaStatus; age: number; limit: number } {
  const limit = SLA_BY_SEVERITY_DAYS[rule.severity];
  const age = ageInDays(finding?.updatedAt);
  if (finding?.status === "corrected" || finding?.status === "exception") return { status: "within", age, limit };
  if (age > limit) return { status: "breached", age, limit };
  if (age >= Math.ceil(limit * 0.75)) return { status: "at_risk", age, limit };
  return { status: "within", age, limit };
}

export function workflowSla(app: AuditApp, workflow: QcAppWorkflow): { status: SlaStatus; age: number; limit: number } {
  const openRules = app.rules.filter(isOpenRule);
  if (!openRules.length) return { status: "within", age: 0, limit: 0 };
  return openRules
    .map((rule) => slaForFinding(rule, workflow.findings[rule.id]))
    .sort((left, right) => slaRank(right.status) - slaRank(left.status) || right.age - left.age)[0] ?? { status: "within", age: 0, limit: 0 };
}

export function slaRank(status: SlaStatus) {
  const ranks: Record<SlaStatus, number> = {
    within: 0,
    at_risk: 1,
    breached: 2,
  };
  return ranks[status];
}

export function packageHasRework(workflow: QcAppWorkflow) {
  if (workflow.gateDecision === "rejected") return true;
  if (workflow.supplierSince) return true;
  return Object.values(workflow.findings).some((finding) => finding.status === "assigned_supplier");
}

export function isFirstTimeRight(app: AuditApp, workflow: QcAppWorkflow) {
  if (packageHasRework(workflow)) return false;
  if (workflow.gateDecision === "accepted_with_exception" || workflow.gateDecision === "rejected") return false;
  if (workflow.gateDecision === "accepted") return true;
  return app.status === "compliant";
}

export function deliveryDays(app: AuditApp, workflow: QcAppWorkflow) {
  const end = workflow.gateDecision !== "pending" ? workflow.gateUpdatedAt : undefined;
  return daysBetween(app.lastModified, end);
}

export function isActionableFinding(finding?: QcFindingWorkflow) {
  return !finding || finding.status === "new" || finding.status === "assigned_supplier";
}
