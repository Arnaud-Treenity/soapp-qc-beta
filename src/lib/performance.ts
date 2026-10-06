import type { AuditApp } from "./types";
import {
  deliveryDays,
  isActionableFinding,
  isFirstTimeRight,
  isOpenRule,
  packageHasRework,
  slaForFinding,
  slaRank,
  workflowSla,
  type QcAppWorkflow,
  type QcWorkflowStore,
  type SlaStatus,
} from "./qc";

export type AttentionReason = "breached" | "critical" | "rejected" | "at_risk" | "pending";

export type AttentionPackage = {
  app: AuditApp;
  reason: AttentionReason;
  slaStatus: SlaStatus;
  openFindings: number;
};

export type ContractMetrics = {
  qualityScore: number;
  slaPercent: number;
  openBlockers: number;
  firstTimeRightPercent: number;
  firstTimeRightCount: number;
  packageCount: number;
  reworkRate: number;
  reworkCount: number;
  averageDeliveryDays: number | null;
  openFindings: number;
  withinSla: number;
};

export type SupplierPerformanceRow = {
  supplier: string;
  packages: number;
  firstTimeRightPercent: number;
  reworkRate: number;
  slaPercent: number;
  averageDeliveryDays: number | null;
  openBlockers: number;
};

const REASON_RANK: Record<AttentionReason, number> = {
  breached: 0,
  rejected: 1,
  critical: 2,
  at_risk: 3,
  pending: 4,
};

export function contractMetrics(apps: AuditApp[], workflows: QcWorkflowStore): ContractMetrics {
  const measured = apps.map((app) => ({ app, workflow: workflowFor(app, workflows) }));
  const sla = measured.flatMap((row) => openSlaFindings(row.app, row.workflow));
  const withinSla = sla.filter((entry) => entry.status !== "breached").length;
  const delivery = measured
    .map((row) => deliveryDays(row.app, row.workflow))
    .filter((value): value is number => value !== null);
  const reworkCount = measured.filter((row) => packageHasRework(row.workflow)).length;
  const firstTimeRightCount = measured.filter((row) => isFirstTimeRight(row.app, row.workflow)).length;
  const population = measured.length;

  return {
    qualityScore: average(apps.map((app) => app.score)),
    slaPercent: sla.length ? Math.round((withinSla / sla.length) * 100) : 100,
    openBlockers: measured.reduce((sum, row) => sum + openBlockers(row.app, row.workflow), 0),
    firstTimeRightPercent: population ? Math.round((firstTimeRightCount / population) * 100) : 0,
    firstTimeRightCount,
    packageCount: population,
    reworkRate: population ? Math.round((reworkCount / population) * 100) : 0,
    reworkCount,
    averageDeliveryDays: delivery.length ? Math.round(average(delivery)) : null,
    openFindings: sla.length,
    withinSla,
  };
}

export function supplierPerformance(apps: AuditApp[], workflows: QcWorkflowStore): SupplierPerformanceRow[] {
  const groups = new Map<string, AuditApp[]>();
  for (const app of apps) {
    const supplier = app.owner || "—";
    groups.set(supplier, [...(groups.get(supplier) ?? []), app]);
  }

  return [...groups.entries()]
    .map(([supplier, supplierApps]) => {
      const metrics = contractMetrics(supplierApps, workflows);
      return {
        supplier,
        packages: supplierApps.length,
        firstTimeRightPercent: metrics.firstTimeRightPercent,
        reworkRate: metrics.reworkRate,
        slaPercent: metrics.slaPercent,
        averageDeliveryDays: metrics.averageDeliveryDays,
        openBlockers: metrics.openBlockers,
      };
    })
    .sort((left, right) => right.openBlockers - left.openBlockers || right.reworkRate - left.reworkRate || left.supplier.localeCompare(right.supplier));
}

export function attentionPackages(apps: AuditApp[], workflows: QcWorkflowStore, limit = 5): AttentionPackage[] {
  return apps
    .flatMap((app) => {
      const workflow = workflowFor(app, workflows);
      const reason = attentionReason(app, workflow);
      if (!reason) return [];
      const sla = workflowSla(app, workflow);
      return [{
        app,
        reason,
        slaStatus: sla.status,
        openFindings: app.rules.filter(isOpenRule).length,
      }];
    })
    .sort((left, right) => {
      const reasonDelta = REASON_RANK[left.reason] - REASON_RANK[right.reason];
      if (reasonDelta) return reasonDelta;
      const slaDelta = slaRank(right.slaStatus) - slaRank(left.slaStatus);
      if (slaDelta) return slaDelta;
      return left.app.score - right.app.score;
    })
    .slice(0, limit);
}

function attentionReason(app: AuditApp, workflow: QcAppWorkflow): AttentionReason | null {
  const sla = workflowSla(app, workflow);
  if (sla.status === "breached") return "breached";
  if (workflow.gateDecision === "rejected") return "rejected";
  if (openBlockers(app, workflow) > 0) return "critical";
  if (sla.status === "at_risk") return "at_risk";
  if (workflow.gateDecision === "pending" && app.rules.some(isOpenRule)) return "pending";
  return null;
}

function workflowFor(app: AuditApp, workflows: QcWorkflowStore): QcAppWorkflow {
  const existing = workflows[app.id];
  if (existing) return existing;
  const updatedAt = app.lastModified || new Date().toISOString();
  return {
    appId: app.id,
    gateDecision: "pending",
    gateComment: "",
    internalSince: updatedAt,
    findings: Object.fromEntries(
      app.rules.filter(isOpenRule).map((rule) => [rule.id, {
        ruleId: rule.id,
        status: "new" as const,
        assignee: "",
        comment: "",
        updatedAt,
        history: [],
      }]),
    ),
    exceptions: [],
    history: [],
  };
}

function openSlaFindings(app: AuditApp, workflow: QcAppWorkflow) {
  return app.rules.filter(isOpenRule).flatMap((rule) => {
    const finding = workflow.findings[rule.id];
    if (!isActionableFinding(finding)) return [];
    return [slaForFinding(rule, finding)];
  });
}

function openBlockers(app: AuditApp, workflow: QcAppWorkflow) {
  return app.rules.filter((rule) => isOpenRule(rule) && rule.severity === "critical" && isActionableFinding(workflow.findings[rule.id])).length;
}

function average(values: number[]) {
  if (!values.length) return 0;
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length);
}
