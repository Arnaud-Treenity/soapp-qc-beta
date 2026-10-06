export type RawAuditFile = {
  extractedAt: string;
  tenantId: string;
  account: string;
  requestedTop: number;
  returnedApps: number;
  resolvedGroups: number;
  groups: Record<string, { displayName?: string; id?: string }>;
  records: RawAuditRecord[];
};

export type RawAuditRecord = {
  app: Record<string, unknown>;
  assignments?: RawAssignment[];
  assignments_error?: string;
  categories?: unknown;
  categories_error?: string;
  relationships?: unknown[];
  relationships_error?: string;
};

export type RawAssignment = {
  intent?: string;
  id?: string;
  settings?: Record<string, unknown> | null;
  target?: {
    groupId?: string;
    "@odata.type"?: string;
  };
};

export type GuidelineRule = {
  id: string;
  domain: string;
  phase: string;
  title: string;
  requirement: string;
  control_type: string;
  severity: Severity;
  weight_within_domain: number;
  evidence_sources: string[];
  applicability: string[];
  remediation: string;
};

export type RuleCatalogFile = {
  rules: GuidelineRule[];
};

export type Severity = "critical" | "high" | "medium" | "low";

export type AuditStatus =
  | "compliant"
  | "non_compliant"
  | "to_clarify"
  | "non_verifiable"
  | "exception";

export type RuleResult = {
  id: string;
  title: string;
  domain: string;
  severity: Severity;
  status: AuditStatus;
  scoreImpact: number;
  scoringEnabled: boolean;
  evidence: string;
  remediation: string;
};

export type AuditApp = {
  id: string;
  name: string;
  publisher: string;
  version: string;
  owner: string;
  type: string;
  platform: string;
  lastModified: string;
  assignments: AssignmentView[];
  detectionRules: DetectionRuleView[];
  returnCodes: string[];
  score: number;
  status: AuditStatus;
  rules: RuleResult[];
};

export type DetectionRuleKind = "registry" | "file" | "msi" | "script" | "unknown";

export type DetectionRuleView = {
  kind: DetectionRuleKind;
  type: string;
  indicator: string;
  value: string;
};

export type AssignmentView = {
  intent: string;
  target: string;
  targetId?: string;
  targetResolved: boolean;
  mode: "included" | "excluded";
  notifications: string;
};

export type AuditModel = {
  metadata: {
    extractedAt: string;
    sourceLabel: string;
    perimeterLabel: string;
    evaluatedControls: number;
  };
  apps: AuditApp[];
  rules: GuidelineRule[];
  stats: {
    globalScore: number;
    appCount: number;
    compliantApps: number;
    criticalFindings: number;
    nonVerifiableRules: number;
    openFindings: number;
    nonCompliantApps: number;
    createdThisWeek: number;
    updatedThisWeek: number;
    correctedThisWeek: number | null;
  };
  topViolations: { id: string; title: string; count: number }[];
  statusDistribution: { name: string; value: number; status: AuditStatus }[];
  weeklyActivity: { week: string; created: number; updated: number }[];
  backlogBySeverity: { severity: Severity; name: string; value: number }[];
  ownerBacklog: { owner: string; findings: number; apps: number }[];
  controlHotspots: { id: string; label: string; value: number }[];
};

export type ScoringConfig = {
  version: 1;
  severityWeights: Record<Severity, number>;
  statusCredits: Record<AuditStatus, number>;
  nonVerifiableMode: "excluded" | "zero";
  thresholds: {
    compliant: number;
    warning: number;
  };
  blockers: {
    criticalFailure: boolean;
    toClarify: boolean;
    nonVerifiable: boolean;
  };
  ruleOverrides: Record<string, {
    enabled: boolean;
    weight?: number;
  }>;
};
