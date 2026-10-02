import type {
  AssignmentView,
  AuditApp,
  AuditModel,
  AuditStatus,
  DetectionRuleView,
  GuidelineRule,
  RawAssignment,
  RawAuditFile,
  RawAuditRecord,
  RuleCatalogFile,
  RuleResult,
  ScoringConfig,
} from "./types";
import { ruleCopy, severityLabel, statusLabel as localizedStatusLabel, type Language } from "./i18n";

const CHECKED_RULE_IDS = [
  "INT-OWN-001",
  "INT-CAT-001",
  "INT-FEATURED-001",
  "INT-CMD-001",
  "INT-BEHAVIOR-001",
  "INT-RESTART-001",
  "INT-RC-001",
  "INT-REQ-001",
  "INT-REQ-003",
  "INT-DET-001",
  "INT-DET-004",
  "DEP-GROUP-001",
  "DEP-TARGET-001",
  "PKG-PATH-001",
];

export const DEFAULT_SCORING_CONFIG: ScoringConfig = {
  version: 1,
  severityWeights: {
    critical: 24,
    high: 16,
    medium: 10,
    low: 6,
  },
  statusCredits: {
    compliant: 1,
    exception: 1,
    to_clarify: 0.45,
    non_compliant: 0,
    non_verifiable: 0,
  },
  nonVerifiableMode: "excluded",
  thresholds: {
    compliant: 92,
    warning: 80,
  },
  blockers: {
    criticalFailure: true,
    toClarify: true,
    nonVerifiable: true,
  },
  ruleOverrides: {},
};

const AUDIT_TEXT: Record<Language, Record<string, string>> = {
  fr: {
    unnamedApp: "Application sans nom",
    unknownPublisher: "Editeur non renseigne",
    unknownVersion: "Version non renseignee",
    unassigned: "Non assigne",
    sourceLabel: "Graph API + export Intune",
    ownerMissing: "Proprietaire manquant",
    categoryMissing: "Categorie absente ou non collectee",
    featuredOn: "Featured active",
    featuredOff: "Featured desactive",
    installCommandUnavailable: "Commande d'installation non disponible",
    nonBlockingControl: "controle non bloquant",
    runAsMissing: "runAsAccount absent",
    restartMissing: "Comportement de redemarrage absent",
    returnCodesMissing: "Codes retour absents",
    architectureMissing: "Architecture non renseignee",
    hardwareSet: "Prerequis hardware renseignes",
    noHardware: "Aucun prerequis hardware specifique",
    detectionNotEvaluated: "regle non evaluee en V0",
    detectionMissing: "Aucune regle de detection",
    assignmentsNotCollected: "Deploiements non collectes via Graph",
    noAssignment: "Aucun assignment detecte",
    allUsersDetected: "All Users detecte",
    noAllUsersDetected: "Pas de ciblage All Users detecte",
    packageSourceRequired: "Package source requis",
    unresolvedTarget: "Cible non resolue",
    scriptDetection: "detection par script",
    missingPath: "Chemin manquant",
    unknown: "Inconnu",
    ownerGap: "Ownership",
    detectionGap: "Detection",
    assignmentGap: "Ciblage",
    returnCodeGap: "Codes retour",
    sourceGap: "Source package",
  },
  en: {
    unnamedApp: "Unnamed application",
    unknownPublisher: "Publisher not provided",
    unknownVersion: "Version not provided",
    unassigned: "Unassigned",
    sourceLabel: "Graph API + Intune export",
    ownerMissing: "Owner missing",
    categoryMissing: "Category missing or not collected",
    featuredOn: "Featured enabled",
    featuredOff: "Featured disabled",
    installCommandUnavailable: "Install command unavailable",
    nonBlockingControl: "non-blocking control",
    runAsMissing: "runAsAccount missing",
    restartMissing: "Restart behavior missing",
    returnCodesMissing: "Return codes missing",
    architectureMissing: "Architecture not provided",
    hardwareSet: "Hardware requirements configured",
    noHardware: "No specific hardware requirement",
    detectionNotEvaluated: "rule not evaluated in V0",
    detectionMissing: "No detection rule",
    assignmentsNotCollected: "Assignments not collected through Graph",
    noAssignment: "No assignment detected",
    allUsersDetected: "All Users detected",
    noAllUsersDetected: "No All Users targeting detected",
    packageSourceRequired: "Package source required",
    unresolvedTarget: "Unresolved target",
    scriptDetection: "script detection",
    missingPath: "Missing path",
    unknown: "Unknown",
    ownerGap: "Ownership",
    detectionGap: "Detection",
    assignmentGap: "Targeting",
    returnCodeGap: "Return codes",
    sourceGap: "Package source",
  },
};

export function normalizeScoringConfig(config?: Partial<ScoringConfig>): ScoringConfig {
  return {
    ...DEFAULT_SCORING_CONFIG,
    ...config,
    severityWeights: {
      ...DEFAULT_SCORING_CONFIG.severityWeights,
      ...config?.severityWeights,
    },
    statusCredits: {
      ...DEFAULT_SCORING_CONFIG.statusCredits,
      ...config?.statusCredits,
    },
    thresholds: {
      ...DEFAULT_SCORING_CONFIG.thresholds,
      ...config?.thresholds,
    },
    blockers: {
      ...DEFAULT_SCORING_CONFIG.blockers,
      ...config?.blockers,
    },
    ruleOverrides: {
      ...config?.ruleOverrides,
    },
  };
}

export async function loadAuditModel(
  scoringConfig?: ScoringConfig,
  language: Language = "fr",
  customRules?: GuidelineRule[],
): Promise<AuditModel> {
  const config = normalizeScoringConfig(scoringConfig);
  const [auditFile, ruleFile] = await Promise.all([
    fetch(`${import.meta.env.BASE_URL}data/intune_apps_sample_30.json`).then((r) => r.json()) as Promise<RawAuditFile>,
    fetch(`${import.meta.env.BASE_URL}data/guidelines_rules_v1.json`).then((r) => r.json()) as Promise<RuleCatalogFile>,
  ]);

  const rules = customRules ?? ruleFile.rules;
  const rulesById = new Map(rules.map((rule) => [rule.id, rule]));
  const apps = auditFile.records.map((record) => buildAuditApp(record, auditFile.groups, rulesById, config, language));
  const appScores = apps.map((app) => app.score);
  const globalScore = Math.round(appScores.reduce((sum, score) => sum + score, 0) / Math.max(1, appScores.length));
  const allRuleResults = apps.flatMap((app) => app.rules).filter((rule) => rule.scoringEnabled);
  const violations = allRuleResults.filter((rule) => rule.status === "non_compliant");
  const openFindings = allRuleResults.filter((rule) => ["non_compliant", "to_clarify", "non_verifiable"].includes(rule.status));
  const referenceDate = parseDate(auditFile.extractedAt) ?? new Date();

  return {
    metadata: {
      extractedAt: auditFile.extractedAt,
      sourceLabel: label(language, "sourceLabel"),
      perimeterLabel: `${auditFile.returnedApps} apps`,
      evaluatedControls: CHECKED_RULE_IDS.length,
    },
    apps,
    rules,
    stats: {
      globalScore,
      appCount: apps.length,
      compliantApps: apps.filter((app) => app.status === "compliant").length,
      criticalFindings: violations.filter((rule) => rule.severity === "critical").length,
      nonVerifiableRules: allRuleResults.filter((rule) => rule.status === "non_verifiable").length,
      openFindings: openFindings.length,
      nonCompliantApps: apps.filter((app) => app.status !== "compliant" && app.status !== "exception").length,
      createdThisWeek: countAppsInLastDays(auditFile.records, "createdDateTime", referenceDate, 7),
      updatedThisWeek: countAppsInLastDays(auditFile.records, "lastModifiedDateTime", referenceDate, 7),
      correctedThisWeek: null,
    },
    topViolations: topViolations(violations),
    statusDistribution: buildStatusDistribution(apps, language),
    weeklyActivity: buildWeeklyActivity(auditFile.records, referenceDate, language),
    backlogBySeverity: buildBacklogBySeverity(openFindings, language),
    ownerBacklog: buildOwnerBacklog(apps, language),
    controlHotspots: buildControlHotspots(openFindings, language),
  };
}

export function statusLabel(status: AuditStatus, language: Language = "fr"): string {
  return localizedStatusLabel(language, status);
}

function buildAuditApp(
  record: RawAuditRecord,
  groups: RawAuditFile["groups"],
  rulesById: Map<string, GuidelineRule>,
  scoringConfig: ScoringConfig,
  language: Language,
): AuditApp {
  const app = record.app;
  const assignments = normalizeAssignments(record.assignments, groups, language);
  const detectionRules = normalizeDetectionRules(app.rules, language);
  const returnCodes = normalizeReturnCodes(app.returnCodes);
  const type = appType(String(app["@odata.type"] ?? ""));
  const owner = cleanString(app.owner);
  const results = CHECKED_RULE_IDS.map((id) => evaluateRule(id, record, groups, rulesById, scoringConfig, language)).filter(Boolean) as RuleResult[];
  const score = computeScore(results, scoringConfig);
  const status = computeAppStatus(score, results, scoringConfig);

  return {
    id: cleanString(app.id) || crypto.randomUUID(),
    name: cleanString(app.displayName) || label(language, "unnamedApp"),
    publisher: cleanString(app.publisher) || label(language, "unknownPublisher"),
    version: cleanString(app.displayVersion) || cleanString(app.committedContentVersion) || label(language, "unknownVersion"),
    owner: owner || label(language, "unassigned"),
    type,
    platform: platformFromType(type),
    lastModified: cleanString(app.lastModifiedDateTime),
    assignments,
    detectionRules,
    returnCodes,
    score,
    status,
    rules: results,
  };
}

function evaluateRule(
  id: string,
  record: RawAuditRecord,
  groups: RawAuditFile["groups"],
  rulesById: Map<string, GuidelineRule>,
  scoringConfig: ScoringConfig,
  language: Language,
): RuleResult | undefined {
  const rule = rulesById.get(id);
  if (!rule) return undefined;

  const app = record.app;
  const assignments = normalizeAssignments(record.assignments, groups, language);
  const detectionRules = normalizeDetectionRules(app.rules, language);
  const returnCodes = normalizeReturnCodes(app.returnCodes);
  const type = appType(String(app["@odata.type"] ?? ""));
  const installExperience = app.installExperience as Record<string, unknown> | undefined;

  switch (id) {
    case "INT-OWN-001": {
      const owner = cleanString(app.owner);
      return result(rule, owner ? "compliant" : "non_compliant", owner || label(language, "ownerMissing"), scoringConfig, language);
    }
    case "INT-CAT-001": {
      const categories = normalizeCategories(record.categories);
      return result(
        rule,
        categories.length ? "compliant" : "to_clarify",
        categories.length ? categories.join(", ") : label(language, "categoryMissing"),
        scoringConfig,
        language,
      );
    }
    case "INT-FEATURED-001": {
      return result(rule, app.isFeatured ? "to_clarify" : "compliant", app.isFeatured ? label(language, "featuredOn") : label(language, "featuredOff"), scoringConfig, language);
    }
    case "INT-CMD-001": {
      const cmd = cleanString(app.installCommandLine);
      if (!cmd) return result(rule, "non_verifiable", label(language, "installCommandUnavailable"), scoringConfig, language);
      const isPowershell = cmd.toLowerCase().includes("powershell");
      const uses64Bit = cmd.toLowerCase().includes("sysnative") || !cmd.toLowerCase().includes("system32");
      return result(rule, !isPowershell || uses64Bit ? "compliant" : "non_compliant", cmd, scoringConfig, language);
    }
    case "INT-BEHAVIOR-001": {
      const runAs = cleanString(installExperience?.runAsAccount);
      if (type !== "Win32") return result(rule, "compliant", `${type}: ${label(language, "nonBlockingControl")}`, scoringConfig, language);
      return result(rule, runAs === "system" ? "compliant" : "non_compliant", runAs || label(language, "runAsMissing"), scoringConfig, language);
    }
    case "INT-RESTART-001": {
      const behavior = cleanString(installExperience?.deviceRestartBehavior);
      return result(
        rule,
        behavior && behavior !== "force" ? "compliant" : "to_clarify",
        behavior || label(language, "restartMissing"),
        scoringConfig,
        language,
      );
    }
    case "INT-RC-001": {
      const hasSuccess = returnCodes.some((code) => code.startsWith("0="));
      const hasReboot = returnCodes.some((code) => code.includes("3010=") || code.includes("1641="));
      return result(
        rule,
        hasSuccess && hasReboot ? "compliant" : "non_compliant",
        returnCodes.length ? returnCodes.join(", ") : label(language, "returnCodesMissing"),
        scoringConfig,
        language,
      );
    }
    case "INT-REQ-001": {
      const arch = cleanString(app.applicableArchitectures) || cleanString(app.allowedArchitectures);
      return result(rule, arch ? "compliant" : "to_clarify", arch || label(language, "architectureMissing"), scoringConfig, language);
    }
    case "INT-REQ-003": {
      const hasHardwareRequirement =
        app.minimumFreeDiskSpaceInMB || app.minimumMemoryInMB || app.minimumCpuSpeedInMHz || app.minimumNumberOfProcessors;
      return result(
        rule,
        hasHardwareRequirement ? "to_clarify" : "compliant",
        hasHardwareRequirement ? label(language, "hardwareSet") : label(language, "noHardware"),
        scoringConfig,
        language,
      );
    }
    case "INT-DET-001":
    case "INT-DET-004": {
      if (type !== "Win32") return result(rule, "non_verifiable", `${type}: ${label(language, "detectionNotEvaluated")}`, scoringConfig, language);
      if (!detectionRules.length) return result(rule, "non_compliant", label(language, "detectionMissing"), scoringConfig, language);
      const weakDetection = detectionRules.some((detectionRule) => detectionRule.kind === "unknown" || /missing path|not configured|unknown/i.test(detectionRuleSummary(detectionRule)));
      return result(rule, weakDetection ? "to_clarify" : "compliant", detectionRules.map(detectionRuleSummary).join(" | "), scoringConfig, language);
    }
    case "DEP-GROUP-001": {
      if (record.assignments_error) return result(rule, "non_verifiable", label(language, "assignmentsNotCollected"), scoringConfig, language);
      if (!assignments.length) return result(rule, "to_clarify", label(language, "noAssignment"), scoringConfig, language);
      const hasTestMarker = assignments.some((assignment) => /test|poc/i.test(assignment.target));
      return result(
        rule,
        hasTestMarker ? "to_clarify" : "compliant",
        assignments.map((assignment) => `${assignment.target} (${assignment.intent})`).join(" | "),
        scoringConfig,
        language,
      );
    }
    case "DEP-TARGET-001": {
      if (record.assignments_error) return result(rule, "non_verifiable", label(language, "assignmentsNotCollected"), scoringConfig, language);
      const allUsers = assignments.some((assignment) => /all users/i.test(assignment.target));
      return result(rule, allUsers ? "to_clarify" : "compliant", allUsers ? label(language, "allUsersDetected") : label(language, "noAllUsersDetected"), scoringConfig, language);
    }
    case "PKG-PATH-001": {
      return result(rule, "non_verifiable", label(language, "packageSourceRequired"), scoringConfig, language);
    }
    default:
      return undefined;
  }
}

function result(rule: GuidelineRule, status: AuditStatus, evidence: string, scoringConfig: ScoringConfig, language: Language): RuleResult {
  const override = scoringConfig.ruleOverrides[rule.id];
  const scoringEnabled = override?.enabled ?? true;
  const configuredWeight = override?.weight ?? scoringConfig.severityWeights[rule.severity];
  const copy = ruleCopy(language, rule);
  return {
    id: rule.id,
    title: copy.title,
    domain: rule.domain,
    severity: rule.severity,
    status,
    scoreImpact: scoringEnabled ? Math.max(0, configuredWeight) : 0,
    scoringEnabled,
    evidence,
    remediation: copy.remediation,
  };
}

function computeScore(results: RuleResult[], scoringConfig: ScoringConfig): number {
  const scoringResults = results.filter((rule) =>
    rule.scoringEnabled && (rule.status !== "non_verifiable" || scoringConfig.nonVerifiableMode === "zero"),
  );
  const max = scoringResults.reduce((sum, rule) => sum + rule.scoreImpact, 0);
  const earned = scoringResults.reduce((sum, rule) => {
    const credit = Math.min(1, Math.max(0, scoringConfig.statusCredits[rule.status] ?? 0));
    return sum + rule.scoreImpact * credit;
  }, 0);
  return Math.round((earned / Math.max(1, max)) * 100);
}

function computeAppStatus(score: number, results: RuleResult[], scoringConfig: ScoringConfig): AuditStatus {
  const scoringResults = results.filter((rule) => rule.scoringEnabled);
  const failures = scoringResults.filter((rule) => rule.status === "non_compliant");
  if (
    !failures.length &&
    score >= scoringConfig.thresholds.compliant &&
    (!scoringConfig.blockers.toClarify || !scoringResults.some((rule) => rule.status === "to_clarify")) &&
    (!scoringConfig.blockers.nonVerifiable || !scoringResults.some((rule) => rule.status === "non_verifiable"))
  ) {
    return "compliant";
  }
  if (scoringConfig.blockers.criticalFailure && failures.some((rule) => rule.severity === "critical")) return "non_compliant";
  if (scoringConfig.blockers.toClarify && scoringResults.some((rule) => rule.status === "to_clarify")) return "to_clarify";
  if (scoringConfig.blockers.nonVerifiable && scoringResults.some((rule) => rule.status === "non_verifiable")) return "non_verifiable";
  if (failures.length && score < scoringConfig.thresholds.warning) return "non_compliant";
  return score >= scoringConfig.thresholds.warning ? "to_clarify" : "non_compliant";
}

function normalizeAssignments(assignments: RawAssignment[] | undefined, groups: RawAuditFile["groups"], language: Language): AssignmentView[] {
  if (!Array.isArray(assignments)) return [];
  return assignments.map((assignment) => {
    const targetType = assignment.target?.["@odata.type"] ?? "";
    const groupId = assignment.target?.groupId ?? "";
    const groupName = groupId ? groups[groupId]?.displayName || groupId : targetTypeLabel(targetType, language);
    return {
      intent: assignment.intent || "unknown",
      target: groupName,
      mode: targetType.includes("exclusion") ? "excluded" : "included",
      notifications: cleanString(assignment.settings?.notifications) || "notConfigured",
    };
  });
}

function targetTypeLabel(targetType: string, language: Language): string {
  if (targetType.includes("allDevices")) return "All Devices";
  if (targetType.includes("allLicensedUsers")) return "All Users";
  return label(language, "unresolvedTarget");
}

function normalizeDetectionRules(value: unknown, language: Language): DetectionRuleView[] {
  if (!Array.isArray(value)) return [];
  return value.map((rule) => {
    const item = rule as Record<string, unknown>;
    const type = cleanString(item["@odata.type"]).replace("#microsoft.graph.win32LobApp", "").replace("Rule", "").replace("Detection", "");
    const keyPath = cleanString(item.keyPath);
    const valueName = cleanString(item.valueName);
    const operator = cleanString(item.operator);
    const operationType = cleanString(item.operationType);
    const detectionValue = cleanString(item.detectionValue);
    const detectionType = cleanString(item.detectionType);
    const path = cleanString(item.path);
    const fileOrFolderName = cleanString(item.fileOrFolderName);
    const productCode = cleanString(item.productCode);
    const productVersionOperator = cleanString(item.productVersionOperator);
    const productVersion = cleanString(item.productVersion);
    const scriptContent = cleanString(item.scriptContent);
    if (keyPath) {
      return {
        kind: "registry",
        type: type || "Registry",
        indicator: valueName ? `${keyPath}\\${valueName}` : keyPath,
        value: compactJoin([operationType || operator, detectionValue, item.check32BitOn64System === true ? "32-bit on 64-bit" : ""]),
      };
    }
    if (path || fileOrFolderName) {
      return {
        kind: "file",
        type: type || "File",
        indicator: `${path}/${fileOrFolderName}`.replace("//", "/"),
        value: compactJoin([detectionType, operator, detectionValue, item.check32BitOn64System === true ? "32-bit on 64-bit" : ""]),
      };
    }
    if (productCode) {
      return {
        kind: "msi",
        type: type || "MSI",
        indicator: productCode,
        value: compactJoin([productVersionOperator, productVersion]),
      };
    }
    if (scriptContent) {
      return {
        kind: "script",
        type: type || "Script",
        indicator: label(language, "scriptDetection"),
        value: compactJoin([operationType || operator, detectionValue]),
      };
    }
    return {
      kind: "unknown",
      type: type || label(language, "unknown"),
      indicator: label(language, "missingPath"),
      value: "",
    };
  });
}

function detectionRuleSummary(rule: DetectionRuleView): string {
  return `${rule.type} ${rule.indicator}${rule.value ? ` (${rule.value})` : ""}`;
}

function compactJoin(values: string[]): string {
  return values.filter(Boolean).join(" - ");
}

function normalizeReturnCodes(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => {
    const code = item as Record<string, unknown>;
    return `${code.returnCode ?? "?"}=${code.type ?? "unknown"}`;
  });
}

function normalizeCategories(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((item) => cleanString((item as Record<string, unknown>).displayName)).filter(Boolean);
  if (value && typeof value === "object" && Array.isArray((value as Record<string, unknown>).value)) {
    return ((value as { value: Record<string, unknown>[] }).value ?? []).map((item) => cleanString(item.displayName)).filter(Boolean);
  }
  return [];
}

function cleanString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function appType(odataType: string): string {
  if (odataType.includes("win32LobApp")) return "Win32";
  if (odataType.includes("ios")) return "iOS";
  if (odataType.includes("macOS")) return "macOS";
  if (odataType.includes("android")) return "Android";
  if (odataType.includes("officeSuiteApp")) return "M365";
  return "LOB";
}

function platformFromType(type: string): string {
  if (type === "iOS") return "iOS";
  if (type === "macOS") return "macOS";
  if (type === "Android") return "Android";
  return "Windows";
}

function topViolations(violations: RuleResult[]): AuditModel["topViolations"] {
  const counts = new Map<string, { id: string; title: string; count: number }>();
  for (const violation of violations) {
    const current = counts.get(violation.id) ?? { id: violation.id, title: violation.title, count: 0 };
    current.count += 1;
    counts.set(violation.id, current);
  }
  return [...counts.values()].sort((a, b) => b.count - a.count).slice(0, 5);
}

function buildStatusDistribution(apps: AuditApp[], language: Language): AuditModel["statusDistribution"] {
  const ordered: AuditStatus[] = ["compliant", "non_compliant", "to_clarify", "non_verifiable", "exception"];
  return ordered.map((status) => ({
    status,
    name: statusLabel(status, language),
    value: apps.filter((app) => app.status === status).length,
  }));
}

function buildWeeklyActivity(records: RawAuditRecord[], referenceDate: Date, language: Language): AuditModel["weeklyActivity"] {
  const weeks = Array.from({ length: 8 }, (_, index) => {
    const start = startOfWeek(addDays(referenceDate, -(7 * (7 - index))));
    return {
      start,
      end: addDays(start, 7),
      week: formatWeekLabel(start, language),
      created: 0,
      updated: 0,
    };
  });

  for (const record of records) {
    const created = parseDate(record.app.createdDateTime);
    const updated = parseDate(record.app.lastModifiedDateTime);
    for (const bucket of weeks) {
      if (created && created >= bucket.start && created < bucket.end) bucket.created += 1;
      if (updated && updated >= bucket.start && updated < bucket.end) bucket.updated += 1;
    }
  }

  return weeks.map(({ week, created, updated }) => ({ week, created, updated }));
}

function buildBacklogBySeverity(findings: RuleResult[], language: Language): AuditModel["backlogBySeverity"] {
  const ordered: GuidelineRule["severity"][] = ["critical", "high", "medium", "low"];
  return ordered.map((severity) => ({
    severity,
    name: severityLabel(language, severity),
    value: findings.filter((finding) => finding.severity === severity).length,
  }));
}

function buildOwnerBacklog(apps: AuditApp[], language: Language): AuditModel["ownerBacklog"] {
  const owners = new Map<string, { owner: string; findings: number; apps: Set<string> }>();
  for (const app of apps) {
    const owner = app.owner || label(language, "unassigned");
    const findingCount = app.rules.filter((rule) => rule.scoringEnabled && ["non_compliant", "to_clarify", "non_verifiable"].includes(rule.status)).length;
    if (!findingCount) continue;
    const current = owners.get(owner) ?? { owner, findings: 0, apps: new Set<string>() };
    current.findings += findingCount;
    current.apps.add(app.id);
    owners.set(owner, current);
  }

  return [...owners.values()]
    .map((entry) => ({ owner: entry.owner, findings: entry.findings, apps: entry.apps.size }))
    .sort((a, b) => b.findings - a.findings)
    .slice(0, 6);
}

function buildControlHotspots(findings: RuleResult[], language: Language): AuditModel["controlHotspots"] {
  const definitions = [
    { id: "owner", label: label(language, "ownerGap"), match: (rule: RuleResult) => /OWN/i.test(rule.id) },
    { id: "detection", label: label(language, "detectionGap"), match: (rule: RuleResult) => /DET/i.test(rule.id) },
    { id: "assignment", label: label(language, "assignmentGap"), match: (rule: RuleResult) => /DEP|ASSG/i.test(rule.id) },
    { id: "returnCodes", label: label(language, "returnCodeGap"), match: (rule: RuleResult) => /RC/i.test(rule.id) },
    { id: "packageSource", label: label(language, "sourceGap"), match: (rule: RuleResult) => /PKG/i.test(rule.id) },
  ];

  return definitions.map((definition) => ({
    id: definition.id,
    label: definition.label,
    value: findings.filter(definition.match).length,
  }));
}

function countAppsInLastDays(records: RawAuditRecord[], field: "createdDateTime" | "lastModifiedDateTime", referenceDate: Date, days: number): number {
  const start = addDays(referenceDate, -days);
  return records.filter((record) => {
    const date = parseDate(record.app[field]);
    return date ? date >= start && date <= referenceDate : false;
  }).length;
}

function parseDate(value: unknown): Date | null {
  if (typeof value !== "string" || !value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function addDays(date: Date, days: number): Date {
  const next = new Date(date);
  next.setUTCDate(next.getUTCDate() + days);
  return next;
}

function startOfWeek(date: Date): Date {
  const next = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const day = next.getUTCDay() || 7;
  next.setUTCDate(next.getUTCDate() - day + 1);
  return next;
}

function formatWeekLabel(date: Date, language: Language): string {
  return date.toLocaleDateString(language === "fr" ? "fr-FR" : "en-GB", { day: "2-digit", month: "short", timeZone: "UTC" });
}

function label(language: Language, key: string): string {
  return AUDIT_TEXT[language][key] ?? AUDIT_TEXT.en[key] ?? key;
}
