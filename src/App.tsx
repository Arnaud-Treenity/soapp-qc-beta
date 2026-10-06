import { createContext, Fragment, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  AlertCircle,
  AlertTriangle,
  Calendar,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Code2,
  Database,
  Download,
  EyeOff,
  FileText,
  Info,
  ClipboardCheck,
  Gauge,
  LayoutDashboard,
  ListChecks,
  Loader2,
  Menu,
  Package,
  PackagePlus,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Target,
  Ticket,
  Timer,
  Trash2,
  Users,
  Wrench,
  X,
  XCircle,
} from "lucide-react";
import { dataClient } from "./api";
import { DEFAULT_SCORING_CONFIG, loadAuditModel, normalizeScoringConfig, statusLabel } from "./lib/audit";
import {
  controlTypeLabel,
  domainLabel,
  evidenceSourceLabel,
  LANGUAGES,
  ruleCopy,
  severityLabel,
  t,
  type Language,
} from "./lib/i18n";
import { attentionPackages, contractMetrics, supplierPerformance, type AttentionReason } from "./lib/performance";
import {
  ageInDays,
  isActionableFinding,
  isOpenRule,
  slaForFinding,
  workflowSla,
  type QcAppWorkflow,
  type QcFindingStatus,
  type QcFindingWorkflow,
  type QcGateDecision,
  type QcTimelineEntry,
  type QcWorkflowStore,
  type SlaStatus,
} from "./lib/qc";
import type { AuditApp, AuditModel, AuditStatus, DetectionRuleKind, GuidelineRule, RuleResult, ScoringConfig, Severity } from "./lib/types";

type ViewKey = "overview" | "packages" | "qcQueue" | "findings" | "rules" | "assignments" | "supplierPerformance";

const STATUS_COLORS: Record<AuditStatus, string> = {
  compliant: "#10b981",
  non_compliant: "#f43f5e",
  to_clarify: "#f59e0b",
  non_verifiable: "#94a3b8",
  exception: "#8b5cf6",
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#e11d48",
  high: "#ea580c",
  medium: "#f59e0b",
  low: "#0e7490",
};

const STATUS_CLASS: Record<AuditStatus, string> = {
  compliant: "status status-compliant",
  non_compliant: "status status-non-compliant",
  to_clarify: "status status-to-clarify",
  non_verifiable: "status status-non-verifiable",
  exception: "status status-exception",
};

const NAV_SECTIONS: { labelKey: string; items: { key: ViewKey; labelKey: string; icon: typeof LayoutDashboard }[] }[] = [
  {
    labelKey: "operations",
    items: [
      { key: "overview", labelKey: "overview", icon: LayoutDashboard },
      { key: "packages", labelKey: "packages", icon: Package },
      { key: "qcQueue", labelKey: "qcQueue", icon: ClipboardCheck },
    ],
  },
  {
    labelKey: "governance",
    items: [
      { key: "findings", labelKey: "findings", icon: AlertCircle },
      { key: "rules", labelKey: "rulesBaselines", icon: ListChecks },
    ],
  },
  {
    labelKey: "deployment",
    items: [
      { key: "assignments", labelKey: "assignments", icon: Users },
    ],
  },
  {
    labelKey: "performance",
    items: [
      { key: "supplierPerformance", labelKey: "supplierPerformance", icon: Gauge },
    ],
  },
];

const ATTENTION_LABEL: Record<AttentionReason, string> = {
  breached: "attentionReasonBreached",
  rejected: "attentionReasonRejected",
  critical: "attentionReasonCritical",
  at_risk: "attentionReasonAtRisk",
  pending: "attentionReasonPending",
};

const RULE_DOMAIN_OPTIONS = ["pre_validation", "source_files", "packaging", "testing", "intune_setup", "deployment"];
const RULE_PHASE_OPTIONS = [
  "request_intake",
  "technical_assessment",
  "approval",
  "source_collection",
  "source_preparation",
  "package_build",
  "local_validation",
  "intune_metadata",
  "intune_configuration",
  "program",
  "requirements",
  "detection",
  "dependencies",
  "supersedence",
  "review_save",
  "deployment_strategy",
  "targeting",
  "communication",
  "production_rollout",
];
const RULE_CONTROL_TYPE_OPTIONS = ["automatic", "semi_automatic", "manual"];
const RULE_SEVERITY_OPTIONS: Severity[] = ["critical", "high", "medium", "low"];

const LANGUAGE_STORAGE_KEY = "soapp-qc-language";

const LocaleContext = createContext<{ language: Language; setLanguage: (language: Language) => void }>({
  language: "fr",
  setLanguage: () => undefined,
});

function useLocale() {
  return useContext(LocaleContext);
}

function loadStoredLanguage(): Language {
  if (typeof window === "undefined") return "fr";
  const stored = window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
  return stored === "en" || stored === "fr" ? stored : "fr";
}

function storeLanguage(language: Language) {
  window.localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
}

function nextCustomRuleId(rules: GuidelineRule[]) {
  const existingIds = new Set(rules.map((rule) => rule.id));
  for (let index = 1; index < 1000; index += 1) {
    const candidate = `CUSTOM-${String(index).padStart(3, "0")}`;
    if (!existingIds.has(candidate)) return candidate;
  }
  return `CUSTOM-${Date.now()}`;
}

function createBlankRule(rules: GuidelineRule[]): GuidelineRule {
  return {
    id: nextCustomRuleId(rules),
    domain: "intune_setup",
    phase: "intune_configuration",
    title: "",
    requirement: "",
    control_type: "manual",
    severity: "medium",
    weight_within_domain: DEFAULT_SCORING_CONFIG.severityWeights.medium,
    evidence_sources: [],
    applicability: ["Win32"],
    remediation: "",
  };
}

function reconcileWorkflows(apps: AuditApp[], current: QcWorkflowStore): QcWorkflowStore {
  let changed = false;
  const next: QcWorkflowStore = { ...current };
  for (const app of apps) {
    const existing = next[app.id] ?? buildDefaultWorkflow(app);
    const openRules = app.rules.filter(isOpenRule);
    const findings = { ...existing.findings };
    for (const rule of openRules) {
      if (!findings[rule.id]) {
        findings[rule.id] = buildDefaultFindingWorkflow(rule.id, app);
        changed = true;
      }
    }
    if (!next[app.id] || Object.keys(findings).length !== Object.keys(existing.findings).length) {
      next[app.id] = {
        ...existing,
        findings,
      };
      changed = true;
    }
  }
  return changed ? next : current;
}

function buildDefaultWorkflow(app: AuditApp): QcAppWorkflow {
  const now = new Date().toISOString();
  const baseDate = safeIsoDate(app.lastModified) || now;
  const findings = Object.fromEntries(
    app.rules.filter(isOpenRule).map((rule) => [rule.id, buildDefaultFindingWorkflow(rule.id, app)]),
  );

  return {
    appId: app.id,
    gateDecision: "pending",
    gateComment: "",
    internalSince: baseDate,
    findings,
    history: [
      timelineEntry("Intune snapshot", `${app.name} - ${app.score}%`, baseDate),
    ],
  };
}

function buildDefaultFindingWorkflow(ruleId: string, app: AuditApp): QcFindingWorkflow {
  const updatedAt = safeIsoDate(app.lastModified) || new Date().toISOString();
  return {
    ruleId,
    status: "new",
    assignee: "",
    comment: "",
    updatedAt,
    history: [
      timelineEntry("Finding created", ruleId, updatedAt),
    ],
  };
}

function timelineEntry(action: string, detail: string, at = new Date().toISOString()): QcTimelineEntry {
  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    at,
    actor: "SoApp QC",
    action,
    detail,
  };
}

function safeIsoDate(value: string) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function gateDecisionLabel(language: Language, decision: QcGateDecision) {
  const labels: Record<Language, Record<QcGateDecision, string>> = {
    fr: {
      pending: "En attente de décision",
      accepted: "Accepté",
      rejected: "Rejeté et retourné au fournisseur",
    },
    en: {
      pending: "Pending decision",
      accepted: "Accepted",
      rejected: "Rejected and returned to supplier",
    },
  };
  return labels[language][decision];
}

function findingStatusLabel(language: Language, status: QcFindingStatus) {
  const labels: Record<Language, Record<QcFindingStatus, string>> = {
    fr: {
      new: "Nouveau",
      assigned_supplier: "Assigné au fournisseur",
      corrected: "Corrigé",
    },
    en: {
      new: "New",
      assigned_supplier: "Assigned to supplier",
      corrected: "Corrected",
    },
  };
  return labels[language][status];
}

function slaLabel(language: Language, status: SlaStatus) {
  const labels: Record<Language, Record<SlaStatus, string>> = {
    fr: {
      within: "Dans le SLA",
      at_risk: "À risque",
      breached: "SLA dépassé",
    },
    en: {
      within: "Within SLA",
      at_risk: "At risk",
      breached: "Breached",
    },
  };
  return labels[language][status];
}

function findingWorkflowDetail(language: Language, patch: Partial<Pick<QcFindingWorkflow, "status" | "assignee" | "comment">>) {
  return [
    patch.status ? findingStatusLabel(language, patch.status) : "",
    patch.assignee ? `${t(language, "assignedTo")}: ${patch.assignee}` : "",
    patch.comment ? `${t(language, "comment")}: ${patch.comment}` : "",
  ].filter(Boolean).join(" - ") || t(language, "workflowUpdated");
}

export default function App() {
  const [language, setLanguageState] = useState<Language>(() => loadStoredLanguage());
  const [scoringConfig, setScoringConfig] = useState<ScoringConfig>(DEFAULT_SCORING_CONFIG);
  const [customRules, setCustomRules] = useState<GuidelineRule[] | null>(null);
  const [model, setModel] = useState<AuditModel | null>(null);
  const [workflows, setWorkflows] = useState<QcWorkflowStore>({});
  const [dataReady, setDataReady] = useState(false);
  const [activeView, setActiveView] = useState<ViewKey>("overview");
  const [selectedApp, setSelectedApp] = useState<AuditApp | null>(null);
  const [scoringOpen, setScoringOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [query, setQuery] = useState("");

  const setLanguage = (nextLanguage: Language) => {
    storeLanguage(nextLanguage);
    setLanguageState(nextLanguage);
  };

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      dataClient.scoring.load(),
      dataClient.rules.loadCatalog(),
      dataClient.findings.loadWorkflows(),
    ]).then(([scoring, rules, storedWorkflows]) => {
      if (cancelled) return;
      setScoringConfig(scoring ? normalizeScoringConfig(scoring) : DEFAULT_SCORING_CONFIG);
      setCustomRules(rules);
      setWorkflows(storedWorkflows);
      setDataReady(true);
    }).catch((error) => {
      console.error(error);
      if (!cancelled) setDataReady(true);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!dataReady) return;
    loadAuditModel(scoringConfig, language, customRules ?? undefined).then(setModel).catch((error) => {
      console.error(error);
      setModel(null);
    });
  }, [customRules, dataReady, scoringConfig, language]);

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  useEffect(() => {
    if (!dataReady) return;
    void dataClient.findings.saveWorkflows(workflows);
  }, [dataReady, workflows]);

  useEffect(() => {
    if (!model) return;
    setWorkflows((current) => reconcileWorkflows(model.apps, current));
  }, [model]);

  useEffect(() => {
    setSelectedApp((current) => {
      if (!current || !model) return current;
      return model.apps.find((app) => app.id === current.id) ?? null;
    });
  }, [model]);

  const changeView = (view: ViewKey) => {
    setActiveView(view);
    setMobileNavOpen(false);
  };

  const updateAppWorkflow = (app: AuditApp, updater: (workflow: QcAppWorkflow) => QcAppWorkflow) => {
    setWorkflows((current) => {
      const currentWorkflow = current[app.id] ?? buildDefaultWorkflow(app);
      return {
        ...current,
        [app.id]: updater(currentWorkflow),
      };
    });
  };

  const updateGateDecision = (app: AuditApp, decision: QcGateDecision) => {
    updateAppWorkflow(app, (workflow) => {
      const detail = gateDecisionLabel(language, decision);
      return {
        ...workflow,
        gateDecision: decision,
        gateUpdatedAt: new Date().toISOString(),
        history: [
          timelineEntry("QC gate", detail),
          ...workflow.history,
        ],
      };
    });
  };

  const updateFindingWorkflow = (app: AuditApp, ruleId: string, patch: Partial<Pick<QcFindingWorkflow, "status" | "assignee" | "comment">>) => {
    updateAppWorkflow(app, (workflow) => {
      const currentFinding = workflow.findings[ruleId] ?? buildDefaultFindingWorkflow(ruleId, app);
      const nextFinding = {
        ...currentFinding,
        ...patch,
        updatedAt: new Date().toISOString(),
        history: [
          timelineEntry("Work queue", findingWorkflowDetail(language, patch)),
          ...currentFinding.history,
        ],
      };
      return {
        ...workflow,
        supplierSince: patch.status === "assigned_supplier" ? nextFinding.updatedAt : workflow.supplierSince,
        internalSince: patch.status === "corrected" ? nextFinding.updatedAt : workflow.internalSince,
        findings: {
          ...workflow.findings,
          [ruleId]: nextFinding,
        },
        history: [
          timelineEntry("Work queue", `${ruleId} - ${findingWorkflowDetail(language, patch)}`),
          ...workflow.history,
        ],
      };
    });
  };

  const filteredApps = useMemo(() => {
    if (!model) return [];
    const needle = query.trim().toLowerCase();
    if (!needle) return model.apps;
    return model.apps.filter((app) =>
      [app.name, app.publisher, app.owner, app.type, statusLabel(app.status, language)].some((value) =>
        value.toLowerCase().includes(needle),
      ),
    );
  }, [language, model, query]);

  const navCounts = useMemo(() => {
    const counts: Partial<Record<ViewKey, number>> = {};
    if (!model) return counts;
    counts.packages = model.apps.length;
    counts.rules = model.rules.length;
    counts.findings = model.stats.openFindings;
    counts.qcQueue = model.apps.reduce((sum, app) => {
      const workflow = workflows[app.id];
      return sum + app.rules.filter((rule) => isOpenRule(rule) && isActionableFinding(workflow?.findings[rule.id])).length;
    }, 0);
    return counts;
  }, [model, workflows]);

  const saveRuleCatalog = (rules: GuidelineRule[]) => {
    void dataClient.rules.saveCatalog(rules);
    setCustomRules(rules);
  };

  const handleSaveRule = (rule: GuidelineRule) => {
    if (!model) return;
    const exists = model.rules.some((currentRule) => currentRule.id === rule.id);
    const nextRules = exists
      ? model.rules.map((currentRule) => (currentRule.id === rule.id ? rule : currentRule))
      : [...model.rules, rule];
    saveRuleCatalog(nextRules);
  };

  const handleDeleteRule = (ruleId: string) => {
    if (!model) return;
    saveRuleCatalog(model.rules.filter((rule) => rule.id !== ruleId));
    setScoringConfig((current) => {
      const nextOverrides = { ...current.ruleOverrides };
      delete nextOverrides[ruleId];
      const normalized = normalizeScoringConfig({ ...current, ruleOverrides: nextOverrides });
      void dataClient.scoring.save(normalized);
      return normalized;
    });
  };

  if (!dataReady || !model) {
    return (
      <main className="loading-screen">
        <Loader2 className="spin" size={28} />
        <span>{t(language, "loading")}</span>
      </main>
    );
  }

  return (
    <LocaleContext.Provider value={{ language, setLanguage }}>
      <div className="app-shell">
        <Sidebar
          activeView={activeView}
          counts={navCounts}
          isOpen={mobileNavOpen}
          perimeterLabel={model.metadata.perimeterLabel}
          onChange={changeView}
        />
        {mobileNavOpen && <button className="mobile-sidebar-scrim" type="button" aria-label={t(language, "closeMenu")} onClick={() => setMobileNavOpen(false)} />}

        <main className="main">
          <header className="topbar">
            <div className="topbar-title">
              <button className="mobile-menu-button" type="button" aria-label={t(language, "menu")} onClick={() => setMobileNavOpen(true)}>
                <Menu size={22} />
              </button>
              <h1>{t(language, "appTitle")}</h1>
            </div>
            <div className="topbar-actions">
              <LanguageSwitch />
              <label className="search">
                <Search size={18} />
                <input
                  type="search"
                  placeholder={t(language, "searchPlaceholder")}
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                />
              </label>
            </div>
          </header>

          <section className="content">
            {activeView === "overview" && (
              <Dashboard
                model={model}
                apps={filteredApps}
                workflows={workflows}
                onSelectApp={setSelectedApp}
                onViewAllInventory={() => changeView("packages")}
                onOpenQueue={() => changeView("qcQueue")}
              />
            )}
            {activeView === "packages" && (
              <InventoryView apps={filteredApps} onSelectApp={setSelectedApp} />
            )}
            {activeView === "qcQueue" && (
              <QcQueueView apps={filteredApps} workflows={workflows} onSelectApp={setSelectedApp} />
            )}
            {activeView === "findings" && (
              <FindingsView apps={filteredApps} workflows={workflows} onSelectApp={setSelectedApp} />
            )}
            {activeView === "rules" && (
              <RulesView
                model={model}
                onConfigureScoring={() => setScoringOpen(true)}
                onDeleteRule={handleDeleteRule}
                onSaveRule={handleSaveRule}
                onSelectApp={setSelectedApp}
              />
            )}
            {activeView === "assignments" && (
              <AssignmentsView apps={filteredApps} onSelectApp={setSelectedApp} />
            )}
            {activeView === "supplierPerformance" && (
              <SupplierPerformanceView apps={filteredApps} workflows={workflows} />
            )}
          </section>
        </main>

        {selectedApp && (
          <AppDrawer
            app={selectedApp}
            workflow={workflows[selectedApp.id] ?? buildDefaultWorkflow(selectedApp)}
            onClose={() => setSelectedApp(null)}
            onUpdateFinding={updateFindingWorkflow}
            onUpdateGate={updateGateDecision}
          />
        )}
        {scoringOpen && (
          <ScoringPanel
            config={scoringConfig}
            model={model}
            onClose={() => setScoringOpen(false)}
            onSave={(nextConfig) => {
              const normalized = normalizeScoringConfig(nextConfig);
              void dataClient.scoring.save(normalized);
              setScoringConfig(normalized);
              setScoringOpen(false);
            }}
          />
        )}
      </div>
    </LocaleContext.Provider>
  );
}

function LanguageSwitch() {
  const { language, setLanguage } = useLocale();

  return (
    <div className="language-switch" role="group" aria-label={t(language, "language")}>
      {LANGUAGES.map((option) => (
        <button
          aria-label={option.label}
          aria-pressed={language === option.code}
          className={language === option.code ? "language-option active" : "language-option"}
          key={option.code}
          onClick={() => setLanguage(option.code)}
          title={option.label}
          type="button"
        >
          <span className={`flag-icon flag-${option.code}`} aria-hidden="true" />
          <span>{option.shortLabel}</span>
        </button>
      ))}
    </div>
  );
}

function Sidebar({
  activeView,
  counts,
  isOpen,
  perimeterLabel,
  onChange,
}: {
  activeView: ViewKey;
  counts: Partial<Record<ViewKey, number>>;
  isOpen: boolean;
  perimeterLabel: string;
  onChange: (view: ViewKey) => void;
}) {
  const { language } = useLocale();

  return (
    <aside className={isOpen ? "sidebar open" : "sidebar"}>
      <div className="brand">
        <IntuneLogo />
        <span>SoApp <span>QC</span></span>
      </div>

      <nav>
        {NAV_SECTIONS.map((section) => (
          <div className="nav-section" key={section.labelKey}>
            <p className="nav-heading">{t(language, section.labelKey)}</p>
            {section.items.map((view) => {
              const Icon = view.icon;
              const count = counts[view.key];
              return (
                <button
                  className={activeView === view.key ? "nav-item active" : "nav-item"}
                  type="button"
                  key={view.key}
                  onClick={() => onChange(view.key)}
                >
                  <Icon size={20} />
                  <span>{t(language, view.labelKey)}</span>
                  {typeof count === "number" && <em className="nav-count">{count}</em>}
                </button>
              );
            })}
          </div>
        ))}

        <div className="source-pill">
          <FileText size={18} />
          <span>{t(language, "perimeter")} : {perimeterLabel}</span>
        </div>
      </nav>

      <button className="nav-item settings disabled-nav" type="button" disabled title={t(language, "comingSoon")}>
        <Settings size={20} />
        <span>{t(language, "settings")}</span>
        <em>{t(language, "comingSoon")}</em>
      </button>
    </aside>
  );
}

function IntuneLogo() {
  return (
    <svg className="intune-logo" viewBox="0 0 44 44" aria-hidden="true">
      <rect className="intune-logo-bg" x="2" y="2" width="40" height="40" rx="10" />
      <rect className="intune-logo-bar primary" x="11" y="10" width="5" height="24" rx="2.5" />
      <rect className="intune-logo-bar secondary" x="19" y="7" width="5" height="30" rx="2.5" />
      <rect className="intune-logo-bar tertiary" x="27" y="12" width="5" height="20" rx="2.5" />
      <path className="intune-logo-line" d="M12 28h20" />
    </svg>
  );
}

function Dashboard({
  model,
  apps,
  workflows,
  onSelectApp,
  onViewAllInventory,
  onOpenQueue,
}: {
  model: AuditModel;
  apps: AuditApp[];
  workflows: QcWorkflowStore;
  onSelectApp: (app: AuditApp) => void;
  onViewAllInventory: () => void;
  onOpenQueue: () => void;
}) {
  const { language } = useLocale();
  const metrics = contractMetrics(model.apps, workflows);
  const attention = attentionPackages(model.apps, workflows, 5);
  const maxSeverityCount = Math.max(1, ...model.backlogBySeverity.map((entry) => entry.value));
  const maxHotspotCount = Math.max(1, ...model.controlHotspots.map((entry) => entry.value));
  const maxTopViolationCount = Math.max(1, ...model.topViolations.map((entry) => entry.count));
  const statusRows = model.statusDistribution.map((entry) => ({
    id: entry.status,
    label: entry.name,
    value: String(entry.value),
    detail: unitLabel(language, entry.value, "app", "apps", "app", "apps"),
    percent: (entry.value / Math.max(1, model.stats.appCount)) * 100,
    color: STATUS_COLORS[entry.status],
  }));
  const severityRows = model.backlogBySeverity.map((entry) => ({
    id: entry.severity,
    label: entry.name,
    value: String(entry.value),
    detail: unitLabel(language, entry.value, "écart", "écarts", "finding", "findings"),
    percent: (entry.value / maxSeverityCount) * 100,
    color: SEVERITY_COLORS[entry.severity],
  }));
  const hotspotRows = model.controlHotspots.map((entry) => ({
    id: entry.id,
    label: entry.label,
    value: formatCount(language, entry.value, "écart", "écarts", "finding", "findings"),
    percent: (entry.value / maxHotspotCount) * 100,
    color: "#4f46e5",
  }));
  const topRuleRows = model.topViolations.map((entry) => ({
    id: entry.id,
    label: entry.id,
    value: String(entry.count),
    detail: entry.title,
    percent: (entry.count / maxTopViolationCount) * 100,
    color: "#4f46e5",
  }));

  return (
    <>
      <section className="audit-banner dashboard-banner">
        <div className="banner-icon">
          <ShieldCheck size={26} />
        </div>
        <div>
          <h2>{t(language, "auditTitle")}</h2>
          <div className="banner-meta">
            <span><Calendar size={15} /> {t(language, "lastAudit")} : {formatDate(model.metadata.extractedAt, language)}</span>
            <span><Database size={15} /> {t(language, "source")} : {model.metadata.sourceLabel}</span>
            <span><Target size={15} /> {t(language, "perimeter")} : {model.metadata.perimeterLabel}</span>
          </div>
        </div>
        <ComingSoonButton icon={<Download size={18} />} label={t(language, "exportBacklog")} />
      </section>

      <section className="dashboard-stage">
        <StageHeading index="01" title={t(language, "healthStage")} subtitle={t(language, "healthStageHelp")} />
        <section className="northstar-grid">
          <NorthStarCard
            detail={`${metrics.packageCount} ${t(language, "packages").toLowerCase()}`}
            icon={<ShieldCheck size={18} />}
            subtitle={t(language, "weightedScore")}
            title={t(language, "qualityKpi")}
            tone="brand"
            tooltip={t(language, "weightedScoreTooltip")}
            value={`${model.stats.globalScore}%`}
          />
          <NorthStarCard
            detail={`${metrics.withinSla}/${metrics.openFindings} ${t(language, "openFindingsShort").toLowerCase()}`}
            icon={<Timer size={18} />}
            subtitle={t(language, "slaHelp")}
            title={t(language, "slaPercent")}
            tone="green"
            value={`${metrics.slaPercent}%`}
          />
          <NorthStarCard
            detail={t(language, "blockersHelp")}
            icon={<AlertTriangle size={18} />}
            subtitle={t(language, "urgentRemediation")}
            title={t(language, "openBlockers")}
            tone="red"
            value={metrics.openBlockers.toString()}
          />
          <NorthStarCard
            detail={`${metrics.firstTimeRightCount}/${metrics.packageCount}`}
            featured
            icon={<Target size={18} />}
            subtitle={t(language, "ftrHelp")}
            title={t(language, "firstTimeRight")}
            tone="green"
            value={`${metrics.firstTimeRightPercent}%`}
          />
        </section>
      </section>

      <section className="dashboard-stage">
        <StageHeading
          index="02"
          title={t(language, "attentionStage")}
          subtitle={t(language, "attentionStageHelp")}
          actionLabel={t(language, "viewQcQueue")}
          onAction={onOpenQueue}
        />
        {attention.length === 0 ? (
          <article className="empty-panel">
            <CheckCircle2 size={22} />
            <strong>{t(language, "attentionEmpty")}</strong>
          </article>
        ) : (
          <div className="attention-list">
            {attention.map((item) => (
              <button className="attention-card" key={item.app.id} type="button" onClick={() => onSelectApp(item.app)}>
                <span className={`attention-reason ${item.reason}`}>{t(language, ATTENTION_LABEL[item.reason])}</span>
                <strong>{item.app.name}</strong>
                <span>{item.app.owner} · {item.app.score}%</span>
                <em>{formatCount(language, item.openFindings, "écart ouvert", "écarts ouverts", "open finding", "open findings")}</em>
                <SlaPill status={item.slaStatus} />
              </button>
            ))}
          </div>
        )}
      </section>

      <section className="dashboard-stage">
        <StageHeading index="03" title={t(language, "trendsStage")} subtitle={t(language, "trendsStageHelp")} />
        <section className="dashboard-bento">
        <article className="bento-card activity-summary-card">
          <div className="bento-heading">
            <div>
              <h3>{t(language, "sevenDayActivity")}</h3>
              <p>{t(language, "snapshotWindow")}</p>
            </div>
          </div>
          <div className="activity-mini-list">
            <MiniMetric icon={<PackagePlus size={20} />} label={t(language, "newPackages")} tone="brand" value={`+${model.stats.createdThisWeek}`} />
            <MiniMetric icon={<RefreshCw size={20} />} label={t(language, "changedPackages")} tone="amber" value={`+${model.stats.updatedThisWeek}`} />
            <MiniMetric
              icon={<Wrench size={20} />}
              label={t(language, "correctedAnomalies")}
              tone="green"
              value={model.stats.correctedThisWeek === null ? "-" : `+${model.stats.correctedThisWeek}`}
            />
          </div>
        </article>

        <article className="bento-card packaging-trend-card">
          <div className="bento-heading">
            <div>
              <h3>{t(language, "weeklyPackagingActivity")}</h3>
              <p>{t(language, "activityTrendSubtitle")}</p>
            </div>
            <SoonBadge label={t(language, "trend")} />
          </div>
          <div className="compact-chart">
            <ActivityTrend data={model.weeklyActivity} />
          </div>
        </article>

        <article className="bento-card severity-card">
          <div className="bento-heading">
            <div>
              <h3>{t(language, "backlogBySeverity")}</h3>
              <p>{formatCount(language, model.stats.openFindings, "écart", "écarts", "finding", "findings")}</p>
            </div>
            <SoonBadge label={t(language, "actionable")} />
          </div>
          <ProgressList rows={severityRows} />
        </article>

        <article className="bento-card status-card">
          <div className="bento-heading">
            <div>
              <h3>{t(language, "complianceStatus")}</h3>
              <p>{model.stats.appCount} {t(language, "auditedApps").toLowerCase()}</p>
            </div>
          </div>
          <ProgressList rows={statusRows} />
        </article>

        <article className="bento-card hotspot-card">
          <div className="bento-heading">
            <div>
              <h3>{t(language, "controlHotspots")}</h3>
              <p>{model.metadata.evaluatedControls} {t(language, "evaluatedControls")}</p>
            </div>
          </div>
          <ProgressList rows={hotspotRows} compact />
        </article>

        <article className="bento-card owner-card">
          <div className="bento-heading">
            <div>
              <h3>{t(language, "ownerAccountability")}</h3>
              <p>{t(language, "auditEvidenceBase")}</p>
            </div>
          </div>
          <div className="owner-leaderboard">
            {model.ownerBacklog.slice(0, 5).map((entry, index) => (
              <div className="owner-leaderboard-row" key={entry.owner}>
                <div className="leader-rank">{index + 1}</div>
                <div>
                  <strong className={["Non assigné", "Unassigned"].includes(entry.owner) ? "danger-text" : ""}>{entry.owner}</strong>
                  <span>{formatCount(language, entry.apps, "app impactée", "apps impactées", "impacted app", "impacted apps")}</span>
                </div>
                <span>{formatCount(language, entry.findings, "écart", "écarts", "finding", "findings")}</span>
              </div>
            ))}
          </div>
        </article>

        <article className="bento-card evidence-panel compact-evidence-card">
          <div className="bento-heading">
            <div>
              <h3>{t(language, "auditEvidenceBase")}</h3>
              <p>{t(language, "currentSnapshotOnly")}</p>
            </div>
          </div>
          <div className="evidence-facts compact">
            <div>
              <span>{t(language, "lastAudit")}</span>
              <strong>{formatDate(model.metadata.extractedAt, language)}</strong>
            </div>
            <div>
              <span>{t(language, "dailyExport")}</span>
              <strong>{model.metadata.sourceLabel}</strong>
            </div>
            <div>
              <span>{t(language, "perimeter")}</span>
              <strong>{model.metadata.perimeterLabel}</strong>
            </div>
          </div>
          <p>{t(language, "correctionHistoryNotice")}</p>
        </article>

        <article className="bento-card rule-breakdown-card">
          <div className="bento-heading">
            <div>
              <h3>{t(language, "topBrokenRules")}</h3>
              <p>{t(language, "viewFullBacklog")}</p>
            </div>
          </div>
          <ProgressList rows={topRuleRows} compact />
        </article>
      </section>

      <section className="dashboard-inventory">
        <InventoryTable apps={apps.slice(0, 8)} onSelectApp={onSelectApp} compact onViewAll={onViewAllInventory} />
      </section>
      </section>
    </>
  );
}

function NorthStarCard({
  children,
  detail,
  featured = false,
  icon,
  subtitle,
  title,
  tone,
  tooltip,
  value,
}: {
  children?: ReactNode;
  detail: string;
  featured?: boolean;
  icon: ReactNode;
  subtitle: string;
  title: string;
  tone: "brand" | "green" | "red" | "amber";
  tooltip?: string;
  value: string;
}) {
  return (
    <article className={`northstar-card tone-${tone}${featured ? " featured" : ""}`}>
      <div className="northstar-card-header">
        <span>{title}</span>
        <div className="northstar-icon">{icon}</div>
      </div>
      <strong>{value}</strong>
      <p>{subtitle}</p>
      {children ?? (
        <span className="northstar-detail" title={tooltip}>
          {detail}
          {tooltip && <Info size={13} />}
        </span>
      )}
    </article>
  );
}

function StageHeading({
  actionLabel,
  index,
  onAction,
  subtitle,
  title,
}: {
  actionLabel?: string;
  index: string;
  onAction?: () => void;
  subtitle: string;
  title: string;
}) {
  return (
    <div className="stage-heading">
      <div>
        <span>{index}</span>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
      {actionLabel && onAction && (
        <button className="inline-link-button" type="button" onClick={onAction}>
          {actionLabel}
          <ChevronRight size={15} />
        </button>
      )}
    </div>
  );
}

function MiniMetric({ icon, label, tone, value }: { icon: ReactNode; label: string; tone: "brand" | "amber" | "green"; value: string }) {
  return (
    <div className={`mini-metric tone-${tone}`}>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
      <div>
        {icon}
      </div>
    </div>
  );
}

function ActivityTrend({ data }: { data: AuditModel["weeklyActivity"] }) {
  const { language } = useLocale();
  const maxActivity = Math.max(1, ...data.map((entry) => entry.created + entry.updated));
  const totalCreated = data.reduce((sum, entry) => sum + entry.created, 0);
  const totalUpdated = data.reduce((sum, entry) => sum + entry.updated, 0);
  const hasActivity = totalCreated + totalUpdated > 0;
  const chartWidth = 860;
  const chartHeight = 170;
  const chartPadding = { bottom: 34, left: 34, right: 34, top: 16 };
  const plotHeight = chartHeight - chartPadding.top - chartPadding.bottom;
  const baseline = chartPadding.top + plotHeight;
  const step = data.length > 1 ? (chartWidth - chartPadding.left - chartPadding.right) / (data.length - 1) : 0;
  const barWidth = 8;
  const barGap = 4;
  const getX = (index: number) => chartPadding.left + index * step;
  const getBarHeight = (value: number) => Math.max(10, (value / maxActivity) * (plotHeight * 0.68));

  if (!hasActivity) {
    return (
      <div className="empty-activity-state">
        <PackagePlus size={28} />
        <strong>{t(language, "noPackagingActivity")}</strong>
        <span>{t(language, "noPackagingActivityDetail")}</span>
      </div>
    );
  }

  return (
    <div className="activity-trend">
      <div className="activity-chart-frame">
        <svg className="activity-chart" role="img" viewBox={`0 0 ${chartWidth} ${chartHeight}`}>
          <title>{t(language, "weeklyPackagingActivity")}</title>
          {[0, 0.33, 0.66, 1].map((ratio) => {
            const y = chartPadding.top + plotHeight * ratio;
            return <line className="activity-chart-gridline" key={ratio} x1={chartPadding.left} x2={chartWidth - chartPadding.right} y1={y} y2={y} />;
          })}
          {data.map((entry, index) => {
            const x = getX(index);
            const hasCreated = entry.created > 0;
            const hasUpdated = entry.updated > 0;
            const visibleBars = [hasCreated, hasUpdated].filter(Boolean).length;
            const groupWidth = visibleBars > 1 ? barWidth * 2 + barGap : barWidth;
            const firstBarX = x - groupWidth / 2;
            const createdX = firstBarX;
            const updatedX = hasCreated ? firstBarX + barWidth + barGap : firstBarX;
            const createdHeight = hasCreated ? getBarHeight(entry.created) : 0;
            const updatedHeight = hasUpdated ? getBarHeight(entry.updated) : 0;

            return (
              <Fragment key={entry.week}>
                {!hasCreated && !hasUpdated && <line className="activity-chart-zero" x1={x - 14} x2={x + 14} y1={baseline} y2={baseline} />}
                {hasCreated && (
                  <rect
                    className="activity-chart-bar created"
                    height={createdHeight}
                    rx="4"
                    width={barWidth}
                    x={createdX}
                    y={baseline - createdHeight}
                  >
                    <title>{`${entry.week}: ${entry.created} ${t(language, "createdPackages")}`}</title>
                  </rect>
                )}
                {hasUpdated && (
                  <rect
                    className="activity-chart-bar updated"
                    height={updatedHeight}
                    rx="4"
                    width={barWidth}
                    x={updatedX}
                    y={baseline - updatedHeight}
                  >
                    <title>{`${entry.week}: ${entry.updated} ${t(language, "updatedPackages")}`}</title>
                  </rect>
                )}
                <text className="activity-chart-label" textAnchor="middle" x={x} y={chartHeight - 9}>
                  {entry.week}
                </text>
              </Fragment>
            );
          })}
        </svg>
      </div>
      <div className="sparkline-legend">
        <span className="created-dot">{totalCreated} {t(language, "createdPackages")}</span>
        <span className="updated-dot">{totalUpdated} {t(language, "updatedPackages")}</span>
      </div>
    </div>
  );
}

type ProgressRow = {
  id: string;
  label: string;
  value: string;
  detail?: string;
  percent: number;
  color: string;
};

function ProgressList({ compact = false, rows }: { compact?: boolean; rows: ProgressRow[] }) {
  return (
    <div className={compact ? "progress-list compact" : "progress-list"}>
      {rows.map((row) => (
        <div className="progress-row" key={row.id}>
          <div className="progress-row-label">
            <span>{row.label}</span>
            <strong>{row.value}{!compact && row.detail ? <em>{row.detail}</em> : null}</strong>
          </div>
          <div className="progress-track">
            <span style={{ background: row.color, width: `${Math.max(3, Math.min(100, row.percent))}%` }} />
          </div>
          {compact && row.detail && <p>{row.detail}</p>}
        </div>
      ))}
    </div>
  );
}

function QcQueueView({
  apps,
  workflows,
  onSelectApp,
}: {
  apps: AuditApp[];
  workflows: QcWorkflowStore;
  onSelectApp: (app: AuditApp) => void;
}) {
  const { language } = useLocale();
  const queue = apps.flatMap((app) => {
    const workflow = workflows[app.id] ?? buildDefaultWorkflow(app);
    return app.rules.filter(isOpenRule).flatMap((rule) => {
      const finding = workflow.findings[rule.id] ?? buildDefaultFindingWorkflow(rule.id, app);
      if (!isActionableFinding(finding)) return [];
      return [{ app, rule, finding, sla: slaForFinding(rule, finding) }];
    });
  }).sort((left, right) => {
    const slaDelta = slaSeverity(right.sla.status) - slaSeverity(left.sla.status);
    if (slaDelta) return slaDelta;
    return severityRank(left.rule.severity) - severityRank(right.rule.severity);
  });

  return (
    <section>
      <PageHeading
        title={t(language, "qcQueueTitle")}
        subtitle={`${queue.length} ${t(language, "qcQueueSubtitle")}`}
      />
      {queue.length === 0 ? (
        <article className="empty-panel">
          <CheckCircle2 size={22} />
          <strong>{t(language, "qcQueueEmpty")}</strong>
        </article>
      ) : (
        <article className="table-card">
          <div className="table-wrap qc-queue-wrap">
            <table className="qc-queue-table">
              <thead>
                <tr>
                  <th>{t(language, "application")}</th>
                  <th>{t(language, "rule")}</th>
                  <th>{t(language, "severity")}</th>
                  <th>{t(language, "workQueue")}</th>
                  <th>{t(language, "assignedTo")}</th>
                  <th>{t(language, "sla")}</th>
                </tr>
              </thead>
              <tbody>
                {queue.map(({ app, rule, finding, sla }) => (
                  <tr className="clickable-row" key={`${app.id}-${rule.id}`} onClick={() => onSelectApp(app)}>
                    <td>
                      <strong>{app.name}</strong>
                      <span className="cell-sub">{app.owner}</span>
                    </td>
                    <td>{rule.id}</td>
                    <td><SeverityPill severity={rule.severity} /></td>
                    <td><span className={`finding-workflow-pill ${finding.status}`}>{findingStatusLabel(language, finding.status)}</span></td>
                    <td>{finding.assignee || t(language, "notProvided")}</td>
                    <td><SlaPill status={sla.status} detail={`${sla.age}/${sla.limit}j`} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>
      )}
    </section>
  );
}

function SupplierPerformanceView({ apps, workflows }: { apps: AuditApp[]; workflows: QcWorkflowStore }) {
  const { language } = useLocale();
  const metrics = contractMetrics(apps, workflows);
  const rows = supplierPerformance(apps, workflows);

  return (
    <section>
      <PageHeading title={t(language, "supplierPerformanceTitle")} subtitle={t(language, "supplierPerformanceSubtitle")} />
      <section className="northstar-grid">
        <NorthStarCard
          detail={t(language, "reworkHelp")}
          icon={<RefreshCw size={18} />}
          subtitle={`${metrics.reworkCount}/${metrics.packageCount}`}
          title={t(language, "reworkRate")}
          tone="amber"
          value={`${metrics.reworkRate}%`}
        />
        <NorthStarCard
          detail={t(language, "ftrHelp")}
          featured
          icon={<Target size={18} />}
          subtitle={`${metrics.firstTimeRightCount}/${metrics.packageCount}`}
          title={t(language, "firstTimeRight")}
          tone="green"
          value={`${metrics.firstTimeRightPercent}%`}
        />
        <NorthStarCard
          detail={t(language, "avgDeliveryHelp")}
          icon={<Timer size={18} />}
          subtitle={metrics.averageDeliveryDays === null ? t(language, "noSupplierLoop") : t(language, "days")}
          title={t(language, "avgDelivery")}
          tone="brand"
          value={metrics.averageDeliveryDays === null ? "—" : `${metrics.averageDeliveryDays}j`}
        />
        <NorthStarCard
          detail={`${metrics.withinSla}/${metrics.openFindings || metrics.packageCount}`}
          icon={<ShieldCheck size={18} />}
          subtitle={t(language, "slaHelp")}
          title={t(language, "slaPercent")}
          tone="green"
          value={`${metrics.slaPercent}%`}
        />
      </section>
      <article className="table-card">
        <div className="table-title">
          <h3>{t(language, "bySupplier")}</h3>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t(language, "supplier")}</th>
                <th>{t(language, "packages")}</th>
                <th>{t(language, "firstTimeRight")}</th>
                <th>{t(language, "reworkRate")}</th>
                <th>{t(language, "slaPercent")}</th>
                <th>{t(language, "avgDelivery")}</th>
                <th>{t(language, "openBlockers")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.supplier}>
                  <td><strong>{row.supplier}</strong></td>
                  <td>{row.packages}</td>
                  <td>{row.firstTimeRightPercent}%</td>
                  <td>{row.reworkRate}%</td>
                  <td>{row.slaPercent}%</td>
                  <td>{row.averageDeliveryDays === null ? "—" : `${row.averageDeliveryDays}j`}</td>
                  <td>{row.openBlockers}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </article>
    </section>
  );
}

function slaSeverity(status: SlaStatus) {
  if (status === "breached") return 2;
  if (status === "at_risk") return 1;
  return 0;
}

function InventoryView({ apps, onSelectApp }: { apps: AuditApp[]; onSelectApp: (app: AuditApp) => void }) {
  const { language } = useLocale();

  return (
    <section>
      <PageHeading
        title={t(language, "qualityInventory")}
        subtitle={`${apps.length} ${t(language, "displayedApps")}`}
        action={t(language, "filterStatusOwner")}
      />
      <InventoryTable apps={apps} onSelectApp={onSelectApp} />
    </section>
  );
}

function InventoryTable({
  apps,
  onSelectApp,
  compact = false,
  onViewAll,
}: {
  apps: AuditApp[];
  onSelectApp: (app: AuditApp) => void;
  compact?: boolean;
  onViewAll?: () => void;
}) {
  const { language } = useLocale();
  const unassignedLabels = ["Non assigné", "Unassigned"];

  return (
    <article className="table-card">
      <div className="table-title">
        <h3>{t(language, "qualityInventory")}</h3>
        <ComingSoonButton className="small" icon={<SlidersHorizontal size={16} />} label={t(language, "filter")} />
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t(language, "application")}</th>
              <th>{t(language, "type")}</th>
              <th>{t(language, "owner")}</th>
              <th>{t(language, "score")}</th>
              <th>{t(language, "qualityStatus")}</th>
              <th>{t(language, "actions")}</th>
            </tr>
          </thead>
          <tbody>
            {apps.map((app) => (
              <tr key={app.id}>
                <td>
                  <div className="app-cell">
                    <div className="app-icon">{app.platform === "macOS" ? "mac" : "win"}</div>
                    <div>
                      <strong>{app.name}</strong>
                      <span>{app.version} - {app.publisher}</span>
                    </div>
                  </div>
                </td>
                <td><span className="type-pill">{app.type}</span></td>
                <td className={unassignedLabels.includes(app.owner) ? "danger-text" : ""}>{app.owner}</td>
                <td><strong className={scoreClass(app.score)}>{app.score}%</strong></td>
                <td><StatusPill status={app.status} /></td>
                <td>
                  <button className="icon-button" type="button" onClick={() => onSelectApp(app)} aria-label={`${t(language, "open")} ${app.name}`}>
                    <ChevronRight size={20} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {compact && apps.length === 8 && (
        <div className="table-footnote actionable-footnote">
          <span>{t(language, "limitedRows")}</span>
          {onViewAll && (
            <button className="inline-link-button" type="button" onClick={onViewAll}>
              {t(language, "viewAll")}
              <ChevronRight size={15} />
            </button>
          )}
        </div>
      )}
    </article>
  );
}

function FindingsView({ apps, workflows, onSelectApp }: { apps: AuditApp[]; workflows: QcWorkflowStore; onSelectApp: (app: AuditApp) => void }) {
  const { language } = useLocale();
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);
  const findings = apps.flatMap((app) =>
    app.rules
      .filter((rule) => ["non_compliant", "to_clarify", "non_verifiable"].includes(rule.status))
      .map((rule) => ({ app, rule })),
  );
  const groupedFindings = useMemo(() => {
    const groups = new Map<string, { rule: RuleResult; apps: { app: AuditApp; rule: RuleResult }[] }>();
    for (const finding of findings) {
      const current = groups.get(finding.rule.id) ?? { rule: finding.rule, apps: [] };
      current.apps.push(finding);
      groups.set(finding.rule.id, current);
    }
    return [...groups.values()]
      .map((group) => ({
        ...group,
        apps: group.apps.sort((left, right) => left.app.score - right.app.score),
      }))
      .sort((left, right) => {
        const severityDelta = severityRank(left.rule.severity) - severityRank(right.rule.severity);
        if (severityDelta) return severityDelta;
        return right.apps.length - left.apps.length;
      });
  }, [findings]);

  return (
    <section>
      <PageHeading
        title={t(language, "findingsBacklog")}
        subtitle={`${findings.length} ${t(language, "actionsToQualify")} · ${t(language, "groupedByRule")}`}
        action={t(language, "exportBacklog")}
      />
      <div className="finding-rule-groups">
        {groupedFindings.map((group) => {
          const isExpanded = expandedRuleId === group.rule.id;
          const statusCounts = group.apps.reduce(
            (counts, finding) => ({ ...counts, [finding.rule.status]: counts[finding.rule.status] + 1 }),
            { compliant: 0, exception: 0, non_compliant: 0, non_verifiable: 0, to_clarify: 0 } as Record<AuditStatus, number>,
          );

          return (
            <article className={isExpanded ? "finding-rule-group expanded" : "finding-rule-group"} key={group.rule.id}>
              <button
                aria-expanded={isExpanded}
                className="finding-rule-header"
                type="button"
                onClick={() => setExpandedRuleId(isExpanded ? null : group.rule.id)}
              >
                <div className="finding-rule-title">
                  <StatusIcon status={group.rule.status} />
                  <div>
                    <strong>{group.rule.id} - {findingTitle(group.rule, language)}</strong>
                    <span>{ruleCopy(language, group.rule).title}</span>
                  </div>
                </div>
                <div className="finding-rule-summary">
                  <SeverityPill severity={group.rule.severity} />
                  <span className="count-pill">
                    {formatCount(language, group.apps.length, "application concernée", "applications concernées", "affected application", "affected applications")}
                  </span>
                  <ChevronDown size={19} />
                </div>
              </button>

              <div className="finding-rule-status-strip">
                {statusCounts.non_compliant > 0 && <span className="status-dot-label bad">{statusCounts.non_compliant} {statusLabel("non_compliant", language)}</span>}
                {statusCounts.to_clarify > 0 && <span className="status-dot-label warn">{statusCounts.to_clarify} {statusLabel("to_clarify", language)}</span>}
                {statusCounts.non_verifiable > 0 && <span className="status-dot-label muted">{statusCounts.non_verifiable} {statusLabel("non_verifiable", language)}</span>}
              </div>

              {isExpanded && (
                <div className="finding-rule-apps">
                  <table>
                    <thead>
                      <tr>
                        <th>{t(language, "application")}</th>
                        <th>{t(language, "owner")}</th>
                        <th>{t(language, "score")}</th>
                        <th>{t(language, "qualityStatus")}</th>
                        <th>{t(language, "workQueue")}</th>
                        <th>{t(language, "sla")}</th>
                        <th>{t(language, "evidence")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {group.apps.map(({ app, rule }) => {
                        const workflow = workflows[app.id] ?? buildDefaultWorkflow(app);
                        const finding = workflow.findings[rule.id] ?? buildDefaultFindingWorkflow(rule.id, app);
                        const sla = slaForFinding(rule, finding);
                        return (
                          <tr key={`${group.rule.id}-${app.id}`} onClick={() => onSelectApp(app)}>
                            <td>
                              <div className="affected-app-cell">
                                <strong>{app.name}</strong>
                                <span>{app.version} - {app.publisher}</span>
                              </div>
                            </td>
                            <td>{app.owner}</td>
                            <td><strong className={scoreClass(app.score)}>{app.score}%</strong></td>
                            <td><StatusPill status={rule.status} /></td>
                            <td><span className={`finding-workflow-pill ${finding.status}`}>{findingStatusLabel(language, finding.status)}</span></td>
                            <td><SlaPill status={sla.status} detail={`${sla.age}/${sla.limit}j`} /></td>
                            <td className="affected-evidence">{rule.evidence}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </article>
          );
        })}
      </div>
    </section>
  );
}

function RulesView({
  model,
  onConfigureScoring,
  onDeleteRule,
  onSaveRule,
  onSelectApp,
}: {
  model: AuditModel;
  onConfigureScoring: () => void;
  onDeleteRule: (ruleId: string) => void;
  onSaveRule: (rule: GuidelineRule) => void;
  onSelectApp: (app: AuditApp) => void;
}) {
  const { language } = useLocale();
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);
  const [ruleEditor, setRuleEditor] = useState<{ mode: "create" | "edit"; rule: GuidelineRule } | null>(null);
  const [deleteCandidate, setDeleteCandidate] = useState<GuidelineRule | null>(null);
  const ruleStats = useMemo(() => {
    const map = new Map<string, { pass: number; fail: number; clarify: number; unknown: number }>();
    for (const app of model.apps) {
      for (const rule of app.rules) {
        const current = map.get(rule.id) ?? { pass: 0, fail: 0, clarify: 0, unknown: 0 };
        if (rule.status === "compliant" || rule.status === "exception") current.pass += 1;
        if (rule.status === "non_compliant") current.fail += 1;
        if (rule.status === "to_clarify") current.clarify += 1;
        if (rule.status === "non_verifiable") current.unknown += 1;
        map.set(rule.id, current);
      }
    }
    return map;
  }, [model.apps]);
  const ruleScoring = useMemo(() => {
    const map = new Map<string, RuleResult>();
    for (const app of model.apps) {
      for (const rule of app.rules) {
        if (!map.has(rule.id)) map.set(rule.id, rule);
      }
    }
    return map;
  }, [model.apps]);

  return (
    <section>
      <PageHeading
        title={t(language, "rulesCatalog")}
        subtitle={`${model.rules.length} ${t(language, "rulesFromGuidelines")}`}
        action={t(language, "configureScoring")}
        onAction={onConfigureScoring}
      >
        <button className="primary-button heading-action" type="button" onClick={() => setRuleEditor({ mode: "create", rule: createBlankRule(model.rules) })}>
          <Plus size={17} />
          {t(language, "addRule")}
        </button>
      </PageHeading>
      <article className="table-card">
        <div className="table-wrap rules-table-wrap">
          <table className="rules-table">
            <thead>
              <tr>
                <th>{t(language, "rule")}</th>
                <th>{t(language, "domain")}</th>
                <th>{t(language, "severity")}</th>
                <th>{t(language, "weight")}</th>
                <th>V0</th>
                <th>{t(language, "sample")}</th>
                <th>{t(language, "details")}</th>
              </tr>
            </thead>
            <tbody>
              {model.rules.map((rule) => {
                const stats = ruleStats.get(rule.id);
                const scoring = ruleScoring.get(rule.id);
                const isExpanded = expandedRuleId === rule.id;
                const copy = ruleCopy(language, rule);
                return (
                  <Fragment key={rule.id}>
                    <tr
                      className={isExpanded ? "rule-row expanded" : "rule-row"}
                      onClick={() => setExpandedRuleId(isExpanded ? null : rule.id)}
                    >
                      <td>
                        <strong>{rule.id}</strong>
                        <span className="muted-row">{copy.title}</span>
                      </td>
                      <td><span className="domain-pill">{formatDomain(rule.domain, language)}</span></td>
                      <td><SeverityPill severity={rule.severity} /></td>
                      <td>
                        <span className={scoring?.scoringEnabled === false ? "score-weight muted" : "score-weight"}>
                          {scoring ? `${scoring.scoreImpact} ${t(language, "points")}` : "-"}
                        </span>
                      </td>
                      <td>{stats ? <span className="type-pill green">{t(language, "activeControl")}</span> : <span className="type-pill">{t(language, "toIntegrate")}</span>}</td>
                      <td className="rule-stats">
                        {formatRuleStats(stats, language)}
                      </td>
                      <td>
                        <button
                          aria-expanded={isExpanded}
                          aria-label={`${t(language, "details")} ${rule.id}`}
                          className="row-expander"
                          type="button"
                        >
                          <ChevronDown size={18} />
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="rule-detail-row">
                        <td colSpan={7}>
                          <RuleDetailPanel
                            apps={model.apps}
                            onDeleteRule={() => setDeleteCandidate(rule)}
                            onEditRule={() => setRuleEditor({ mode: "edit", rule })}
                            onSelectApp={onSelectApp}
                            rule={rule}
                            scoring={scoring}
                            stats={stats}
                          />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </article>
      {ruleEditor && (
        <RuleEditorModal
          existingRuleIds={model.rules.map((rule) => rule.id)}
          initialRule={ruleEditor.rule}
          mode={ruleEditor.mode}
          onClose={() => setRuleEditor(null)}
          onSave={(rule) => {
            onSaveRule(rule);
            setExpandedRuleId(rule.id);
            setRuleEditor(null);
          }}
        />
      )}
      {deleteCandidate && (
        <RuleDeleteDialog
          rule={deleteCandidate}
          onCancel={() => setDeleteCandidate(null)}
          onConfirm={() => {
            onDeleteRule(deleteCandidate.id);
            setExpandedRuleId((current) => (current === deleteCandidate.id ? null : current));
            setDeleteCandidate(null);
          }}
        />
      )}
    </section>
  );
}

function RuleDetailPanel({
  apps,
  onDeleteRule,
  onEditRule,
  onSelectApp,
  rule,
  stats,
  scoring,
}: {
  apps: AuditApp[];
  onDeleteRule: () => void;
  onEditRule: () => void;
  onSelectApp: (app: AuditApp) => void;
  rule: GuidelineRule;
  stats?: { pass: number; fail: number; clarify: number; unknown: number };
  scoring?: RuleResult;
}) {
  const { language } = useLocale();
  const impactedPackages = apps
    .map((app) => ({ app, result: app.rules.find((appRule) => appRule.id === rule.id) }))
    .filter(({ result }) => result?.scoringEnabled && result.status !== "compliant" && result.status !== "exception")
    .sort((left, right) => left.app.score - right.app.score);

  return (
    <div className="rule-detail-panel">
      <div className="rule-management-actions">
        <button className="secondary-button small" type="button" onClick={onEditRule}>
          <Pencil size={15} />
          {t(language, "editRule")}
        </button>
        <button className="danger-button small" type="button" onClick={onDeleteRule}>
          <Trash2 size={15} />
          {t(language, "deleteRule")}
        </button>
      </div>

      <div className="rule-objective">
        <div className="detail-icon">
          <Info size={18} />
        </div>
        <div>
          <h4>{t(language, "ruleObjective")}</h4>
          <p>{ruleObjective(rule, language)}</p>
        </div>
      </div>

      <div className="rule-detail-grid">
        <div className="rule-detail-card remediation">
          <div className="rule-detail-title">
            <Wrench size={16} />
            <span>{t(language, "expectedRemediation")}</span>
          </div>
          <p>{ruleRemediation(rule, language)}</p>
        </div>

        <div className="rule-detail-card source">
          <div className="rule-detail-title">
            <Code2 size={16} />
            <span>{t(language, "controlSource")}</span>
          </div>
          <div className="source-tags">
            {rule.evidence_sources.map((source) => (
              <span key={source}>{formatEvidenceSource(source, language)}</span>
            ))}
          </div>
        </div>
      </div>

      <div className="rule-detail-meta">
        <span>{t(language, "controlType")} : {formatControlType(rule.control_type, language)}</span>
        <span>{t(language, "phase")} : {formatDomain(rule.phase, language)}</span>
        <span>{t(language, "scoring")} : {scoring ? (scoring.scoringEnabled ? `${scoring.scoreImpact} ${t(language, "points")}` : t(language, "excluded")) : t(language, "toIntegrate")}</span>
        <span>
          {t(language, "sample")} : {formatRuleStats(stats, language, ", ")}
        </span>
      </div>

      <div className="rule-affected-card">
        <div className="rule-affected-title">
          <div>
            <h4>{t(language, "packagesInGap")}</h4>
            <p>{impactedPackages.length} {t(language, "packagesImpactedByRule")}</p>
          </div>
        </div>
        {impactedPackages.length ? (
          <div className="rule-affected-table-wrap">
            <table className="rule-affected-table">
              <thead>
                <tr>
                  <th>{t(language, "application")}</th>
                  <th>{t(language, "owner")}</th>
                  <th>{t(language, "score")}</th>
                  <th>{t(language, "qualityStatus")}</th>
                  <th>{t(language, "evidence")}</th>
                  <th>{t(language, "actions")}</th>
                </tr>
              </thead>
              <tbody>
                {impactedPackages.map(({ app, result }) => (
                  <tr key={`${rule.id}-${app.id}`}>
                    <td>
                      <div className="affected-app-cell">
                        <strong>{app.name}</strong>
                        <span>{app.version} - {app.publisher}</span>
                      </div>
                    </td>
                    <td>{app.owner}</td>
                    <td><strong className={scoreClass(app.score)}>{app.score}%</strong></td>
                    <td>{result && <StatusPill status={result.status} />}</td>
                    <td className="affected-evidence">{result?.evidence}</td>
                    <td>
                      <button className="secondary-button small" type="button" onClick={() => onSelectApp(app)}>
                        {t(language, "open")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-affected-packages">
            <CheckCircle2 size={20} />
            <span>{t(language, "noPackageInGap")}</span>
          </div>
        )}
      </div>
    </div>
  );
}

type RuleFormState = {
  id: string;
  domain: string;
  phase: string;
  title: string;
  requirement: string;
  control_type: string;
  severity: Severity;
  weight_within_domain: string;
  evidence_sources: string;
  applicability: string;
  remediation: string;
};

function normalizeRuleId(value: string) {
  return value.trim().toUpperCase().replace(/\s+/g, "-");
}

function toRuleFormState(rule: GuidelineRule): RuleFormState {
  return {
    id: rule.id,
    domain: rule.domain,
    phase: rule.phase,
    title: rule.title,
    requirement: rule.requirement,
    control_type: rule.control_type,
    severity: rule.severity,
    weight_within_domain: String(rule.weight_within_domain),
    evidence_sources: rule.evidence_sources.join("\n"),
    applicability: rule.applicability.join("\n"),
    remediation: rule.remediation,
  };
}

function parseTextList(value: string) {
  return value
    .split(/\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formStateToRule(form: RuleFormState, forcedId?: string): GuidelineRule {
  const parsedWeight = Number(form.weight_within_domain);
  return {
    id: forcedId ?? normalizeRuleId(form.id),
    domain: form.domain.trim() || "intune_setup",
    phase: form.phase.trim() || "intune_configuration",
    title: form.title.trim(),
    requirement: form.requirement.trim(),
    control_type: form.control_type.trim() || "manual",
    severity: form.severity,
    weight_within_domain: Number.isFinite(parsedWeight) ? Math.max(0, parsedWeight) : DEFAULT_SCORING_CONFIG.severityWeights[form.severity],
    evidence_sources: parseTextList(form.evidence_sources),
    applicability: parseTextList(form.applicability),
    remediation: form.remediation.trim(),
  };
}

function RuleEditorModal({
  existingRuleIds,
  initialRule,
  mode,
  onClose,
  onSave,
}: {
  existingRuleIds: string[];
  initialRule: GuidelineRule;
  mode: "create" | "edit";
  onClose: () => void;
  onSave: (rule: GuidelineRule) => void;
}) {
  const { language } = useLocale();
  const [draft, setDraft] = useState<RuleFormState>(() => toRuleFormState(initialRule));
  const dialogRef = useDialogFocus<HTMLElement>();
  const normalizedId = normalizeRuleId(draft.id);
  const idExists = mode === "create" && existingRuleIds.includes(normalizedId);
  const canSave = Boolean(normalizedId && draft.title.trim() && draft.requirement.trim() && draft.remediation.trim() && !idExists);

  useDismissOnEscape(onClose);

  const updateDraft = <K extends keyof RuleFormState>(key: K, value: RuleFormState[K]) => {
    setDraft((current) => ({ ...current, [key]: value }));
  };

  const handleSave = () => {
    if (!canSave) return;
    onSave(formStateToRule(draft, mode === "edit" ? initialRule.id : undefined));
  };

  return (
    <div
      className="rule-editor-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <aside className="rule-editor-panel" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="rule-editor-title" tabIndex={-1}>
        <header className="rule-editor-header">
          <div>
            <h2 id="rule-editor-title">{mode === "create" ? t(language, "createRule") : t(language, "editRule")}</h2>
            <p>{t(language, "ruleEditorSubtitle")}</p>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label={t(language, "close")}>
            <X size={22} />
          </button>
        </header>

        <div className="rule-editor-content">
          <section className="rule-form-grid">
            <label className="rule-form-field">
              <span>{t(language, "ruleId")}</span>
              <input
                disabled={mode === "edit"}
                value={draft.id}
                onChange={(event) => updateDraft("id", normalizeRuleId(event.target.value))}
              />
              {idExists && <em>{t(language, "ruleIdAlreadyExists")}</em>}
            </label>

            <label className="rule-form-field">
              <span>{t(language, "ruleSeverity")}</span>
              <select value={draft.severity} onChange={(event) => updateDraft("severity", event.target.value as Severity)}>
                {RULE_SEVERITY_OPTIONS.map((severity) => (
                  <option key={severity} value={severity}>{severityLabel(language, severity)}</option>
                ))}
              </select>
            </label>

            <label className="rule-form-field">
              <span>{t(language, "domain")}</span>
              <select value={draft.domain} onChange={(event) => updateDraft("domain", event.target.value)}>
                {RULE_DOMAIN_OPTIONS.map((domain) => (
                  <option key={domain} value={domain}>{formatDomain(domain, language)}</option>
                ))}
              </select>
            </label>

            <label className="rule-form-field">
              <span>{t(language, "phase")}</span>
              <select value={draft.phase} onChange={(event) => updateDraft("phase", event.target.value)}>
                {RULE_PHASE_OPTIONS.map((phase) => (
                  <option key={phase} value={phase}>{formatDomain(phase, language)}</option>
                ))}
              </select>
            </label>

            <label className="rule-form-field">
              <span>{t(language, "controlType")}</span>
              <select value={draft.control_type} onChange={(event) => updateDraft("control_type", event.target.value)}>
                {RULE_CONTROL_TYPE_OPTIONS.map((controlType) => (
                  <option key={controlType} value={controlType}>{formatControlType(controlType, language)}</option>
                ))}
              </select>
            </label>

            <label className="rule-form-field">
              <span>{t(language, "defaultWeight")}</span>
              <input
                min={0}
                type="number"
                value={draft.weight_within_domain}
                onChange={(event) => updateDraft("weight_within_domain", event.target.value)}
              />
            </label>

            <label className="rule-form-field full">
              <span>{t(language, "ruleTitle")}</span>
              <input value={draft.title} onChange={(event) => updateDraft("title", event.target.value)} />
            </label>

            <label className="rule-form-field full">
              <span>{t(language, "ruleRequirement")}</span>
              <textarea rows={3} value={draft.requirement} onChange={(event) => updateDraft("requirement", event.target.value)} />
            </label>

            <label className="rule-form-field full">
              <span>{t(language, "ruleRemediationField")}</span>
              <textarea rows={3} value={draft.remediation} onChange={(event) => updateDraft("remediation", event.target.value)} />
            </label>

            <label className="rule-form-field">
              <span>{t(language, "evidenceSources")}</span>
              <textarea rows={5} value={draft.evidence_sources} onChange={(event) => updateDraft("evidence_sources", event.target.value)} />
            </label>

            <label className="rule-form-field">
              <span>{t(language, "applicability")}</span>
              <textarea rows={5} value={draft.applicability} onChange={(event) => updateDraft("applicability", event.target.value)} />
            </label>
          </section>
        </div>

        <footer className="rule-editor-footer">
          <button className="secondary-button" type="button" onClick={onClose}>{t(language, "cancel")}</button>
          <button className={canSave ? "primary-button" : "primary-button disabled"} type="button" disabled={!canSave} onClick={handleSave}>
            <CheckCircle2 size={18} />
            {t(language, "saveRule")}
          </button>
        </footer>
      </aside>
    </div>
  );
}

function RuleDeleteDialog({
  onCancel,
  onConfirm,
  rule,
}: {
  onCancel: () => void;
  onConfirm: () => void;
  rule: GuidelineRule;
}) {
  const { language } = useLocale();
  const dialogRef = useDialogFocus<HTMLElement>();

  useDismissOnEscape(onCancel);

  return (
    <div
      className="rule-editor-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <aside className="rule-delete-dialog" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="rule-delete-title" tabIndex={-1}>
        <header>
          <div className="delete-icon">
            <Trash2 size={20} />
          </div>
          <div>
            <h2 id="rule-delete-title">{t(language, "deleteRuleTitle")}</h2>
            <p>{t(language, "deleteRuleBody")}</p>
          </div>
        </header>
        <div className="delete-rule-summary">
          <strong>{rule.id}</strong>
          <span>{ruleCopy(language, rule).title}</span>
        </div>
        <footer>
          <button className="secondary-button" type="button" onClick={onCancel}>{t(language, "cancel")}</button>
          <button className="danger-button" type="button" onClick={onConfirm}>
            <Trash2 size={17} />
            {t(language, "confirmDelete")}
          </button>
        </footer>
      </aside>
    </div>
  );
}

function AssignmentsView({ apps, onSelectApp }: { apps: AuditApp[]; onSelectApp: (app: AuditApp) => void }) {
  const { language } = useLocale();
  const assignedApps = apps.filter((app) => app.assignments.length > 0);
  const assignmentCount = assignedApps.reduce((count, app) => count + app.assignments.length, 0);

  return (
    <section>
      <PageHeading title={t(language, "assignments")} subtitle={`${assignedApps.length} ${t(language, "apps")} · ${assignmentCount} ${t(language, "detectedTargets")}`} action={t(language, "analyzeAllUsersDevices")} />
      <article className="table-card">
        <div className="table-wrap assignments-overview-wrap">
          <table className="assignments-overview-table">
            <thead>
              <tr>
                <th>{t(language, "application")}</th>
                <th>{t(language, "deploymentTargets")}</th>
                <th>{t(language, "actions")}</th>
              </tr>
            </thead>
            <tbody>
              {assignedApps.map((app) => (
                <tr key={app.id}>
                  <td>
                    <div className="assignment-app-cell">
                      <strong>{app.name}</strong>
                      <span>{app.publisher || t(language, "notProvided")} · {app.version || t(language, "notProvidedFemale")}</span>
                      <em>{app.assignments.length} {app.assignments.length > 1 ? t(language, "targetsCount") : t(language, "targetCount")}</em>
                    </div>
                  </td>
                  <td>
                    <AssignmentTargetsTable assignments={app.assignments} />
                  </td>
                  <td>
                    <button className="assignment-open-button" type="button" onClick={() => onSelectApp(app)}>
                      {t(language, "open")}
                      <ChevronRight size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </article>
    </section>
  );
}

function AssignmentTargetsTable({ assignments }: { assignments: AuditApp["assignments"] }) {
  const { language } = useLocale();
  const [showAll, setShowAll] = useState(false);
  const visibleAssignments = showAll ? assignments : assignments.slice(0, 5);
  const hiddenCount = Math.max(0, assignments.length - visibleAssignments.length);

  return (
    <div>
      <div className="assignment-targets-table-wrap">
        <table className="assignment-targets-table">
          <thead>
            <tr>
              <th>{t(language, "target")}</th>
              <th>{t(language, "intent")}</th>
              <th>Mode</th>
              <th>{t(language, "notifications")}</th>
            </tr>
          </thead>
          <tbody>
            {visibleAssignments.map((assignment, index) => {
              const isBroadTarget = /all users|all devices/i.test(assignment.target);
              return (
                <tr className={isBroadTarget ? "broad-target" : ""} key={`${assignment.target}-${assignment.intent}-${index}`}>
                  <td>
                    <div className={assignment.targetResolved ? "assignment-target" : "assignment-target unresolved"}>
                      <strong>{assignment.target}</strong>
                      {isBroadTarget && <span>{t(language, "broadTarget")}</span>}
                      {!assignment.targetResolved && <span>{t(language, "unresolvedGroup")}</span>}
                    </div>
                  </td>
                  <td>
                    <span className={`assignment-intent ${assignmentIntentClass(assignment.intent)}`}>
                      {formatAssignmentIntent(assignment.intent, language)}
                    </span>
                  </td>
                  <td>
                    <span className={`assignment-mode ${assignment.mode}`}>
                      {assignment.mode === "excluded" ? t(language, "excludedAssignment") : t(language, "included")}
                    </span>
                  </td>
                  <td>{formatAssignmentNotification(assignment.notifications, language)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {assignments.length > 5 && (
        <button className="inline-link-button assignment-more-button" type="button" onClick={() => setShowAll((current) => !current)}>
          {showAll ? t(language, "showLess") : `${t(language, "showAllTargets")} (${hiddenCount})`}
          <ChevronDown size={15} />
        </button>
      )}
    </div>
  );
}

function useDismissOnEscape(onClose: () => void) {
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" || event.key === "Esc" || event.key === "Echap") onClose();
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);
}

function useDialogFocus<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    ref.current?.focus({ preventScroll: true });
    return () => previouslyFocused?.focus({ preventScroll: true });
  }, []);

  return ref;
}

function AppDrawer({
  app,
  workflow,
  onClose,
  onUpdateFinding,
  onUpdateGate,
}: {
  app: AuditApp;
  workflow: QcAppWorkflow;
  onClose: () => void;
  onUpdateFinding: (app: AuditApp, ruleId: string, patch: Partial<Pick<QcFindingWorkflow, "status" | "assignee" | "comment">>) => void;
  onUpdateGate: (app: AuditApp, decision: QcGateDecision) => void;
}) {
  const { language } = useLocale();
  const [activeTab, setActiveTab] = useState<"overview" | "qc" | "deployment" | "history" | "activity">("overview");
  const [showAllIssues, setShowAllIssues] = useState(false);
  const majorIssues = app.rules.filter((rule) => ["non_compliant", "to_clarify", "non_verifiable"].includes(rule.status));
  const visibleMajorIssues = showAllIssues ? majorIssues : majorIssues.slice(0, 5);
  const remediationRequired = app.status !== "compliant" && app.status !== "exception";
  const packageSla = workflowSla(app, workflow);
  const dialogRef = useDialogFocus<HTMLElement>();

  useDismissOnEscape(onClose);

  return (
    <div
      className="drawer-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <aside className="drawer" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="app-drawer-title" tabIndex={-1}>
        <header className="drawer-header">
          <div className="drawer-title" id="app-drawer-title">
            <FileText size={24} />
            <span>{t(language, "package360")}</span>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label={t(language, "close")}>
            <X size={22} />
          </button>
        </header>

        <div className="drawer-content">
          <section className="app-summary">
            <div>
              <h2>{app.name}</h2>
              <p>{app.publisher} - {app.version}</p>
              <div className="pill-row">
                <StatusPill status={app.status} />
                <span className="type-pill">{app.type}</span>
                <SlaPill status={packageSla.status} />
              </div>
            </div>
            <div className={scoreClass(app.score, "drawer-score")}>
              <strong>{app.score}%</strong>
              <span>{t(language, "qualityScore")}</span>
            </div>
          </section>

          <nav className="package-tabs" aria-label={t(language, "package360Tabs")}>
            {[
              ["overview", t(language, "overviewTab")],
              ["qc", t(language, "qcTab")],
              ["deployment", t(language, "deploymentTab")],
              ["history", t(language, "historyTab")],
              ["activity", t(language, "activityTab")],
            ].map(([key, label]) => (
              <button className={activeTab === key ? "active" : ""} key={key} type="button" onClick={() => setActiveTab(key as typeof activeTab)}>
                {label}
              </button>
            ))}
          </nav>

          {activeTab === "overview" && (
            <div className="package-tab-panel">
              <WorkflowGate app={app} workflow={workflow} onUpdateGate={onUpdateGate} />
              <LeadTimePanel app={app} workflow={workflow} />
              <section>
                <h3>{majorIssues.length ? t(language, "majorAnomalies") : t(language, "anomaliesAndRemediation")}</h3>
                {majorIssues.length ? (
                  <div className="issue-stack">
                    {visibleMajorIssues.map((rule) => (
                      <div className={`issue-card ${rule.status}`} key={rule.id}>
                        <span>{rule.id} - {findingTitle(rule, language)}</span>
                        <SeverityPill severity={rule.severity} />
                      </div>
                    ))}
                    {majorIssues.length > 5 && (
                      <button className="inline-link-button issue-more-button" type="button" onClick={() => setShowAllIssues((current) => !current)}>
                        {showAllIssues ? t(language, "showLess") : `${t(language, "viewAll")} (${majorIssues.length - visibleMajorIssues.length})`}
                        <ChevronDown size={15} />
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="success-box">
                    <CheckCircle2 size={22} />
                    {t(language, "noAnomaly")}
                  </div>
                )}
              </section>
            </div>
          )}

          {activeTab === "qc" && (
            <div className="package-tab-panel">
              <WorkQueuePanel app={app} workflow={workflow} onUpdateFinding={onUpdateFinding} />
              <section>
                <h3>{t(language, "ruleControl")}</h3>
                <div className="rule-checks">
                  {app.rules.map((rule) => (
                    <div className="rule-check" key={rule.id}>
                      <StatusIcon status={rule.status} />
                      <strong>{rule.id}</strong>
                      <span>{shortRuleTitle(rule, language)}</span>
                      <StatusPill status={rule.status} />
                      {rule.status === "non_verifiable" && <em>{rule.evidence}</em>}
                    </div>
                  ))}
                </div>
              </section>
            </div>
          )}

          {activeTab === "deployment" && (
            <div className="package-tab-panel">
              <section>
                <h3>{t(language, "deploymentsAssignments")}</h3>
                <AssignmentsEvidence assignments={app.assignments} />
              </section>
            </div>
          )}

          {activeTab === "history" && (
            <div className="package-tab-panel">
              <TimelinePanel workflow={workflow} />
            </div>
          )}

          {activeTab === "activity" && (
            <div className="package-tab-panel">
              <section>
                <h3>{t(language, "controlEvidence")}</h3>
                <Evidence label={t(language, "ownerLabel")} value={app.owner} />
                <Evidence label={t(language, "lastModified")} value={formatDate(app.lastModified, language)} />
                <DetectionRulesEvidence rules={app.detectionRules} />
                <Evidence label={t(language, "returnCodes")} value={app.returnCodes.join(", ") || t(language, "noReturnCode")} code />
              </section>
            </div>
          )}
        </div>

        <footer className="drawer-footer">
          <button className="secondary-button" type="button" onClick={onClose}>{t(language, "close")}</button>
          <button className="primary-button disabled" type="button" disabled title={remediationRequired ? t(language, "comingSoon") : undefined}>
            <Ticket size={18} />
            {remediationRequired ? t(language, "createRemediationTicket") : t(language, "ticketNotRequired")}
            {remediationRequired && <span className="coming-soon-inline">{t(language, "comingSoon")}</span>}
          </button>
        </footer>
      </aside>
    </div>
  );
}

function WorkflowGate({ app, workflow, onUpdateGate }: { app: AuditApp; workflow: QcAppWorkflow; onUpdateGate: (app: AuditApp, decision: QcGateDecision) => void }) {
  const { language } = useLocale();
  const decisions: QcGateDecision[] = ["accepted", "rejected"];

  return (
    <section className="workflow-card">
      <div className="workflow-card-title">
        <div>
          <h3>{t(language, "qcGate")}</h3>
          <p>{t(language, "qcGateSubtitle")}</p>
        </div>
        <span className={`gate-pill ${workflow.gateDecision}`}>{gateDecisionLabel(language, workflow.gateDecision)}</span>
      </div>
      <div className="gate-actions">
        {decisions.map((decision) => (
          <button className={workflow.gateDecision === decision ? "active" : ""} key={decision} type="button" onClick={() => onUpdateGate(app, decision)}>
            {gateDecisionLabel(language, decision)}
          </button>
        ))}
      </div>
      {workflow.gateUpdatedAt && <p className="workflow-meta">{t(language, "lastDecision")} : {formatDate(workflow.gateUpdatedAt, language)}</p>}
    </section>
  );
}

function LeadTimePanel({ app, workflow }: { app: AuditApp; workflow: QcAppWorkflow }) {
  const { language } = useLocale();
  const sla = workflowSla(app, workflow);

  return (
    <section className="leadtime-grid">
      <article>
        <span>{t(language, "slaStatus")}</span>
        <strong><SlaPill status={sla.status} /></strong>
        <p>{formatCount(language, sla.age, "jour ouvert", "jours ouverts", "day open", "days open")} / SLA {sla.limit}j</p>
      </article>
      <article>
        <span>{t(language, "supplierLeadTime")}</span>
        <strong>{ageInDays(workflow.supplierSince)}j</strong>
        <p>{t(language, "supplierLeadTimeHelp")}</p>
      </article>
      <article>
        <span>{t(language, "internalWaitingTime")}</span>
        <strong>{ageInDays(workflow.internalSince)}j</strong>
        <p>{t(language, "internalWaitingTimeHelp")}</p>
      </article>
    </section>
  );
}

function WorkQueuePanel({
  app,
  workflow,
  onUpdateFinding,
}: {
  app: AuditApp;
  workflow: QcAppWorkflow;
  onUpdateFinding: (app: AuditApp, ruleId: string, patch: Partial<Pick<QcFindingWorkflow, "status" | "assignee" | "comment">>) => void;
}) {
  const { language } = useLocale();
  const openRules = app.rules.filter(isOpenRule);

  return (
    <section>
      <h3>{t(language, "workQueue")}</h3>
      {openRules.length ? (
        <div className="work-queue-wrap">
          <table className="work-queue-table">
            <thead>
              <tr>
                <th>{t(language, "rule")}</th>
                <th>{t(language, "status")}</th>
                <th>{t(language, "assignedTo")}</th>
                <th>{t(language, "sla")}</th>
                <th>{t(language, "comment")}</th>
              </tr>
            </thead>
            <tbody>
              {openRules.map((rule) => {
                const finding = workflow.findings[rule.id] ?? buildDefaultFindingWorkflow(rule.id, app);
                const sla = slaForFinding(rule, finding);
                return (
                  <tr key={rule.id}>
                    <td>
                      <strong>{rule.id}</strong>
                      <span>{shortRuleTitle(rule, language)}</span>
                    </td>
                    <td>
                      <select value={finding.status} onChange={(event) => onUpdateFinding(app, rule.id, { status: event.target.value as QcFindingStatus })}>
                        {(["new", "assigned_supplier", "corrected"] as QcFindingStatus[]).map((status) => (
                          <option key={status} value={status}>{findingStatusLabel(language, status)}</option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <input
                        defaultValue={finding.assignee}
                        placeholder={t(language, "supplierOrOwner")}
                        onBlur={(event) => {
                          if (event.currentTarget.value !== finding.assignee) onUpdateFinding(app, rule.id, { assignee: event.currentTarget.value });
                        }}
                      />
                    </td>
                    <td><SlaPill status={sla.status} detail={`${sla.age}/${sla.limit}j`} /></td>
                    <td>
                      <input
                        defaultValue={finding.comment}
                        placeholder={t(language, "addComment")}
                        onBlur={(event) => {
                          if (event.currentTarget.value !== finding.comment) onUpdateFinding(app, rule.id, { comment: event.currentTarget.value });
                        }}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="success-box">
          <CheckCircle2 size={22} />
          {t(language, "noOpenFinding")}
        </div>
      )}
    </section>
  );
}

function TimelinePanel({ workflow }: { workflow: QcAppWorkflow }) {
  const { language } = useLocale();
  const entries = [
    ...workflow.history,
    ...Object.values(workflow.findings).flatMap((finding) => finding.history),
  ].sort((left, right) => new Date(right.at).getTime() - new Date(left.at).getTime());

  return (
    <section>
      <h3>{t(language, "historyTimeline")}</h3>
      <div className="timeline">
        {entries.map((entry) => (
          <article key={entry.id}>
            <span>{formatDate(entry.at, language)}</span>
            <strong>{entry.action}</strong>
            <p>{entry.detail}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

function SlaPill({ detail, status }: { detail?: string; status: SlaStatus }) {
  const { language } = useLocale();

  return (
    <span className={`sla-pill ${status}`}>
      {slaLabel(language, status)}
      {detail && <em>{detail}</em>}
    </span>
  );
}

function ScoringPanel({
  config,
  model,
  onClose,
  onSave,
}: {
  config: ScoringConfig;
  model: AuditModel;
  onClose: () => void;
  onSave: (config: ScoringConfig) => void;
}) {
  const { language } = useLocale();
  const [draft, setDraft] = useState<ScoringConfig>(() => normalizeScoringConfig(config));
  const dialogRef = useDialogFocus<HTMLElement>();
  const evaluatedRuleIds = useMemo(() => {
    const ids = new Set<string>();
    for (const app of model.apps) {
      for (const rule of app.rules) ids.add(rule.id);
    }
    return ids;
  }, [model.apps]);

  const enabledRules = model.rules.filter((rule) => draft.ruleOverrides[rule.id]?.enabled ?? true).length;
  const evaluatedEnabledRules = model.rules.filter((rule) => evaluatedRuleIds.has(rule.id) && (draft.ruleOverrides[rule.id]?.enabled ?? true)).length;

  const updateSeverityWeight = (severity: Severity, value: number) => {
    setDraft((current) => ({
      ...current,
      severityWeights: {
        ...current.severityWeights,
        [severity]: Math.max(0, value),
      },
    }));
  };

  const updateStatusCredit = (status: AuditStatus, value: number) => {
    setDraft((current) => ({
      ...current,
      statusCredits: {
        ...current.statusCredits,
        [status]: Math.min(1, Math.max(0, value / 100)),
      },
    }));
  };

  const updateRuleOverride = (rule: GuidelineRule, patch: Partial<ScoringConfig["ruleOverrides"][string]>) => {
    setDraft((current) => {
      const previous = current.ruleOverrides[rule.id] ?? {
        enabled: true,
        weight: current.severityWeights[rule.severity],
      };
      return {
        ...current,
        ruleOverrides: {
          ...current.ruleOverrides,
          [rule.id]: {
            ...previous,
            ...patch,
          },
        },
      };
    });
  };

  const ruleWeight = (rule: GuidelineRule) => draft.ruleOverrides[rule.id]?.weight ?? draft.severityWeights[rule.severity];
  const ruleEnabled = (rule: GuidelineRule) => draft.ruleOverrides[rule.id]?.enabled ?? true;

  useDismissOnEscape(onClose);

  return (
    <div
      className="scoring-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <aside className="scoring-panel" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="scoring-panel-title" tabIndex={-1}>
        <header className="scoring-header">
          <div>
            <h2 id="scoring-panel-title">{t(language, "scoringConfig")}</h2>
            <p>{enabledRules} {t(language, "scoringSubtitle")} {evaluatedEnabledRules} {t(language, "evaluatedV0")}</p>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label={t(language, "close")}>
            <X size={22} />
          </button>
        </header>

        <div className="scoring-content">
          <section className="scoring-grid">
            <article className="scoring-card">
              <h3>{t(language, "severityWeights")}</h3>
              {(["critical", "high", "medium", "low"] as Severity[]).map((severity) => (
                <label className="scoring-field" key={severity}>
                  <span><SeverityPill severity={severity} /></span>
                  <input
                    min={0}
                    type="number"
                    value={draft.severityWeights[severity]}
                    onChange={(event) => updateSeverityWeight(severity, Number(event.target.value))}
                  />
                </label>
              ))}
            </article>

            <article className="scoring-card">
              <h3>{t(language, "statusCredit")}</h3>
              {(["compliant", "exception", "to_clarify", "non_compliant"] as AuditStatus[]).map((status) => (
                <label className="scoring-field" key={status}>
                  <span>{statusLabel(status, language)}</span>
                  <input
                    min={0}
                    max={100}
                    type="number"
                    value={Math.round(draft.statusCredits[status] * 100)}
                    onChange={(event) => updateStatusCredit(status, Number(event.target.value))}
                  />
                </label>
              ))}
              <label className="scoring-field">
                <span>{t(language, "nonVerifiable")}</span>
                <select
                  value={draft.nonVerifiableMode}
                  onChange={(event) => setDraft((current) => ({ ...current, nonVerifiableMode: event.target.value as ScoringConfig["nonVerifiableMode"] }))}
                >
                  <option value="excluded">{t(language, "excludedFromCalculation")}</option>
                  <option value="zero">{t(language, "countsAsZero")}</option>
                </select>
              </label>
            </article>

            <article className="scoring-card">
              <h3>{t(language, "appThresholds")}</h3>
              <label className="scoring-field">
                <span>{t(language, "compliantIfScore")}</span>
                <input
                  min={0}
                  max={100}
                  type="number"
                  value={draft.thresholds.compliant}
                  onChange={(event) => setDraft((current) => ({ ...current, thresholds: { ...current.thresholds, compliant: Number(event.target.value) } }))}
                />
              </label>
              <label className="scoring-field">
                <span>{t(language, "clarifyIfScore")}</span>
                <input
                  min={0}
                  max={100}
                  type="number"
                  value={draft.thresholds.warning}
                  onChange={(event) => setDraft((current) => ({ ...current, thresholds: { ...current.thresholds, warning: Number(event.target.value) } }))}
                />
              </label>
              <label className="toggle-row">
                <input
                  checked={draft.blockers.criticalFailure}
                  type="checkbox"
                  onChange={(event) => setDraft((current) => ({ ...current, blockers: { ...current.blockers, criticalFailure: event.target.checked } }))}
                />
                <span>{t(language, "criticalGapBlocking")}</span>
              </label>
              <label className="toggle-row">
                <input
                  checked={draft.blockers.toClarify}
                  type="checkbox"
                  onChange={(event) => setDraft((current) => ({ ...current, blockers: { ...current.blockers, toClarify: event.target.checked } }))}
                />
                <span>{t(language, "clarifyBlocksCompliance")}</span>
              </label>
              <label className="toggle-row">
                <input
                  checked={draft.blockers.nonVerifiable}
                  type="checkbox"
                  onChange={(event) => setDraft((current) => ({ ...current, blockers: { ...current.blockers, nonVerifiable: event.target.checked } }))}
                />
                <span>{t(language, "nonVerifiableBlocksCompliance")}</span>
              </label>
            </article>
          </section>

          <section className="scoring-rules-card">
            <div className="scoring-rules-title">
              <div>
                <h3>{t(language, "rulesAndWeights")}</h3>
                <p>{model.rules.length} {t(language, "rulesInCatalog")}</p>
              </div>
              <button className="secondary-button small" type="button" onClick={() => setDraft(DEFAULT_SCORING_CONFIG)}>
                {t(language, "reset")}
              </button>
            </div>
            <div className="scoring-rules-wrap">
              <table className="scoring-rules-table">
                <thead>
                  <tr>
                    <th>{t(language, "includedColumn")}</th>
                    <th>{t(language, "rule")}</th>
                    <th>{t(language, "domain")}</th>
                    <th>{t(language, "severity")}</th>
                    <th>{t(language, "weight")}</th>
                    <th>V0</th>
                  </tr>
                </thead>
                <tbody>
                  {model.rules.map((rule) => (
                    <tr key={rule.id}>
                      <td>
                        <input
                          checked={ruleEnabled(rule)}
                          type="checkbox"
                          onChange={(event) => updateRuleOverride(rule, { enabled: event.target.checked })}
                        />
                      </td>
                      <td>
                        <strong>{rule.id}</strong>
                        <span>{ruleCopy(language, rule).title}</span>
                      </td>
                      <td>{formatDomain(rule.domain, language)}</td>
                      <td><SeverityPill severity={rule.severity} /></td>
                      <td>
                        <input
                          min={0}
                          type="number"
                          value={ruleWeight(rule)}
                          onChange={(event) => updateRuleOverride(rule, { weight: Math.max(0, Number(event.target.value)) })}
                        />
                      </td>
                      <td>
                        {evaluatedRuleIds.has(rule.id) ? <span className="type-pill green">{t(language, "evaluated")}</span> : <span className="type-pill">{t(language, "toIntegrate")}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        <footer className="scoring-footer">
          <button className="secondary-button" type="button" onClick={onClose}>{t(language, "cancel")}</button>
          <button className="primary-button" type="button" onClick={() => onSave(draft)}>
            <CheckCircle2 size={18} />
            {t(language, "saveScoring")}
          </button>
        </footer>
      </aside>
    </div>
  );
}

function PageHeading({
  title,
  subtitle,
  action,
  onAction,
  children,
}: {
  title: string;
  subtitle: string;
  action?: string;
  onAction?: () => void;
  children?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
      {(children || action) && (
        <div className="page-heading-actions">
          {children}
          {action && (onAction ? (
            <button className="secondary-button" type="button" onClick={onAction}>
              <SlidersHorizontal size={17} />
              {action}
            </button>
          ) : (
            <ComingSoonButton icon={<SlidersHorizontal size={17} />} label={action} />
          ))}
        </div>
      )}
    </div>
  );
}

function ComingSoonButton({ className = "", icon, label }: { className?: string; icon: ReactNode; label: string }) {
  const { language } = useLocale();

  return (
    <button className={`secondary-button disabled-action ${className}`.trim()} type="button" disabled title={t(language, "comingSoon")}>
      {icon}
      <span>{label}</span>
      <em>{t(language, "comingSoon")}</em>
    </button>
  );
}

function SoonBadge({ label }: { label: string }) {
  const { language } = useLocale();

  return (
    <span className="panel-badge soon" title={t(language, "comingSoon")}>
      {label}
      <em>{t(language, "comingSoon")}</em>
    </span>
  );
}

function Evidence({ label, value, code = false, danger = false }: { label: string; value: string; code?: boolean; danger?: boolean }) {
  return (
    <div className={danger ? "evidence danger" : "evidence"}>
      <span>{label}</span>
      <strong className={code ? "code" : ""}>{value}</strong>
    </div>
  );
}

function DetectionRulesEvidence({ rules }: { rules: AuditApp["detectionRules"] }) {
  const { language } = useLocale();

  if (!rules.length) {
    return (
      <div className="detection-evidence empty">
        <div className="detection-evidence-header">
          <span>{t(language, "detectionRules")}</span>
          <strong>0 {t(language, "detectionRuleCount")}</strong>
        </div>
        <p>{t(language, "noDetectionRule")}</p>
      </div>
    );
  }

  return (
    <div className="detection-evidence">
      <div className="detection-evidence-header">
        <span>{t(language, "detectionRules")}</span>
        <strong>{rules.length} {rules.length > 1 ? t(language, "detectionRulesCount") : t(language, "detectionRuleCount")}</strong>
      </div>
      <div className="detection-table-wrap">
        <table className="detection-table">
          <thead>
            <tr>
              <th>{t(language, "detectionType")}</th>
              <th>{t(language, "detectionIndicator")}</th>
              <th>{t(language, "detectionValue")}</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule, index) => (
              <tr key={`${rule.kind}-${rule.indicator}-${index}`}>
                <td>
                  <span className={`detection-kind ${rule.kind}`}>
                    {formatDetectionKind(rule.kind, language)}
                  </span>
                </td>
                <td>
                  <code>{rule.indicator || t(language, "notProvided")}</code>
                </td>
                <td>
                  {rule.value ? <code>{rule.value}</code> : <span className="muted-value">-</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function formatDetectionKind(kind: DetectionRuleKind, language: Language) {
  const labels: Record<DetectionRuleKind, string> = {
    registry: t(language, "detectionRegistry"),
    file: t(language, "detectionFile"),
    msi: t(language, "detectionMsi"),
    script: t(language, "detectionScript"),
    unknown: t(language, "detectionUnknown"),
  };
  return labels[kind];
}

function AssignmentsEvidence({ assignments }: { assignments: AuditApp["assignments"] }) {
  const { language } = useLocale();
  const [showAll, setShowAll] = useState(false);

  if (!assignments.length) {
    return (
      <div className="assignments-evidence empty">
        <div className="assignments-evidence-header">
          <span>{t(language, "deploymentsAssignments")}</span>
          <strong>0 {t(language, "targetCount")}</strong>
        </div>
        <p>{t(language, "noAssignment")}</p>
      </div>
    );
  }

  const visibleAssignments = showAll ? assignments : assignments.slice(0, 5);
  const hiddenCount = Math.max(0, assignments.length - visibleAssignments.length);

  return (
    <div className="assignments-evidence">
      <div className="assignments-evidence-header">
        <span>{t(language, "deploymentsAssignments")}</span>
        <strong>{assignments.length} {assignments.length > 1 ? t(language, "targetsCount") : t(language, "targetCount")}</strong>
      </div>
      <div className="assignments-table-wrap">
        <table className="assignments-table">
          <thead>
            <tr>
              <th>{t(language, "target")}</th>
              <th>{t(language, "intent")}</th>
              <th>Mode</th>
              <th>{t(language, "notifications")}</th>
            </tr>
          </thead>
          <tbody>
            {visibleAssignments.map((assignment, index) => {
              const isBroadTarget = /all users|all devices/i.test(assignment.target);
              return (
                <tr className={isBroadTarget ? "broad-target" : ""} key={`${assignment.target}-${assignment.intent}-${index}`}>
                  <td>
                    <div className={assignment.targetResolved ? "assignment-target" : "assignment-target unresolved"}>
                      <strong>{assignment.target}</strong>
                      {isBroadTarget && <span>{t(language, "broadTarget")}</span>}
                      {!assignment.targetResolved && <span>{t(language, "unresolvedGroup")}</span>}
                    </div>
                  </td>
                  <td>
                    <span className={`assignment-intent ${assignmentIntentClass(assignment.intent)}`}>
                      {formatAssignmentIntent(assignment.intent, language)}
                    </span>
                  </td>
                  <td>
                    <span className={`assignment-mode ${assignment.mode}`}>
                      {assignment.mode === "excluded" ? t(language, "excludedAssignment") : t(language, "included")}
                    </span>
                  </td>
                  <td>{formatAssignmentNotification(assignment.notifications, language)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {assignments.length > 5 && (
        <button className="inline-link-button assignment-more-button" type="button" onClick={() => setShowAll((current) => !current)}>
          {showAll ? t(language, "showLess") : `${t(language, "showAllTargets")} (${hiddenCount})`}
          <ChevronDown size={15} />
        </button>
      )}
    </div>
  );
}

function formatAssignmentIntent(intent: string, language: Language) {
  const labels: Record<Language, Record<string, string>> = {
    fr: {
      available: "Disponible",
      required: "Obligatoire",
      uninstall: "Désinstallation",
    },
    en: {
      available: "Available",
      required: "Required",
      uninstall: "Uninstall",
    },
  };
  return labels[language][intent.toLowerCase()] ?? (intent || t(language, "notProvided"));
}

function assignmentIntentClass(intent: string) {
  const normalized = intent.toLowerCase();
  if (normalized.includes("required")) return "required";
  if (normalized.includes("available")) return "available";
  if (normalized.includes("uninstall")) return "uninstall";
  return "unknown";
}

function formatAssignmentNotification(notification: string, language: Language) {
  const labels: Record<string, string> = {
    hideAll: t(language, "hidden"),
    hideAllToastNotifications: t(language, "hidden"),
    notConfigured: t(language, "notConfigured"),
    showAll: t(language, "showAllNotifications"),
    showReboot: t(language, "rebootOnly"),
    showAllToastNotifications: t(language, "visible"),
    showRebootToastNotifications: t(language, "rebootOnly"),
  };
  return labels[notification] ?? (notification || t(language, "notProvidedFemale"));
}

function StatusPill({ status }: { status: AuditStatus }) {
  const { language } = useLocale();
  return <span className={STATUS_CLASS[status]}>{statusLabel(status, language)}</span>;
}

function StatusIcon({ status }: { status: AuditStatus }) {
  if (status === "compliant" || status === "exception") return <CheckCircle2 className="icon-ok" size={19} />;
  if (status === "non_compliant") return <XCircle className="icon-ko" size={19} />;
  if (status === "non_verifiable") return <EyeOff className="icon-muted" size={19} />;
  return <AlertCircle className="icon-warn" size={19} />;
}

function SeverityPill({ severity }: { severity: GuidelineRule["severity"] }) {
  const { language } = useLocale();
  return <span className={`severity severity-${severity}`}>{severityLabel(language, severity)}</span>;
}

function ruleObjective(rule: GuidelineRule, language: Language) {
  const domainContext: Record<Language, Record<string, string>> = {
    fr: {
      pre_validation: "Ce contrôle sécurise la phase de cadrage avant packaging.",
      source_files: "Ce contrôle garantit que les sources utilisées sont fiables, documentées et conformes.",
      packaging: "Ce contrôle vérifie la qualité technique du package avant publication.",
      testing: "Ce contrôle s'assure que le package a été validé localement avant son industrialisation.",
      intune_setup: "Ce contrôle vérifie la configuration Intune et les métadonnées de l'application.",
      deployment: "Ce contrôle encadre le déploiement pour limiter les risques de production.",
      fallback: "Ce contrôle vérifie le respect de la guideline.",
      requirement: "Exigence",
    },
    en: {
      pre_validation: "This control secures the request framing phase before packaging.",
      source_files: "This control ensures that source files are reliable, documented and compliant.",
      packaging: "This control checks the technical quality of the package before publication.",
      testing: "This control ensures that the package was validated locally before industrialization.",
      intune_setup: "This control checks the Intune configuration and application metadata.",
      deployment: "This control frames deployment to limit production risk.",
      fallback: "This control checks compliance with the guideline.",
      requirement: "Requirement",
    },
  };
  const copy = ruleCopy(language, rule);
  const context = domainContext[language][rule.domain] ?? domainContext[language].fallback;
  return `${context} ${domainContext[language].requirement}: ${copy.requirement}`;
}

function ruleRemediation(rule: GuidelineRule, language: Language) {
  const fallback: Record<Language, string> = {
    fr: "Documenter l'écart, définir l'action corrective attendue et faire valider l'exception si elle est maintenue.",
    en: "Document the gap, define the expected corrective action and approve the exception if it remains.",
  };
  return ruleCopy(language, rule).remediation || fallback[language];
}

function formatControlType(value: string, language: Language) {
  return controlTypeLabel(language, value);
}

function formatDomain(value: string, language: Language) {
  return domainLabel(language, value);
}

function formatEvidenceSource(value: string, language: Language) {
  return evidenceSourceLabel(language, value);
}

function formatDate(value: string, language: Language) {
  if (!value) return t(language, "notProvided");
  return new Intl.DateTimeFormat(language === "fr" ? "fr-FR" : "en-GB").format(new Date(value));
}

function unitLabel(language: Language, count: number, frSingular: string, frPlural: string, enSingular: string, enPlural: string) {
  if (language === "fr") return count === 1 ? frSingular : frPlural;
  return count === 1 ? enSingular : enPlural;
}

function formatCount(language: Language, count: number, frSingular: string, frPlural: string, enSingular: string, enPlural: string) {
  return `${count} ${unitLabel(language, count, frSingular, frPlural, enSingular, enPlural)}`;
}

function scoreClass(score: number, base = "score") {
  if (score >= 90) return `${base} good`;
  if (score >= 70) return `${base} warn`;
  return `${base} bad`;
}

function severityRank(severity: Severity) {
  const ranks: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };
  return ranks[severity];
}

function findingTitle(rule: RuleResult, language: Language) {
  const shortTitle = shortRuleTitle(rule, language);
  if (language === "fr") {
    if (rule.status === "non_verifiable") return `${shortTitle} non vérifiable`;
    if (/owner|propriétaire/i.test(rule.title)) return "Propriétaire manquant";
    if (/detection|détection/i.test(rule.title)) return "Détection invalide ou à vérifier";
    if (/codes retour|return codes/i.test(rule.title)) return "Codes retour incomplets";
    if (/group|target|ciblage/i.test(rule.title)) return "Ciblage à vérifier";
    return shortTitle;
  }
  if (rule.status === "non_verifiable") return `${shortTitle} non-verifiable`;
  if (/Owner/i.test(rule.title)) return "Missing owner";
  if (/Detection/i.test(rule.title)) return "Invalid or unverified detection";
  if (/return codes/i.test(rule.title)) return "Incomplete return codes";
  if (/group|target/i.test(rule.title)) return "Targeting to review";
  return shortTitle;
}

function shortRuleTitle(rule: RuleResult, language: Language) {
  const title = ruleCopy(language, rule).title;
  if (language === "fr") return title.replace("L'application ", "").replace("Le déploiement ", "");
  return title
    .replace("Application ", "")
    .replace("Deployment ", "")
    .replace("Installation ", "")
    .replace("configured", "configured");
}

function formatRuleStats(
  stats: { pass: number; fail: number; clarify: number; unknown: number } | undefined,
  language: Language,
  separator = " / ",
) {
  if (!stats) return t(language, "notEvaluatedV0");
  return [
    `${stats.pass} ${t(language, "ok")}`,
    `${stats.fail} ${t(language, "ko")}`,
    `${stats.clarify} ${t(language, "toClarifyShort")}`,
    `${stats.unknown} ${t(language, "notVerifiedShort")}`,
  ].join(separator);
}
