import { createContext, Fragment, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Box,
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
  LayoutDashboard,
  ListChecks,
  Loader2,
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
  Trash2,
  Users,
  Wrench,
  X,
  XCircle,
} from "lucide-react";
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
import type { AuditApp, AuditModel, AuditStatus, DetectionRuleKind, GuidelineRule, RuleResult, ScoringConfig, Severity } from "./lib/types";

type ViewKey = "dashboard" | "inventory" | "findings" | "rules" | "assignments";

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

const VIEWS: { key: ViewKey; labelKey: string; icon: typeof LayoutDashboard }[] = [
  { key: "dashboard", labelKey: "dashboard", icon: LayoutDashboard },
  { key: "inventory", labelKey: "inventory", icon: Package },
  { key: "findings", labelKey: "findings", icon: AlertCircle },
  { key: "rules", labelKey: "rules", icon: ListChecks },
  { key: "assignments", labelKey: "assignments", icon: Users },
];

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

const SCORING_STORAGE_KEY = "soapp-qc-scoring-config-v1";
const LANGUAGE_STORAGE_KEY = "soapp-qc-language";
const RULE_CATALOG_STORAGE_KEY = "soapp-qc-rule-catalog-v1";

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

function loadStoredScoringConfig(): ScoringConfig {
  if (typeof window === "undefined") return DEFAULT_SCORING_CONFIG;
  try {
    const stored = window.localStorage.getItem(SCORING_STORAGE_KEY);
    return stored ? normalizeScoringConfig(JSON.parse(stored) as Partial<ScoringConfig>) : DEFAULT_SCORING_CONFIG;
  } catch {
    return DEFAULT_SCORING_CONFIG;
  }
}

function storeScoringConfig(config: ScoringConfig) {
  window.localStorage.setItem(SCORING_STORAGE_KEY, JSON.stringify(config));
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

function loadStoredRuleCatalog(): GuidelineRule[] | null {
  if (typeof window === "undefined") return null;
  try {
    const stored = window.localStorage.getItem(RULE_CATALOG_STORAGE_KEY);
    if (!stored) return null;
    const parsed = JSON.parse(stored) as unknown;
    return Array.isArray(parsed) && parsed.every(isGuidelineRule) ? parsed : null;
  } catch {
    return null;
  }
}

function storeRuleCatalog(rules: GuidelineRule[]) {
  window.localStorage.setItem(RULE_CATALOG_STORAGE_KEY, JSON.stringify(rules));
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

export default function App() {
  const [language, setLanguageState] = useState<Language>(() => loadStoredLanguage());
  const [scoringConfig, setScoringConfig] = useState<ScoringConfig>(() => loadStoredScoringConfig());
  const [customRules, setCustomRules] = useState<GuidelineRule[] | null>(() => loadStoredRuleCatalog());
  const [model, setModel] = useState<AuditModel | null>(null);
  const [activeView, setActiveView] = useState<ViewKey>("dashboard");
  const [selectedApp, setSelectedApp] = useState<AuditApp | null>(null);
  const [scoringOpen, setScoringOpen] = useState(false);
  const [query, setQuery] = useState("");

  const setLanguage = (nextLanguage: Language) => {
    storeLanguage(nextLanguage);
    setLanguageState(nextLanguage);
  };

  useEffect(() => {
    loadAuditModel(scoringConfig, language, customRules ?? undefined).then(setModel).catch((error) => {
      console.error(error);
      setModel(null);
    });
  }, [customRules, scoringConfig, language]);

  useEffect(() => {
    setSelectedApp((current) => {
      if (!current || !model) return current;
      return model.apps.find((app) => app.id === current.id) ?? null;
    });
  }, [model]);

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

  const saveRuleCatalog = (rules: GuidelineRule[]) => {
    storeRuleCatalog(rules);
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
      storeScoringConfig(normalized);
      return normalized;
    });
  };

  if (!model) {
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
          appCount={model.stats.appCount}
          rulesCount={model.rules.length}
          perimeterLabel={model.metadata.perimeterLabel}
          onChange={setActiveView}
        />

        <main className="main">
          <header className="topbar">
            <div>
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
            {activeView === "dashboard" && (
              <Dashboard model={model} apps={filteredApps} scoringConfig={scoringConfig} onSelectApp={setSelectedApp} />
            )}
            {activeView === "inventory" && (
              <InventoryView apps={filteredApps} onSelectApp={setSelectedApp} />
            )}
            {activeView === "findings" && (
              <FindingsView apps={filteredApps} onSelectApp={setSelectedApp} />
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
          </section>
        </main>

        {selectedApp && <AppDrawer app={selectedApp} onClose={() => setSelectedApp(null)} />}
        {scoringOpen && (
          <ScoringPanel
            config={scoringConfig}
            model={model}
            onClose={() => setScoringOpen(false)}
            onSave={(nextConfig) => {
              const normalized = normalizeScoringConfig(nextConfig);
              storeScoringConfig(normalized);
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
  appCount,
  rulesCount,
  perimeterLabel,
  onChange,
}: {
  activeView: ViewKey;
  appCount: number;
  rulesCount: number;
  perimeterLabel: string;
  onChange: (view: ViewKey) => void;
}) {
  const { language } = useLocale();

  return (
    <aside className="sidebar">
      <div className="brand">
        <IntuneLogo />
        <span>SoApp <span>QC</span></span>
      </div>

      <nav>
        <p className="nav-heading">{t(language, "mainMenu")}</p>
        {VIEWS.map((view) => {
          const Icon = view.icon;
          const count = view.key === "inventory" ? ` (${appCount})` : view.key === "rules" ? ` (${rulesCount})` : "";
          return (
            <button
              className={activeView === view.key ? "nav-item active" : "nav-item"}
              type="button"
              key={view.key}
              onClick={() => onChange(view.key)}
            >
              <Icon size={20} />
              <span>{t(language, view.labelKey)}{count}</span>
            </button>
          );
        })}

        <p className="nav-heading report-heading">{t(language, "reports")}</p>
        <div className="source-pill">
          <FileText size={18} />
          <span>{t(language, "perimeter")} : {perimeterLabel}</span>
        </div>
      </nav>

      <button className="nav-item settings" type="button">
        <Settings size={20} />
        <span>{t(language, "settings")}</span>
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
  scoringConfig,
  onSelectApp,
}: {
  model: AuditModel;
  apps: AuditApp[];
  scoringConfig: ScoringConfig;
  onSelectApp: (app: AuditApp) => void;
}) {
  const { language } = useLocale();
  const appsToReview = Math.max(0, model.stats.appCount - model.stats.compliantApps);
  const auditCoverage = Math.round((model.metadata.evaluatedControls / Math.max(1, model.rules.length)) * 100);
  const rulesToIntegrate = Math.max(0, model.rules.length - model.metadata.evaluatedControls);
  const maxSeverityCount = Math.max(1, ...model.backlogBySeverity.map((entry) => entry.value));
  const maxHotspotCount = Math.max(1, ...model.controlHotspots.map((entry) => entry.value));
  const maxTopViolationCount = Math.max(1, ...model.topViolations.map((entry) => entry.count));
  const statusRows = model.statusDistribution.map((entry) => ({
    id: entry.status,
    label: entry.name,
    value: String(entry.value),
    detail: t(language, "apps"),
    percent: (entry.value / Math.max(1, model.stats.appCount)) * 100,
    color: STATUS_COLORS[entry.status],
  }));
  const severityRows = model.backlogBySeverity.map((entry) => ({
    id: entry.severity,
    label: entry.name,
    value: String(entry.value),
    detail: t(language, "findingsCount"),
    percent: (entry.value / maxSeverityCount) * 100,
    color: SEVERITY_COLORS[entry.severity],
  }));
  const hotspotRows = model.controlHotspots.map((entry) => ({
    id: entry.id,
    label: entry.label,
    value: String(entry.value),
    detail: t(language, "findingsCount"),
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
        <button className="secondary-button" type="button">
          <Download size={18} />
          {t(language, "exportBacklog")}
        </button>
      </section>

      <section className="northstar-grid">
        <NorthStarCard
          detail={`${t(language, "compliantThreshold")} ${scoringConfig.thresholds.compliant}%`}
          icon={<Activity size={18} />}
          subtitle={t(language, "globalScoreSubtitle")}
          title={t(language, "globalScore")}
          tone="brand"
          value={`${model.stats.globalScore}%`}
        />
        <NorthStarCard
          detail={`${model.stats.appCount} ${t(language, "apps")}`}
          icon={<Box size={18} />}
          subtitle={`${model.stats.compliantApps} ${t(language, "compliantApps")}`}
          title={t(language, "parkHealth")}
          tone="green"
          value={`${model.stats.compliantApps}/${model.stats.appCount}`}
        >
          <div className="northstar-split">
            <span className="good-dot">{model.stats.compliantApps} {t(language, "compliant")}</span>
            <span className="warn-dot">{appsToReview} {t(language, "requiresAttention")}</span>
          </div>
        </NorthStarCard>
        <NorthStarCard
          detail={`${model.stats.criticalFindings} ${t(language, "criticalGaps").toLowerCase()}`}
          icon={<AlertTriangle size={18} />}
          subtitle={t(language, "activeBacklog")}
          title={t(language, "remediationBacklog")}
          tone="red"
          value={model.stats.openFindings.toString()}
        />
        <NorthStarCard
          detail={`${rulesToIntegrate} ${t(language, "rulesToIntegrate")}`}
          icon={<EyeOff size={18} />}
          subtitle={`${model.metadata.evaluatedControls} / ${model.rules.length} ${t(language, "activeControlsShort")}`}
          title={t(language, "auditCoverage")}
          tone="amber"
          value={`${auditCoverage}%`}
        />
      </section>

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
            <span className="panel-badge">{t(language, "trend")}</span>
          </div>
          <div className="compact-chart">
            <ActivityTrend data={model.weeklyActivity} />
          </div>
        </article>

        <article className="bento-card severity-card">
          <div className="bento-heading">
            <div>
              <h3>{t(language, "backlogBySeverity")}</h3>
              <p>{model.stats.openFindings} {t(language, "findingsCount")}</p>
            </div>
            <span className="panel-badge">{t(language, "actionable")}</span>
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
                  <strong className={["Non assigne", "Unassigned"].includes(entry.owner) ? "danger-text" : ""}>{entry.owner}</strong>
                  <span>{entry.apps} {t(language, "impactedApps")}</span>
                </div>
                <span>{entry.findings} {t(language, "findingsCount")}</span>
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
        <InventoryTable apps={apps.slice(0, 8)} onSelectApp={onSelectApp} compact />
      </section>
    </>
  );
}

function NorthStarCard({
  children,
  detail,
  icon,
  subtitle,
  title,
  tone,
  value,
}: {
  children?: ReactNode;
  detail: string;
  icon: ReactNode;
  subtitle: string;
  title: string;
  tone: "brand" | "green" | "red" | "amber";
  value: string;
}) {
  return (
    <article className={`northstar-card tone-${tone}`}>
      <div className="northstar-card-header">
        <span>{title}</span>
        <div className="northstar-icon">{icon}</div>
      </div>
      <strong>{value}</strong>
      <p>{subtitle}</p>
      {children ?? <span className="northstar-detail">{detail}</span>}
    </article>
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
            <strong>{row.value}{row.detail ? <em>{row.detail}</em> : null}</strong>
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
}: {
  apps: AuditApp[];
  onSelectApp: (app: AuditApp) => void;
  compact?: boolean;
}) {
  const { language } = useLocale();
  const unassignedLabels = ["Non assigne", "Unassigned"];

  return (
    <article className="table-card">
      <div className="table-title">
        <h3>{t(language, "qualityInventory")}</h3>
        <button className="secondary-button small" type="button">
          <SlidersHorizontal size={16} />
          {t(language, "filter")}
        </button>
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
      {compact && apps.length === 8 && <p className="table-footnote">{t(language, "limitedRows")}</p>}
    </article>
  );
}

function FindingsView({ apps, onSelectApp }: { apps: AuditApp[]; onSelectApp: (app: AuditApp) => void }) {
  const { language } = useLocale();
  const findings = apps.flatMap((app) =>
    app.rules
      .filter((rule) => ["non_compliant", "to_clarify", "non_verifiable"].includes(rule.status))
      .map((rule) => ({ app, rule })),
  );

  return (
    <section>
      <PageHeading title={t(language, "findingsBacklog")} subtitle={`${findings.length} ${t(language, "actionsToQualify")}`} action={t(language, "exportBacklog")} />
      <div className="finding-list">
        {findings.map(({ app, rule }) => (
          <article
            aria-label={`${t(language, "open")} ${app.name}`}
            className="finding-card interactive"
            key={`${app.id}-${rule.id}`}
            onClick={() => onSelectApp(app)}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onSelectApp(app);
              }
            }}
            role="button"
            tabIndex={0}
          >
            <div className="finding-main">
              <StatusIcon status={rule.status} />
              <div>
                <strong>{rule.id} - {findingTitle(rule, language)}</strong>
                <span>{app.name}</span>
              </div>
            </div>
            <SeverityPill severity={rule.severity} />
            <p>{rule.evidence}</p>
          </article>
        ))}
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
      <aside className="rule-editor-panel" role="dialog" aria-modal="true" aria-labelledby="rule-editor-title">
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

  useDismissOnEscape(onCancel);

  return (
    <div
      className="rule-editor-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <aside className="rule-delete-dialog" role="dialog" aria-modal="true" aria-labelledby="rule-delete-title">
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

  return (
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
          {assignments.map((assignment, index) => {
            const isBroadTarget = /all users|all devices/i.test(assignment.target);
            return (
              <tr className={isBroadTarget ? "broad-target" : ""} key={`${assignment.target}-${assignment.intent}-${index}`}>
                <td>
                  <div className="assignment-target">
                    <strong>{assignment.target}</strong>
                    {isBroadTarget && <span>{t(language, "broadTarget")}</span>}
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

function AppDrawer({ app, onClose }: { app: AuditApp; onClose: () => void }) {
  const { language } = useLocale();
  const majorIssues = app.rules.filter((rule) => ["non_compliant", "to_clarify", "non_verifiable"].includes(rule.status));
  const remediationRequired = app.status !== "compliant" && app.status !== "exception";

  useDismissOnEscape(onClose);

  return (
    <div
      className="drawer-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="app-drawer-title">
        <header className="drawer-header">
          <div className="drawer-title" id="app-drawer-title">
            <FileText size={24} />
            <span>{t(language, "appCard")}</span>
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
              </div>
            </div>
            <div className={scoreClass(app.score, "drawer-score")}>
              <strong>{app.score}%</strong>
              <span>{t(language, "qualityScore")}</span>
            </div>
          </section>

          <section>
            <h3>{majorIssues.length ? t(language, "majorAnomalies") : t(language, "anomaliesAndRemediation")}</h3>
            {majorIssues.length ? (
              <div className="issue-stack">
                {majorIssues.slice(0, 5).map((rule) => (
                  <div className={`issue-card ${rule.status}`} key={rule.id}>
                    <span>{rule.id} - {findingTitle(rule, language)}</span>
                    <SeverityPill severity={rule.severity} />
                  </div>
                ))}
              </div>
            ) : (
              <div className="success-box">
                <CheckCircle2 size={22} />
                {t(language, "noAnomaly")}
              </div>
            )}
          </section>

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

          <section>
            <h3>{t(language, "controlEvidence")}</h3>
            <Evidence label={t(language, "ownerLabel")} value={app.owner} />
            <DetectionRulesEvidence rules={app.detectionRules} />
            <Evidence label={t(language, "returnCodes")} value={app.returnCodes.join(", ") || t(language, "noReturnCode")} code />
            <AssignmentsEvidence assignments={app.assignments} />
          </section>
        </div>

        <footer className="drawer-footer">
          <button className="secondary-button" type="button" onClick={onClose}>{t(language, "close")}</button>
          <button className={remediationRequired ? "primary-button" : "primary-button disabled"} type="button" disabled={!remediationRequired}>
            <Ticket size={18} />
            {remediationRequired ? t(language, "createRemediationTicket") : t(language, "ticketNotRequired")}
          </button>
        </footer>
      </aside>
    </div>
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
      <aside className="scoring-panel" role="dialog" aria-modal="true" aria-labelledby="scoring-panel-title">
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
  action: string;
  onAction?: () => void;
  children?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
      <div className="page-heading-actions">
        {children}
        <button className="secondary-button" type="button" onClick={onAction}>
          <SlidersHorizontal size={17} />
          {action}
        </button>
      </div>
    </div>
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
            {assignments.map((assignment, index) => {
              const isBroadTarget = /all users|all devices/i.test(assignment.target);
              return (
                <tr className={isBroadTarget ? "broad-target" : ""} key={`${assignment.target}-${assignment.intent}-${index}`}>
                  <td>
                    <div className="assignment-target">
                      <strong>{assignment.target}</strong>
                      {isBroadTarget && <span>{t(language, "broadTarget")}</span>}
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
    </div>
  );
}

function formatAssignmentIntent(intent: string, language: Language) {
  const labels: Record<Language, Record<string, string>> = {
    fr: {
      available: "Disponible",
      required: "Obligatoire",
      uninstall: "Desinstallation",
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
    hideAllToastNotifications: t(language, "hidden"),
    notConfigured: t(language, "notConfigured"),
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
      pre_validation: "Ce controle securise la phase de cadrage avant packaging.",
      source_files: "Ce controle garantit que les sources utilisees sont fiables, documentees et conformes.",
      packaging: "Ce controle verifie la qualite technique du package avant publication.",
      testing: "Ce controle s'assure que le package a ete valide localement avant son industrialisation.",
      intune_setup: "Ce controle verifie la configuration Intune et les metadonnees de l'application.",
      deployment: "Ce controle encadre le deploiement pour limiter les risques de production.",
      fallback: "Ce controle verifie le respect de la guideline.",
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
    fr: "Documenter l'ecart, definir l'action corrective attendue et faire valider l'exception si elle est maintenue.",
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

function scoreClass(score: number, base = "score") {
  if (score >= 90) return `${base} good`;
  if (score >= 70) return `${base} warn`;
  return `${base} bad`;
}

function findingTitle(rule: RuleResult, language: Language) {
  const shortTitle = shortRuleTitle(rule, language);
  if (language === "fr") {
    if (rule.status === "non_verifiable") return `${shortTitle} non verifiable`;
    if (/owner|proprietaire/i.test(rule.title)) return "Proprietaire manquant";
    if (/detection/i.test(rule.title)) return "Detection invalide ou a verifier";
    if (/codes retour|return codes/i.test(rule.title)) return "Codes retour incomplets";
    if (/group|target|ciblage/i.test(rule.title)) return "Ciblage a verifier";
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
  if (language === "fr") return title.replace("L'application ", "").replace("Le deploiement ", "");
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
