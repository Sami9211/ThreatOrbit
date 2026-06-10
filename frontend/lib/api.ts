/**
 * ThreatOrbit dashboard API client.
 * All requests are authenticated with the JWT stored in localStorage.
 * All snake_case API responses are converted to camelCase before returning.
 */

const BASE =
  (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_API_URL) ||
  'http://localhost:8002'

// ── Key names for localStorage ──────────────────────────────────────
export const TOKEN_KEY = 'to_token'
export const USER_KEY  = 'to_user'

// ── Utility: snake_case → camelCase (recursive) ─────────────────────
function sc2cc(s: string) {
  return s.replace(/_([a-z])/g, (_, c) => c.toUpperCase())
}
function toCamel(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(toCamel)
  if (v && typeof v === 'object' && !(v instanceof Date)) {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>).map(([k, val]) => [sc2cc(k), toCamel(val)])
    )
  }
  return v
}

// ── Core fetch wrapper ───────────────────────────────────────────────
async function api<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const tok = typeof window !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(tok ? { Authorization: `Bearer ${tok}` } : {}),
      ...(opts.headers ?? {}),
    },
  })
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try { const j = await res.json(); msg = j.detail ?? msg } catch { /* ignore */ }
    throw new Error(msg)
  }
  if (res.status === 204) return undefined as T
  const json = await res.json()
  return toCamel(json) as T
}

// ── Types ────────────────────────────────────────────────────────────
export type UserRole = 'admin' | 'manager' | 'analyst' | 'viewer'

export interface User {
  id: string
  email: string
  name: string
  role: UserRole
  status: string
  mfaEnabled?: number
  lastLogin: string | null
  createdAt: string
}

export interface OverviewKpis {
  threats: number
  iocs: number
  sources: number
  score: number
}

export interface ThreatVector {
  label: string
  pct: number
  color: string
}

export interface OverviewAlert {
  id: string
  title: string
  severity: string
  time: string
  src: string
}

export interface Incident {
  id: string
  title: string
  severity: string
  status: string
  category: string
  assigned: string
  age: string
}

export interface TopActor {
  name: string
  origin: string
  score: number
  attacks: number
  threatLevel: string
}

export interface LiveFeedItem {
  id: string
  type: string
  severity: string
  ip: string
  detail: string
  region: string
}

export interface SiemAlert {
  id: string
  ts: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'new' | 'assigned' | 'in-progress' | 'pending' | 'resolved' | 'closed'
  disposition: 'undetermined' | 'true-positive' | 'false-positive' | 'benign' | 'duplicate'
  owner: string | null
  riskScore: number
  ruleId: string
  ruleName: string
  mitreTactic: string
  mitreTacticId: string
  mitreTech: string
  mitreTechId: string
  srcIp: string
  srcCountry: string
  srcPort: number
  srcHostname: string
  srcAsn: string
  destIp: string
  destPort: number
  destService: string
  username: string | null
  hostname: string | null
  hostCriticality: 'critical' | 'high' | 'medium' | 'low'
  processName: string | null
  cmdLine: string | null
  description: string
  rawLog: string
  eventCount: number
  tiHits: number
  bytesOut: number
}

export interface SiemKpis {
  totalAlerts: number
  critical: number
  high: number
  medium: number
  mttd: number
  mttr: number
  mtta: number
  fpRate: number
  automationRate: number
  totalEps: number
  daysData: number
}

export interface Rule {
  id: string
  name: string
  source: string
  category: string
  mitreTactic: string
  mitreTechId: string
  severity: string
  enabled: boolean
  hits24h: number
  lastFired: string | null
  fpRate: number
  description: string
  status: string
}

export interface Correlation {
  pivot: 'src_ip' | 'hostname' | 'username'
  value: string
  alertCount: number
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  alerts: Array<{ id: string; title: string; severity: string; ts: string }>
}

export interface LogSource {
  id: string
  name: string
  type: string
  epsAvg: number
  status: string
  lastEvent: string | null
  events7d: number
}

export interface Case {
  id: string
  title: string
  type: string
  severity: string
  status: string
  owner: string | null
  playbookId: string | null
  slaHours: number
  created: string
  updated: string
  alertCount: number
  description: string
  entities: Array<{ type: string; value: string }>
  warRoom: Array<{ ts: string; actor: string; type: string; content: string }>
  tasks: Array<{ id: string; phase: string; name: string; status: string; assignee: string | null; notes: string }>
  evidence: Array<{ name: string; type: string; added: string; by: string }>
}

export interface Playbook {
  id: string
  name: string
  category: string
  trigger: string
  triggerType: 'auto' | 'manual'
  triggerMatch: Record<string, unknown>
  description: string
  runs: number
  successRate: number
  avgTime: number
  lastRun: string | null
  lastRunStatus: string
  status: string
  enabled: number
  steps: Array<{ kind?: string; name: string; type: string; status: string; duration: number; params?: Record<string, unknown> }>
}

export interface Integration {
  id: string
  name: string
  type: string
  status: string
  url: string | null
  lastSync: string | null
  description: string
}

export interface SoarMetrics {
  openCases: number
  criticalOpen: number
  mttr: number
  mttrTrend: string
  automationRate: number
  automationTrend: string
  timeSavedMonth: number
  playbooksToday: number
  avgPlaybookTime: number
  casesClosedWeek: number
}

export interface Actor {
  id: string
  name: string
  aliases: string[]
  origin: string
  type: string
  motivations: string[]
  active: boolean | number
  firstSeen: string
  lastSeen: string
  sophistication: number
  sectors: string[]
  ttps: string[]
  malware?: string[]
  iocCount: number
  campaignCount?: number
  recentActivity?: string | null
  campaigns: string[]
  description: string
  threatLevel: string
  flag?: string
}

export interface Ioc {
  id: string
  type: string
  value: string
  severity: string
  actor: string
  source: string
  firstSeen: string
  lastSeen: string
  threatType: string
  confidence: number
  tags: string[]
}

export interface IocType {
  label: string
  count: number
}

export interface CtiSummary {
  trackedActors: number
  activeActors: number
  activeCampaigns: number
  nationState: number
  cybercrime: number
  hacktivist: number
  totalIocs: number
}

export interface IocLookup {
  value: string
  found: boolean
  verdict: 'malicious' | 'suspicious' | 'clean'
  confidence: number
  severity: string | null
  threatType: string | null
  actor: string | null
  source: string | null
  firstSeen: string | null
  lastSeen: string | null
  tags: string[]
}

export interface SavedHunt {
  id: string
  name: string
  hypothesis: string
  status: string
  artifacts: number
  analyst: string
  progress: number
  created: string
  lastRun: string | null
  domain: string
}

export interface CtiGraph {
  nodes: Array<{ id: string; label: string; group: string; level?: string; size: number; iocType?: string }>
  links: Array<{ source: string; target: string; kind: string }>
}

export interface Asset {
  id: string
  name: string
  type: string
  value: string
  criticality: string
  status: string
  riskScore: number
  lastScan: string | null
  alerts: number
  cves: { critical: number; high: number; medium: number; low: number }
  openPorts: number[]
  os: string | null
  owner: string | null
  patchAge: number
  tags: string[]
  uptime: number
}

export interface RiskComponent {
  axis: 'vulnerability' | 'exposure' | 'patch' | 'alerts'
  value: number
  weight: number
  contribution: number
}

export interface RiskBreakdown {
  score: number
  band: string
  criticalityMultiplier: number
  components: RiskComponent[]
}

export interface AssetDetail extends Asset {
  riskBreakdown: RiskBreakdown
}

export interface RiskDistribution {
  total: number
  bands: { critical: number; 'at-risk': number; clean: number }
  axisContribution: Array<{ axis: 'vulnerability' | 'exposure' | 'patch' | 'alerts'; avgContribution: number }>
  topDriver: 'vulnerability' | 'exposure' | 'patch' | 'alerts' | null
  meanScore: number
  maxScore: number
}

export interface AssetSummary {
  totalAssets: number
  criticalAssets: number
  atRisk: number
  avgRiskScore: number
  openAlerts: number
  cves: { critical: number; high: number; medium: number; low: number }
}

export interface Feed {
  id: string
  name: string
  type: string
  url: string | null
  status: string
  enabled: boolean
  indicators: number
  lastSync: string | null
  description: string
}

export interface FeedsSummary {
  totalFeeds: number
  active: number
  errored: number
  totalIndicators: number
  byType: Record<string, number>
}

export interface ApiKey {
  id: string
  name: string
  prefix: string
  scope: string
  lastUsed: string | null
  createdAt: string
  createdBy: string
  revoked: boolean
}

export interface AuditEntry {
  id: number
  ts: string
  actor: string | null
  action: string
  target: string | null
  detail: string | null
}

// ── Auth ─────────────────────────────────────────────────────────────
export const authLogin = (email: string, password: string) =>
  api<{ token: string; user: User }>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })

export const authRegister = (body: { name: string; email: string; password: string; company?: string }) =>
  api<{ token: string; user: User }>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(body),
  })

export const authMe = () => api<User>('/auth/me')

export const authChangePassword = (currentPassword: string, newPassword: string) =>
  api<{ ok: boolean }>('/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  })

// ── Overview ─────────────────────────────────────────────────────────
export const fetchKpis    = () => api<OverviewKpis>('/overview/kpis')
export const fetchVectors = () => api<ThreatVector[]>('/overview/threat-vectors')
export const fetchHourly  = () => api<number[]>('/overview/hourly-volume')
export const fetchHeatmap = () => api<Array<{ label: string; vals: number[] }>>('/overview/mitre-heatmap')
export const fetchRecentAlerts    = (limit = 8)  => api<OverviewAlert[]>(`/overview/recent-alerts?limit=${limit}`)
export const fetchRecentIncidents = (limit = 6)  => api<Incident[]>(`/overview/recent-incidents?limit=${limit}`)
export const fetchTopActors  = (limit = 5)  => api<TopActor[]>(`/overview/top-actors?limit=${limit}`)
export const fetchLiveFeed   = (limit = 20) => api<LiveFeedItem[]>(`/overview/live-feed?limit=${limit}`)

// ── SIEM ─────────────────────────────────────────────────────────────
export const fetchSiemAlerts = (params?: Record<string, string>) => {
  const q = params ? '?' + new URLSearchParams(params).toString() : ''
  return api<{ total: number; items: SiemAlert[] }>(`/siem/alerts${q}`)
}
export const patchAlert   = (id: string, body: Partial<Pick<SiemAlert, 'status' | 'disposition' | 'owner'>>) =>
  api<SiemAlert>(`/siem/alerts/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
export const createAlert = (body: {
  title: string; severity?: string; description?: string
  srcIp?: string; srcCountry?: string; mitreTechId?: string; mitreTactic?: string
  ruleName?: string; hostname?: string; username?: string; tiHits?: number
}) =>
  api<SiemAlert>('/siem/alerts', {
    method: 'POST',
    body: JSON.stringify({
      title: body.title, severity: body.severity, description: body.description,
      src_ip: body.srcIp, src_country: body.srcCountry,
      mitre_tech_id: body.mitreTechId, mitre_tactic: body.mitreTactic,
      ...(body.ruleName ? { rule_name: body.ruleName } : {}),
      hostname: body.hostname, username: body.username,
      ...(body.tiHits !== undefined ? { ti_hits: body.tiHits } : {}),
    }),
  })
export const fetchSiemKpis = () => api<SiemKpis>('/siem/kpis')
export const fetchRules    = () => api<Rule[]>('/siem/rules')
export const patchRule     = (id: string, body: { status?: string; severityOverride?: string; suppressionWindow?: number }) =>
  api<Rule>(`/siem/rules/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({
      status: body.status,
      severity_override: body.severityOverride,
      suppression_window: body.suppressionWindow,
    }),
  })
export const deleteRule = (id: string) =>
  api<void>(`/siem/rules/${id}`, { method: 'DELETE' })

// ── Alert tuning: suppressions / allow-lists ─────────────────────────
export interface Suppression {
  id: string; ruleId: string; field: 'src_ip' | 'username' | 'hostname'
  value: string; mode: 'suppress' | 'allow'; reason: string | null
  hits: number; createdAt: string; createdBy: string | null
}
export const fetchSuppressions = () => api<Suppression[]>('/siem/suppressions')
export const createSuppression = (body: {
  value: string; field?: string; ruleId?: string; mode?: string; reason?: string
}) =>
  api<Suppression>('/siem/suppressions', {
    method: 'POST',
    body: JSON.stringify({
      value: body.value, field: body.field, rule_id: body.ruleId,
      mode: body.mode, reason: body.reason,
    }),
  })
export const deleteSuppression = (id: string) =>
  api<void>(`/siem/suppressions/${id}`, { method: 'DELETE' })

// ── Detection rule editor ────────────────────────────────────────────
export interface RuleCondition { field: string; op: string; value: string }
export interface RuleDefinition {
  conditions: RuleCondition[]
  logic: 'and' | 'or'
  aggregation?: { groupBy: string; threshold: number; windowMinutes: number }
  throttleMinutes?: number
}
export interface RuleSchema {
  fields: string[]; operators: string[]; eventTypes: string[]; groupByFields: string[]
}
export const fetchRuleSchema = () => api<RuleSchema>('/siem/rule-schema')
export const testRule = (definition: RuleDefinition) =>
  api<{ matched: number; scanned: number; sample: Array<{ entity: string; count: number; ts: string; raw: string }> }>(
    '/siem/rules/test', { method: 'POST', body: JSON.stringify({ definition }) })
export const createDetectionRule = (body: {
  name: string; category?: string; severity?: string
  mitreTactic?: string; mitreTechId?: string; mitreTech?: string
  description?: string; definition: RuleDefinition
}) => api<Rule>('/siem/rules', { method: 'POST', body: JSON.stringify({
  name: body.name, category: body.category, severity: body.severity,
  mitre_tactic: body.mitreTactic, mitre_tech_id: body.mitreTechId, mitre_tech: body.mitreTech,
  description: body.description, definition: body.definition,
}) })
export const updateRuleDefinition = (id: string, definition: RuleDefinition) =>
  api<Rule>(`/siem/rules/${id}`, { method: 'PATCH', body: JSON.stringify({ definition }) })

// ── Native log ingestion + ATT&CK coverage ──────────────────────────
export const ingestLogs = (lines: string[], format = 'auto', source = 'collector') =>
  api<{ ingested: number; parsed: number; alerts: number; tiMatches: number; source: string }>(
    '/siem/ingest', { method: 'POST', body: JSON.stringify({ lines, format, source }) })

export interface AttackTechnique { technique: string; name: string; rules: number; alerts: number; covered: boolean }
export interface AttackCoverage {
  tactics: Array<{ tactic: string; techniques: AttackTechnique[] }>
  summary: { techniques: number; covered: number; gaps: number; coveragePct: number }
}
export const fetchAttackCoverage = () => api<AttackCoverage>('/siem/attack-coverage')

// ── UEBA (entity risk analytics) ─────────────────────────────────────
export interface RiskEntity {
  value: string; type: 'user' | 'host' | 'ip'; risk: number; alerts: number
  band: 'critical' | 'high' | 'elevated' | 'normal'; open: number
  techniques: string[]; techniqueCount: number; lastSeen: string | null
  bySeverity: Record<string, number>
}
export const fetchEntities = (type = 'all', limit = 25) =>
  api<{ entities: RiskEntity[]; summary: { tracked: number; highRisk: number } }>(
    `/siem/entities?type=${type}&limit=${limit}`)
export interface EntityDetail {
  value: string; type: string; risk: number; alertCount: number
  timeline: Array<{ day: string; count: number }>
  topTechniques: Array<{ technique: string; count: number }>
  alerts: Array<{ id: string; title: string; severity: string; ts: string; status: string; rule_name: string; mitre_tech_id: string }>
}
export const fetchEntityDetail = (type: string, value: string) =>
  api<EntityDetail>(`/siem/entities/detail?type=${type}&value=${encodeURIComponent(value)}`)

// ── Platform: notifications, search, schedules, views, audit ─────────
export interface Notification {
  id: string; ts: string; type: string; severity: string | null
  title: string; detail: string | null; link: string | null; read: number
}
export const fetchNotifications = (unreadOnly = false) =>
  api<{ items: Notification[]; unread: number }>(`/notifications${unreadOnly ? '?unread_only=true' : ''}`)
export const markNotificationRead = (id?: string) =>
  api<{ ok: boolean }>('/notifications/read', { method: 'POST', body: JSON.stringify(id ? { id } : {}) })

export interface SearchResult { kind: string; label: string; sub: string | null; severity: string | null; link: string }
export const globalSearch = (q: string) =>
  api<{ query: string; results: SearchResult[] }>(`/search?q=${encodeURIComponent(q)}`)

export interface ReportSchedule {
  id: string; kind: string; period: string; cadence: string
  webhookUrl: string | null; enabled: number; lastRun: string | null; createdBy: string | null
}
export const fetchReportSchedules = () => api<ReportSchedule[]>('/report-schedules')
export const createReportSchedule = (body: { kind: string; period?: string; cadence?: string; webhook_url?: string }) =>
  api<ReportSchedule>('/report-schedules', { method: 'POST', body: JSON.stringify(body) })
export const runReportSchedule = (id: string) =>
  api<{ generated: boolean; delivered: boolean; title: string }>(`/report-schedules/${id}/run`, { method: 'POST' })
export const deleteReportSchedule = (id: string) =>
  api<void>(`/report-schedules/${id}`, { method: 'DELETE' })

export interface SavedView { id: string; section: string; name: string; filters: Record<string, string>; createdAt: string }
export const fetchSavedViews = (section: string) => api<SavedView[]>(`/saved-views?section=${section}`)
export const createSavedView = (section: string, name: string, filters: Record<string, string>) =>
  api<SavedView>('/saved-views', { method: 'POST', body: JSON.stringify({ section, name, filters }) })
export const deleteSavedView = (id: string) => api<void>(`/saved-views/${id}`, { method: 'DELETE' })

export const enforceRetention = () =>
  api<{ retentionDays: number; cutoff: string; purged: Record<string, number> }>('/config/retention/enforce', { method: 'POST' })
export const fetchSiemSources = () => api<LogSource[]>('/siem/sources')
export const createLogSource = (body: { name: string; type?: string; host?: string; format?: string; tags?: string[] }) =>
  api<LogSource>('/siem/sources', { method: 'POST', body: JSON.stringify(body) })
export const createRule = (body: {
  name: string; category?: string; severity?: string
  mitreTactic?: string; mitreTechId?: string; mitreTech?: string
  description?: string; kql?: string; tags?: string[]
}) =>
  api<Rule>('/siem/rules', {
    method: 'POST',
    body: JSON.stringify({
      name: body.name, category: body.category, severity: body.severity,
      mitre_tactic: body.mitreTactic, mitre_tech_id: body.mitreTechId, mitre_tech: body.mitreTech,
      description: body.description, kql: body.kql, tags: body.tags,
    }),
  })
export const fetchSiemHunts  = () => api<SavedHunt[]>('/siem/hunts')

export interface HuntQueryRow {
  alertId: string
  ts: string
  srcIp: string | null
  destIp: string | null
  destPort: number | null
  protocol: string
  bytes: number
  interval: number
  host: string
  title: string
  severity: string
  technique: string | null
  riskScore: number | null
}
export interface HuntQueryResult {
  scanned: number
  hits: number
  elapsedMs: number
  tokens: { techniques: string[]; ips: string[]; severities: string[]; keywords: string[] }
  results: HuntQueryRow[]
}
export const runHuntQuery = (query: string, timeRange: string) =>
  api<HuntQueryResult>('/siem/hunt-query', {
    method: 'POST',
    body: JSON.stringify({ query, time_range: timeRange }),
  })

// Event-stream search language (field operators + stats over raw events)
export interface EventSearchRow {
  id: string; ts: string | null; category: string | null; eventType: string | null
  srcIp: string | null; destIp: string | null; destPort: number | null
  username: string | null; hostname: string | null; processName: string | null
  action: string | null; bytesOut: number | null; mitreTechId: string | null; raw: string | null
}
export interface EventSearchResult {
  scanned: number; hits: number; elapsedMs: number; groupCount?: number
  interpreted: {
    conditions: Array<{ field: string; op: string; value: string }>
    freetext: string[]; stats: { by: string } | null
  }
  stats: { by: string; groups: Array<{ value: string; count: number }> } | null
  results: EventSearchRow[]
}
export const eventSearch = (query: string, timeRange = '24h') =>
  api<EventSearchResult>('/siem/search', {
    method: 'POST',
    body: JSON.stringify({ query, time_range: timeRange }),
  })

export interface HuntRunOutcome { hunt: SavedHunt; run: { scanned: number; hits: number; elapsedMs: number } }
export const createSiemHunt = (body: { name: string; description?: string; query?: string; technique?: string }) =>
  api<SavedHunt>('/siem/hunts', { method: 'POST', body: JSON.stringify(body) })
export const runSiemHunt = (id: string) =>
  api<HuntRunOutcome>(`/siem/hunts/${id}/run`, { method: 'POST' })
export const fetchCorrelations = (minAlerts = 2) =>
  api<Correlation[]>(`/siem/correlations?min_alerts=${minAlerts}`)
export const fetchMitreDistribution = () =>
  api<Array<{ tactic: string; count: number; color: string }>>('/siem/mitre-distribution')

// ── SOAR ─────────────────────────────────────────────────────────────
export const fetchCases = (params?: Record<string, string>) => {
  const q = params ? '?' + new URLSearchParams(params).toString() : ''
  return api<Case[]>(`/soar/cases${q}`)
}
export const patchCase = (id: string, body: Partial<Pick<Case, 'status' | 'owner' | 'severity'>>) =>
  api<Case>(`/soar/cases/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
export const createCase = (body: {
  title: string; severity?: string; type?: string; description?: string
  owner?: string; slaHours?: number; alertCount?: number
  entities?: Array<{ type: string; value: string }>
}) =>
  api<Case>('/soar/cases', {
    method: 'POST',
    body: JSON.stringify({
      title: body.title, severity: body.severity, type: body.type,
      description: body.description, owner: body.owner,
      ...(body.slaHours !== undefined ? { sla_hours: body.slaHours } : {}),
      ...(body.alertCount !== undefined ? { alert_count: body.alertCount } : {}),
      entities: body.entities,
    }),
  })
export const addCaseNote = (id: string, content: string, type = 'manual') =>
  api<Case>(`/soar/cases/${id}/notes`, { method: 'POST', body: JSON.stringify({ content, type }) })
export const patchCaseTask = (caseId: string, taskId: string, body: { status?: string; assignee?: string; notes?: string }) =>
  api<Case>(`/soar/cases/${caseId}/tasks/${taskId}`, { method: 'PATCH', body: JSON.stringify(body) })
export const fetchPlaybooks = () => api<Playbook[]>('/soar/playbooks')

// ── Playbook execution engine ────────────────────────────────────────
export interface PlaybookRunStep {
  idx: number; kind: string | null; name: string
  status: 'success' | 'skipped' | 'failed' | 'pending-approval'
  detail: string; ts: string
}
export interface PlaybookRun {
  id: string; playbookId: string; playbookName: string | null
  ts: string; finished: string | null
  status: 'success' | 'failed' | 'awaiting-approval' | 'rejected'
  trigger: 'manual' | 'auto'; actor: string | null; alertId: string | null
  currentStep: number
  context: { alert?: Record<string, unknown> | null; entity?: { type: string; value: string } | null; caseId?: string | null }
  steps: PlaybookRunStep[]
}
export const runPlaybook = (id: string, opts?: { alertId?: string }) =>
  api<Playbook & { run: PlaybookRun }>(`/soar/playbooks/${id}/run`, {
    method: 'POST',
    ...(opts?.alertId ? { body: JSON.stringify({ alert_id: opts.alertId }) } : {}),
  })
export const dryRunPlaybook = (id: string, alertId?: string) =>
  api<{ dryRun: boolean; run: PlaybookRun }>(`/soar/playbooks/${id}/run`, {
    method: 'POST',
    body: JSON.stringify({ dry_run: true, ...(alertId ? { alert_id: alertId } : {}) }),
  })
export const fetchPlaybookRuns = (playbookId: string, limit = 20) =>
  api<PlaybookRun[]>(`/soar/playbooks/${playbookId}/runs?limit=${limit}`)
export const fetchSoarRuns = (status?: string, limit = 30) =>
  api<{ items: PlaybookRun[]; awaitingApproval: number }>(
    `/soar/runs?limit=${limit}${status ? `&status=${status}` : ''}`)
export const approvePlaybookRun = (runId: string) =>
  api<PlaybookRun>(`/soar/runs/${runId}/approve`, { method: 'POST' })
export const rejectPlaybookRun = (runId: string) =>
  api<PlaybookRun>(`/soar/runs/${runId}/reject`, { method: 'POST' })
export const updatePlaybook = (id: string, body: {
  enabled?: boolean; steps?: Array<{ kind: string; name: string; params?: Record<string, unknown> }>
  triggerMatch?: Record<string, unknown>; triggerType?: string; description?: string
}) =>
  api<Playbook>(`/soar/playbooks/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({
      enabled: body.enabled, steps: body.steps, trigger_match: body.triggerMatch,
      trigger_type: body.triggerType, description: body.description,
    }),
  })
export const fetchSoarIntegrations = () => api<Integration[]>('/soar/integrations')
export const createIntegration = (body: {
  name: string; vendor?: string; category?: string; description?: string; actions?: string[]
}) => api<Integration>('/soar/integrations', { method: 'POST', body: JSON.stringify(body) })
export const testIntegration = (id: string) =>
  api<Integration>(`/soar/integrations/${id}/test`, { method: 'POST' })
export const runIntegrationAction = (id: string, action: string) =>
  api<Integration & { actionsRun: number }>(`/soar/integrations/${id}/actions/run`, {
    method: 'POST', body: JSON.stringify({ action }),
  })
export const fetchSoarMetrics = () => api<SoarMetrics>('/soar/metrics')

// ── CTI ──────────────────────────────────────────────────────────────
export const fetchActors  = () => api<Actor[]>('/cti/actors')
export const fetchIocs    = (params?: Record<string, string>) => {
  const q = params ? '?' + new URLSearchParams(params).toString() : ''
  return api<{ total: number; items: Ioc[] }>(`/cti/iocs${q}`)
}
export const fetchIocTypes  = () => api<IocType[]>('/cti/ioc-types')
export const fetchCtiSummary = () => api<CtiSummary>('/cti/summary')
export const lookupIoc = (value: string) =>
  api<IocLookup>(`/cti/lookup?value=${encodeURIComponent(value)}`)
export interface ImportResult { imported: number; duplicates: number; skipped: number; total: number }
export const importIocs = (body: {
  indicators: { type: string; value: string }[]
  confidence?: number; severity?: string; source?: string
  actor?: string; threat_type?: string; tags?: string[]
}) => api<ImportResult>('/cti/iocs/import', { method: 'POST', body: JSON.stringify(body) })
export interface ScanEntry {
  id: string
  ts: string
  target: string
  type: string
  verdict: 'malicious' | 'suspicious' | 'clean'
  score: number
  engines: string | null
  actor: string | null
}
export const recordScan = (body: { target: string; type: string; verdict: string; score?: number; engines?: string }) =>
  api<ScanEntry>('/cti/scans', { method: 'POST', body: JSON.stringify(body) })
export const fetchScans = (limit = 20) =>
  api<{ items: ScanEntry[]; scansToday: number; malicious: number }>(`/cti/scans?limit=${limit}`)

export const fetchCtiHunts  = () => api<SavedHunt[]>('/cti/hunts')
export const createCtiHunt = (body: { name: string; description?: string; query?: string; technique?: string }) =>
  api<SavedHunt>('/cti/hunts', { method: 'POST', body: JSON.stringify(body) })
export const runCtiHunt = (id: string) =>
  api<HuntRunOutcome>(`/cti/hunts/${id}/run`, { method: 'POST' })
export const fetchCtiGraph  = () => api<CtiGraph>('/cti/graph')

// ── Assets ───────────────────────────────────────────────────────────
export const fetchAssets = (params?: Record<string, string>) => {
  const q = params ? '?' + new URLSearchParams(params).toString() : ''
  return api<{ total: number; items: Asset[] }>(`/assets${q}`)
}
export const fetchAsset = (id: string) => api<AssetDetail>(`/assets/${id}`)
export const createAsset = (body: {
  name: string; type: string; value: string; criticality: string
  os?: string; owner?: string; tags?: string[]
}) => api<Asset>('/assets', { method: 'POST', body: JSON.stringify(body) })
export const fetchRiskDistribution = () => api<RiskDistribution>('/assets/risk-distribution')
export const fetchAssetsSummary = () => api<AssetSummary>('/assets/summary')
export const fetchVulns = () => api<Asset[]>('/assets/vulns')
export const recomputeAssetRisk = () =>
  api<{ updated: number }>('/assets/recompute-risk', { method: 'POST' })

// ── Feeds ─────────────────────────────────────────────────────────────
export const fetchFeeds   = () => api<Feed[]>('/feeds')
export const createFeed = (body: {
  name: string; provider?: string; type?: string; url?: string
  format?: string; syncInterval?: number; reliability?: string
}) =>
  api<Feed>('/feeds', {
    method: 'POST',
    body: JSON.stringify({
      name: body.name, provider: body.provider, type: body.type, url: body.url,
      format: body.format, reliability: body.reliability,
      ...(body.syncInterval !== undefined ? { sync_interval: body.syncInterval } : {}),
    }),
  })
export const fetchFeedsSummary = () => api<FeedsSummary>('/feeds/summary')
export const toggleFeed   = (id: string, enabled: boolean) =>
  api<Feed>(`/feeds/${id}`, { method: 'PATCH', body: JSON.stringify({ enabled }) })

// ── Config ────────────────────────────────────────────────────────────
export const fetchSettings   = () => api<Record<string, string>>('/config/settings')
export const updateSettings  = (values: Record<string, string>) =>
  api<Record<string, string>>('/config/settings', { method: 'PUT', body: JSON.stringify({ values }) })
export const fetchApiKeys    = () => api<ApiKey[]>('/config/api-keys')
export const createApiKey    = (name: string, scope = 'read') =>
  api<ApiKey & { secret: string }>('/config/api-keys', { method: 'POST', body: JSON.stringify({ name, scope }) })
export const revokeApiKey    = (id: string) =>
  api<void>(`/config/api-keys/${id}`, { method: 'DELETE' })
export interface Webhook {
  id: string
  url: string
  events: string[]
  status: 'active' | 'paused' | 'failing'
  lastDelivery: string | null
  createdAt: string
  createdBy: string | null
}
export const fetchWebhooks = () => api<Webhook[]>('/config/webhooks')
export const createWebhook = (url: string, events: string[]) =>
  api<Webhook>('/config/webhooks', { method: 'POST', body: JSON.stringify({ url, events }) })
export const patchWebhook = (id: string, body: { status?: string; events?: string[] }) =>
  api<Webhook>(`/config/webhooks/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
export const deleteWebhook = (id: string) =>
  api<void>(`/config/webhooks/${id}`, { method: 'DELETE' })
export const testWebhook = (id: string) =>
  api<{ ok: boolean; status: string; lastDelivery: string | null }>(`/config/webhooks/${id}/test`, { method: 'POST' })

export interface JobEntry {
  id: string
  kind: string
  status: string
  progress: number
  createdAt: string
  updatedAt: string
  meta: Record<string, unknown>
}
export const fetchJobs = (limit = 25) => api<JobEntry[]>(`/config/jobs?limit=${limit}`)

export const fetchAuditLog   = (limit = 100, action?: string) => {
  const q = new URLSearchParams({ limit: String(limit), ...(action ? { action } : {}) })
  return api<AuditEntry[]>(`/config/audit-log?${q.toString()}`)
}

// ── Reports (structured, Nessus-style) ───────────────────────────────
export interface ReportFinding {
  title: string
  severity: string
  score?: number
  ts?: string | null
  entity?: string
  technique?: string | null
  tactic?: string | null
  rule?: string | null
  status?: string
  detail?: string
}
export interface ReportData {
  meta: { kind: string; title: string; period: string; from: string; to: string; generatedAt: string }
  summary: { headline: Array<{ label: string; value: number | string; color?: string }>; narrative: string }
  breakdowns: Array<{ heading: string; type: 'severity' | 'bars'; data: Array<{ label?: string; severity?: string; count: number; color?: string }> }>
  findings: ReportFinding[]
  recommendations: string[]
  sections?: string[]
}
export const fetchReportKinds = () => api<Array<{ kind: string; label: string }>>('/reports/kinds')
export const fetchReport = (kind: string, period: string, from?: string, to?: string) => {
  const q = new URLSearchParams({ period })
  if (from) q.set('from', from)
  if (to) q.set('to', to)
  return api<ReportData>(`/reports/${kind}?${q.toString()}`)
}

// ── Dark Web monitoring ──────────────────────────────────────────────
export interface DarkWebFinding {
  id: string
  ts: string
  category: 'credential-leak' | 'data-for-sale' | 'brand-mention' | 'actor-chatter' | 'infrastructure'
  severity: 'critical' | 'high' | 'medium' | 'low'
  source: string
  title: string
  entity: string
  actor: string
  detail: string
  url: string
  status: 'new' | 'investigating' | 'mitigated' | 'dismissed'
}
export interface DarkWebSummary {
  total: number
  critical: number
  credentialLeaks: number
  open: number
  byCategory: Record<string, number>
  last24h: number
}
export const fetchDarkWebFindings = (params?: Record<string, string>) => {
  const q = params ? '?' + new URLSearchParams(params).toString() : ''
  return api<{ total: number; items: DarkWebFinding[] }>(`/darkweb/findings${q}`)
}
export const fetchDarkWebSummary = () => api<DarkWebSummary>('/darkweb/summary')
export const updateDarkWebFinding = (id: string, status: string) =>
  api<DarkWebFinding>(`/darkweb/findings/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) })

// ── Live engine control ──────────────────────────────────────────────
export interface EngineStatus {
  mode: string
  running: boolean
  enabled: boolean
  tickSeconds: number
  alertsProduced: number
  totalAlerts: number
  darkWebFindings: number
}
export const fetchEngineStatus = () => api<EngineStatus>('/config/engine')
export const controlEngine = (body: { enabled?: boolean; generate?: number }) =>
  api<{ enabled?: boolean; generated?: Record<string, number> }>('/config/engine', {
    method: 'POST', body: JSON.stringify(body),
  })

// ── Connectors (real threat-intel ingestion) ────────────────────────
export interface Connector {
  id: string
  name: string
  kind: string
  url: string | null
  authHeader: string | null
  enabled: number
  intervalMinutes: number
  fieldMap: Record<string, string>
  status: string
  lastRun: string | null
  lastError: string | null
  indicatorCount: number
  builtin: number
  hasKey?: number
  createdAt: string
  createdBy: string | null
}
export interface ConnectorKind {
  kind: string
  label: string
  description: string
  needs_key: boolean
  default_url: string
  default_interval: number
}
export const fetchConnectors = () => api<Connector[]>('/connectors')
export const fetchConnectorKinds = () => api<ConnectorKind[]>('/connectors/kinds')
export const createConnector = (body: {
  name: string; kind: string; url?: string; api_key?: string
  auth_header?: string; interval_minutes?: number; field_map?: Record<string, string>
}) => api<Connector>('/connectors', { method: 'POST', body: JSON.stringify(body) })
export const patchConnector = (id: string, body: Partial<{
  name: string; url: string; api_key: string; auth_header: string
  interval_minutes: number; field_map: Record<string, string>; enabled: boolean
}>) => api<Connector>(`/connectors/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
export const deleteConnector = (id: string) =>
  api<void>(`/connectors/${id}`, { method: 'DELETE' })
export interface ConnectorRunResult {
  result: { imported?: number; duplicates?: number; skipped?: number; total?: number; error?: string }
  connector: Connector
}
export const runConnector = (id: string) =>
  api<ConnectorRunResult>(`/connectors/${id}/run`, { method: 'POST' })

// ── Companion services (Threat API + Log API, proxied server-side) ───
export interface ServiceState { url: string; available: boolean; health: unknown }
export interface ServicesStatus { threatApi: ServiceState; logApi: ServiceState; keyConfigured: boolean }
export const fetchServicesStatus = () => api<ServicesStatus>('/services/status')

export interface SourceHealthEntry {
  source: string
  status: string
  lastSuccess?: string | null
  lastError?: string | null
  consecutiveFailures?: number
}
export const fetchThreatSourceHealth = () =>
  api<{ available: boolean; sources: SourceHealthEntry[] | Record<string, unknown> }>('/services/threat/source-health')
export const triggerThreatFetch = () =>
  api<{ jobId?: string; job_id?: string; status?: string }>('/services/threat/fetch', { method: 'POST' })
export const syncThreatIocs = () =>
  api<ImportResult>('/services/threat/sync-iocs', { method: 'POST' })
export const fetchOpenCtiStatus = () =>
  api<{ available: boolean; connected?: boolean }>('/services/threat/opencti-status')

export interface LogAnalysisResult {
  resultId?: string
  status?: string
  jobId?: string
  summary?: Record<string, unknown>
  findings?: Array<Record<string, unknown>>
  anomalies?: Array<Record<string, unknown>>
  [key: string]: unknown
}
// Multipart upload — bypasses the JSON wrapper so the browser sets the boundary.
export async function analyseLogFile(file: globalThis.File, logFormat = 'generic'): Promise<LogAnalysisResult> {
  const tok = typeof window !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null
  const form = new FormData()
  form.append('file', file)
  form.append('log_format', logFormat)
  const res = await fetch(`${BASE}/services/logs/analyse`, {
    method: 'POST',
    headers: tok ? { Authorization: `Bearer ${tok}` } : {},
    body: form,
  })
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try { const j = await res.json(); msg = j.detail ?? j.error ?? msg } catch { /* ignore */ }
    throw new Error(msg)
  }
  return toCamel(await res.json()) as LogAnalysisResult
}

// ── Users ─────────────────────────────────────────────────────────────
export const fetchUsers = () => api<User[]>('/users')
export const createUser = (body: { email: string; password: string; name: string; role: UserRole }) =>
  api<User>('/users', { method: 'POST', body: JSON.stringify(body) })
export const patchUser  = (id: string, body: Partial<Pick<User, 'name' | 'role' | 'status'>> & { mfaEnabled?: boolean }) =>
  api<User>(`/users/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({
      name: body.name, role: body.role, status: body.status,
      ...(body.mfaEnabled !== undefined ? { mfa_enabled: body.mfaEnabled } : {}),
    }),
  })
export const deleteUser = (id: string) => api<void>(`/users/${id}`, { method: 'DELETE' })
