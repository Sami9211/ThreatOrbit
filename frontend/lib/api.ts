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

// Server-Sent Events URL. EventSource can't set an Authorization header, so
// rather than leak the long-lived session JWT in the URL (proxy logs, browser
// history, Referer), we mint a short-lived, single-use stream ticket via
// POST /stream/ticket (sent with the normal Authorization header) and pass THAT
// in the query string. Single-use → fetch a fresh one for every (re)connect.
export async function fetchStreamUrl(): Promise<string | null> {
  if (typeof window === 'undefined') return null
  const tok = localStorage.getItem(TOKEN_KEY)
  if (!tok) return null
  try {
    const res = await fetch(`${BASE}/stream/ticket`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tok}` },
    })
    if (!res.ok) return null
    const { ticket } = await res.json()
    return ticket ? `${BASE}/stream?ticket=${encodeURIComponent(ticket)}` : null
  } catch {
    return null
  }
}

// RBAC: the caller's effective capabilities (UI gates controls on these).
export interface MyPermissions {
  role: string
  permissions: string[]
  capabilities: Record<string, boolean>
}

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
    // The API wraps errors as {"error": ...}; older/3rd-party paths use {"detail": ...}.
    try { const j = await res.json(); msg = j.detail ?? j.error ?? msg } catch { /* ignore */ }
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
  noise?: string | null   // authored noisiness hint (low|medium|high), distinct from observed fpRate
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
  successRate: number   // percent 0–100 (converted from the API's 0–1 fraction)
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
  slaBreached: number
  mttr: number
  /** Real week-over-week MTTR movement (%); null when there is no prior-week baseline. */
  mttrTrendPct: number | null
  automationRate: number
  /** Automation-rate movement in percentage points vs the prior week; null without a baseline. */
  automationTrendPp: number | null
  timeSavedMonth: number
  totalRuns: number
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
  status: 'active' | 'expired' | 'known-good'
  sightings: number
  effectiveConfidence: number
}

export interface IocLifecycle {
  effectiveConfidence: number; assertedConfidence: number
  ageDays: number; halfLifeDays: number; sightings: number
  status: 'active' | 'expired' | 'known-good'; expiresInDays: number | null
}
export interface IocDetail extends Ioc {
  lifecycle: IocLifecycle
  sightingsHistory: Array<{ id: string; ts: string; source: string | null; context: string | null }>
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
  activeIocs: number
  expiredIocs: number
  knownGoodIocs: number
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

export interface CtiGraphNode {
  id: string; label: string; group: string; level?: string; size: number; iocType?: string
}
export interface CtiGraph {
  nodes: CtiGraphNode[]
  links: Array<{ source: string; target: string; kind: string }>
  focus?: string | null
  counts?: Record<string, number>
}
export interface GraphPath {
  found: boolean; reason?: string; hops?: number
  path: CtiGraphNode[]
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
  orgId?: string
  requestsToday?: number   // real per-key telemetry (api_key_usage buckets)
  requestsTotal?: number
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
export const authLogin = (email: string, password: string, code?: string) =>
  api<{ token: string; user: User }>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password, ...(code ? { code } : {}) }),
  })

// TOTP MFA: enrolment is user-driven; the secret is shown once at enrol time.
export const fetchMfaStatus = () => api<{ enabled: boolean; pending: boolean; recoveryCodesRemaining: number }>('/auth/mfa')
export const mfaEnroll = () => api<{ secret: string; otpauthUri: string }>('/auth/mfa/enroll', { method: 'POST' })
export const mfaVerify = (code: string) =>
  api<{ enabled: boolean; recoveryCodes?: string[] }>('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ code }) })
export const mfaDisable = (code: string) =>
  api<{ enabled: boolean }>('/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ code }) })
// One-time backup codes for a lost authenticator; regenerate invalidates the old set.
export const mfaRegenerateRecoveryCodes = (code: string) =>
  api<{ recoveryCodes: string[] }>('/auth/mfa/recovery-codes', { method: 'POST', body: JSON.stringify({ code }) })

export const authRegister = (body: { name: string; email: string; password: string; company?: string }) =>
  api<{ token: string; user: User }>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(body),
  })

export const authMe = () => api<User>('/auth/me')
export const fetchMyPermissions = () => api<MyPermissions>('/auth/permissions')

// Organization mode (simple|power): which feature areas the UI surfaces. A
// UI-curation preference, not a security boundary — the backend keeps
// enforcing real RBAC regardless of what this hides.
export interface OrgMode {
  mode: 'simple' | 'power'
  features: string[]
  /** Whether the org has actually CHOSEN a mode, vs `mode` just being the
   * un-set 'power' fallback. Callers with their own pre-existing local
   * default should only let this response override it when true. */
  explicit: boolean
}
export const fetchOrgMode = () => api<OrgMode>('/config/mode')
export const setOrgMode   = (mode: 'simple' | 'power') =>
  api<OrgMode>('/config/mode', { method: 'PUT', body: JSON.stringify({ mode }) })

// SSO (OIDC) - degrades to { configured: false }. The login link is a full
// browser navigation to the backend, which redirects to the identity provider.
export const fetchSsoStatus = () => api<{ configured: boolean; loginPath: string }>('/auth/sso/status')
export const ssoLoginUrl = () => `${BASE}/auth/sso/login`
// SAML SP - same callback contract as OIDC: the ACS lands on /login with the
// session token in the URL fragment, read by the existing fragment handler.
export const fetchSamlStatus = () => api<{ configured: boolean; loginPath: string }>('/auth/saml/status')
export const samlLoginUrl = () => `${BASE}/auth/saml/login`

// Workspaces (multi-tenancy foundation).
export interface Org {
  id: string; name: string; slug: string; plan: string; status: string
  users?: number; isolationEnforced?: boolean
}
export const fetchCurrentOrg = () => api<Org>('/orgs/current')
export const fetchOrgs = () => api<Org[]>('/orgs')
export const createOrg = (body: { name: string; plan?: string; slug?: string }) =>
  api<Org>('/orgs', { method: 'POST', body: JSON.stringify(body) })

export const authChangePassword = (currentPassword: string, newPassword: string) =>
  api<{ ok: boolean; token?: string }>('/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  }).then((r) => {
    // The backend revokes the user's OTHER sessions and returns a fresh token
    // for this one; persist it so this session continues without a re-login.
    if (r.token && typeof window !== 'undefined') localStorage.setItem(TOKEN_KEY, r.token)
    return r
  })

// Sign out everywhere: invalidates all of the caller's tokens (this one too).
export const authRevokeAllSessions = () =>
  api<{ ok: boolean; revokedAt: number }>('/auth/sessions/revoke-all', { method: 'POST' })

// Per-device sessions: list your active logins and sign individual ones out.
export interface SessionInfo {
  id: string
  createdAt: string
  lastSeen: string
  userAgent: string | null
  ip: string | null
  current: boolean
}
export const fetchSessions = () => api<SessionInfo[]>('/auth/sessions')
export const revokeSession = (id: string) =>
  api<{ ok: boolean }>(`/auth/sessions/${id}/revoke`, { method: 'POST' })

// ── Overview ─────────────────────────────────────────────────────────
export const fetchKpis    = () => api<OverviewKpis>('/overview/kpis')
export const fetchVectors = () => api<ThreatVector[]>('/overview/threat-vectors')
export const fetchHourly  = () => api<number[]>('/overview/hourly-volume')
export interface AlertVolumeDay { day: string; date: string; critical: number; high: number; medium: number; low: number; info: number }
export interface DispositionStat { key: string; label: string; count: number }
export interface AlertAnalytics { volume: AlertVolumeDay[]; disposition: DispositionStat[] }
export const fetchAlertAnalytics = () => api<AlertAnalytics>('/overview/alert-analytics')
export interface GeoCountry { country: string; iso2: string | null; observed: number; critical: number; high: number; lastSeen: string | null }
export const fetchGeo = (limit = 20) =>
  api<{ countries: GeoCountry[]; totalGeolocated: number }>(`/overview/geo?limit=${limit}`)
export const fetchHeatmap = () => api<Array<{ label: string; vals: number[] }>>('/overview/mitre-heatmap')
export const fetchRecentAlerts    = (limit = 8)  => api<OverviewAlert[]>(`/overview/recent-alerts?limit=${limit}`)
export const fetchRecentIncidents = (limit = 6)  => api<Incident[]>(`/overview/recent-incidents?limit=${limit}`)
export const fetchTopActors  = (limit = 5)  => api<TopActor[]>(`/overview/top-actors?limit=${limit}`)
export const fetchLiveFeed   = (limit = 20) => api<LiveFeedItem[]>(`/overview/live-feed?limit=${limit}`)

// Evidence-based false-positive likelihood - advisory only, never mutates
// the alert/IOC it scores. Same shape for both alerts and IOCs.
export interface FpEvidence { signal: string; weight: number; detail: string }
export interface FpAssessment { score: number; band: 'likely-fp' | 'uncertain' | 'likely-real'; evidence: FpEvidence[] }

// ── SIEM ─────────────────────────────────────────────────────────────
export const fetchSiemAlerts = (params?: Record<string, string>) => {
  const q = params ? '?' + new URLSearchParams(params).toString() : ''
  return api<{ total: number; items: SiemAlert[] }>(`/siem/alerts${q}`)
}
export const patchAlert   = (id: string, body: Partial<Pick<SiemAlert, 'status' | 'disposition' | 'owner'>>) =>
  api<SiemAlert>(`/siem/alerts/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
export const fetchAlertFpAssessment = (id: string) => api<FpAssessment>(`/siem/alerts/${id}/fp-assessment`)

// Bulk FP-triage (Phase 3): score a bounded working set of open alerts and
// filter by band, then act on a selection in one call.
export interface FpTriageAlert extends SiemAlert { fpScore: number; fpBand: FpAssessment['band'] }
export const fetchFpTriage = (params?: { band?: string; severity?: string; limit?: number; offset?: number }) => {
  const q = params ? '?' + new URLSearchParams(
    Object.entries(params).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)])
  ).toString() : ''
  return api<{ total: number; workingSetSize: number; items: FpTriageAlert[] }>(`/siem/alerts/fp-triage${q}`)
}
export const bulkDismissAlerts = (ids: string[]) =>
  api<{ dismissed: number; notFound: string[] }>('/siem/alerts/bulk-dismiss',
    { method: 'POST', body: JSON.stringify({ ids }) })
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

export interface SlaBreach {
  id: string; title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; status: string
  owner: string | null; ageMinutes: number; riskScore: number
  mitreTactic: string; mitreTechId: string; srcIp: string; hostname: string | null
  ruleName: string; slaType: 'ack' | 'resolve'; thresholdMinutes: number
}
export interface SocTriage {
  open: { total: number; critical: number; high: number; medium: number; low: number; info: number; unassigned: number }
  byStatus: Record<string, number>
  oldestOpenMinutes: number
  sla: {
    breachCount: number
    breaches: SlaBreach[]
    ackThresholds: Record<string, number>
    resolveThresholds: Record<string, number>
  }
}
export const fetchTriage = () => api<SocTriage>('/siem/triage')

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
export const importSigmaRule = (yamlText: string) =>
  api<Rule & { importNotes: string[] }>('/siem/rules/import-sigma', {
    method: 'POST', body: JSON.stringify({ yaml: yamlText }),
  })
export interface SigmaPackImportResult {
  created: { id: string; name: string; importNotes: string[] }[]
  failed: { index: number; error: string }[]
  createdCount: number
  failedCount: number
}
export const importSigmaPack = (yamlText: string) =>
  api<SigmaPackImportResult>('/siem/rules/import-sigma-pack', {
    method: 'POST', body: JSON.stringify({ yaml: yamlText }),
  })
export const exportSigmaRule = (id: string) =>
  api<{ yaml: string; source: 'original' | 'generated' }>(`/siem/rules/${id}/sigma`)
// Load the curated starter detection pack (idempotent; returns created/skipped names).
export const loadDetectionPack = () =>
  api<{ created: string[]; skipped: string[] }>('/siem/rules/load-pack', { method: 'POST' })

// ── Alert tuning: suppressions / allow-lists ─────────────────────────
export interface Suppression {
  id: string; ruleId: string; field: 'src_ip' | 'username' | 'hostname'
  value: string; mode: 'suppress' | 'allow'; reason: string | null
  hits: number; createdAt: string; createdBy: string | null
  // Time-boxing: absolute expiry and/or a recurring daily UTC window.
  expiresAt: string | null; windowStart: string | null; windowEnd: string | null
  /** Computed server-side: whether the suppression applies right now. */
  active: boolean
}
export const fetchSuppressions = () => api<Suppression[]>('/siem/suppressions')
export const createSuppression = (body: {
  value: string; field?: string; ruleId?: string; mode?: string; reason?: string
  expiresHours?: number; windowStart?: string; windowEnd?: string
}) =>
  api<Suppression>('/siem/suppressions', {
    method: 'POST',
    body: JSON.stringify({
      value: body.value, field: body.field, rule_id: body.ruleId,
      mode: body.mode, reason: body.reason,
      expires_hours: body.expiresHours, window_start: body.windowStart,
      window_end: body.windowEnd,
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
  baseline: { mean: number; stdDev: number; current: number; zScore: number; deviating: boolean; confidence: string }
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
export const createReportSchedule = (body: { kind: string; period?: string; cadence?: string; webhook_url?: string; email?: string }) =>
  api<ReportSchedule>('/report-schedules', { method: 'POST', body: JSON.stringify(body) })
export const runReportSchedule = (id: string) =>
  api<{ generated: boolean; delivered: boolean; title: string }>(`/report-schedules/${id}/run`, { method: 'POST' })
export const deleteReportSchedule = (id: string) =>
  api<void>(`/report-schedules/${id}`, { method: 'DELETE' })

export interface SlackRouting { configured: boolean; webhookUrl: string | null; minSeverity: string }
export const fetchMySlackRouting = () => api<SlackRouting>('/auth/me/slack')
export const setMySlackRouting = (webhook_url: string | null, min_severity: string) =>
  api<SlackRouting>('/auth/me/slack', { method: 'PUT', body: JSON.stringify({ webhook_url, min_severity }) })
export const testMySlackRouting = () => api<{ delivered: boolean }>('/auth/me/slack/test', { method: 'POST' })

export interface SavedView { id: string; section: string; name: string; filters: Record<string, string>; created_at: string }
export const fetchSavedViews = (section: string) => api<SavedView[]>(`/saved-views?section=${section}`)
export const createSavedView = (section: string, name: string, filters: Record<string, string>) =>
  api<SavedView>('/saved-views', { method: 'POST', body: JSON.stringify({ section, name, filters }) })
export const deleteSavedView = (id: string) => api<void>(`/saved-views/${id}`, { method: 'DELETE' })

export const enforceRetention = () =>
  api<{ retentionDays: number; perTableDays?: Record<string, number>; purged: Record<string, number>
        archived?: Record<string, number | string>; archiveDir?: string }>('/config/retention/enforce', { method: 'POST' })
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
export const scheduleHunt = (id: string, scheduleMinutes: number, autoAlert = true) =>
  api<{ id: string; name: string; scheduleMinutes: number; status: string }>(
    `/siem/hunts/${id}/schedule`, { method: 'POST', body: JSON.stringify({ schedule_minutes: scheduleMinutes, auto_alert: autoAlert }) })
export const runScheduledHunts = () =>
  api<{ ran: number; alerts: number }>('/siem/hunts/run-scheduled', { method: 'POST' })
export interface LogListenerStatus {
  syslogPort: number | null; syslogEnabled: boolean
  syslogTlsPort?: number | null; syslogTlsEnabled?: boolean; syslogTlsMtls?: boolean
  watchDir: string | null; watchEnabled: boolean; watchIntervalSeconds: number
}
export const fetchLogListeners = () => api<LogListenerStatus>('/siem/log-listeners')
export const fetchCorrelations = (minAlerts = 2) =>
  api<Correlation[]>(`/siem/correlations?min_alerts=${minAlerts}`)
export const fetchMitreDistribution = () =>
  api<Array<{ tactic: string; count: number; color: string }>>('/siem/mitre-distribution')

export type SiemTrendDay = {
  day: string      // ISO date (UTC), oldest → newest, last entry is today
  alerts: number
  severe: number   // critical+high alerts raised that day
  mttd: number     // minutes
  mttr: number     // minutes
  fpRate: number   // percent
}
export const fetchSiemTrends = (days = 7) =>
  api<{ days: SiemTrendDay[] }>(`/siem/analytics/trends?days=${days}`)

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
// The backend stores success_rate as a 0–1 fraction (its running-average
// math); every UI treats it as a percent, so normalize once at the boundary —
// live cards used to render "0.9%" where the truth was 93.6%.
export const fetchPlaybooks = () =>
  api<Playbook[]>('/soar/playbooks').then((rows) =>
    rows.map((p) => ({ ...p, successRate: Math.round((p.successRate ?? 0) * 1000) / 10 })))

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
export type BuilderStep = { kind: string; name: string; params?: Record<string, unknown> }
export interface StepKind { kind: string; type: string; label: string; params: string[] }
export const fetchStepKinds = () => api<StepKind[]>('/soar/step-kinds')
export const createPlaybook = (body: {
  name: string; category?: string; trigger?: string; triggerType?: string
  description?: string; steps: BuilderStep[]; triggerMatch?: Record<string, unknown>
}) =>
  api<Playbook>('/soar/playbooks', {
    method: 'POST',
    body: JSON.stringify({
      name: body.name, category: body.category, trigger: body.trigger,
      trigger_type: body.triggerType, description: body.description,
      steps: body.steps, trigger_match: body.triggerMatch ?? {},
    }),
  })
export interface PlaybookVersion {
  id: string; version: number; steps: BuilderStep[]
  triggerMatch: Record<string, unknown>; author: string | null; note: string | null; createdAt: string
}
export const fetchPlaybookVersions = (id: string) =>
  api<PlaybookVersion[]>(`/soar/playbooks/${id}/versions`)
export const revertPlaybook = (id: string, version: number) =>
  api<Playbook & { revertedTo: number; newVersion: number }>(
    `/soar/playbooks/${id}/revert/${version}`, { method: 'POST' })
// Case depth: evidence chain-of-custody, linking, merge/split.
export const addCaseEvidence = (caseId: string, body: { type?: string; name: string; content?: string }) =>
  api<Case>(`/soar/cases/${caseId}/evidence`, { method: 'POST', body: JSON.stringify(body) })
export interface SignedEvidenceBundle {
  bundle: Record<string, unknown>
  signature: { alg: string; value: string; contentSha256: string }
}
export const exportEvidenceBundle = (caseId: string) =>
  api<SignedEvidenceBundle>(`/soar/cases/${caseId}/evidence-bundle`)
export const verifyEvidenceBundle = (signed: SignedEvidenceBundle) =>
  api<{ valid: boolean }>('/soar/evidence/verify', { method: 'POST', body: JSON.stringify(signed) })
export const linkCase = (caseId: string, otherId: string, relation = 'related') =>
  api<Case>(`/soar/cases/${caseId}/link`, { method: 'POST', body: JSON.stringify({ case_id: otherId, relation }) })
export const mergeCase = (caseId: string, sourceId: string) =>
  api<Case>(`/soar/cases/${caseId}/merge`, { method: 'POST', body: JSON.stringify({ source_id: sourceId }) })
export const splitCase = (caseId: string, title: string, entities: Array<{ type: string; value: string }> = []) =>
  api<Case>(`/soar/cases/${caseId}/split`, { method: 'POST', body: JSON.stringify({ title, entities }) })
export const fetchSoarIntegrations = () => api<Integration[]>('/soar/integrations')
export const createIntegration = (body: {
  name: string; vendor?: string; category?: string; description?: string; actions?: string[]
  base_url?: string; api_key?: string
}) => api<Integration & { credentialed: boolean }>('/soar/integrations', { method: 'POST', body: JSON.stringify(body) })
export const testIntegration = (id: string) =>
  api<Integration>(`/soar/integrations/${id}/test`, { method: 'POST' })
// Credential entry: set/clear the vendor base URL + API key, toggle enablement.
// The key is write-only; responses expose only `credentialed`.
export const updateIntegration = (id: string, body: {
  baseUrl?: string | null; apiKey?: string | null; enabled?: boolean
}) =>
  api<Integration & { credentialed: boolean; enabled: number }>(`/soar/integrations/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ base_url: body.baseUrl, api_key: body.apiKey, enabled: body.enabled }),
  })
export interface IntegrationActionResult {
  id: string; action: string; target: string; category: string
  status: 'success' | 'failed' | 'simulated' | 'not-configured'; mode: 'live' | 'simulated'; detail: string; ts: string
}
export const runIntegrationAction = (id: string, action: string, params?: Record<string, unknown>) =>
  api<Integration & { actionsRun: number; result: IntegrationActionResult }>(`/soar/integrations/${id}/actions/run`, {
    method: 'POST', body: JSON.stringify({ action, params: params ?? {} }),
  })
export interface IntegrationAction {
  id: string; action: string; target: string | null; status: string; mode: string
  detail: string | null; actor: string | null; ts: string
}
export const fetchIntegrationActions = (id: string) =>
  api<IntegrationAction[]>(`/soar/integrations/${id}/actions`)
export const fetchSoarMetrics = () => api<SoarMetrics>('/soar/metrics')

// Per-analyst case workload + throughput (aggregated from cases.owner).
export interface AnalystStat {
  name: string; handled: number; closed: number; open: number
  critical: number; avgResolveMins: number | null
}
export const fetchSoarAnalysts = () => api<AnalystStat[]>('/soar/analysts')

// ── CTI ──────────────────────────────────────────────────────────────
export const fetchActors  = () => api<Actor[]>('/cti/actors')
export const fetchIocs    = (params?: Record<string, string>) => {
  const q = params ? '?' + new URLSearchParams(params).toString() : ''
  return api<{ total: number; items: Ioc[] }>(`/cti/iocs${q}`)
}
export const fetchIocTypes  = () => api<IocType[]>('/cti/ioc-types')
export const fetchCtiSummary = () => api<CtiSummary>('/cti/summary')
export const fetchIoc = (id: string) => api<IocDetail>(`/cti/iocs/${id}`)
export const addIocSighting = (id: string, source = 'manual', context?: string) =>
  api<IocDetail>(`/cti/iocs/${id}/sighting`, { method: 'POST', body: JSON.stringify({ source, context }) })
export const setIocKnownGood = (id: string) =>
  api<Ioc & { lifecycle: IocLifecycle }>(`/cti/iocs/${id}/known-good`, { method: 'POST' })
export const removeIocKnownGood = (id: string) =>
  api<Ioc & { lifecycle: IocLifecycle }>(`/cti/iocs/${id}/known-good`, { method: 'DELETE' })
export const runIocDecay = () =>
  api<{ scanned: number; expired: number; reactivated: number }>('/cti/iocs/decay', { method: 'POST' })

export interface EnrichmentProvider {
  provider: string; available: boolean; verdict: string; summary: string
  data: Record<string, unknown>; cached?: boolean; reason?: string
}
export interface EnrichmentResult {
  value: string; type: string; verdict: string; providers: EnrichmentProvider[]; ts: string
}
export const enrichIoc = (id: string, refresh = false) =>
  api<EnrichmentResult>(`/cti/iocs/${id}/enrich${refresh ? '?refresh=true' : ''}`, { method: 'POST' })
export const fetchIocFpAssessment = (id: string) => api<FpAssessment>(`/cti/iocs/${id}/fp-assessment`)

// Analyst intel reports + MISP interop (campaign & report management).
export interface IntelReport {
  id: string; title: string; tlp: string; status: 'draft' | 'published'
  summary: string | null; body: string | null
  actors: string[]; iocs: string[]; tags: string[]
  author: string | null; createdAt: string; updatedAt: string
}
export const fetchIntelReports = (status?: string) =>
  api<IntelReport[]>(`/cti/reports${status ? `?status=${status}` : ''}`)
export const createIntelReport = (body: {
  title: string; summary?: string; body?: string; tlp?: string
  actors?: string[]; iocs?: string[]; tags?: string[]
}) => api<IntelReport>('/cti/reports', { method: 'POST', body: JSON.stringify(body) })
export const updateIntelReport = (id: string, body: Partial<{
  title: string; summary: string; body: string; tlp: string
  status: string; actors: string[]; iocs: string[]; tags: string[]
}>) => api<IntelReport>(`/cti/reports/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
export const deleteIntelReport = (id: string) =>
  api<void>(`/cti/reports/${id}`, { method: 'DELETE' })
export const exportIntelReportMisp = (id: string) =>
  api<{ Event: Record<string, unknown> }>(`/cti/reports/${id}/misp`)
export const exportMispEvent = (severity?: string) =>
  api<{ Event: Record<string, unknown> }>(`/cti/misp/export${severity ? `?severity=${severity}` : ''}`)
export const importMispEvent = (event: Record<string, unknown>) =>
  api<{ imported: number; duplicates: number; skipped: number; total: number; tlp: string }>(
    '/cti/misp/import', { method: 'POST', body: JSON.stringify({ event }) })

// Evidence-weighted actor attribution.
export interface AttributionCandidate {
  actor: string; type: string; origin: string | null; threatLevel: string | null
  score: number; raw: number; confidence: 'high' | 'medium' | 'low'
  evidence: Array<{ type: string; weight: number; detail: string }>
}
export const attributeActivity = (body: {
  techniques?: string[]; iocs?: string[]; malware?: string[]; sectors?: string[]; origin?: string
}) => api<{ candidates: AttributionCandidate[] }>('/cti/attribution',
  { method: 'POST', body: JSON.stringify(body) })
export const attributeCase = (caseId: string) =>
  api<{ caseId: string; observed: { techniques: string[]; indicators: string[] }; candidates: AttributionCandidate[] }>(
    `/cti/attribution/case/${caseId}`)
export const fetchStixBundle = (type?: string) =>
  api<{ type: string; id: string; objects: Array<Record<string, unknown>> }>(
    `/cti/stix/bundle${type ? `?type=${type}` : ''}`)
export const lookupIoc = (value: string) =>
  api<IocLookup>(`/cti/lookup?value=${encodeURIComponent(value)}`)
export interface ImportResult { imported: number; duplicates: number; skipped: number; total: number }
export interface ImportHistoryRow {
  id: string; source: string; method: string; imported: number; duplicates: number
  skipped: number; status: 'completed' | 'partial' | 'failed'; actor: string | null; ts: string
}
export const fetchImportHistory = () => api<ImportHistoryRow[]>('/cti/import-history')
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
export const fetchCtiGraph = (focus?: string, depth = 2) =>
  api<CtiGraph>(`/cti/graph${focus ? `?focus=${encodeURIComponent(focus)}&depth=${depth}` : ''}`)
export const expandGraphNode = (node: string) =>
  api<{ node: CtiGraphNode | null; neighbours: Array<CtiGraphNode & { kind: string }> }>(
    `/cti/graph/expand?node=${encodeURIComponent(node)}`)
export const findGraphPath = (from: string, to: string) =>
  api<GraphPath>(`/cti/graph/path?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`)

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
export const deleteAsset = (id: string) => api<void>(`/assets/${id}`, { method: 'DELETE' })
export const fetchRiskDistribution = () => api<RiskDistribution>('/assets/risk-distribution')
export const fetchAssetsSummary = () => api<AssetSummary>('/assets/summary')
export const fetchVulns = () => api<Asset[]>('/assets/vulns')
export interface VulnSummary {
  totalFindings: number; distinctCves: number
  bySeverity: { critical: number; high: number; medium: number; low: number }
  criticalAndHigh: number; activelyExploited: number
  avgPatchAge: number; exposureScore: number; internetFacing: number
}
export const fetchVulnSummary = () => api<VulnSummary>('/assets/vulns/summary')
export interface FleetVulnFinding {
  cve: string; cvss: number; severity: string; summary: string; fixedIn: string | null
  kev: boolean; exploit: boolean; products: string[]; affectedAssets: string[]
  owners: string[]; firstFound: string; reference: string
}
export const fetchFleetVulnFindings = () => api<FleetVulnFinding[]>('/assets/vuln-findings')
export const recomputeAssetRisk = () =>
  api<{ updated: number }>('/assets/recompute-risk', { method: 'POST' })

// Vulnerability scanning (real CVE findings from installed software).
export interface VulnFinding {
  id: string; assetId: string; cve: string; product: string; version: string
  severity: string; cvss: number; fixedIn: string | null; summary: string
  status: string; foundAt: string
}
export interface ScanResult {
  assetId: string; scanned: number
  findings: Array<{ cve: string; product: string; version: string; severity: string; cvss: number; fixedIn: string | null; summary: string }>
  counts: Record<string, number>
}
export const scanAssetVulns = (id: string) =>
  api<ScanResult>(`/assets/${id}/scan`, { method: 'POST' })
export const scanAllVulns = () =>
  api<{ assets: number; findings: number }>('/assets/scan-all', { method: 'POST' })
export const fetchAssetVulns = (id: string) => api<VulnFinding[]>(`/assets/${id}/vulns`)

// Attack-surface discovery + exposure.
export interface ExposureItem {
  id: string; name: string; type: string; value: string; criticality: string
  riskScore: number; score: number; band: string; internetFacing: boolean
  factors: Array<{ factor: string; weight: number }>
}
export const fetchExposure = () =>
  api<{ items: ExposureItem[]; summary: { assets: number; internetFacing: number; criticalExposure: number; avgExposure: number; topFactor: string | null } }>(
    '/assets/exposure')
export interface DiscoveredAsset {
  hostname: string; events: number; alerts: number
  firstSeen: string | null; lastSeen: string | null; sample: string
}
export const fetchDiscoveredAssets = (limit = 50) =>
  api<{ items: DiscoveredAsset[] }>(`/assets/discovered?limit=${limit}`)
export const promoteDiscoveredAsset = (hostname: string, criticality = 'medium', type = 'endpoint') =>
  api<Asset>('/assets/discovered/promote', {
    method: 'POST', body: JSON.stringify({ hostname, criticality, type }),
  })

// Asset ↔ alert ↔ case linkage: everything tied to one asset.
export interface AssetActivity {
  assetId: string; name: string
  alerts: Array<{ id: string; ts: string; title: string; severity: string; status: string; ruleName: string | null; mitreTechId: string | null; srcIp: string | null }>
  cases: Array<{ id: string; title: string; severity: string; status: string; created: string; playbook: string | null }>
  events: Array<{ id: string; ts: string; eventType: string | null; srcIp: string | null; destIp: string | null; raw: string | null }>
  vulnFindings: Array<{ cve: string; severity: string; cvss: number; product: string; version: string; status: string }>
  playbookRuns: Array<{ id: string; playbookName: string | null; ts: string; status: string; trigger: string }>
  summary: { alerts: number; openAlerts: number; cases: number; events: number; openVulns: number; responses: number }
}
export const fetchAssetActivity = (id: string) => api<AssetActivity>(`/assets/${id}/activity`)

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
export const createApiKey    = (name: string, scope = 'read', orgId?: string) =>
  api<ApiKey & { secret: string }>('/config/api-keys', { method: 'POST', body: JSON.stringify({ name, scope, ...(orgId ? { orgId } : {}) }) })
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
  secret?: string   // returned ONCE at create/rotate; never re-listed
}
export const fetchWebhooks = () => api<Webhook[]>('/config/webhooks')
export const createWebhook = (url: string, events: string[]) =>
  api<Webhook>('/config/webhooks', { method: 'POST', body: JSON.stringify({ url, events }) })
export const patchWebhook = (id: string, body: { status?: string; events?: string[] }) =>
  api<Webhook>(`/config/webhooks/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
export const rotateWebhookSecret = (id: string) =>
  api<{ id: string; secret: string }>(`/config/webhooks/${id}/rotate-secret`, { method: 'POST' })
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
  meta: { kind: string; title: string; period: string; from: string; to: string; generatedAt: string; audience?: string }
  summary: { headline: Array<{ label: string; value: number | string; color?: string }>; narrative: string }
  breakdowns: Array<{ heading: string; type: 'severity' | 'bars'; data: Array<{ label?: string; severity?: string; count: number; color?: string }> }>
  findings: ReportFinding[]
  recommendations: string[]
  sections?: string[]
  compliance?: Array<{ control: string; framework: string }>
}
export type ReportAudience = 'technical' | 'executive' | 'compliance'
export type ReportFormat = 'json' | 'csv' | 'markdown' | 'html'
export const fetchReportKinds = () => api<Array<{ kind: string; label: string }>>('/reports/kinds')
export const fetchReport = (kind: string, period: string, from?: string, to?: string, audience: ReportAudience = 'technical') => {
  const q = new URLSearchParams({ period, audience })
  if (from) q.set('from', from)
  if (to) q.set('to', to)
  return api<ReportData>(`/reports/${kind}?${q.toString()}`)
}
export const fetchIncidentReport = (caseId: string, audience: ReportAudience = 'technical') =>
  api<ReportData>(`/reports/incident?case_id=${encodeURIComponent(caseId)}&audience=${audience}`)

/** Download a report from the backend renderer (CSV / Markdown / HTML / JSON),
 *  authenticated, as a browser file download. */
export async function downloadReport(kind: string, opts: {
  format: ReportFormat; period?: string; audience?: ReportAudience
  from?: string; to?: string; caseId?: string
}): Promise<void> {
  if (typeof window === 'undefined') return
  const tok = localStorage.getItem(TOKEN_KEY)
  const incident = !!opts.caseId
  const q = new URLSearchParams({ format: opts.format, audience: opts.audience ?? 'technical' })
  if (incident) q.set('case_id', opts.caseId!)
  else q.set('period', opts.period ?? 'weekly')
  if (opts.from) q.set('from', opts.from)
  if (opts.to) q.set('to', opts.to)
  const path = incident ? 'incident' : kind
  const res = await fetch(`${BASE}/reports/${path}?${q.toString()}`,
    { headers: tok ? { Authorization: `Bearer ${tok}` } : {} })
  if (!res.ok) throw new Error(`report download failed: ${res.status}`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  const ext = opts.format === 'markdown' ? 'md' : opts.format
  a.download = `threatorbit-${path}-${opts.audience ?? 'technical'}-${opts.period ?? 'report'}.${ext}`
  a.click()
  URL.revokeObjectURL(url)
}

// ── Case linked evidence (SLA + related alerts/IOCs/runs/timeline) ───
export interface CaseRelated {
  caseId: string
  alerts: Array<{ id: string; ts: string; title: string; severity: string; status: string
    srcIp: string | null; hostname: string | null; username: string | null
    mitreTechId: string | null; mitreTactic: string | null; ruleName: string | null; riskScore: number }>
  iocs: Array<{ id: string; type: string; value: string; severity: string; confidence: number
    threatType: string | null; source: string | null }>
  runs: Array<{ id: string; playbookName: string | null; ts: string; status: string
    trigger: string; actor: string | null; alertId: string | null }>
  timeline: Array<{ ts: string | null; type: string; actor: string | null
    title: string | null; severity: string | null; technique: string | null }>
  techniques: Array<{ technique: string; count: number }>
}
export const fetchCaseRelated = (caseId: string) =>
  api<CaseRelated>(`/soar/cases/${caseId}/related`)

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
  status: 'new' | 'investigating' | 'takedown-requested' | 'mitigated' | 'dismissed'
  matchedUser?: string | null
}
export interface DarkWebSummary {
  total: number
  critical: number
  credentialLeaks: number
  workforceMatches: number
  takedownsRequested: number
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
export const requestTakedown = (id: string) =>
  api<DarkWebFinding>(`/darkweb/findings/${id}/takedown`, { method: 'POST' })
export const matchCredentialLeaks = () =>
  api<{ scanned: number; matched: number }>('/darkweb/match-credentials', { method: 'POST' })

// Licensing: signed keys + plan limits enforced server-side.
export interface LicenseStatus {
  plan: string; label: string; org: string | null; expires: string | null
  builtin: boolean; warning?: string | null
  limits: { seats: number | null; connectors: number | null }
  usage: { seats: number; connectors: number }
}
export const fetchLicense = () => api<LicenseStatus>('/config/license')
export const activateLicense = (key: string) =>
  api<{ activated: boolean; plan: string }>('/config/license/activate',
    { method: 'POST', body: JSON.stringify({ key }) })
export const clearLicense = () => api<void>('/config/license', { method: 'DELETE' })

// ── Billing (Stripe self-serve; degrades to not-configured) ───────────────
export interface BillingStatus {
  configured: boolean
  plans: Array<{ plan: string; label: string; seats: number | null; connectors: number | null }>
  currentPlan: string | null
  currentPlanBuiltin: boolean
  hasSubscription: boolean
  portalAvailable: boolean
}
export const fetchBillingStatus = () => api<BillingStatus>('/billing/status')
export const startCheckout = (plan: string) =>
  api<{ url: string }>('/billing/checkout', { method: 'POST', body: JSON.stringify({ plan }) })
export const openBillingPortal = () => api<{ url: string }>('/billing/portal', { method: 'POST' })

export interface DatabaseInfo { backend: string; configured: boolean; driverReady: boolean; note: string }
export const fetchDatabaseInfo = () => api<DatabaseInfo>('/config/database')

export interface EmailStatus { configured: boolean; host: string | null; port: number; from: string | null }
export const fetchEmailStatus = () => api<EmailStatus>('/config/email')
export const sendTestEmail = (to: string) =>
  api<{ sent: boolean; reason?: string; recipients?: string[] }>('/config/email/test',
    { method: 'POST', body: JSON.stringify({ to }) })

// First-run onboarding checklist (computed from real platform state).
export interface OnboardingStatus {
  steps: Array<{ id: string; label: string; done: boolean; link: string }>
  done: number; total: number; pct: number; complete: boolean; dismissed: boolean
}
export const fetchOnboarding = () => api<OnboardingStatus>('/config/onboarding')
export const dismissOnboarding = () =>
  api<{ dismissed: boolean }>('/config/onboarding/dismiss', { method: 'POST' })

// ── Live engine control ──────────────────────────────────────────────
export interface EngineQueue {
  depth: number
  inFlight: number
  lagSeconds: number
  maxBacklog: number
  shedding: boolean
}
export interface EngineStatus {
  mode: string
  running: boolean
  enabled: boolean
  tickSeconds: number
  alertsProduced: number
  totalAlerts: number
  darkWebFindings: number
  queue?: EngineQueue
}
export const fetchEngineStatus = () => api<EngineStatus>('/config/engine')

/** Platform self-health: the SOC's own vitals (DB, schema, queue, leader, process). */
export type HealthStatus = 'ok' | 'degraded' | 'down' | 'unknown'
export interface SelfHealth {
  status: HealthStatus
  generatedAt: string
  checks: {
    database: { status: HealthStatus; latencyMs?: number; error?: string }
    schema:   { status: HealthStatus; code?: number; db?: number | null; detail?: string }
    queue:    { status: HealthStatus; depth?: number; inFlight?: number; lagSeconds?: number; detail?: string }
    leader:   { status: HealthStatus; isLeader?: boolean; holder?: string | null; electionEnabled?: boolean; expiresInSeconds?: number }
    process:  { status: HealthStatus; uptimeSeconds?: number; errors?: number; engineTicks?: number; engineTickFailures?: number; ingestedEvents?: number }
  }
}
export const fetchSelfHealth = () => api<SelfHealth>('/self-health')
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
// Multipart upload - bypasses the JSON wrapper so the browser sets the boundary.
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

// ── Dashboard assistant (security-bounded, read-only agent) ───────────
export interface AssistantNav { label: string; path: string }
export interface AssistantReply {
  reply: string; toolsUsed: string[]; navigations: AssistantNav[]; mode: 'ai' | 'basic' | 'empty'
}
export interface AssistantStatus { configured: boolean; mode: 'ai' | 'basic'; capabilities: string[] }
export const fetchAssistantStatus = () => api<AssistantStatus>('/assistant/status')
export const sendAssistantChat = (message: string, history: { role: string; text: string }[]) =>
  api<AssistantReply>('/assistant/chat', { method: 'POST', body: JSON.stringify({ message, history }) })
