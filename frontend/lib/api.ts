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
  trigger: string
  description: string
  runs: number
  successRate: number
  avgTime: number
  lastRun: string | null
  status: string
  steps: Array<{ name: string; type: string; status: string; duration: number }>
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
  motivation: string
  active: boolean
  firstSeen: string
  lastSeen: string
  sophistication: number
  sectors: string[]
  ttps: string[]
  iocCount: number
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
export const fetchSiemSources = () => api<LogSource[]>('/siem/sources')
export const fetchSiemHunts  = () => api<SavedHunt[]>('/siem/hunts')
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
export const fetchPlaybooks = () => api<Playbook[]>('/soar/playbooks')
export const runPlaybook = (id: string) =>
  api<Playbook>(`/soar/playbooks/${id}/run`, { method: 'POST' })
export const fetchSoarIntegrations = () => api<Integration[]>('/soar/integrations')
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
export const fetchCtiHunts  = () => api<SavedHunt[]>('/cti/hunts')
export const fetchCtiGraph  = () => api<CtiGraph>('/cti/graph')

// ── Assets ───────────────────────────────────────────────────────────
export const fetchAssets = (params?: Record<string, string>) => {
  const q = params ? '?' + new URLSearchParams(params).toString() : ''
  return api<{ total: number; items: Asset[] }>(`/assets${q}`)
}
export const fetchAsset = (id: string) => api<AssetDetail>(`/assets/${id}`)
export const fetchRiskDistribution = () => api<RiskDistribution>('/assets/risk-distribution')
export const fetchAssetsSummary = () => api<AssetSummary>('/assets/summary')
export const fetchVulns = () => api<Asset[]>('/assets/vulns')
export const recomputeAssetRisk = () =>
  api<{ updated: number }>('/assets/recompute-risk', { method: 'POST' })

// ── Feeds ─────────────────────────────────────────────────────────────
export const fetchFeeds   = () => api<Feed[]>('/feeds')
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
export const fetchAuditLog   = (limit = 100, action?: string) => {
  const q = new URLSearchParams({ limit: String(limit), ...(action ? { action } : {}) })
  return api<AuditEntry[]>(`/config/audit-log?${q.toString()}`)
}

// ── Users ─────────────────────────────────────────────────────────────
export const fetchUsers = () => api<User[]>('/users')
export const createUser = (body: { email: string; password: string; name: string; role: UserRole }) =>
  api<User>('/users', { method: 'POST', body: JSON.stringify(body) })
export const patchUser  = (id: string, body: Partial<Pick<User, 'name' | 'role' | 'status'>>) =>
  api<User>(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
export const deleteUser = (id: string) => api<void>(`/users/${id}`, { method: 'DELETE' })
