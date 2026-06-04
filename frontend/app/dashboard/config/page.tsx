'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Settings, Key, Bell, Shield, Database, Globe, Plug,
  Eye, EyeOff, Copy, RefreshCw, CheckCircle, Save,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ── Shared input ────────────────────────────────────────────────── */
function Field({ label, value, type = 'text', hint }: { label: string; value: string; type?: string; hint?: string }) {
  return (
    <div>
      <label className="block text-xs font-medium text-ink-300 mb-1.5">{label}</label>
      <input
        type={type}
        defaultValue={value}
        className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 focus:ring-1 focus:ring-magenta/15 transition-colors placeholder-ink-600"
      />
      {hint && <p className="text-[10px] text-ink-600 mt-1">{hint}</p>}
    </div>
  )
}

function Toggle({ label, description, checked }: { label: string; description: string; checked: boolean }) {
  const [on, setOn] = useState(checked)
  return (
    <div className="flex items-center justify-between py-3 border-b border-white/4 last:border-0">
      <div>
        <p className="text-xs font-medium text-ink-200">{label}</p>
        <p className="text-[10px] text-ink-600 mt-0.5">{description}</p>
      </div>
      <button
        onClick={() => setOn((o) => !o)}
        className={cn('w-9 h-5 rounded-full transition-colors shrink-0', on ? 'bg-safe' : 'bg-ink-600')}
      >
        <div className={cn('w-3.5 h-3.5 rounded-full bg-white mt-0.5 transition-transform mx-auto', on ? 'translate-x-2' : '-translate-x-2')} />
      </button>
    </div>
  )
}

/* ── API Key row ─────────────────────────────────────────────────── */
function APIKey({ label, value, scope }: { label: string; value: string; scope: string }) {
  const [show, setShow] = useState(false)
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard?.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="glass border border-white/5 rounded-xl p-4">
      <div className="flex items-center justify-between mb-2">
        <div>
          <span className="text-xs font-semibold text-white">{label}</span>
          <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded-full bg-violet/15 text-violet border border-violet/20">{scope}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={copy} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors">
            {copied ? <CheckCircle className="w-3.5 h-3.5 text-safe" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
          <button className="p-1.5 rounded-lg text-ink-500 hover:text-amber hover:bg-amber/5 transition-colors">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => setShow((s) => !s)} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors">
            {show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>
      <div className="font-mono text-xs text-ink-400 bg-surface-3 px-3 py-2 rounded-lg tracking-wider">
        {show ? value : value.slice(0, 8) + '•'.repeat(32)}
      </div>
    </div>
  )
}

/* ── Feed source row ─────────────────────────────────────────────── */
function FeedSource({ name, url, enabled, lastSync, icon }: {
  name: string; url: string; enabled: boolean; lastSync: string; icon: string
}) {
  const [on, setOn] = useState(enabled)
  return (
    <div className="flex items-center gap-4 py-3 border-b border-white/4 last:border-0">
      <span className="text-lg shrink-0">{icon}</span>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-ink-200">{name}</p>
        <p className="text-[10px] text-ink-600 font-mono truncate">{url}</p>
        <p className="text-[9px] text-ink-700 mt-0.5">Last sync: {lastSync}</p>
      </div>
      <button
        onClick={() => setOn((o) => !o)}
        className={cn('w-9 h-5 rounded-full transition-colors shrink-0', on ? 'bg-safe' : 'bg-ink-600')}
      >
        <div className={cn('w-3.5 h-3.5 rounded-full bg-white mt-0.5 transition-transform mx-auto', on ? 'translate-x-2' : '-translate-x-2')} />
      </button>
    </div>
  )
}

/* ── Section wrapper ─────────────────────────────────────────────── */
function Section({ title, icon: Icon, color, children }: {
  title: string; icon: React.ElementType; color: string; children: React.ReactNode
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass border border-white/5 rounded-xl overflow-hidden"
    >
      <div className="flex items-center gap-3 px-5 py-4 border-b border-white/5">
        <div className="p-2 rounded-lg" style={{ background: `${color}18` }}>
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
        <h2 className="text-sm font-semibold text-white">{title}</h2>
      </div>
      <div className="p-5">{children}</div>
    </motion.div>
  )
}

/* ── Tabs ────────────────────────────────────────────────────────── */
const TABS = [
  { id: 'general',     label: 'General',         icon: Settings },
  { id: 'api',         label: 'API Keys',         icon: Key      },
  { id: 'sources',     label: 'Feed Sources',     icon: Globe    },
  { id: 'alerts',      label: 'Notifications',    icon: Bell     },
  { id: 'security',    label: 'Security',         icon: Shield   },
  { id: 'integrations',label: 'Integrations',     icon: Plug     },
]

/* ── Page ────────────────────────────────────────────────────────── */
export default function ConfigPage() {
  const [tab, setTab] = useState('general')
  const [saved, setSaved] = useState(false)

  const save = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 2500)
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="font-display text-xl font-bold text-white">Configuration</h1>
          <p className="text-xs text-ink-500 mt-0.5">Platform settings, API keys, integrations, and notifications</p>
        </div>
        <button
          onClick={save}
          className={cn(
            'flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all',
            saved ? 'bg-safe/15 text-safe border border-safe/25' : 'bg-plasma text-white hover:shadow-magenta-sm',
          )}
        >
          {saved ? <><CheckCircle className="w-4 h-4" /> Saved!</> : <><Save className="w-4 h-4" /> Save Changes</>}
        </button>
      </div>

      <div className="flex gap-6">
        {/* Side nav */}
        <nav className="w-44 shrink-0">
          <div className="space-y-0.5">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={cn(
                  'w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-medium transition-colors text-left',
                  tab === id
                    ? 'bg-magenta/10 text-magenta border border-magenta/20'
                    : 'text-ink-400 hover:text-white hover:bg-white/5',
                )}
              >
                <Icon className="w-3.5 h-3.5 shrink-0" />
                {label}
              </button>
            ))}
          </div>
        </nav>

        {/* Content */}
        <div className="flex-1 space-y-5">
          {tab === 'general' && (
            <>
              <Section title="Platform Settings" icon={Settings} color="#7A3CFF">
                <div className="space-y-4">
                  <Field label="Platform Name" value="ThreatOrbit Production" />
                  <Field label="Organization" value="Acme Security Corp" />
                  <Field label="API Base URL" value="https://api.threatorbit.space" hint="The base URL for all API endpoints" />
                  <div className="grid grid-cols-2 gap-4">
                    <Field label="Timezone" value="UTC" />
                    <Field label="Feed Update Interval (seconds)" value="3" type="number" hint="Minimum: 1 second" />
                  </div>
                  <Field label="Data Retention (days)" value="90" type="number" hint="Older events are automatically purged" />
                </div>
              </Section>

              <Section title="Display Preferences" icon={Eye} color="#2DD4BF">
                <div className="space-y-0">
                  <Toggle label="Dark Mode" description="Use dark Plasma Noir theme (default)" checked={true} />
                  <Toggle label="Compact View" description="Show more rows in event tables" checked={false} />
                  <Toggle label="Animated Effects" description="Enable canvas animations and transitions" checked={true} />
                  <Toggle label="Auto-refresh Dashboard" description="Refresh overview widgets every 30s" checked={true} />
                </div>
              </Section>
            </>
          )}

          {tab === 'api' && (
            <Section title="API Keys" icon={Key} color="#FFB23E">
              <div className="space-y-3 mb-6">
                <APIKey
                  label="Standard API Key"
                  value="to_sk_live_a7f8e92b1d47c61e83dd2a9f7c4b5e01abc"
                  scope="Read + Write"
                />
                <APIKey
                  label="Admin API Key"
                  value="to_ak_live_9d4f2e8b3c71a54d67ee3c1f9b2a8e04xyz"
                  scope="Full Admin"
                />
                <APIKey
                  label="Read-Only API Key"
                  value="to_rk_live_5c1b9a3d72e4f84a96bc5d8e3a7f2c01mno"
                  scope="Read Only"
                />
              </div>
              <div className="glass border border-white/5 rounded-xl p-4">
                <h3 className="text-xs font-semibold text-white mb-3">Create New API Key</h3>
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <Field label="Key Name" value="" />
                  <div>
                    <label className="block text-xs font-medium text-ink-300 mb-1.5">Scope</label>
                    <select className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40">
                      <option>Read Only</option>
                      <option>Read + Write</option>
                      <option>Full Admin</option>
                    </select>
                  </div>
                </div>
                <button className="px-4 py-2 rounded-xl bg-plasma text-white text-xs font-semibold hover:shadow-magenta-sm transition-all">
                  Generate Key
                </button>
              </div>
            </Section>
          )}

          {tab === 'sources' && (
            <Section title="Threat Feed Sources" icon={Globe} color="#FF2E97">
              <div className="mb-4 text-xs text-ink-400">Configure and enable/disable threat intelligence feed sources. Changes take effect on the next scheduled sync.</div>
              <div>
                {[
                  { name: 'AlienVault OTX',      url: 'otx.alienvault.com/api/v1',           enabled: true,  lastSync: '3m ago',  icon: '🛸' },
                  { name: 'abuse.ch Malware Bazaar',url: 'mb-api.abuse.ch/api/v1',            enabled: true,  lastSync: '5m ago',  icon: '🦠' },
                  { name: 'MISP Feed (Circl.lu)', url: 'www.circl.lu/doc/misp/feed-osint',    enabled: true,  lastSync: '12m ago', icon: '🔴' },
                  { name: 'Shodan Stream',         url: 'stream.shodan.io',                    enabled: true,  lastSync: '1s ago',  icon: '🔍' },
                  { name: 'VirusTotal Intelligence',url: 'www.virustotal.com/api/v3',          enabled: false, lastSync: 'Never',   icon: '🛡️' },
                  { name: 'Recorded Future API',   url: 'api.recordedfuture.com/v2',           enabled: false, lastSync: 'Never',   icon: '📊' },
                  { name: 'Mandiant Threat Intel', url: 'api.intelligence.mandiant.com',       enabled: true,  lastSync: '8m ago',  icon: '🌐' },
                  { name: 'NVD CVE Feed',          url: 'nvd.nist.gov/feeds/json/cve/1.1',     enabled: true,  lastSync: '1h ago',  icon: '📋' },
                ].map((s) => <FeedSource key={s.name} {...s} />)}
              </div>
            </Section>
          )}

          {tab === 'alerts' && (
            <Section title="Notification Settings" icon={Bell} color="#FF4D6D">
              <div className="space-y-4 mb-5">
                <Field label="Alert Email" value="soc-team@acmesecurity.com" type="email" />
                <Field label="Slack Webhook URL" value="https://hooks.slack.com/services/T00000000/B00000000/..." hint="Receives critical and high severity alerts" />
                <Field label="PagerDuty Integration Key" value="your-integration-key-here" hint="Used for P0 escalations" />
              </div>
              <div>
                <p className="text-xs font-semibold text-white mb-3">Notification Rules</p>
                <Toggle label="Critical Severity Alerts"    description="Email + Slack + PagerDuty immediately"   checked={true}  />
                <Toggle label="High Severity Alerts"        description="Email + Slack within 5 minutes"          checked={true}  />
                <Toggle label="Medium Severity Alerts"      description="Daily digest email"                      checked={false} />
                <Toggle label="New IOC Matches"             description="Slack notification for new IOC hits"     checked={true}  />
                <Toggle label="Feed Source Failures"        description="Alert when a feed source goes offline"   checked={true}  />
                <Toggle label="Playbook Failures"           description="Notify SOC lead when a SOAR playbook fails" checked={true}/>
              </div>
            </Section>
          )}

          {tab === 'security' && (
            <Section title="Security Settings" icon={Shield} color="#34F5C5">
              <div className="space-y-4 mb-5">
                <div>
                  <label className="block text-xs font-medium text-ink-300 mb-1.5">Authentication Method</label>
                  <select className="w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40">
                    <option>API Key (default)</option>
                    <option>OAuth 2.0 (OIDC)</option>
                    <option>SAML 2.0 SSO</option>
                  </select>
                </div>
                <Field label="Session Timeout (minutes)" value="60" type="number" />
                <Field label="Allowed IP Ranges" value="0.0.0.0/0" hint="Comma-separated CIDR blocks. Use 0.0.0.0/0 to allow all." />
              </div>
              <Toggle label="Enforce MFA"                  description="Require TOTP for all dashboard logins"           checked={true}  />
              <Toggle label="Audit Logging"                description="Log all API calls and user actions"               checked={true}  />
              <Toggle label="Rate Limiting"                description="Limit API requests per key to 1000/minute"       checked={true}  />
              <Toggle label="TLS Certificate Pinning"      description="Pin TLS cert for API communications"             checked={false} />
              <Toggle label="Automated Threat Blocking"    description="Auto-block IPs with confidence score > 90%"     checked={true}  />
            </Section>
          )}

          {tab === 'integrations' && (
            <Section title="Integrations" icon={Plug} color="#FFB23E">
              <div className="space-y-3">
                {[
                  { name: 'OpenCTI',         status: 'Connected',    color: 'safe',   hint: 'STIX 2.1 bundle export every 15 minutes'  },
                  { name: 'Elasticsearch',   status: 'Connected',    color: 'safe',   hint: 'Log ingestion cluster: es-prod-01:9200'    },
                  { name: 'Splunk HEC',      status: 'Disconnected', color: 'threat', hint: 'Enterprise license required'               },
                  { name: 'Grafana',         status: 'Connected',    color: 'safe',   hint: 'Dashboard provisioned at /d/threatorbit'   },
                  { name: 'MISP',            status: 'Connected',    color: 'safe',   hint: 'Bi-directional sync enabled'              },
                  { name: 'TheHive',         status: 'Connected',    color: 'safe',   hint: 'Incident cases synced automatically'       },
                  { name: 'Cortex',          status: 'Disconnected', color: 'threat', hint: 'Cortex 3.x required for analyzer support'  },
                  { name: 'Jira Service Mgmt',status: 'Connected',  color: 'safe',   hint: 'Tickets created for P0/P1 incidents'       },
                ].map(({ name, status, color, hint }) => (
                  <div key={name} className="flex items-center gap-4 py-3 border-b border-white/4 last:border-0">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium text-ink-200">{name}</span>
                        <span className={cn(
                          'text-[9px] px-1.5 py-0.5 rounded-full border font-semibold',
                          color === 'safe' ? 'bg-safe/10 text-safe border-safe/20' : 'bg-threat/10 text-threat border-threat/20',
                        )}>
                          {status}
                        </span>
                      </div>
                      <p className="text-[10px] text-ink-600 mt-0.5">{hint}</p>
                    </div>
                    <button className={cn(
                      'text-xs px-3 py-1.5 rounded-lg border transition-colors',
                      color === 'safe'
                        ? 'border-white/10 text-ink-400 hover:text-white hover:border-white/20'
                        : 'border-magenta/25 text-magenta hover:bg-magenta/5',
                    )}>
                      {color === 'safe' ? 'Configure' : 'Connect'}
                    </button>
                  </div>
                ))}
              </div>
            </Section>
          )}
        </div>
      </div>
    </div>
  )
}
