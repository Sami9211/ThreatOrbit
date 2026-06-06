'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Brain, Globe, Hash, Target, ChevronRight, ExternalLink,
  Shield, AlertTriangle, Clock, TrendingUp, Network, Eye,
  Search, Play, Pause, CheckCircle, Crosshair, Building2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useExperienceMode } from '@/lib/useExperienceMode'
import EntityGraph, { type GraphData } from '@/components/dashboard/EntityGraph'

/* ── Threat Actors ───────────────────────────────────────────────── */
type Actor = {
  id: string
  name: string
  aliases: string[]
  origin: string
  flag: string
  type: string
  motivation: string[]
  active: boolean
  firstSeen: string
  lastSeen: string
  sophistication: string
  sectors: string[]
  ttps: string[]
  iocCount: number
  campaigns: number
  description: string
}

const ACTORS: Actor[] = [
  {
    id: 'apt38',
    name: 'Lazarus Group',
    aliases: ['APT38', 'UNC4736', 'Hidden Cobra', 'ZINC'],
    origin: 'North Korea', flag: '🇰🇵',
    type: 'Nation-State APT',
    motivation: ['Financial', 'Espionage', 'Disruption'],
    active: true,
    firstSeen: '2009', lastSeen: '2024-11-12',
    sophistication: 'Advanced',
    sectors: ['Finance', 'Defense', 'Cryptocurrency', 'Software'],
    ttps: ['T1566', 'T1059', 'T1486', 'T1078', 'T1027', 'T1105'],
    iocCount: 4821, campaigns: 47,
    description: 'North Korean state-sponsored group responsible for the 2016 Bangladesh bank heist ($81M), WannaCry ransomware, Sony Pictures breach, and ongoing crypto theft campaigns.',
  },
  {
    id: 'apt29',
    name: 'APT29 / Cozy Bear',
    aliases: ['The Dukes', 'Midnight Blizzard', 'NOBELIUM', 'UNC2452'],
    origin: 'Russia', flag: '🇷🇺',
    type: 'Nation-State APT',
    motivation: ['Espionage', 'Intelligence Collection'],
    active: true,
    firstSeen: '2008', lastSeen: '2024-11-11',
    sophistication: 'Expert',
    sectors: ['Government', 'Defense', 'NGO', 'Technology', 'Healthcare'],
    ttps: ['T1566', 'T1078', 'T1195', 'T1021', 'T1059.001'],
    iocCount: 6234, campaigns: 89,
    description: 'Russian SVR intelligence service APT responsible for the 2020 SolarWinds supply chain attack, 2016 DNC hack, and ongoing campaigns against NATO members and government entities.',
  },
  {
    id: 'volt',
    name: 'Volt Typhoon',
    aliases: ['Bronze Silhouette', 'VANGUARD PANDA', 'DEV-0391'],
    origin: 'China', flag: '🇨🇳',
    type: 'Nation-State APT',
    motivation: ['Pre-positioning', 'Espionage'],
    active: true,
    firstSeen: '2021', lastSeen: '2024-11-12',
    sophistication: 'Expert',
    sectors: ['Critical Infrastructure', 'Energy', 'Water', 'Communications'],
    ttps: ['T1078', 'T1021', 'T1070', 'T1590', 'T1591'],
    iocCount: 2847, campaigns: 23,
    description: 'Chinese MSS-linked APT focused on living-off-the-land techniques to pre-position in US critical infrastructure for potential destructive attacks. CISA-designated as "most dangerous."',
  },
  {
    id: 'scattered',
    name: 'Scattered Spider',
    aliases: ['UNC3944', 'Muddled Libra', 'Oktapus', 'Star Fraud'],
    origin: 'United States / UK', flag: '🇺🇸',
    type: 'Cybercriminal',
    motivation: ['Financial', 'Ransomware'],
    active: true,
    firstSeen: '2022', lastSeen: '2024-11-10',
    sophistication: 'High',
    sectors: ['Hospitality', 'Gaming', 'Retail', 'Telecommunications'],
    ttps: ['T1598', 'T1621', 'T1078', 'T1566.004'],
    iocCount: 892, campaigns: 18,
    description: 'Western-based cybercriminal group using social engineering (SIM swapping, vishing) to breach major enterprises. Responsible for MGM Resorts and Caesars attacks (2023).',
  },
  {
    id: 'fin7',
    name: 'FIN7',
    aliases: ['Carbon Spider', 'Carbanak', 'Sangria Tempest'],
    origin: 'Russia', flag: '🇷🇺',
    type: 'Cybercriminal',
    motivation: ['Financial'],
    active: true,
    firstSeen: '2015', lastSeen: '2024-11-08',
    sophistication: 'Advanced',
    sectors: ['Finance', 'Retail', 'Restaurant', 'Hospitality'],
    ttps: ['T1566', 'T1059.001', 'T1055', 'T1041'],
    iocCount: 3421, campaigns: 112,
    description: 'Russian cybercriminal APT responsible for over $1 billion in financial theft. Uses spear-phishing with sophisticated lures to install CARBANAK/BATELEUR backdoors at POS systems.',
  },
]

/* ── MITRE ATT&CK mini matrix ────────────────────────────────────── */
const MITRE_TACTICS = [
  { id: 'recon',        name: 'Recon',         techs: ['T1590', 'T1591', 'T1593'] },
  { id: 'resource',     name: 'Resource Dev',  techs: ['T1583', 'T1584', 'T1585'] },
  { id: 'initial',      name: 'Initial Access',techs: ['T1566', 'T1078', 'T1195'] },
  { id: 'exec',         name: 'Execution',     techs: ['T1059', 'T1055', 'T1047'] },
  { id: 'persist',      name: 'Persistence',   techs: ['T1053', 'T1547', 'T1098'] },
  { id: 'privesc',      name: 'Priv Esc',      techs: ['T1055', 'T1068', 'T1134'] },
  { id: 'evade',        name: 'Defense Eva',   techs: ['T1027', 'T1036', 'T1070'] },
  { id: 'credential',   name: 'Credential',    techs: ['T1003', 'T1558', 'T1555'] },
  { id: 'discovery',    name: 'Discovery',     techs: ['T1082', 'T1016', 'T1083'] },
  { id: 'lateral',      name: 'Lateral Mov',   techs: ['T1021', 'T1534', 'T1080'] },
  { id: 'collection',   name: 'Collection',    techs: ['T1005', 'T1074', 'T1113'] },
  { id: 'c2',           name: 'C2',            techs: ['T1071', 'T1095', 'T1105'] },
  { id: 'exfil',        name: 'Exfiltration',  techs: ['T1041', 'T1048', 'T1052'] },
  { id: 'impact',       name: 'Impact',        techs: ['T1486', 'T1490', 'T1498'] },
]

const HEAT_LEVELS: Record<string, number> = {
  T1566: 95, T1078: 88, T1059: 91, T1055: 76, T1027: 82,
  T1195: 71, T1486: 84, T1490: 69, T1021: 78, T1041: 65,
  T1082: 73, T1590: 60, T1003: 77, T1071: 62,
}

function heatColor(level: number) {
  if (level >= 80) return '#FF2E97'
  if (level >= 60) return '#FF4D6D'
  if (level >= 40) return '#FFB23E'
  if (level > 0)  return '#7A3CFF'
  return 'transparent'
}

/* ── IOC counts ──────────────────────────────────────────────────── */
const IOC_TYPES = [
  { type: 'IP Addresses',   count: 4821,  icon: Globe,  color: '#FF2E97' },
  { type: 'Domains',        count: 3247,  icon: Network, color: '#7A3CFF' },
  { type: 'File Hashes',    count: 8914,  icon: Hash,   color: '#FFB23E' },
  { type: 'URLs',           count: 2103,  icon: Target,  color: '#2DD4BF' },
]

/* ── Actor card ──────────────────────────────────────────────────── */
function ActorCard({ actor, selected, onSelect }: { actor: Actor; selected: boolean; onSelect: () => void }) {
  return (
    <div
      onClick={onSelect}
      className={cn(
        'glass border rounded-xl p-4 cursor-pointer transition-all duration-200',
        selected ? 'border-magenta/30 bg-magenta/5' : 'border-white/5 hover:border-white/10',
      )}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-lg leading-none">{actor.flag}</span>
            <span className="text-sm font-semibold text-white">{actor.name}</span>
            {actor.active && <span className="w-1.5 h-1.5 rounded-full bg-threat animate-pulse" />}
          </div>
          <p className="text-[10px] text-ink-500 mt-0.5">{actor.type} · {actor.origin}</p>
        </div>
        <ChevronRight className={cn('w-3.5 h-3.5 text-ink-600 transition-transform shrink-0', selected && 'rotate-90 text-magenta')} />
      </div>

      <div className="flex items-center gap-3 text-[10px] text-ink-500 mb-2">
        <span>{actor.iocCount.toLocaleString()} IOCs</span>
        <span>{actor.campaigns} campaigns</span>
        <span>{actor.sophistication}</span>
      </div>

      <div className="flex flex-wrap gap-1">
        {actor.sectors.slice(0, 3).map((s) => (
          <span key={s} className="text-[9px] px-1.5 py-0.5 rounded-full bg-surface-3 border border-white/8 text-ink-500">{s}</span>
        ))}
        {actor.sectors.length > 3 && (
          <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-surface-3 border border-white/8 text-ink-600">+{actor.sectors.length - 3}</span>
        )}
      </div>
    </div>
  )
}

/* ── Actor detail ────────────────────────────────────────────────── */
function ActorDetail({ actor }: { actor: Actor }) {
  return (
    <motion.div
      key={actor.id}
      initial={{ opacity: 0, x: 12 }}
      animate={{ opacity: 1, x: 0 }}
      className="glass border border-white/5 rounded-xl p-6 space-y-5"
    >
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-2xl">{actor.flag}</span>
            <h2 className="font-display text-xl font-bold text-white">{actor.name}</h2>
            {actor.active && (
              <span className="flex items-center gap-1 text-[9px] px-2 py-0.5 rounded-full bg-threat/10 text-threat border border-threat/20 font-semibold">
                <span className="w-1 h-1 rounded-full bg-threat animate-pulse" />
                ACTIVE
              </span>
            )}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {actor.aliases.map((a) => (
              <span key={a} className="text-[10px] px-1.5 py-0.5 rounded bg-surface-3 text-ink-500 font-mono">{a}</span>
            ))}
          </div>
        </div>
        <a href="#" className="flex items-center gap-1 text-xs text-magenta hover:underline">
          <ExternalLink className="w-3 h-3" /> MITRE ATT&CK
        </a>
      </div>

      <p className="text-xs text-ink-300 leading-relaxed">{actor.description}</p>

      <div className="grid grid-cols-2 gap-4 text-xs">
        <div>
          <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-2">Details</p>
          <div className="space-y-1.5">
            {[
              { k: 'Origin',         v: `${actor.flag} ${actor.origin}` },
              { k: 'Type',           v: actor.type },
              { k: 'Sophistication', v: actor.sophistication },
              { k: 'First Seen',     v: actor.firstSeen },
              { k: 'Last Seen',      v: actor.lastSeen },
            ].map(({ k, v }) => (
              <div key={k} className="flex justify-between">
                <span className="text-ink-500">{k}</span>
                <span className="text-ink-200 font-medium">{v}</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-2">Motivation</p>
          <div className="space-y-1.5 mb-4">
            {actor.motivation.map((m) => (
              <div key={m} className="flex items-center gap-2">
                <Target className="w-3 h-3 text-magenta" />
                <span className="text-ink-200">{m}</span>
              </div>
            ))}
          </div>
          <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-2">Key TTPs</p>
          <div className="flex flex-wrap gap-1">
            {actor.ttps.map((t) => (
              <span key={t} className="text-[9px] px-1.5 py-0.5 rounded bg-violet/15 text-violet font-mono border border-violet/20">{t}</span>
            ))}
          </div>
        </div>
      </div>

      <div>
        <p className="text-[10px] text-ink-600 uppercase tracking-wide mb-2">Target Sectors</p>
        <div className="flex flex-wrap gap-1.5">
          {actor.sectors.map((s) => (
            <span key={s} className="text-[10px] px-2 py-0.5 rounded-full bg-surface-2 border border-white/10 text-ink-300">{s}</span>
          ))}
        </div>
      </div>
    </motion.div>
  )
}

/* ── Per-actor campaign names (for the investigation graph) ──────── */
const ACTOR_CAMPAIGNS: Record<string, string[]> = {
  apt38:     ['TraderTraitor', 'AppleJeus', 'Operation Dream Job'],
  apt29:     ['SolarWinds', 'Midnight Blizzard', 'Cozy Bear DNC'],
  volt:      ['Living-off-the-land US grid', 'Water utility intrusion'],
  scattered: ['MGM Resorts breach', 'Caesars extortion', '0ktapus'],
  fin7:      ['CARBANAK POS', 'Bateleur retail', 'Carbon Spider'],
}

/* Build investigation-graph data from a selected actor */
function buildGraph(actor: Actor): GraphData {
  const campaigns = ACTOR_CAMPAIGNS[actor.id] ?? []
  const hashK = Math.round(actor.iocCount * 0.55)
  const domK = Math.round(actor.iocCount * 0.25)
  const ipK = actor.iocCount - hashK - domK
  return {
    center: { label: actor.name, sub: `${actor.flag} ${actor.origin} · ${actor.type}` },
    groups: [
      {
        kind: 'Campaigns', color: '#FF2E97',
        nodes: campaigns.map((c, i) => ({ id: `c-${actor.id}-${i}`, label: c })),
      },
      {
        kind: 'TTPs', color: '#7A3CFF',
        nodes: actor.ttps.map((t) => ({ id: `t-${actor.id}-${t}`, label: t, meta: 'MITRE' })),
      },
      {
        kind: 'IOCs', color: '#FFB23E',
        nodes: [
          { id: `i-${actor.id}-hash`, label: 'File Hashes', meta: hashK.toLocaleString() },
          { id: `i-${actor.id}-dom`,  label: 'Domains',     meta: domK.toLocaleString() },
          { id: `i-${actor.id}-ip`,   label: 'IP Addresses', meta: ipK.toLocaleString() },
        ],
      },
      {
        kind: 'Target Sectors', color: '#2DD4BF',
        nodes: actor.sectors.map((s, i) => ({ id: `s-${actor.id}-${i}`, label: s })),
      },
    ],
  }
}

/* ── Threat Hunt Panel ───────────────────────────────────────────── */
type HuntStatus = 'active' | 'completed' | 'paused'
const HUNTS = [
  { id: 'h1', name: 'Lazarus BLINDINGCAN Sweep', hypothesis: 'Undetected BLINDINGCAN RAT samples in endpoint telemetry', status: 'active' as HuntStatus, artifacts: 3, analyst: 'Alice', progress: 62, created: '2d ago' },
  { id: 'h2', name: 'Living-off-the-land in OT',  hypothesis: 'LOLBins used as beachhead in OT/ICS network segments',     status: 'active' as HuntStatus, artifacts: 7, analyst: 'Bob',   progress: 45, created: '3d ago' },
  { id: 'h3', name: 'MFA fatigue campaign',        hypothesis: 'Systematic MFA prompt bombing against Azure AD accounts',   status: 'completed' as HuntStatus, artifacts: 12, analyst: 'auto',  progress: 100, created: '5d ago' },
  { id: 'h4', name: 'C2 via DNS tunneling',        hypothesis: 'DNS-based C2 beaconing masked in legitimate DNS traffic',   status: 'paused' as HuntStatus, artifacts: 1, analyst: 'Charlie', progress: 28, created: '6d ago' },
]

const HUNT_COLOR: Record<HuntStatus, string> = { active: '#34F5C5', completed: '#7A3CFF', paused: '#FFB23E' }
const HUNT_ICON: Record<HuntStatus, React.ElementType> = { active: Play, completed: CheckCircle, paused: Pause }

function ThreatHuntPanel() {
  const [selected, setSelected] = useState<string | null>(null)
  return (
    <div className="glass border border-white/5 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Crosshair className="w-3.5 h-3.5 text-violet" />
          <h3 className="text-sm font-semibold text-white">Threat Hunt</h3>
          <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-safe/10 border border-safe/20 text-safe font-medium">
            {HUNTS.filter((h) => h.status === 'active').length} active
          </span>
        </div>
        <button className="flex items-center gap-1 text-xs text-magenta hover:underline">
          <Search className="w-3 h-3" /> New Hunt
        </button>
      </div>
      <div className="divide-y divide-white/4">
        {HUNTS.map((hunt) => {
          const Icon = HUNT_ICON[hunt.status]
          const color = HUNT_COLOR[hunt.status]
          return (
            <div
              key={hunt.id}
              onClick={() => setSelected((s) => (s === hunt.id ? null : hunt.id))}
              className="px-5 py-3 cursor-pointer hover:bg-white/2 transition-colors"
            >
              <div className="flex items-center gap-3">
                <Icon className="w-3.5 h-3.5 shrink-0" style={{ color }} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-ink-200 truncate">{hunt.name}</p>
                  <div className="flex items-center gap-3 mt-0.5 text-[10px] text-ink-600">
                    <span>{hunt.analyst}</span>
                    <span>{hunt.artifacts} artifacts</span>
                    <span>{hunt.created}</span>
                  </div>
                </div>
                <ChevronRight className={cn('w-3 h-3 text-ink-700 transition-transform', selected === hunt.id && 'rotate-90 text-magenta')} />
              </div>
              <div className="mt-2 h-1 bg-surface-3 rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${hunt.progress}%` }}
                  transition={{ duration: 0.8, ease: 'easeOut' }}
                  className="h-full rounded-full"
                  style={{ background: color }}
                />
              </div>
              <AnimatePresence>
                {selected === hunt.id && (
                  <motion.p
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="text-[10px] text-ink-500 mt-2 leading-snug italic"
                  >
                    Hypothesis: {hunt.hypothesis}
                  </motion.p>
                )}
              </AnimatePresence>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/* ── Sector Targeting ────────────────────────────────────────────── */
const SECTOR_DATA = [
  { sector: 'Finance',              score: 94, actors: ['Lazarus', 'FIN7'] },
  { sector: 'Government',           score: 88, actors: ['APT29', 'Volt Typhoon'] },
  { sector: 'Critical Infrastructure', score: 85, actors: ['Volt Typhoon'] },
  { sector: 'Defense',              score: 82, actors: ['Lazarus', 'APT29'] },
  { sector: 'Healthcare',           score: 71, actors: ['Lazarus', 'FIN7'] },
  { sector: 'Technology',           score: 68, actors: ['APT29', 'FIN7'] },
  { sector: 'Energy',               score: 62, actors: ['Volt Typhoon'] },
  { sector: 'Telecommunications',   score: 58, actors: ['Scattered Spider'] },
]

function SectorTargeting() {
  return (
    <div className="glass border border-white/5 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <Building2 className="w-3.5 h-3.5 text-amber" />
        <h3 className="text-sm font-semibold text-white">Sector Targeting Heat</h3>
      </div>
      <div className="space-y-2.5">
        {SECTOR_DATA.map(({ sector, score, actors }, i) => (
          <div key={sector}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-ink-300">{sector}</span>
              <div className="flex items-center gap-2">
                <div className="flex gap-1">
                  {actors.map((a) => (
                    <span key={a} className="text-[8px] px-1 py-px rounded bg-magenta/10 text-magenta font-mono border border-magenta/15">{a.split(' ')[0]}</span>
                  ))}
                </div>
                <span className="text-[10px] font-mono text-ink-400 w-6">{score}</span>
              </div>
            </div>
            <div className="h-1.5 bg-surface-3 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${score}%` }}
                transition={{ delay: i * 0.07, duration: 0.8, ease: 'easeOut' }}
                className="h-full rounded-full"
                style={{ background: score >= 80 ? '#FF2E97' : score >= 65 ? '#FF4D6D' : '#FFB23E' }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Page ────────────────────────────────────────────────────────── */
export default function CTIPage() {
  const [selectedActor, setSelectedActor] = useState<Actor>(ACTORS[0])
  const [mode] = useExperienceMode()
  const isPower = mode === 'power'
  const graph = buildGraph(selectedActor)

  return (
    <div className="p-6 space-y-6">
      {/* Header with mode pill */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-xl font-bold text-white">Cyber Threat Intelligence</h1>
          <p className="text-xs text-ink-500 mt-0.5">
            {ACTORS.length} tracked actors · {ACTORS.reduce((s, a) => s + a.iocCount, 0).toLocaleString()} IOCs ·
            {' '}{ACTORS.reduce((s, a) => s + a.campaigns, 0)} campaigns
          </p>
        </div>
        <span className={cn('flex items-center gap-1.5 text-[10px] px-2 py-1 rounded-full border',
          isPower ? 'border-magenta/25 bg-magenta/10 text-magenta' : 'border-safe/25 bg-safe/10 text-safe')}>
          {isPower ? <Brain className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
          {isPower ? 'Power User' : 'Normal mode'}
        </span>
      </div>

      {/* IOC counts */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {IOC_TYPES.map(({ type, count, icon: Icon, color }) => (
          <motion.div
            key={type}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass border border-white/5 rounded-xl p-4 flex items-center gap-3"
          >
            <div className="p-2.5 rounded-xl shrink-0" style={{ background: `${color}18` }}>
              <Icon className="w-4 h-4" style={{ color }} />
            </div>
            <div>
              <p className="text-xs text-ink-500">{type}</p>
              <p className="font-display text-xl font-bold text-white">{count.toLocaleString()}</p>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Actor list */}
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-white">Threat Actors</h2>
          {ACTORS.map((actor) => (
            <ActorCard
              key={actor.id}
              actor={actor}
              selected={selectedActor.id === actor.id}
              onSelect={() => setSelectedActor(actor)}
            />
          ))}
        </div>

        {/* Actor detail + MITRE */}
        <div className="lg:col-span-2 space-y-5">
          <AnimatePresence mode="wait">
            <ActorDetail key={selectedActor.id} actor={selectedActor} />
          </AnimatePresence>

          {/* Investigation graph (Power User only) */}
          {isPower && (
            <div className="glass border border-white/5 rounded-xl p-5">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Network className="w-4 h-4 text-magenta" />
                  <h3 className="text-sm font-semibold text-white">Investigation Graph</h3>
                </div>
                <span className="text-[10px] text-ink-600">hover nodes to trace relationships</span>
              </div>
              <EntityGraph data={graph} />
            </div>
          )}

          {/* MITRE mini matrix (Power User only) */}
          {isPower && (
          <div className="glass border border-white/5 rounded-xl p-5 overflow-x-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-white">MITRE ATT&CK Heatmap</h3>
              <div className="flex items-center gap-4 text-[9px] text-ink-500">
                {[
                  { label: '> 80%', color: '#FF2E97' },
                  { label: '60–80%', color: '#FF4D6D' },
                  { label: '40–60%', color: '#FFB23E' },
                  { label: '< 40%', color: '#7A3CFF' },
                ].map(({ label, color }) => (
                  <div key={label} className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded" style={{ background: color }} />
                    {label}
                  </div>
                ))}
              </div>
            </div>
            <div className="grid" style={{ gridTemplateColumns: `repeat(${MITRE_TACTICS.length}, minmax(52px, 1fr))`, gap: '2px' }}>
              {MITRE_TACTICS.map(({ id, name }) => (
                <div key={id} className="text-center text-[8px] text-ink-600 truncate pb-1">{name}</div>
              ))}
              {MITRE_TACTICS.map(({ id, techs }) => (
                <div key={id} className="flex flex-col gap-0.5">
                  {techs.map((tech) => {
                    const heat = HEAT_LEVELS[tech] ?? 0
                    return (
                      <div
                        key={tech}
                        title={`${tech} · ${heat}%`}
                        className="h-6 rounded text-center text-[7px] font-mono leading-6 truncate px-0.5 cursor-pointer hover:opacity-80 transition-opacity"
                        style={{
                          background: heat ? heatColor(heat) : 'rgba(255,255,255,0.04)',
                          color: heat ? 'rgba(255,255,255,0.9)' : 'transparent',
                        }}
                      >
                        {tech}
                      </div>
                    )
                  })}
                </div>
              ))}
            </div>
          </div>
          )}

          {/* Threat hunt + sector targeting */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <ThreatHuntPanel />
            <SectorTargeting />
          </div>

          {/* Campaign timeline */}
          <div className="glass border border-white/5 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-white mb-4">Recent Campaigns</h3>
            <div className="space-y-3 relative before:absolute before:left-3 before:top-0 before:bottom-0 before:w-px before:bg-white/8">
              {[
                { date: 'Nov 2024', name: 'Operation Midnight Blizzard (Exchange online)', actor: 'APT29',   severity: 'critical' },
                { date: 'Oct 2024', name: 'Ryuk ransomware hospital campaign',              actor: 'Lazarus', severity: 'critical' },
                { date: 'Oct 2024', name: 'Living-off-the-land in US water utilities',      actor: 'Volt Typhoon', severity: 'high' },
                { date: 'Sep 2024', name: 'BEC phishing against hospitality sector',       actor: 'Scattered Spider', severity: 'high' },
                { date: 'Aug 2024', name: 'CARBANAK POS system deployment — retail',       actor: 'FIN7',    severity: 'medium' },
              ].map(({ date, name, actor, severity }) => (
                <div key={name} className="flex items-start gap-4 pl-7 relative">
                  <div className="absolute left-2 top-1.5 w-2 h-2 rounded-full border border-white/20"
                    style={{
                      background: severity === 'critical' ? '#FF2E97' : severity === 'high' ? '#FF4D6D' : '#FFB23E',
                    }}
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-ink-200">{name}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] text-magenta">{actor}</span>
                      <span className="text-[10px] text-ink-600">{date}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
