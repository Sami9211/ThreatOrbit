'use client'

import { useState, useMemo, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { fetchActors, fetchCtiSummary, type Actor as ApiActor, type CtiSummary } from '@/lib/api'
import {
  UserSearch, Search, X, ChevronRight, ExternalLink, Shield,
  Crosshair, Bug, Clock, Activity, Building2, Filter,
  Globe, Skull, DollarSign, Megaphone, Flame, Users,
} from 'lucide-react'
import { cn } from '@/lib/utils'

/* ─── Types ─────────────────────────────────────────────────────────── */
type Motivation = 'Espionage' | 'Financial' | 'Hacktivism' | 'Destruction'
type ActorType = 'Nation-State' | 'Cybercrime' | 'Hacktivist'

interface Campaign {
  year: string
  name: string
  note: string
}

interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  origin: string
  flag: string
  type: ActorType
  motivations: Motivation[]
  sophistication: number // 1..5
  threatLevel: 'critical' | 'high' | 'elevated'
  sectors: string[]
  campaignCount: number
  firstSeen: string
  malware: string[]
  ttps: string[]
  recentActivity: string
  description: string
  campaigns: Campaign[]
  iocs: string[]
}

/* ─── Seed data ─────────────────────────────────────────────────────── */
const ACTORS: ThreatActor[] = [
  {
    id: 'apt29',
    name: 'APT29',
    aliases: ['Cozy Bear', 'Nobelium', 'Midnight Blizzard', 'The Dukes'],
    origin: 'Russia (SVR)', flag: '🇷🇺',
    type: 'Nation-State',
    motivations: ['Espionage'],
    sophistication: 5,
    threatLevel: 'critical',
    sectors: ['Government', 'Defense', 'Technology', 'Think Tanks', 'Healthcare'],
    campaignCount: 89,
    firstSeen: '2008',
    malware: ['WellMess', 'WellMail', 'SUNBURST', 'FoggyWeb', 'EnvyScout'],
    ttps: ['T1566', 'T1078', 'T1195.002', 'T1059.001', 'T1114'],
    recentActivity: 'Ongoing credential-theft operations against cloud tenants and ongoing targeting of NATO-aligned foreign ministries.',
    description: 'Russian SVR foreign-intelligence APT known for patient, stealthy espionage. Responsible for the 2020 SolarWinds supply-chain compromise and the 2016 DNC intrusion. Highly capable in cloud and identity-based attack paths.',
    campaigns: [
      { year: '2024', name: 'Microsoft 365 mailbox theft', note: 'Targeted senior leadership inboxes via stolen OAuth tokens.' },
      { year: '2021', name: 'SolarWinds (SUNBURST)', note: 'Supply-chain backdoor affecting 18,000+ organizations.' },
      { year: '2016', name: 'DNC intrusion', note: 'Long-dwell espionage against US political organizations.' },
    ],
    iocs: ['domain: avsvmcloud[.]com', 'sha256:32519b…', 'ua: SolarWinds.BusinessLayerHost'],
  },
  {
    id: 'apt28',
    name: 'APT28',
    aliases: ['Fancy Bear', 'Sofacy', 'Sednit', 'Strontium', 'Forest Blizzard'],
    origin: 'Russia (GRU)', flag: '🇷🇺',
    type: 'Nation-State',
    motivations: ['Espionage'],
    sophistication: 5,
    threatLevel: 'critical',
    sectors: ['Government', 'Military', 'Media', 'Energy', 'Aerospace'],
    campaignCount: 76,
    firstSeen: '2004',
    malware: ['X-Agent', 'X-Tunnel', 'Zebrocy', 'Sofacy', 'GooseEgg'],
    ttps: ['T1566.001', 'T1190', 'T1071', 'T1003', 'T1068'],
    recentActivity: 'Exploitation of edge devices and Outlook elevation-of-privilege flaws against government and aerospace targets.',
    description: 'Russian GRU military-intelligence APT focused on aggressive geopolitical espionage and influence operations. Linked to the 2016 DNC hack alongside APT29 and numerous attacks on Olympic and electoral infrastructure.',
    campaigns: [
      { year: '2024', name: 'GooseEgg / CVE-2022-38028', note: 'Print Spooler abuse for credential theft.' },
      { year: '2018', name: 'VPNFilter', note: 'Router botnet affecting 500,000+ devices.' },
      { year: '2015', name: 'Bundestag breach', note: 'Espionage against the German parliament.' },
    ],
    iocs: ['ip: 95.215.x.x', 'sha256:4b8806…', 'domain: actalliance[.]org'],
  },
  {
    id: 'lazarus',
    name: 'Lazarus Group',
    aliases: ['Hidden Cobra', 'UNC4736', 'ZINC', 'Diamond Sleet', 'APT38'],
    origin: 'North Korea (RGB)', flag: '🇰🇵',
    type: 'Nation-State',
    motivations: ['Financial', 'Espionage'],
    sophistication: 5,
    threatLevel: 'critical',
    sectors: ['Finance', 'Cryptocurrency', 'Defense', 'Software', 'Aerospace'],
    campaignCount: 64,
    firstSeen: '2009',
    malware: ['WannaCry', 'AppleJeus', 'BLINDINGCAN', 'MagicRAT', 'Manuscrypt'],
    ttps: ['T1566', 'T1195.001', 'T1486', 'T1059', 'T1105'],
    recentActivity: 'Aggressive cryptocurrency exchange heists and fake-job-offer social engineering against blockchain developers.',
    description: 'North Korean state-sponsored umbrella group conducting both espionage and revenue-generating cybercrime to fund the regime. Behind the 2014 Sony hack, 2017 WannaCry outbreak, and billions in crypto theft.',
    campaigns: [
      { year: '2024', name: 'Operation Dream Job', note: 'Fake recruiter lures against defense and crypto staff.' },
      { year: '2022', name: 'Ronin Bridge heist', note: '$625M cryptocurrency theft.' },
      { year: '2017', name: 'WannaCry', note: 'Global ransomware worm via EternalBlue.' },
    ],
    iocs: ['sha256:ed01eb…', 'domain: blockchain-newtab[.]com', 'ip: 175.45.x.x'],
  },
  {
    id: 'apt41',
    name: 'APT41',
    aliases: ['Double Dragon', 'Winnti', 'Barium', 'Wicked Panda'],
    origin: 'China (MSS)', flag: '🇨🇳',
    type: 'Nation-State',
    motivations: ['Espionage', 'Financial'],
    sophistication: 5,
    threatLevel: 'critical',
    sectors: ['Healthcare', 'Telecom', 'Gaming', 'Technology', 'Government'],
    campaignCount: 58,
    firstSeen: '2012',
    malware: ['ShadowPad', 'Winnti', 'PlugX', 'Crosswalk', 'KEYPLUG'],
    ttps: ['T1190', 'T1195.002', 'T1071', 'T1505.003', 'T1078'],
    recentActivity: 'Web-application exploitation of state-government networks and continued gaming-industry supply-chain abuse.',
    description: 'Chinese MSS-linked group uniquely blending state-directed espionage with personal financial cybercrime. Known for software supply-chain compromises and prolific use of digitally signed malware.',
    campaigns: [
      { year: '2022', name: 'US state government breaches', note: 'Exploited web apps across multiple state networks.' },
      { year: '2019', name: 'Gaming supply chain', note: 'Trojanized game updates for mass distribution.' },
      { year: '2017', name: 'CCleaner compromise', note: 'Supply-chain backdoor (Winnti overlap).' },
    ],
    iocs: ['sha256:6f7e…', 'domain: update.microsoft-cdn[.]net', 'ip: 67.229.x.x'],
  },
  {
    id: 'volt',
    name: 'Volt Typhoon',
    aliases: ['Bronze Silhouette', 'Vanguard Panda', 'DEV-0391'],
    origin: 'China (MSS)', flag: '🇨🇳',
    type: 'Nation-State',
    motivations: ['Espionage', 'Destruction'],
    sophistication: 5,
    threatLevel: 'critical',
    sectors: ['Critical Infrastructure', 'Energy', 'Water', 'Communications', 'Transportation'],
    campaignCount: 23,
    firstSeen: '2021',
    malware: ['(LOTL - no custom malware)', 'Earthworm', 'Fast Reverse Proxy'],
    ttps: ['T1059', 'T1218', 'T1070', 'T1078', 'T1090'],
    recentActivity: 'Pre-positioning within US critical-infrastructure OT networks via living-off-the-land and compromised SOHO routers.',
    description: 'Chinese state-sponsored group focused on pre-positioning for potential disruptive or destructive attacks against US critical infrastructure. Relies almost entirely on living-off-the-land techniques to evade detection.',
    campaigns: [
      { year: '2024', name: 'Critical infra pre-positioning', note: 'Long-dwell access to energy and water utilities.' },
      { year: '2023', name: 'Guam telecom intrusion', note: 'Targeted communications infrastructure.' },
    ],
    iocs: ['ip: SOHO-router proxies', 'cmd: wmic /node:', 'evt:1102 (log cleared)'],
  },
  {
    id: 'sandworm',
    name: 'Sandworm',
    aliases: ['Voodoo Bear', 'Telebots', 'Iron Viking', 'Seashell Blizzard'],
    origin: 'Russia (GRU)', flag: '🇷🇺',
    type: 'Nation-State',
    motivations: ['Destruction', 'Espionage'],
    sophistication: 5,
    threatLevel: 'critical',
    sectors: ['Energy', 'Government', 'Critical Infrastructure', 'Logistics'],
    campaignCount: 41,
    firstSeen: '2009',
    malware: ['NotPetya', 'Industroyer', 'BlackEnergy', 'CaddyWiper', 'Olympic Destroyer'],
    ttps: ['T1485', 'T1561', 'T1499', 'T1190', 'T1078'],
    recentActivity: 'Destructive wiper deployment and OT-targeted attacks against Ukrainian energy and government systems.',
    description: 'Russian GRU Unit 74455, the most destructive known APT. Responsible for the 2015/2016 Ukraine power-grid blackouts, the 2017 NotPetya wiper ($10B+ damage), and ongoing wartime OT attacks.',
    campaigns: [
      { year: '2022', name: 'Industroyer2', note: 'Attempted blackout of a Ukrainian substation.' },
      { year: '2017', name: 'NotPetya', note: 'Pseudo-ransomware wiper, $10B+ global damage.' },
      { year: '2015', name: 'Ukraine grid blackout', note: 'First confirmed cyber-induced power outage.' },
    ],
    iocs: ['sha256:027cc4…', 'domain: coffeinoffice[.]xyz', 'tool: CaddyWiper'],
  },
  {
    id: 'fin7',
    name: 'FIN7',
    aliases: ['Carbanak', 'Carbon Spider', 'Sangria Tempest'],
    origin: 'Russia', flag: '🇷🇺',
    type: 'Cybercrime',
    motivations: ['Financial'],
    sophistication: 4,
    threatLevel: 'high',
    sectors: ['Retail', 'Hospitality', 'Restaurant', 'Finance'],
    campaignCount: 112,
    firstSeen: '2015',
    malware: ['Carbanak', 'GRIFFON', 'BIRDWATCH', 'POWERPLANT', 'Lizar'],
    ttps: ['T1566.001', 'T1059.001', 'T1055', 'T1041', 'T1486'],
    recentActivity: 'Pivot toward ransomware affiliation and malvertising-driven loader distribution.',
    description: 'Financially motivated Russian-speaking cybercrime group responsible for over $1B in theft. Historically targeted point-of-sale systems via sophisticated spear-phishing, later pivoting to ransomware operations.',
    campaigns: [
      { year: '2023', name: 'Malvertising loaders', note: 'SEO-poisoned ads delivering POWERPLANT.' },
      { year: '2018', name: 'POS data theft', note: '15M+ payment cards stolen from US chains.' },
    ],
    iocs: ['sha256:9b2c…', 'domain: gw-cdn[.]net', 'doc: macro-enabled invoice'],
  },
  {
    id: 'scattered',
    name: 'Scattered Spider',
    aliases: ['UNC3944', 'Octo Tempest', 'Muddled Libra', 'Star Fraud'],
    origin: 'Distributed (US/UK)', flag: '🌐',
    type: 'Cybercrime',
    motivations: ['Financial'],
    sophistication: 4,
    threatLevel: 'high',
    sectors: ['Hospitality', 'Gaming', 'Telecom', 'Retail', 'Finance'],
    campaignCount: 31,
    firstSeen: '2022',
    malware: ['(social engineering)', 'AveMaria/Warzone', 'RattyRAT', 'ALPHV (affiliate)'],
    ttps: ['T1598', 'T1621', 'T1556', 'T1078', 'T1486'],
    recentActivity: 'High-tempo help-desk social engineering and SIM-swap-driven account takeovers preceding ransomware deployment.',
    description: 'Young, English-speaking financially motivated collective skilled at help-desk social engineering, SIM swapping, and MFA fatigue. Known for the 2023 MGM Resorts and Caesars Entertainment breaches.',
    campaigns: [
      { year: '2023', name: 'MGM Resorts breach', note: 'Vishing the help desk led to ALPHV ransomware.' },
      { year: '2023', name: 'Caesars extortion', note: 'Reported multi-million-dollar ransom payment.' },
      { year: '2022', name: '0ktapus', note: 'Phishing kit targeting Okta credentials at 130+ orgs.' },
    ],
    iocs: ['phish: okta-sso[.]help', 'technique: SIM swap', 'tool: AnyDesk abuse'],
  },
  {
    id: 'lockbit',
    name: 'LockBit',
    aliases: ['Bitwise Spider', 'LockBit 3.0', 'Gold Mystic'],
    origin: 'Russia-affiliated', flag: '🇷🇺',
    type: 'Cybercrime',
    motivations: ['Financial'],
    sophistication: 4,
    threatLevel: 'critical',
    sectors: ['Manufacturing', 'Healthcare', 'Finance', 'Government', 'Logistics'],
    campaignCount: 200,
    firstSeen: '2019',
    malware: ['LockBit 2.0', 'LockBit 3.0 (Black)', 'StealBit', 'LockBit Green'],
    ttps: ['T1486', 'T1490', 'T1567', 'T1078', 'T1133'],
    recentActivity: 'Rebuilding affiliate operations following Operation Cronos law-enforcement disruption.',
    description: 'Prolific Ransomware-as-a-Service (RaaS) operation that dominated the ransomware ecosystem for years. Operates a double-extortion model with a public leak site; disrupted by Operation Cronos in early 2024.',
    campaigns: [
      { year: '2023', name: 'Boeing & ICBC attacks', note: 'High-profile double-extortion victims.' },
      { year: '2022', name: 'LockBit 3.0 launch', note: 'Introduced a ransomware bug-bounty program.' },
    ],
    iocs: ['ext: .lockbit', 'leak: lockbitsupp', 'sha256:7a3b…'],
  },
  {
    id: 'blackcat',
    name: 'BlackCat',
    aliases: ['ALPHV', 'Noberus', 'Coffin'],
    origin: 'Russia-affiliated', flag: '🇷🇺',
    type: 'Cybercrime',
    motivations: ['Financial'],
    sophistication: 4,
    threatLevel: 'high',
    sectors: ['Healthcare', 'Finance', 'Energy', 'Manufacturing'],
    campaignCount: 95,
    firstSeen: '2021',
    malware: ['ALPHV/BlackCat (Rust)', 'Exmatter', 'Munchkin'],
    ttps: ['T1486', 'T1567.002', 'T1490', 'T1059.001', 'T1078'],
    recentActivity: 'Exit-scam allegations after the Change Healthcare attack; affiliates migrating to other RaaS brands.',
    description: 'Sophisticated Rust-based RaaS, one of the first to use a cross-platform encryptor. Behind the 2024 Change Healthcare attack that disrupted US healthcare payments nationwide.',
    campaigns: [
      { year: '2024', name: 'Change Healthcare', note: '$22M ransom; nationwide healthcare disruption.' },
      { year: '2023', name: 'MGM (via Scattered Spider)', note: 'Encrypted hundreds of hypervisors.' },
    ],
    iocs: ['ext: random 7-char', 'leak: alphv-tor', 'sha256:3d1a…'],
  },
  {
    id: 'kimsuky',
    name: 'Kimsuky',
    aliases: ['Velvet Chollima', 'Thallium', 'APT43', 'Emerald Sleet'],
    origin: 'North Korea (RGB)', flag: '🇰🇵',
    type: 'Nation-State',
    motivations: ['Espionage'],
    sophistication: 3,
    threatLevel: 'high',
    sectors: ['Government', 'Think Tanks', 'Academia', 'Defense', 'Media'],
    campaignCount: 47,
    firstSeen: '2012',
    malware: ['BabyShark', 'AppleSeed', 'FlowerPower', 'ReconShark'],
    ttps: ['T1566.001', 'T1598', 'T1056.001', 'T1114', 'T1059.001'],
    recentActivity: 'Spear-phishing of Korea-policy experts and journalists, often impersonating reporters or academics.',
    description: 'North Korean espionage group focused on intelligence collection regarding foreign policy and nuclear matters. Specializes in highly targeted spear-phishing and credential harvesting.',
    campaigns: [
      { year: '2023', name: 'ReconShark', note: 'Modular recon tool against policy experts.' },
      { year: '2020', name: 'COVID research targeting', note: 'Phishing pharma and research bodies.' },
    ],
    iocs: ['domain: nid-security[.]com', 'sha256:5c8e…', 'phish: KISA notice'],
  },
  {
    id: 'cl0p',
    name: 'Cl0p',
    aliases: ['TA505', 'FIN11', 'Lace Tempest'],
    origin: 'Russia-affiliated', flag: '🇷🇺',
    type: 'Cybercrime',
    motivations: ['Financial'],
    sophistication: 4,
    threatLevel: 'critical',
    sectors: ['Finance', 'Healthcare', 'Government', 'Education', 'Energy'],
    campaignCount: 70,
    firstSeen: '2019',
    malware: ['Cl0p Ransomware', 'GET2', 'SDBOT', 'TrueBot', 'DEWMODE webshell'],
    ttps: ['T1190', 'T1567.002', 'T1486', 'T1505.003', 'T1059'],
    recentActivity: 'Mass exploitation of managed-file-transfer zero-days for data-theft extortion at scale.',
    description: 'Russia-affiliated extortion group that pioneered mass zero-day exploitation of file-transfer appliances. Behind the 2023 MOVEit campaign affecting 2,700+ organizations and tens of millions of individuals.',
    campaigns: [
      { year: '2023', name: 'MOVEit Transfer (CVE-2023-34362)', note: '2,700+ orgs breached via SQLi zero-day.' },
      { year: '2021', name: 'Accellion FTA', note: 'Mass exploitation of legacy file-transfer appliances.' },
    ],
    iocs: ['webshell: human2.aspx', 'domain: cl0p-leaks', 'sha256:1f4d…'],
  },
]

/* ─── Config / lookups ──────────────────────────────────────────────── */
const MOTIVATION_CFG: Record<Motivation, { color: string; icon: React.ComponentType<any> }> = {
  Espionage:   { color: '#7A3CFF', icon: Globe },
  Financial:   { color: '#34F5C5', icon: DollarSign },
  Hacktivism:  { color: '#FFB23E', icon: Megaphone },
  Destruction: { color: '#FF4D6D', icon: Flame },
}

const TYPE_CFG: Record<ActorType, { color: string; icon: React.ComponentType<any> }> = {
  'Nation-State': { color: '#FF2E97', icon: Globe },
  Cybercrime:     { color: '#FFB23E', icon: DollarSign },
  Hacktivist:     { color: '#34F5C5', icon: Megaphone },
}

const THREAT_CFG: Record<ThreatActor['threatLevel'], { color: string; label: string }> = {
  critical: { color: '#FF2E97', label: 'Critical' },
  high:     { color: '#FF4D6D', label: 'High' },
  elevated: { color: '#FFB23E', label: 'Elevated' },
}

/* ─── Sophistication meter ──────────────────────────────────────────── */
function SophMeter({ level, color = '#FF2E97' }: { level: number; color?: string }) {
  return (
    <div className="flex items-center gap-0.5">
      {[1, 2, 3, 4, 5].map((n) => (
        <span
          key={n}
          className="w-1.5 rounded-sm"
          style={{
            height: `${6 + n * 2}px`,
            background: n <= level ? color : 'rgba(255,255,255,0.10)',
          }}
        />
      ))}
    </div>
  )
}

/* ─── Motivation badge ──────────────────────────────────────────────── */
function MotivationBadge({ m }: { m: Motivation }) {
  const cfg = MOTIVATION_CFG[m]
  const Icon = cfg.icon
  return (
    <span
      className="inline-flex items-center gap-1 text-[9px] font-semibold px-1.5 py-0.5 rounded-full border"
      style={{ color: cfg.color, background: `${cfg.color}15`, borderColor: `${cfg.color}33` }}
    >
      <Icon className="w-2.5 h-2.5" /> {m}
    </span>
  )
}

/* ─── Actor card ────────────────────────────────────────────────────── */
function ActorCard({ actor, onSelect }: { actor: ThreatActor; onSelect: () => void }) {
  const threat = THREAT_CFG[actor.threatLevel]
  return (
    <div
      onClick={onSelect}
      className="glass border border-white/5 rounded-xl p-4 cursor-pointer transition-all duration-200 hover:border-magenta/30 hover:bg-magenta/5"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-lg leading-none">{actor.flag}</span>
            <span className="text-sm font-semibold text-white truncate">{actor.name}</span>
          </div>
          <p className="text-[10px] text-ink-500 mt-1 truncate">{actor.aliases.slice(0, 2).join(' · ')}</p>
        </div>
        <span
          className="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded-full border shrink-0"
          style={{ color: threat.color, background: `${threat.color}15`, borderColor: `${threat.color}33` }}
        >
          {threat.label}
        </span>
      </div>

      <p className="text-[10px] text-ink-500 mt-2">{actor.origin} · {actor.type}</p>

      <div className="flex items-center justify-between mt-3">
        <div className="flex flex-wrap gap-1">
          {actor.motivations.map((m) => <MotivationBadge key={m} m={m} />)}
        </div>
        <SophMeter level={actor.sophistication} color={threat.color} />
      </div>

      <div className="flex flex-wrap gap-1 mt-3">
        {actor.sectors.slice(0, 3).map((s) => (
          <span key={s} className="text-[9px] px-1.5 py-0.5 rounded-full bg-surface-3 border border-white/8 text-ink-500">{s}</span>
        ))}
        {actor.sectors.length > 3 && (
          <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-surface-3 border border-white/8 text-ink-600">+{actor.sectors.length - 3}</span>
        )}
      </div>

      <div className="flex items-center gap-3 mt-3 pt-3 border-t border-white/5 text-[10px] text-ink-500">
        <span className="flex items-center gap-1"><Crosshair className="w-3 h-3" /> {actor.campaignCount} campaigns</span>
        <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> since {actor.firstSeen}</span>
      </div>
    </div>
  )
}

/* ─── Detail slide-over ─────────────────────────────────────────────── */
function ActorPanel({ actor, onClose }: { actor: ThreatActor; onClose: () => void }) {
  const threat = THREAT_CFG[actor.threatLevel]
  return (
    <motion.div
      key={actor.id}
      initial={{ x: '100%', opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: '100%', opacity: 0 }}
      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      className="fixed right-0 top-0 bottom-0 z-[60] w-full max-w-[600px] flex flex-col bg-surface border-l border-white/8 shadow-2xl overflow-hidden"
    >
      {/* Header */}
      <div className="p-5 border-b border-white/8 shrink-0">
        <div className="flex items-start gap-3">
          <span className="text-3xl leading-none">{actor.flag}</span>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="font-display text-lg font-bold text-white">{actor.name}</h2>
              <span
                className="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded-full border"
                style={{ color: threat.color, background: `${threat.color}15`, borderColor: `${threat.color}33` }}
              >
                {threat.label} Threat
              </span>
            </div>
            <p className="text-[10px] text-ink-500 mt-1">{actor.origin} · {actor.type} · since {actor.firstSeen}</p>
            <div className="flex flex-wrap gap-1.5 mt-2">
              {actor.aliases.map((a) => (
                <span key={a} className="text-[10px] px-1.5 py-0.5 rounded bg-surface-3 text-ink-500 font-mono">{a}</span>
              ))}
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex items-center gap-4 mt-4 flex-wrap">
          <div className="flex flex-col px-3 py-1.5 rounded-lg bg-surface-2 border border-white/6">
            <span className="text-[9px] text-ink-600 uppercase tracking-wide">Sophistication</span>
            <div className="mt-1"><SophMeter level={actor.sophistication} color={threat.color} /></div>
          </div>
          <div className="flex flex-col px-3 py-1.5 rounded-lg bg-surface-2 border border-white/6">
            <span className="text-[9px] text-ink-600 uppercase tracking-wide">Campaigns</span>
            <span className="text-sm font-semibold text-white mt-0.5">{actor.campaignCount}</span>
          </div>
          <div className="flex flex-col px-3 py-1.5 rounded-lg bg-surface-2 border border-white/6">
            <span className="text-[9px] text-ink-600 uppercase tracking-wide">Motivation</span>
            <div className="flex gap-1 mt-1">{actor.motivations.map((m) => <MotivationBadge key={m} m={m} />)}</div>
          </div>
          <a
            href={`https://attack.mitre.org/groups/?search=${encodeURIComponent(actor.name)}`}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto flex items-center gap-1 text-xs text-magenta hover:underline"
          >
            <ExternalLink className="w-3 h-3" /> MITRE ATT&amp;CK
          </a>
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        <section>
          <SectionHead icon={UserSearch} title="Description" />
          <p className="text-xs text-ink-300 leading-relaxed mt-2">{actor.description}</p>
        </section>

        <section>
          <SectionHead icon={Activity} title="Recent Activity" />
          <p className="text-xs text-ink-300 leading-relaxed mt-2">{actor.recentActivity}</p>
        </section>

        <section>
          <SectionHead icon={Shield} title="MITRE ATT&CK Techniques" />
          <div className="flex flex-wrap gap-1.5 mt-2">
            {actor.ttps.map((t) => (
              <a
                key={t}
                href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] px-2 py-0.5 rounded bg-violet/15 text-violet font-mono border border-violet/20 hover:bg-violet/25 transition-colors"
              >
                {t}
              </a>
            ))}
          </div>
        </section>

        <section>
          <SectionHead icon={Bug} title="Tools &amp; Malware" />
          <div className="flex flex-wrap gap-1.5 mt-2">
            {actor.malware.map((m) => (
              <span key={m} className="text-[10px] px-2 py-0.5 rounded bg-threat/10 text-threat border border-threat/20">{m}</span>
            ))}
          </div>
        </section>

        <section>
          <SectionHead icon={Building2} title="Target Sectors" />
          <div className="flex flex-wrap gap-1.5 mt-2">
            {actor.sectors.map((s) => (
              <span key={s} className="text-[10px] px-2 py-0.5 rounded-full bg-surface-2 border border-white/10 text-ink-300">{s}</span>
            ))}
          </div>
        </section>

        <section>
          <SectionHead icon={Clock} title="Known Campaigns" />
          <div className="mt-3 space-y-3 relative before:absolute before:left-[5px] before:top-1 before:bottom-1 before:w-px before:bg-white/8">
            {actor.campaigns.map((c) => (
              <div key={c.name} className="flex items-start gap-3 pl-5 relative">
                <span className="absolute left-[1px] top-1 w-2.5 h-2.5 rounded-full border border-white/20" style={{ background: threat.color }} />
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-magenta">{c.year}</span>
                    <span className="text-xs text-ink-200 font-medium">{c.name}</span>
                  </div>
                  <p className="text-[11px] text-ink-500 mt-0.5 leading-snug">{c.note}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section>
          <SectionHead icon={Crosshair} title="Associated IOCs" />
          <div className="flex flex-wrap gap-1.5 mt-2">
            {actor.iocs.map((ioc) => (
              <span key={ioc} className="text-[10px] px-2 py-0.5 rounded bg-magenta/10 text-magenta font-mono border border-magenta/20">{ioc}</span>
            ))}
          </div>
        </section>
      </div>
    </motion.div>
  )
}

function SectionHead({ icon: Icon, title }: { icon: React.ComponentType<any>; title: string }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="w-3.5 h-3.5 text-ink-600" />
      <span className="text-[10px] font-semibold text-ink-500 uppercase tracking-widest">{title}</span>
    </div>
  )
}

/* ─── KPI strip ─────────────────────────────────────────────────────── */
const KPIS: { label: string; value: string | number; icon: React.ComponentType<any>; color: string; sub: string }[] = [
  { label: 'Tracked Actors',     value: 47, icon: Users,    color: '#7A3CFF', sub: 'in library' },
  { label: 'Active Campaigns',   value: 12, icon: Activity, color: '#FF2E97', sub: 'ongoing' },
  { label: 'Nation-State',       value: 23, icon: Globe,    color: '#FF4D6D', sub: 'APT groups' },
  { label: 'Ransomware Groups',  value: 16, icon: Skull,    color: '#FFB23E', sub: 'RaaS / extortion' },
]

/* ─── Filter pill ───────────────────────────────────────────────────── */
function FilterSelect({
  value, onChange, options, icon: Icon,
}: {
  value: string
  onChange: (v: string) => void
  options: { value: string; label: string }[]
  icon: React.ComponentType<any>
}) {
  return (
    <div className="relative flex items-center gap-2 px-3 py-2 rounded-xl bg-surface-2 border border-white/8 hover:border-white/15 transition-colors">
      <Icon className="w-3.5 h-3.5 text-ink-600 shrink-0" />
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="appearance-none bg-transparent text-xs text-ink-300 focus:outline-none cursor-pointer pr-3"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} className="bg-[#100A1C]">{o.label}</option>
        ))}
      </select>
    </div>
  )
}

/* ─── Page ──────────────────────────────────────────────────────────── */
export default function ActorProfilesPage() {
  const [search, setSearch] = useState('')
  const [filterOrigin, setFilterOrigin] = useState<string>('all')
  const [filterMotivation, setFilterMotivation] = useState<string>('all')
  const [filterType, setFilterType] = useState<string>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [actors, setActors] = useState<ThreatActor[]>(ACTORS)
  const [summary, setSummary] = useState<CtiSummary | null>(null)

  useEffect(() => {
    fetchCtiSummary().then(setSummary).catch(() => {})
    fetchActors().then((data: ApiActor[]) => {
      if (data.length > 0) {
        const mapped: ThreatActor[] = data.map((a) => {
          const seed = ACTORS.find((s) => s.id === a.id || s.name === a.name)
          return {
            id: a.id,
            name: a.name,
            aliases: Array.isArray(a.aliases) ? a.aliases : [],
            origin: a.origin,
            flag: a.flag ?? seed?.flag ?? '🌐',
            type: ((t) => t === 'nation-state' ? 'Nation-State' : t === 'cybercrime' ? 'Cybercrime' : 'Hacktivist')((a.type ?? '').toLowerCase()) as ActorType,
            motivations: ((Array.isArray(a.motivations) ? a.motivations : []) as Motivation[]),
            sophistication: a.sophistication,
            threatLevel: (a.threatLevel as 'critical' | 'high' | 'elevated') ?? 'high',
            sectors: Array.isArray(a.sectors) ? a.sectors : [],
            campaignCount: a.campaignCount ?? (Array.isArray(a.campaigns) ? a.campaigns.length : 0),
            firstSeen: a.firstSeen?.split('-')[0] ?? 'Unknown',
            malware: seed?.malware ?? (Array.isArray(a.malware) ? a.malware : []),
            ttps: Array.isArray(a.ttps) ? a.ttps : [],
            recentActivity: seed?.recentActivity ?? a.description,
            description: a.description,
            campaigns: seed?.campaigns ?? (Array.isArray(a.campaigns) ? a.campaigns : []).map((c) => ({ year: '', name: c, note: '' })),
            iocs: seed?.iocs ?? [],
          }
        })
        setActors(mapped)
      }
    }).catch(() => {})
  }, [])

  const selected = actors.find((a) => a.id === selectedId) ?? null

  // Live KPI values from the API summary, falling back to the static demo figures.
  const kpis = useMemo(() => {
    if (!summary) return KPIS
    const live: Record<string, number> = {
      'Tracked Actors': summary.trackedActors,
      'Active Campaigns': summary.activeCampaigns,
      'Nation-State': summary.nationState,
      'Ransomware Groups': summary.cybercrime,
    }
    return KPIS.map((k) => ({ ...k, value: live[k.label] ?? k.value }))
  }, [summary])

  const origins = useMemo(() => {
    const set = new Set(actors.map((a) => a.origin))
    return Array.from(set).sort()
  }, [actors])

  const filtered = useMemo(() => actors.filter((a) => {
    if (filterOrigin !== 'all' && a.origin !== filterOrigin) return false
    if (filterMotivation !== 'all' && !a.motivations.includes(filterMotivation as Motivation)) return false
    if (filterType !== 'all' && a.type !== filterType) return false
    if (search) {
      const q = search.toLowerCase()
      return (
        a.name.toLowerCase().includes(q) ||
        a.aliases.some((al) => al.toLowerCase().includes(q)) ||
        a.origin.toLowerCase().includes(q) ||
        a.malware.some((m) => m.toLowerCase().includes(q)) ||
        a.sectors.some((s) => s.toLowerCase().includes(q))
      )
    }
    return true
  }), [actors, search, filterOrigin, filterMotivation, filterType])

  return (
    <div className="flex flex-col h-full bg-[#0A0612]">
      {/* Header */}
      <div className="px-6 py-4 border-b border-white/5 shrink-0">
        <div className="flex items-center gap-2 mb-1">
          <div className="p-1.5 rounded-lg bg-magenta/15 border border-magenta/25">
            <UserSearch className="w-4 h-4 text-magenta" />
          </div>
          <h1 className="font-display text-xl font-bold text-white tracking-tight">Actor Profiles</h1>
        </div>
        <p className="text-sm text-ink-500">Tracked threat actors, APT groups, and their TTPs</p>
      </div>

      {/* KPI strip */}
      <div className="px-6 py-4 border-b border-white/5 shrink-0">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {kpis.map(({ label, value, icon: Icon, color, sub }) => (
            <motion.div
              key={label}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass border border-white/5 rounded-xl p-4 relative overflow-hidden"
            >
              <div className="absolute inset-0 opacity-30" style={{ background: `radial-gradient(circle at 0% 0%, ${color}20, transparent 70%)` }} />
              <div className="relative flex items-start justify-between">
                <div>
                  <p className="text-xs text-ink-500 mb-1">{label}</p>
                  <p className="font-display text-2xl font-bold text-white">{value}</p>
                  <p className="text-[10px] text-ink-600 mt-0.5">{sub}</p>
                </div>
                <div className="p-2 rounded-lg shrink-0" style={{ background: `${color}18` }}>
                  <Icon className="w-4 h-4" style={{ color }} />
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Filter bar */}
      <div className="px-6 py-3 border-b border-white/5 shrink-0">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 flex-1 min-w-[200px] max-w-xs px-3 py-2 rounded-xl bg-surface-2 border border-white/8 focus-within:border-violet/40 transition-colors">
            <Search className="w-3.5 h-3.5 text-ink-600 shrink-0" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search actors, aliases, malware…"
              className="flex-1 bg-transparent text-xs text-ink-200 placeholder-ink-700 focus:outline-none"
            />
            {search && (
              <button onClick={() => setSearch('')} className="text-ink-600 hover:text-ink-300">
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          <FilterSelect
            value={filterOrigin}
            onChange={setFilterOrigin}
            icon={Globe}
            options={[{ value: 'all', label: 'All Origins' }, ...origins.map((o) => ({ value: o, label: o }))]}
          />
          <FilterSelect
            value={filterMotivation}
            onChange={setFilterMotivation}
            icon={Crosshair}
            options={[
              { value: 'all', label: 'All Motivations' },
              { value: 'Espionage', label: 'Espionage' },
              { value: 'Financial', label: 'Financial' },
              { value: 'Hacktivism', label: 'Hacktivism' },
              { value: 'Destruction', label: 'Destruction' },
            ]}
          />
          <FilterSelect
            value={filterType}
            onChange={setFilterType}
            icon={Filter}
            options={[
              { value: 'all', label: 'All Types' },
              { value: 'Nation-State', label: 'Nation-State' },
              { value: 'Cybercrime', label: 'Cybercrime' },
              { value: 'Hacktivist', label: 'Hacktivist' },
            ]}
          />

          <span className="text-[10px] text-ink-600 ml-auto">{filtered.length} of {actors.length} actors</span>
        </div>
      </div>

      {/* Grid */}
      <div className="flex-1 overflow-y-auto px-6 py-5">
        {filtered.length === 0 ? (
          <div className="py-20 text-center text-ink-600 text-sm">No actors match current filters</div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {filtered.map((actor) => (
              <ActorCard key={actor.id} actor={actor} onSelect={() => setSelectedId(actor.id)} />
            ))}
          </div>
        )}
      </div>

      {/* Slide-over */}
      <AnimatePresence>
        {selected && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-black/40 backdrop-blur-[2px]"
              onClick={() => setSelectedId(null)}
            />
            <ActorPanel actor={selected} onClose={() => setSelectedId(null)} />
          </>
        )}
      </AnimatePresence>
    </div>
  )
}
