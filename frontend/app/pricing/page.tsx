'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence, useInView } from 'framer-motion'
import {
  Brain,
  Radio,
  Server,
  Activity,
  Zap,
  Share2,
  Bell,
  Eye,
  Code,
  Users,
  Shield,
  Check,
  X,
  ChevronRight,
  ArrowLeft,
  Sparkles,
  ToggleLeft,
  ToggleRight,
  Calculator,
  Star,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import Navbar from '@/components/layout/Navbar'
import Logo from '@/components/ui/Logo'

// ─── Types ───────────────────────────────────────────────────────────────────

interface Module {
  id: string
  name: string
  price: number
  icon: React.ElementType
  description: string
  tag?: string
  alwaysOn?: boolean
  color: string
}

interface TierFeature {
  name: string
  free: boolean | string
  starter: boolean | string
  professional: boolean | string
  enterprise: boolean | string
}

// ─── Data ────────────────────────────────────────────────────────────────────

const MODULES: Module[] = [
  {
    id: 'intel-scope',
    name: 'IntelScope Scanner',
    price: 0,
    icon: Shield,
    description: 'VirusTotal-like threat scanner, IOC lookup, reputation engine',
    tag: 'FREE',
    alwaysOn: true,
    color: '#34F5C5',
  },
  {
    id: 'cti',
    name: 'CTI Intelligence',
    price: 149,
    icon: Brain,
    description: 'STIX 2.1 threat intel ingestion, actor profiling, threat hunt',
    color: '#FF2E97',
  },
  {
    id: 'threat-feeds',
    name: 'Threat Feeds',
    price: 79,
    icon: Radio,
    description: 'Real-time IOC feeds, 200+ sources, MISP integration',
    color: '#7A3CFF',
  },
  {
    id: 'asset-surface',
    name: 'Asset Surface',
    price: 99,
    icon: Server,
    description: 'Asset inventory, CVE tracking, risk scoring',
    color: '#FFB23E',
  },
  {
    id: 'siem',
    name: 'SIEM',
    price: 249,
    icon: Activity,
    description: 'Log ingestion, detection rules, alert queue, threat hunt',
    color: '#FF4D6D',
  },
  {
    id: 'soar',
    name: 'SOAR',
    price: 199,
    icon: Zap,
    description: 'Case management, playbooks, automation workflows',
    color: '#FF2E97',
  },
  {
    id: 'opencti',
    name: 'OpenCTI Integration',
    price: 89,
    icon: Share2,
    description: 'STIX 2.1 push/sync, OpenCTI connector, bi-directional feeds',
    color: '#7A3CFF',
  },
  {
    id: 'asset-alerts',
    name: 'Asset Alerts',
    price: 49,
    icon: Bell,
    description: 'Email/Slack/PagerDuty alerts for asset vulnerability changes',
    color: '#FFB23E',
  },
  {
    id: 'dark-web',
    name: 'Dark Web Monitoring',
    price: 129,
    icon: Eye,
    description: 'Monitor paste sites, forums, breach data for your assets',
    color: '#FF4D6D',
  },
  {
    id: 'api-access',
    name: 'API Access',
    price: 39,
    icon: Code,
    description: 'REST API + webhook delivery, up to 1M calls/mo',
    color: '#34F5C5',
  },
  {
    id: 'multi-tenant',
    name: 'Multi-tenant',
    price: 199,
    icon: Users,
    description: 'Multiple organizations, role-based access, white-label',
    color: '#7A3CFF',
  },
]

const TIER_FEATURES: TierFeature[] = [
  {
    name: 'IntelScope Scanner',
    free: true,
    starter: true,
    professional: true,
    enterprise: true,
  },
  {
    name: 'CTI Intelligence',
    free: false,
    starter: true,
    professional: true,
    enterprise: true,
  },
  {
    name: 'Threat Feeds',
    free: false,
    starter: true,
    professional: true,
    enterprise: true,
  },
  {
    name: 'Asset Surface',
    free: false,
    starter: true,
    professional: true,
    enterprise: true,
  },
  {
    name: 'SIEM',
    free: false,
    starter: false,
    professional: true,
    enterprise: true,
  },
  {
    name: 'SOAR',
    free: false,
    starter: false,
    professional: true,
    enterprise: true,
  },
  {
    name: 'OpenCTI Integration',
    free: false,
    starter: false,
    professional: true,
    enterprise: true,
  },
  {
    name: 'Asset Alerts',
    free: false,
    starter: true,
    professional: true,
    enterprise: true,
  },
  {
    name: 'Dark Web Monitoring',
    free: false,
    starter: false,
    professional: true,
    enterprise: true,
  },
  {
    name: 'API Access',
    free: false,
    starter: false,
    professional: true,
    enterprise: true,
  },
  {
    name: 'Multi-tenant',
    free: false,
    starter: false,
    professional: false,
    enterprise: true,
  },
  {
    name: 'Priority Support',
    free: false,
    starter: false,
    professional: '48h SLA',
    enterprise: '4h SLA',
  },
]

// ─── Animated Total ───────────────────────────────────────────────────────────

function AnimatedPrice({ value }: { value: number }) {
  const [displayValue, setDisplayValue] = useState(value)
  const prevValue = useRef(value)
  const rafRef = useRef<number>(0)

  useEffect(() => {
    const from = prevValue.current
    const to = value
    const duration = 600
    const start = performance.now()

    cancelAnimationFrame(rafRef.current)

    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1)
      const eased = t === 1 ? 1 : 1 - Math.pow(2, -10 * t)
      setDisplayValue(Math.round(from + (to - from) * eased))
      if (t < 1) rafRef.current = requestAnimationFrame(tick)
      else prevValue.current = to
    }

    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [value])

  return <span>{displayValue.toLocaleString()}</span>
}

// ─── Feature Cell ─────────────────────────────────────────────────────────────

function FeatureCell({ value }: { value: boolean | string }) {
  if (typeof value === 'string') {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-violet-100 border border-violet-200 text-[#7A3CFF] text-xs font-medium">
        {value}
      </span>
    )
  }
  if (value) {
    return (
      <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-safe/10 border border-safe/25">
        <Check className="w-3.5 h-3.5 text-safe" />
      </span>
    )
  }
  return (
    <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-white/5">
      <X className="w-3.5 h-3.5 text-ink-600" />
    </span>
  )
}

// ─── Module Chip ─────────────────────────────────────────────────────────────

function ModuleChip({
  module,
  selected,
  onToggle,
}: {
  module: Module
  selected: boolean
  onToggle: (id: string) => void
}) {
  const Icon = module.icon
  const isAlwaysOn = module.alwaysOn

  return (
    <motion.button
      onClick={() => !isAlwaysOn && onToggle(module.id)}
      whileHover={!isAlwaysOn ? { scale: 1.02, y: -1 } : undefined}
      whileTap={!isAlwaysOn ? { scale: 0.98 } : undefined}
      className={cn(
        'relative flex flex-col gap-2.5 p-4 rounded-xl border text-left transition-all duration-300 group',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-magenta/60',
        isAlwaysOn
          ? 'cursor-default border-safe/25 bg-safe/5'
          : selected
            ? 'cursor-pointer border-magenta/40 bg-magenta/5 shadow-[0_0_22px_rgba(255,46,151,0.12)]'
            : 'cursor-pointer border-white/8 bg-surface-2/50 hover:border-white/15 hover:bg-surface-2',
      )}
    >
      {/* Selection ring glow */}
      {selected && !isAlwaysOn && (
        <motion.div
          layoutId={`chip-glow-${module.id}`}
          className="absolute inset-0 rounded-xl"
          style={{
            background: `radial-gradient(ellipse 80% 60% at 50% 0%, ${module.color}18, transparent)`,
          }}
        />
      )}

      {/* Header row */}
      <div className="relative flex items-start justify-between gap-2">
        <div
          className="flex items-center justify-center w-8 h-8 rounded-lg shrink-0"
          style={{
            background: `${module.color}15`,
            border: `1px solid ${module.color}30`,
          }}
        >
          <Icon
            className="w-4 h-4"
            style={{ color: module.color }}
          />
        </div>

        {/* Status badge */}
        <div className="flex items-center gap-1.5 shrink-0">
          {module.tag ? (
            <span className="px-2 py-0.5 rounded-full bg-safe/15 border border-safe/30 text-safe text-[10px] font-bold tracking-wide">
              {module.tag}
            </span>
          ) : selected ? (
            <motion.span
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              className="flex items-center justify-center w-5 h-5 rounded-full bg-magenta"
            >
              <Check className="w-3 h-3 text-white" />
            </motion.span>
          ) : (
            <span className="w-5 h-5 rounded-full border border-white/15 flex items-center justify-center">
              <span className="w-1.5 h-1.5 rounded-full bg-white/20" />
            </span>
          )}
        </div>
      </div>

      {/* Name + Price */}
      <div className="relative">
        <p
          className={cn(
            'text-sm font-semibold leading-tight mb-1',
            isAlwaysOn ? 'text-safe' : selected ? 'text-white' : 'text-ink-200 group-hover:text-white',
          )}
        >
          {module.name}
        </p>
        <p className="text-xs text-ink-400 leading-snug line-clamp-2">{module.description}</p>
      </div>

      {/* Price tag */}
      <div className="relative">
        {module.price === 0 ? (
          <span className="text-safe text-xs font-bold">Always included</span>
        ) : (
          <span
            className={cn(
              'text-xs font-bold',
              selected ? 'text-magenta' : 'text-ink-300',
            )}
          >
            ${module.price}
            <span className="font-normal text-ink-500">/mo</span>
          </span>
        )}
      </div>
    </motion.button>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function PricingPage() {
  const [selected, setSelected] = useState<Set<string>>(
    new Set(['intel-scope'])
  )
  const [annual, setAnnual] = useState(false)
  const tableRef = useRef<HTMLDivElement>(null)
  const tableInView = useInView(tableRef, { once: true, margin: '-80px' })

  const toggleModule = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  const monthlyTotal = MODULES.filter((m) => selected.has(m.id)).reduce(
    (sum, m) => sum + m.price,
    0,
  )

  const effectiveTotal = annual
    ? Math.round(monthlyTotal * 0.8)
    : monthlyTotal

  const selectedModules = MODULES.filter((m) => selected.has(m.id) && m.price > 0)

  // Background orb positions
  const orbs = [
    { x: '10%', y: '8%', color: '#FF2E97', size: 420, opacity: 0.08 },
    { x: '85%', y: '15%', color: '#7A3CFF', size: 500, opacity: 0.07 },
    { x: '50%', y: '55%', color: '#FFB23E', size: 350, opacity: 0.04 },
    { x: '15%', y: '75%', color: '#7A3CFF', size: 380, opacity: 0.06 },
    { x: '90%', y: '80%', color: '#FF2E97', size: 300, opacity: 0.05 },
  ]

  return (
    <div className="min-h-screen bg-[#0A0612] text-ink-100 overflow-x-hidden">
      {/* ── Ambient background ── */}
      <div className="fixed inset-0 pointer-events-none z-0" aria-hidden>
        {orbs.map((orb, i) => (
          <div
            key={i}
            className="absolute rounded-full"
            style={{
              left: orb.x,
              top: orb.y,
              width: orb.size,
              height: orb.size,
              background: `radial-gradient(circle, ${orb.color} 0%, transparent 70%)`,
              opacity: orb.opacity,
              transform: 'translate(-50%, -50%)',
              filter: 'blur(60px)',
            }}
          />
        ))}
        {/* Grid */}
        <div
          className="absolute inset-0 opacity-[0.025]"
          style={{
            backgroundImage:
              "url(\"data:image/svg+xml,%3Csvg width='60' height='60' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M60 0 L60 60 M0 60 L60 60' stroke='%23ffffff' stroke-width='0.5' fill='none'/%3E%3C/svg%3E\")",
          }}
        />
      </div>

      {/* ── Navbar ── */}
      <Navbar />

      <main id="main-content" className="relative z-10">
        {/* ── Hero ── */}
        <section className="pt-32 pb-16 px-4 sm:px-6 text-center">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          >
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-magenta/25 bg-magenta/8 mb-6">
              <Calculator className="w-3.5 h-3.5 text-magenta" />
              <span className="text-xs font-semibold text-magenta tracking-wide uppercase">
                Interactive Pricing
              </span>
            </div>

            <h1 className="font-display text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight mb-5">
              <span className="text-white">Build Your</span>
              <br />
              <span className="text-gradient-plasma">Plan</span>
            </h1>

            <p className="text-ink-300 text-lg sm:text-xl max-w-2xl mx-auto leading-relaxed">
              Only pay for what you need.{' '}
              <span className="text-safe font-medium">Start free</span>, scale as
              you grow. Mix and match modules to build your perfect security stack.
            </p>
          </motion.div>
        </section>

        {/* ══════════════════════════════════════════════════════════════════
            SECTION 1 — INTERACTIVE PRICING CALCULATOR
        ═══════════════════════════════════════════════════════════════════ */}
        <section className="px-4 sm:px-6 pb-24 max-w-[1400px] mx-auto">
          <div className="grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-8 xl:gap-10 items-start">

            {/* ── Left: Module grid ── */}
            <div>
              <motion.p
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.3 }}
                className="text-xs text-ink-400 uppercase tracking-widest font-semibold mb-4 flex items-center gap-2"
              >
                <Sparkles className="w-3.5 h-3.5 text-magenta" />
                Select modules to add to your stack
              </motion.p>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.35, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
                className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3"
              >
                {MODULES.map((module, i) => (
                  <motion.div
                    key={module.id}
                    initial={{ opacity: 0, y: 16 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{
                      delay: 0.4 + i * 0.04,
                      duration: 0.5,
                      ease: [0.22, 1, 0.36, 1],
                    }}
                  >
                    <ModuleChip
                      module={module}
                      selected={selected.has(module.id)}
                      onToggle={toggleModule}
                    />
                  </motion.div>
                ))}
              </motion.div>

              {/* Selection summary strip */}
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.9 }}
                className="mt-6 px-4 py-3 rounded-xl border border-white/8 bg-surface-2/30 flex flex-wrap items-center gap-x-6 gap-y-2"
              >
                <span className="text-xs text-ink-400">
                  <span className="text-white font-semibold">{selected.size}</span> modules selected
                </span>
                <span className="text-xs text-ink-400">
                  Paid modules:{' '}
                  <span className="text-magenta font-semibold">{selectedModules.length}</span>
                </span>
                <span className="text-xs text-ink-400 ml-auto">
                  Click any card to toggle · IntelScope is always free
                </span>
              </motion.div>
            </div>

            {/* ── Right: Pricing summary card ── */}
            <motion.div
              initial={{ opacity: 0, x: 24 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.5, duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
              className="xl:sticky xl:top-24"
            >
              <div className="glass rounded-2xl border border-white/10 overflow-hidden shadow-[0_0_0_1px_rgba(255,255,255,0.06),0_24px_64px_rgba(0,0,0,0.6)]">
                {/* Card top accent */}
                <div className="h-0.5 w-full bg-plasma" />

                <div className="p-6">
                  {/* Header */}
                  <div className="flex items-center justify-between mb-6">
                    <div>
                      <p className="text-xs text-ink-400 uppercase tracking-widest font-semibold mb-1">
                        Monthly Total
                      </p>
                      <div className="flex items-end gap-1.5">
                        <span className="font-display text-4xl font-bold text-white leading-none">
                          $<AnimatedPrice value={effectiveTotal} />
                        </span>
                        <span className="text-ink-400 text-sm mb-0.5">/mo</span>
                      </div>
                      {annual && monthlyTotal > 0 && (
                        <motion.p
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          className="text-safe text-xs mt-1 font-medium"
                        >
                          Saving ${Math.round(monthlyTotal * 0.2)}/mo with annual billing
                        </motion.p>
                      )}
                    </div>

                    {/* Annual toggle */}
                    <button
                      onClick={() => setAnnual((v) => !v)}
                      className="flex flex-col items-end gap-1 group"
                      aria-pressed={annual}
                    >
                      <div className="flex items-center gap-2">
                        {annual ? (
                          <ToggleRight className="w-8 h-8 text-safe transition-colors" />
                        ) : (
                          <ToggleLeft className="w-8 h-8 text-ink-400 group-hover:text-ink-200 transition-colors" />
                        )}
                      </div>
                      <span className="text-[10px] text-ink-400 group-hover:text-ink-200 transition-colors text-right leading-tight">
                        Annual billing
                        <br />
                        <span className={cn(annual ? 'text-safe font-bold' : 'text-ink-500')}>
                          save 20%
                        </span>
                      </span>
                    </button>
                  </div>

                  {/* Module breakdown */}
                  <div className="mb-5">
                    <p className="text-[11px] text-ink-500 uppercase tracking-widest font-semibold mb-3">
                      Selected Modules
                    </p>

                    {/* Always-on free module */}
                    <div className="flex items-center justify-between py-2 border-b border-white/5">
                      <div className="flex items-center gap-2">
                        <Shield className="w-3.5 h-3.5 text-safe shrink-0" />
                        <span className="text-xs text-ink-300">IntelScope Scanner</span>
                      </div>
                      <span className="text-xs font-semibold text-safe">FREE</span>
                    </div>

                    {/* Paid modules */}
                    <div className="space-y-0 max-h-64 overflow-y-auto pr-1 thin-scroll">
                      <AnimatePresence mode="popLayout">
                        {selectedModules.length === 0 ? (
                          <motion.div
                            key="empty"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="py-4 text-center"
                          >
                            <p className="text-xs text-ink-500">
                              Select modules above to build your stack
                            </p>
                          </motion.div>
                        ) : (
                          selectedModules.map((module) => {
                            const ModIcon = module.icon
                            const modulePrice = annual
                              ? Math.round(module.price * 0.8)
                              : module.price
                            return (
                              <motion.div
                                key={module.id}
                                initial={{ opacity: 0, x: -10, height: 0 }}
                                animate={{ opacity: 1, x: 0, height: 'auto' }}
                                exit={{ opacity: 0, x: 10, height: 0 }}
                                transition={{ duration: 0.25, ease: 'easeInOut' }}
                                className="flex items-center justify-between py-2 border-b border-white/5 overflow-hidden"
                              >
                                <div className="flex items-center gap-2 min-w-0">
                                  <ModIcon
                                    className="w-3.5 h-3.5 shrink-0"
                                    style={{ color: module.color }}
                                  />
                                  <span className="text-xs text-ink-300 truncate">{module.name}</span>
                                </div>
                                <div className="flex items-center gap-2 shrink-0 ml-3">
                                  <span className="text-xs font-semibold text-ink-200">
                                    ${modulePrice}
                                  </span>
                                  <button
                                    onClick={() => toggleModule(module.id)}
                                    className="w-4 h-4 rounded-full bg-white/8 hover:bg-threat/20 hover:text-threat flex items-center justify-center transition-colors text-ink-500"
                                    aria-label={`Remove ${module.name}`}
                                  >
                                    <X className="w-2.5 h-2.5" />
                                  </button>
                                </div>
                              </motion.div>
                            )
                          })
                        )}
                      </AnimatePresence>
                    </div>

                    {/* Total line */}
                    {selectedModules.length > 0 && (
                      <motion.div
                        layout
                        className="flex items-center justify-between pt-3 mt-1"
                      >
                        <span className="text-xs font-semibold text-ink-300 uppercase tracking-wide">
                          Total
                        </span>
                        <span className="text-sm font-bold text-white">
                          ${effectiveTotal.toLocaleString()}/mo
                        </span>
                      </motion.div>
                    )}
                  </div>

                  {/* CTA Buttons */}
                  <div className="space-y-2.5">
                    <a
                      href="/signup"
                      className="group relative flex items-center justify-center gap-2 w-full py-3 px-5 rounded-xl font-semibold text-sm text-white transition-all duration-300 overflow-hidden hover:scale-[1.02] hover:shadow-magenta-md"
                      style={{
                        background: 'linear-gradient(135deg, #FF2E97 0%, #7A3CFF 55%, #FFB23E 100%)',
                      }}
                    >
                      <span className="relative z-10 flex items-center gap-2">
                        <Sparkles className="w-4 h-4" />
                        Start Free Trial
                        <ChevronRight className="w-4 h-4 transition-transform group-hover:translate-x-0.5" />
                      </span>
                      <div className="absolute inset-0 bg-white/0 group-hover:bg-white/8 transition-colors duration-300" />
                    </a>

                    <a
                      href="mailto:sales@threatorbit.space"
                      className="glass group flex items-center justify-center gap-2 w-full py-3 px-5 rounded-xl font-semibold text-sm text-ink-200 hover:text-white border border-white/10 hover:border-white/20 transition-all duration-300 hover:scale-[1.01]"
                    >
                      Talk to Sales
                      <ChevronRight className="w-4 h-4 opacity-60 transition-transform group-hover:translate-x-0.5" />
                    </a>

                    <a
                      href="#tiers"
                      className="group flex items-center justify-center gap-2 w-full py-2.5 px-5 rounded-xl font-medium text-sm text-ink-400 hover:text-ink-200 transition-colors duration-200"
                    >
                      See Enterprise Plans
                      <ChevronRight className="w-3.5 h-3.5 opacity-50 transition-transform group-hover:translate-x-0.5" />
                    </a>
                  </div>

                  {/* Fine print */}
                  <p className="mt-4 text-[11px] text-ink-500 text-center leading-relaxed">
                    No credit card required for free tier.
                    <br />
                    Enterprise pricing available for 10+ seat teams.
                  </p>
                </div>
              </div>
            </motion.div>
          </div>
        </section>

        {/* ══════════════════════════════════════════════════════════════════
            SECTION 2 — COMPARISON TIERS TABLE
        ═══════════════════════════════════════════════════════════════════ */}
        <section id="tiers" ref={tableRef} className="px-4 sm:px-6 pb-32 max-w-[1200px] mx-auto">

          {/* Section header */}
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={tableInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            className="text-center mb-14"
          >
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-violet/30 bg-violet-100 mb-6">
              <Star className="w-3.5 h-3.5 text-violet" />
              <span className="text-xs font-semibold text-violet tracking-wide uppercase">
                Compare Plans
              </span>
            </div>
            <h2 className="font-display text-4xl sm:text-5xl font-bold tracking-tight text-white mb-4">
              Find Your Fit
            </h2>
            <p className="text-ink-300 text-lg max-w-xl mx-auto">
              Pre-built tiers for teams that want a quick starting point. Mix and match above for exact pricing.
            </p>
          </motion.div>

          {/* Tier cards header row */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={tableInView ? { opacity: 1, y: 0 } : {}}
            transition={{ delay: 0.15, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            className="grid grid-cols-[200px_1fr_1fr_1fr_1fr] gap-px mb-px rounded-t-2xl overflow-hidden"
          >
            {/* Empty feature label column header */}
            <div className="bg-[#0D0920] px-4 py-5 flex items-end">
              <span className="text-xs text-ink-500 uppercase tracking-widest font-semibold">
                Features
              </span>
            </div>

            {/* Free */}
            <TierHeader
              name="Free"
              price="$0"
              priceSub="forever"
              description="Start exploring threat intelligence with zero cost."
              users="1 user"
              highlight={false}
              delay={0.2}
              inView={tableInView}
              color="#34F5C5"
            />

            {/* Starter */}
            <TierHeader
              name="Starter"
              price="$149"
              priceSub="/mo starting"
              description="CTI, Feeds & Asset Surface for growing security teams."
              users="Up to 3 users"
              highlight={false}
              delay={0.25}
              inView={tableInView}
              color="#FFB23E"
            />

            {/* Professional */}
            <TierHeader
              name="Professional"
              price="$499"
              priceSub="/mo starting"
              description="Full stack security ops. Everything but multi-tenant."
              users="Up to 10 users"
              highlight={true}
              badge="Most Popular"
              delay={0.3}
              inView={tableInView}
              color="#FF2E97"
            />

            {/* Enterprise */}
            <TierHeader
              name="Enterprise"
              price="Custom"
              priceSub="contact us"
              description="White-glove onboarding, SLA, multi-tenant & dedicated support."
              users="Unlimited users"
              highlight={false}
              delay={0.35}
              inView={tableInView}
              color="#7A3CFF"
            />
          </motion.div>

          {/* Feature rows */}
          <div className="rounded-b-2xl overflow-hidden border border-white/8 divide-y divide-white/5">
            {TIER_FEATURES.map((feature, i) => (
              <motion.div
                key={feature.name}
                initial={{ opacity: 0, x: -10 }}
                animate={tableInView ? { opacity: 1, x: 0 } : {}}
                transition={{
                  delay: 0.4 + i * 0.04,
                  duration: 0.5,
                  ease: [0.22, 1, 0.36, 1],
                }}
                className={cn(
                  'grid grid-cols-[200px_1fr_1fr_1fr_1fr] gap-px',
                  i % 2 === 0 ? 'bg-white/[0.015]' : 'bg-transparent',
                  'hover:bg-white/[0.03] transition-colors duration-150',
                )}
              >
                {/* Feature name */}
                <div className="px-4 py-4 flex items-center">
                  <span className="text-sm text-ink-300">{feature.name}</span>
                </div>
                {/* Free */}
                <div className="px-4 py-4 flex items-center justify-center">
                  <FeatureCell value={feature.free} />
                </div>
                {/* Starter */}
                <div className="px-4 py-4 flex items-center justify-center">
                  <FeatureCell value={feature.starter} />
                </div>
                {/* Professional */}
                <div className="relative px-4 py-4 flex items-center justify-center bg-magenta-50">
                  <FeatureCell value={feature.professional} />
                </div>
                {/* Enterprise */}
                <div className="px-4 py-4 flex items-center justify-center">
                  <FeatureCell value={feature.enterprise} />
                </div>
              </motion.div>
            ))}

            {/* CTA row */}
            <div className="grid grid-cols-[200px_1fr_1fr_1fr_1fr] gap-px bg-[#0D0920]">
              <div className="px-4 py-5" />
              {/* Free CTA */}
              <div className="px-4 py-5 flex items-center justify-center">
                <a
                  href="/signup"
                  className="text-xs font-semibold text-safe/80 hover:text-safe border border-safe/20 hover:border-safe/40 rounded-lg px-3 py-2 transition-all duration-200 text-center whitespace-nowrap"
                >
                  Get started free
                </a>
              </div>
              {/* Starter CTA */}
              <div className="px-4 py-5 flex items-center justify-center">
                <a
                  href="/signup"
                  className="text-xs font-semibold text-amber/80 hover:text-amber border border-amber/20 hover:border-amber/40 rounded-lg px-3 py-2 transition-all duration-200 text-center whitespace-nowrap"
                >
                  Start Starter
                </a>
              </div>
              {/* Professional CTA */}
              <div className="px-4 py-5 flex items-center justify-center bg-magenta-50">
                <a
                  href="/signup"
                  className="text-xs font-semibold text-white bg-magenta hover:bg-magenta/90 rounded-lg px-4 py-2 transition-all duration-200 text-center whitespace-nowrap shadow-magenta-sm hover:shadow-magenta-md"
                >
                  Go Pro
                </a>
              </div>
              {/* Enterprise CTA */}
              <div className="px-4 py-5 flex items-center justify-center">
                <a
                  href="mailto:enterprise@threatorbit.space"
                  className="text-xs font-semibold text-violet/80 hover:text-violet border border-violet/20 hover:border-violet/40 rounded-lg px-3 py-2 transition-all duration-200 text-center whitespace-nowrap"
                >
                  Contact Sales
                </a>
              </div>
            </div>
          </div>
        </section>

        {/* ── FAQ / Trust strip ── */}
        <section className="px-4 sm:px-6 pb-32 max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          >
            <div className="glass rounded-2xl border border-white/8 p-10 relative overflow-hidden">
              {/* bg glow */}
              <div
                className="absolute inset-0 opacity-40 pointer-events-none"
                style={{
                  background:
                    'radial-gradient(ellipse 60% 50% at 50% 100%, rgba(122,60,255,0.10), transparent)',
                }}
              />

              <div className="relative">
                <div className="flex items-center justify-center mb-5">
                  <Logo size={40} />
                </div>
                <h3 className="font-display text-2xl sm:text-3xl font-bold text-white mb-3">
                  Need a custom quote?
                </h3>
                <p className="text-ink-300 text-base mb-8 max-w-lg mx-auto">
                  Our security solutions team will map ThreatOrbit to your threat landscape, compliance requirements, and team structure — and build you a tailored proposal.
                </p>

                <div className="flex flex-wrap items-center justify-center gap-3">
                  <a
                    href="mailto:enterprise@threatorbit.space"
                    className="group flex items-center gap-2 px-6 py-3 rounded-xl font-semibold text-sm text-white transition-all duration-300 hover:scale-[1.03] hover:shadow-magenta-md"
                    style={{
                      background: 'linear-gradient(135deg, #FF2E97 0%, #7A3CFF 100%)',
                    }}
                  >
                    Talk to Enterprise Sales
                    <ChevronRight className="w-4 h-4 transition-transform group-hover:translate-x-0.5" />
                  </a>

                  <a
                    href="/docs"
                    className="glass group flex items-center gap-2 px-6 py-3 rounded-xl font-semibold text-sm text-ink-200 hover:text-white border border-white/10 hover:border-white/20 transition-all duration-300"
                  >
                    Read the Docs
                    <ChevronRight className="w-4 h-4 opacity-60 transition-transform group-hover:translate-x-0.5" />
                  </a>
                </div>

                {/* Trust badges */}
                <div className="mt-10 flex flex-wrap items-center justify-center gap-6 text-xs text-ink-500">
                  <span className="flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5 text-safe" />
                    SOC 2 Type II Ready
                  </span>
                  <span className="flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5 text-safe" />
                    STIX 2.1 Compliant
                  </span>
                  <span className="flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5 text-safe" />
                    99.9% Uptime SLA
                  </span>
                  <span className="flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5 text-safe" />
                    End-to-end Encryption
                  </span>
                  <span className="flex items-center gap-1.5">
                    <Check className="w-3.5 h-3.5 text-safe" />
                    No credit card to start
                  </span>
                </div>
              </div>
            </div>
          </motion.div>
        </section>
      </main>
    </div>
  )
}

// ─── Tier Header Sub-component ───────────────────────────────────────────────

interface TierHeaderProps {
  name: string
  price: string
  priceSub: string
  description: string
  users: string
  highlight: boolean
  badge?: string
  delay: number
  inView: boolean
  color: string
}

function TierHeader({
  name,
  price,
  priceSub,
  description,
  users,
  highlight,
  badge,
  delay,
  inView,
  color,
}: TierHeaderProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ delay, duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      className={cn(
        'relative px-5 py-6 flex flex-col gap-3',
        highlight
          ? 'bg-magenta-50 border-x border-t border-magenta/25'
          : 'bg-[#0D0920]',
      )}
    >
      {/* Top accent line */}
      <div
        className="absolute top-0 left-0 right-0 h-0.5"
        style={{
          background: highlight
            ? 'linear-gradient(90deg, #FF2E97, #7A3CFF)'
            : `linear-gradient(90deg, ${color}60, transparent)`,
        }}
      />

      {/* Popular badge */}
      {badge && (
        <div className="absolute -top-3 left-1/2 -translate-x-1/2">
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-magenta text-white text-[10px] font-bold tracking-wide shadow-magenta-sm whitespace-nowrap">
            <Star className="w-2.5 h-2.5" />
            {badge}
          </span>
        </div>
      )}

      {/* Tier name */}
      <div>
        <p
          className="text-xs font-bold uppercase tracking-widest mb-2"
          style={{ color }}
        >
          {name}
        </p>
        <div className="flex items-end gap-1 mb-1">
          <span className="font-display text-2xl font-bold text-white leading-none">
            {price}
          </span>
          <span className="text-xs text-ink-500 mb-0.5">{priceSub}</span>
        </div>
        <p className="text-[11px] text-ink-500 leading-snug">{users}</p>
      </div>

      {/* Description */}
      <p className="text-xs text-ink-400 leading-relaxed">{description}</p>
    </motion.div>
  )
}
