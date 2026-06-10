'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Rocket, CheckCircle2, Circle, X, ArrowRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchOnboarding, dismissOnboarding, type OnboardingStatus } from '@/lib/api'

/**
 * First-run checklist — computed server-side from REAL platform state (a step
 * is done only when the thing actually exists), so it can never drift from
 * reality. Hidden once complete or dismissed.
 */
export default function OnboardingCard() {
  const [ob, setOb] = useState<OnboardingStatus | null>(null)
  const [hidden, setHidden] = useState(false)

  useEffect(() => {
    fetchOnboarding().then(setOb).catch(() => {})
  }, [])

  if (!ob || ob.complete || ob.dismissed || hidden) return null

  function dismiss() {
    setHidden(true)
    dismissOnboarding().catch(() => {})
  }

  return (
    <AnimatePresence>
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
        className="glass border border-violet/20 rounded-xl overflow-hidden">
        <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/5">
          <div className="p-1.5 rounded-lg bg-violet/15 border border-violet/25 shrink-0">
            <Rocket className="w-4 h-4 text-violet" />
          </div>
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-white">Get fully operational</h3>
            <p className="text-[10px] text-ink-500">{ob.done} of {ob.total} setup steps complete — each verified against live platform state</p>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <div className="w-28 hidden sm:block">
              <div className="h-1.5 rounded-full bg-white/8 overflow-hidden">
                <div className="h-full rounded-full bg-violet transition-all" style={{ width: `${ob.pct}%` }} />
              </div>
              <p className="text-[9px] text-ink-600 mt-0.5 text-right font-mono">{ob.pct}%</p>
            </div>
            <button onClick={dismiss} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5" title="Dismiss checklist">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 divide-white/4">
          {ob.steps.filter((s) => !s.done).slice(0, 4).map((s) => (
            <a key={s.id} href={s.link}
              className="flex items-center gap-2.5 px-4 py-3 hover:bg-white/3 transition-colors group">
              <Circle className="w-3.5 h-3.5 text-ink-600 shrink-0" />
              <span className="text-[11px] text-ink-300 flex-1 truncate">{s.label}</span>
              <ArrowRight className="w-3 h-3 text-ink-700 group-hover:text-violet shrink-0 transition-colors" />
            </a>
          ))}
          {ob.steps.filter((s) => !s.done).length === 0 && (
            <div className="flex items-center gap-2 px-4 py-3 text-[11px] text-safe">
              <CheckCircle2 className="w-3.5 h-3.5" /> All set — you’re fully operational.
            </div>
          )}
        </div>
      </motion.div>
    </AnimatePresence>
  )
}
