'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import { X, ArrowRight } from 'lucide-react'

/* ── Public payload + helper ─────────────────────────────────────────
   Any component can open the drawer without prop-drilling:
     import { openDetail } from '@/components/dashboard/DetailDrawer'
     openDetail({ title, subtitle, severity, rows, actions, body })            */
export interface DetailRow { label: string; value: React.ReactNode; mono?: boolean }
export interface DetailAction { label: string; href: string }
export interface DetailPayload {
  title: string
  subtitle?: string
  severity?: string
  rows?: DetailRow[]
  tags?: string[]
  body?: string
  actions?: DetailAction[]
}

const SEV_COLOR: Record<string, string> = {
  critical: '#FF2E97', high: '#FF4D6D', medium: '#FFB23E', low: '#34F5C5', info: '#7A3CFF',
}

const EVENT = 'to:detail'

export function openDetail(payload: DetailPayload) {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent<DetailPayload>(EVENT, { detail: payload }))
  }
}

/** Mounted once in the dashboard layout; renders whatever `openDetail` sends. */
export default function DetailDrawer() {
  const [payload, setPayload] = useState<DetailPayload | null>(null)

  useEffect(() => {
    const handler = (e: Event) => setPayload((e as CustomEvent<DetailPayload>).detail)
    window.addEventListener(EVENT, handler)
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setPayload(null) }
    window.addEventListener('keydown', esc)
    return () => { window.removeEventListener(EVENT, handler); window.removeEventListener('keydown', esc) }
  }, [])

  const accent = payload?.severity ? SEV_COLOR[payload.severity] ?? '#7A3CFF' : '#7A3CFF'

  return (
    <AnimatePresence>
      {payload && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          className="fixed inset-0 z-[75] flex justify-end bg-black/50 backdrop-blur-sm" onClick={() => setPayload(null)}>
          <motion.div initial={{ x: 460 }} animate={{ x: 0 }} exit={{ x: 460 }}
            transition={{ type: 'tween', duration: 0.2 }} onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md h-full bg-surface border-l border-white/8 overflow-y-auto">
            <div className="px-5 py-4 border-b border-white/8 sticky top-0 bg-surface z-10" style={{ boxShadow: `inset 3px 0 0 ${accent}` }}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  {payload.severity && (
                    <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded mb-1.5 inline-block"
                      style={{ color: accent, background: `${accent}1a` }}>{payload.severity}</span>
                  )}
                  <h2 className="text-sm font-semibold text-white leading-snug">{payload.title}</h2>
                  {payload.subtitle && <p className="text-[11px] text-ink-500 mt-0.5">{payload.subtitle}</p>}
                </div>
                <button onClick={() => setPayload(null)} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 shrink-0">
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="p-5 space-y-5">
              {payload.body && <p className="text-xs text-ink-300 leading-relaxed">{payload.body}</p>}

              {payload.rows && payload.rows.length > 0 && (
                <div className="space-y-1.5">
                  {payload.rows.map((r, i) => (
                    <div key={i} className="flex items-start justify-between gap-3 py-1.5 border-b border-white/4 last:border-0">
                      <span className="text-[10px] text-ink-500 uppercase tracking-wide shrink-0">{r.label}</span>
                      <span className={`text-[11px] text-ink-200 text-right min-w-0 ${r.mono ? 'font-mono break-all' : ''}`}>{r.value}</span>
                    </div>
                  ))}
                </div>
              )}

              {payload.tags && payload.tags.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {payload.tags.map((t) => (
                    <span key={t} className="text-[10px] px-2 py-0.5 rounded-full bg-violet/10 text-violet border border-violet/20">{t}</span>
                  ))}
                </div>
              )}

              {payload.actions && payload.actions.length > 0 && (
                <div className="space-y-2 pt-1">
                  {payload.actions.map((a) => (
                    <Link key={a.href} href={a.href} onClick={() => setPayload(null)}
                      className="flex items-center justify-between gap-2 px-3 py-2.5 rounded-xl border border-white/10 text-xs text-ink-200 hover:text-white hover:border-magenta/40 hover:bg-magenta/5 transition-colors">
                      {a.label}<ArrowRight className="w-3.5 h-3.5" />
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
