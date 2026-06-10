'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { FileUp, X, Loader2, CheckCircle2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { importSigmaRule } from '@/lib/api'

const SAMPLE = `title: Suspicious brute force from scanner range
description: Multiple failed logins from a known scanner subnet
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  category: authentication
detection:
  selection:
    event_type: failed_login
    src_ip|cidr: 203.0.113.0/24
  condition: selection
level: high`

/**
 * Import a Sigma YAML rule as a live detection rule. Field names resolve via
 * the Sigma/ECS alias layers; the rule is enabled immediately and evaluates
 * the raw event stream like any natively-authored rule.
 */
export default function SigmaImportButton({ onImported }: { onImported?: () => void }) {
  const [open, setOpen] = useState(false)
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<{ name: string; notes: string[] } | null>(null)

  function doImport() {
    if (!text.trim() || busy) return
    setBusy(true)
    setError(null)
    setResult(null)
    importSigmaRule(text)
      .then((r) => {
        setResult({ name: r.name, notes: r.importNotes ?? [] })
        setText('')
        onImported?.()
      })
      .catch((e) => setError(e?.message || 'Import failed'))
      .finally(() => setBusy(false))
  }

  return (
    <>
      <button onClick={() => setOpen(true)}
        className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-white hover:border-white/20 transition-colors active:scale-95">
        <FileUp className="w-4 h-4" />
        Import Sigma
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-[80] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
            onClick={() => setOpen(false)}>
            <motion.div initial={{ scale: 0.97, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.97, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-xl rounded-2xl border border-white/10 bg-surface overflow-hidden">
              <div className="flex items-center gap-2 px-5 py-3.5 border-b border-white/8">
                <FileUp className="w-4 h-4 text-violet" />
                <h2 className="text-sm font-semibold text-white">Import Sigma rule</h2>
                <p className="text-[10px] text-ink-500 ml-2 hidden sm:block">YAML → live detection rule (ECS/Sigma field names resolve automatically)</p>
                <button onClick={() => setOpen(false)} className="ml-auto p-1.5 rounded-lg text-ink-500 hover:text-white"><X className="w-4 h-4" /></button>
              </div>
              <div className="p-4 space-y-3">
                <textarea value={text} onChange={(e) => setText(e.target.value)} rows={12}
                  placeholder="Paste a Sigma rule (YAML)…"
                  className="w-full px-3 py-2.5 rounded-xl bg-[#080614] border border-white/8 text-[11px] font-mono text-ink-100 focus:outline-none focus:border-violet/40 placeholder-ink-700 resize-none" />
                <div className="flex items-center gap-2 flex-wrap">
                  <button onClick={doImport} disabled={busy || !text.trim()}
                    className={cn('flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold transition-all',
                      text.trim() && !busy ? 'bg-violet/20 border border-violet/35 text-violet hover:bg-violet/30' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
                    {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileUp className="w-3.5 h-3.5" />}
                    Import as live rule
                  </button>
                  <button onClick={() => setText(SAMPLE)} className="text-[11px] text-ink-500 hover:text-ink-200">load sample</button>
                  {error && <span className="text-[11px] text-threat ml-auto">{error}</span>}
                </div>
                {result && (
                  <div className="flex items-start gap-2 text-xs text-safe bg-safe/10 border border-safe/20 rounded-lg px-3 py-2">
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    <div>
                      <p>Imported “{result.name}” — enabled and evaluating the event stream now.</p>
                      {result.notes.length > 0 && (
                        <p className="text-[10px] text-ink-400 mt-1">Mapping notes: {result.notes.join('; ')}</p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
