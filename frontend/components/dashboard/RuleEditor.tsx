'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { X, Plus, Trash2, FlaskConical, Loader2, ShieldCheck } from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchRuleSchema, testRule, createDetectionRule,
  type RuleSchema, type RuleCondition, type RuleDefinition,
} from '@/lib/api'

/**
 * Detection rule editor - author a real, evaluable correlation rule: field
 * conditions, AND/OR logic, an optional aggregation threshold over a time
 * window, and a live backtest against recent events before you save it.
 */
export default function RuleEditor({ onClose, onCreated }: {
  onClose: () => void
  onCreated: () => void
}) {
  const [schema, setSchema] = useState<RuleSchema | null>(null)
  const [name, setName] = useState('')
  const [severity, setSeverity] = useState('high')
  const category = 'Custom'
  const [techId, setTechId] = useState('')
  const [logic, setLogic] = useState<'and' | 'or'>('and')
  const [conditions, setConditions] = useState<RuleCondition[]>([{ field: 'event_type', op: 'equals', value: '' }])
  const [useAgg, setUseAgg] = useState(false)
  const [groupBy, setGroupBy] = useState('src_ip')
  const [threshold, setThreshold] = useState(5)
  const [windowMinutes, setWindowMinutes] = useState(5)
  const [test, setTest] = useState<{ matched: number; scanned: number; sample: Array<{ entity: string; count: number; raw: string }> } | null>(null)
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => { fetchRuleSchema().then(setSchema).catch(() => {}) }, [])

  function buildDef(): RuleDefinition {
    const def: RuleDefinition = {
      conditions: conditions.filter((c) => c.field && c.op),
      logic,
    }
    if (useAgg) def.aggregation = { groupBy, threshold, windowMinutes }
    return def
  }

  const canRun = name.trim() && conditions.some((c) => c.field && c.value)

  function runTest() {
    setTesting(true)
    setError(null)
    testRule(buildDef())
      .then(setTest)
      .catch(() => setError('Backtest failed - check your conditions.'))
      .finally(() => setTesting(false))
  }

  function save() {
    if (!canRun || saving) return
    setSaving(true)
    setError(null)
    createDetectionRule({
      name: name.trim(), severity, category, mitreTechId: techId || undefined,
      definition: buildDef(),
    })
      .then(() => { onCreated(); onClose() })
      .catch(() => { setError('Could not save the rule.'); setSaving(false) })
  }

  const fld = 'px-2.5 py-2 rounded-lg bg-surface-2 border border-white/8 text-xs text-ink-100 focus:outline-hidden focus:border-magenta/40'

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-70 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 sm:p-8" onClick={onClose}>
      <motion.div initial={{ scale: 0.97, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.97, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-2xl max-h-[90vh] rounded-2xl border border-white/10 bg-surface flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/8 shrink-0">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-magenta/15"><ShieldCheck className="w-4 h-4 text-magenta" /></div>
            <h2 className="text-sm font-semibold text-white">New Detection Rule</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5"><X className="w-4 h-4" /></button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Identity */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="sm:col-span-2">
              <label className="block text-[11px] font-medium text-ink-300 mb-1.5">Rule name <span className="text-magenta">*</span></label>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Outbound beacon to rare ASN" className={cn(fld, 'w-full')} />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-ink-300 mb-1.5">Severity</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={cn(fld, 'w-full')}>
                {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[11px] font-medium text-ink-300 mb-1.5">MITRE technique</label>
              <input value={techId} onChange={(e) => setTechId(e.target.value)} placeholder="e.g. T1071.001" className={cn(fld, 'w-full')} />
            </div>
          </div>

          {/* Conditions */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-[11px] font-medium text-ink-300">Conditions</label>
              <div className="flex items-center gap-1 text-[10px]">
                <span className="text-ink-600">Match</span>
                {(['and', 'or'] as const).map((l) => (
                  <button key={l} onClick={() => setLogic(l)}
                    className={cn('px-2 py-0.5 rounded-sm uppercase font-semibold',
                      logic === l ? 'bg-magenta/15 text-magenta' : 'text-ink-500 hover:text-ink-300')}>
                    {l === 'and' ? 'ALL' : 'ANY'}
                  </button>
                ))}
              </div>
            </div>
            <div className="space-y-2">
              {conditions.map((c, i) => (
                <div key={i} className="flex items-center gap-1.5">
                  <select value={c.field} onChange={(e) => setConditions((cs) => cs.map((x, j) => j === i ? { ...x, field: e.target.value } : x))} className={cn(fld, 'w-32')}>
                    {schema?.fields.map((f) => <option key={f} value={f}>{f}</option>)}
                  </select>
                  <select value={c.op} onChange={(e) => setConditions((cs) => cs.map((x, j) => j === i ? { ...x, op: e.target.value } : x))} className={cn(fld, 'w-24')}>
                    {schema?.operators.map((o) => <option key={o} value={o}>{o}</option>)}
                  </select>
                  <input value={c.value} onChange={(e) => setConditions((cs) => cs.map((x, j) => j === i ? { ...x, value: e.target.value } : x))}
                    placeholder={c.field === 'event_type' ? schema?.eventTypes[0] : 'value'} className={cn(fld, 'flex-1')} />
                  <button onClick={() => setConditions((cs) => cs.filter((_, j) => j !== i))} disabled={conditions.length === 1}
                    className="p-1.5 rounded-lg text-ink-500 hover:text-threat hover:bg-threat/5 disabled:opacity-30"><Trash2 className="w-3.5 h-3.5" /></button>
                </div>
              ))}
            </div>
            <button onClick={() => setConditions((cs) => [...cs, { field: 'src_ip', op: 'equals', value: '' }])}
              className="flex items-center gap-1 mt-2 text-[11px] text-magenta hover:underline"><Plus className="w-3 h-3" /> Add condition</button>
            {schema && <p className="text-[10px] text-ink-600 mt-2">Event types: {schema.eventTypes.join(', ')}</p>}
          </div>

          {/* Aggregation */}
          <div className="rounded-xl border border-white/8 bg-surface-2/40 p-3">
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={useAgg} onChange={(e) => setUseAgg(e.target.checked)} className="accent-magenta" />
              <span className="text-[11px] font-medium text-ink-200">Threshold over a time window (e.g. brute-force, beaconing)</span>
            </label>
            {useAgg && (
              <div className="grid grid-cols-3 gap-2 mt-3">
                <div>
                  <label className="block text-[10px] text-ink-500 mb-1">Group by</label>
                  <select value={groupBy} onChange={(e) => setGroupBy(e.target.value)} className={cn(fld, 'w-full')}>
                    {schema?.groupByFields.map((f) => <option key={f} value={f}>{f}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] text-ink-500 mb-1">≥ count</label>
                  <input type="number" value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} className={cn(fld, 'w-full')} />
                </div>
                <div>
                  <label className="block text-[10px] text-ink-500 mb-1">in (minutes)</label>
                  <input type="number" value={windowMinutes} onChange={(e) => setWindowMinutes(Number(e.target.value))} className={cn(fld, 'w-full')} />
                </div>
              </div>
            )}
          </div>

          {/* Backtest results */}
          {test && (
            <div className="rounded-xl border border-violet/20 bg-violet/5 p-3">
              <p className="text-xs text-ink-200 mb-2">
                Backtest: <b className="text-violet">{test.matched}</b> match{test.matched === 1 ? '' : 'es'} across {test.scanned} recent events.
              </p>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {test.sample.map((s, i) => (
                  <div key={i} className="text-[10px] text-ink-500 font-mono truncate">
                    <span className="text-ink-300">{s.entity}</span> {s.count > 1 ? `×${s.count}` : ''} · {s.raw}
                  </div>
                ))}
                {test.sample.length === 0 && <p className="text-[10px] text-ink-600">No matches - tune the conditions, or wait for more telemetry.</p>}
              </div>
            </div>
          )}

          {error && <p className="px-3 py-2 rounded-lg bg-threat/10 border border-threat/25 text-[11px] text-threat">{error}</p>}
        </div>

        <div className="flex items-center gap-2 px-5 py-3 border-t border-white/8 shrink-0">
          <button onClick={runTest} disabled={!canRun || testing}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-surface-2 border border-white/10 text-ink-200 hover:text-white hover:border-white/20 transition-colors disabled:opacity-50">
            {testing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FlaskConical className="w-3.5 h-3.5" />} Backtest
          </button>
          <button onClick={save} disabled={!canRun || saving}
            className={cn('ml-auto px-4 py-2 rounded-xl text-xs font-semibold transition-all',
              canRun && !saving ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
            {saving ? 'Saving…' : 'Create & enable rule'}
          </button>
        </div>
      </motion.div>
    </motion.div>
  )
}
