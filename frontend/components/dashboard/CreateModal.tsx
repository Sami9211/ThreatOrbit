'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { X, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface CreateField {
  key: string
  label: string
  type?: 'text' | 'textarea' | 'select'
  placeholder?: string
  options?: Array<{ value: string; label: string }>
  required?: boolean
  hint?: string
  default?: string
}

/**
 * Generic create-record modal used by the New Rule / Add Source / Add Feed /
 * New Hunt flows. Renders the given fields, validates required ones, and
 * submits the collected values; the caller does the API call.
 */
export default function CreateModal({ title, icon: Icon, accent = '#FF2E97', fields, submitLabel, onSubmit, onClose }: {
  title: string
  icon: LucideIcon
  accent?: string
  fields: CreateField[]
  submitLabel: string
  onSubmit: (values: Record<string, string>) => Promise<void>
  onClose: () => void
}) {
  const [values, setValues] = useState<Record<string, string>>(
    Object.fromEntries(fields.map((f) => [f.key, f.default ?? (f.type === 'select' ? f.options?.[0]?.value ?? '' : '')])),
  )
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const canSubmit = fields.every((f) => !f.required || values[f.key]?.trim())

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!canSubmit || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      await onSubmit(values)
      onClose()
    } catch {
      setError('Could not save. Check that the dashboard API is running and you are signed in.')
      setSubmitting(false)
    }
  }

  const inputCls = 'w-full px-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 placeholder-ink-600'

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60 backdrop-blur-sm p-6"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md rounded-2xl border border-white/10 bg-surface p-6 max-h-[85vh] overflow-y-auto"
      >
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg" style={{ background: `${accent}26` }}>
              <Icon className="w-4 h-4" style={{ color: accent }} />
            </div>
            <h2 className="text-sm font-semibold text-white">{title}</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          {fields.map((f) => (
            <div key={f.key}>
              <label className="block text-xs font-medium text-ink-300 mb-1.5">
                {f.label}{f.required && <span className="text-magenta ml-0.5">*</span>}
              </label>
              {f.type === 'textarea' ? (
                <textarea
                  rows={3}
                  value={values[f.key]}
                  onChange={(e) => setValues((v) => ({ ...v, [f.key]: e.target.value }))}
                  placeholder={f.placeholder}
                  className={cn(inputCls, 'resize-none font-mono text-xs')}
                />
              ) : f.type === 'select' ? (
                <select
                  value={values[f.key]}
                  onChange={(e) => setValues((v) => ({ ...v, [f.key]: e.target.value }))}
                  className={inputCls}
                >
                  {f.options?.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              ) : (
                <input
                  value={values[f.key]}
                  onChange={(e) => setValues((v) => ({ ...v, [f.key]: e.target.value }))}
                  placeholder={f.placeholder}
                  className={inputCls}
                />
              )}
              {f.hint && <p className="text-[10px] text-ink-600 mt-1">{f.hint}</p>}
            </div>
          ))}

          {error && <p className="px-3 py-2 rounded-lg bg-threat/10 border border-threat/25 text-[11px] text-threat" role="alert">{error}</p>}

          <button type="submit" disabled={!canSubmit || submitting}
            className={cn('w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold transition-all',
              canSubmit && !submitting ? 'bg-plasma text-white hover:shadow-magenta-sm' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
            {submitting ? 'Saving…' : submitLabel}
          </button>
        </form>
      </motion.div>
    </motion.div>
  )
}
