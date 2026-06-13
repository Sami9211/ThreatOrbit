'use client'

import { useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Bookmark, BookmarkPlus, Loader2, Trash2, X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchSavedViews, createSavedView, deleteSavedView, type SavedView } from '@/lib/api'

/**
 * Per-section "save this view" control backed by `/saved-views` (per-user +
 * per-section on the server). Drop into any section header next to the
 * filters:
 *
 *   <SavedViewsButton
 *     section="siem"
 *     filters={{ q: search, severity: filterSev }}
 *     onApply={(f) => { setSearch(f.q ?? ''); setFilterSev(f.severity ?? 'all') }}
 *   />
 *
 * `filters` is the page's current filter state (defaults/empties are stripped
 * before saving); `onApply` restores a saved set into the page's state.
 */
export default function SavedViewsButton({ section, filters, onApply }: {
  section: string
  filters: Record<string, string>
  onApply: (filters: Record<string, string>) => void
}) {
  const [open, setOpen] = useState(false)
  const [views, setViews] = useState<SavedView[] | null>(null)
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    fetchSavedViews(section)
      .then((v) => { setViews(v); setError(null) })
      .catch(() => setError('Could not load saved views.'))
  }, [section])

  function toggle() {
    const next = !open
    setOpen(next)
    if (next && views === null) load()
  }

  // Persist only meaningful filter values - defaults add noise, not state.
  function currentFilters(): Record<string, string> {
    const out: Record<string, string> = {}
    for (const [k, v] of Object.entries(filters)) {
      if (v && v !== 'all' && v !== 'All') out[k] = v
    }
    return out
  }

  function saveCurrent() {
    const trimmed = name.trim()
    if (!trimmed || busy) return
    setBusy(true)
    createSavedView(section, trimmed, currentFilters())
      .then(() => { setName(''); load() })
      .catch(() => setError('Could not save the view.'))
      .finally(() => setBusy(false))
  }

  function remove(id: string) {
    deleteSavedView(id)
      .then(() => setViews((v) => (v ?? []).filter((x) => x.id !== id)))
      .catch(() => setError('Could not delete the view.'))
  }

  const hasFilters = Object.keys(currentFilters()).length > 0

  return (
    <div className="relative">
      <button
        onClick={toggle}
        title="Saved views for this section"
        className={cn(
          'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors',
          open
            ? 'bg-violet/10 border-violet/30 text-violet'
            : 'bg-surface-2 border-white/10 text-ink-300 hover:text-white hover:border-white/20',
        )}>
        <Bookmark className="w-3.5 h-3.5" />
        Views
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.12 }}
            className="absolute right-0 top-full mt-1.5 w-72 z-40 rounded-xl border border-white/10 bg-surface-1 shadow-xl p-3">
            <div className="flex items-center justify-between mb-2">
              <p className="text-[11px] font-semibold text-ink-300 uppercase tracking-wide">Saved views</p>
              <button onClick={() => setOpen(false)} className="text-ink-600 hover:text-white">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Save the current filter set */}
            <div className="flex items-center gap-1.5 mb-2.5">
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && saveCurrent()}
                placeholder={hasFilters ? 'Name this view…' : 'No active filters to save'}
                disabled={!hasFilters}
                className="flex-1 px-2 py-1.5 rounded-lg bg-surface-2 border border-white/10 text-xs text-white placeholder:text-ink-600 outline-none focus:border-violet/40 disabled:opacity-50"
              />
              <button
                onClick={saveCurrent}
                disabled={!hasFilters || !name.trim() || busy}
                className="p-1.5 rounded-lg bg-violet/10 border border-violet/25 text-violet hover:bg-violet/15 disabled:opacity-40 transition-colors"
                title="Save current filters as a view">
                {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <BookmarkPlus className="w-3.5 h-3.5" />}
              </button>
            </div>

            {error && <p className="text-[11px] text-magenta mb-2">{error}</p>}

            {views === null ? (
              <p className="text-[11px] text-ink-600 py-1.5">Loading…</p>
            ) : views.length === 0 ? (
              <p className="text-[11px] text-ink-600 py-1.5">
                Nothing saved yet - set some filters and save them here.
              </p>
            ) : (
              <ul className="space-y-0.5 max-h-56 overflow-y-auto">
                {views.map((v) => (
                  <li key={v.id} className="group flex items-center gap-1.5">
                    <button
                      onClick={() => { onApply(v.filters || {}); setOpen(false) }}
                      className="flex-1 text-left px-2 py-1.5 rounded-lg text-xs text-ink-300 hover:text-white hover:bg-white/5 transition-colors truncate"
                      title={Object.entries(v.filters || {}).map(([k, val]) => `${k}=${val}`).join('  ') || 'No filters'}>
                      {v.name}
                      <span className="ml-1.5 text-[10px] text-ink-600">
                        {Object.keys(v.filters || {}).length} filter{Object.keys(v.filters || {}).length === 1 ? '' : 's'}
                      </span>
                    </button>
                    <button
                      onClick={() => remove(v.id)}
                      className="p-1 rounded text-ink-700 opacity-0 group-hover:opacity-100 hover:text-magenta transition-all"
                      title="Delete this view">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
