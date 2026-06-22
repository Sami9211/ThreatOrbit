'use client'

import { Save, CheckCircle } from 'lucide-react'
import { cn } from '@/lib/utils'

/**
 * A compact, always-reachable Save control. Pinned to the top-right of the
 * viewport (just below the TopBar) so settings can be saved from any scroll
 * position without returning to the page header. Collapses to an icon and
 * expands the label on hover/focus; shows a transient "Saved" state.
 *
 * `show` lets callers reveal it only when there are unsaved changes; omit it
 * to keep Save permanently available (the default for settings pages).
 */
export default function FloatingSave({
  onSave, saved = false, show = true, label = 'Save Changes',
}: {
  onSave: () => void
  saved?: boolean
  show?: boolean
  label?: string
}) {
  return (
    <button
      type="button"
      onClick={onSave}
      aria-label={label}
      title={label}
      className={cn(
        'group fixed top-[4.5rem] right-5 z-40 flex items-center gap-0 hover:gap-2 focus-visible:gap-2',
        'rounded-full p-3 hover:pr-4 focus-visible:pr-4 shadow-xl transition-all duration-200',
        saved ? 'bg-safe/20 text-safe border border-safe/30' : 'bg-plasma text-white hover:shadow-magenta-sm',
        show ? 'opacity-100' : 'pointer-events-none translate-y-[-8px] opacity-0',
      )}
    >
      {saved ? <CheckCircle className="w-4 h-4 shrink-0" /> : <Save className="w-4 h-4 shrink-0" />}
      <span className="max-w-0 group-hover:max-w-[120px] group-focus-visible:max-w-[120px] overflow-hidden whitespace-nowrap text-sm font-medium transition-[max-width] duration-200 ease-out">
        {saved ? 'Saved!' : label}
      </span>
    </button>
  )
}
