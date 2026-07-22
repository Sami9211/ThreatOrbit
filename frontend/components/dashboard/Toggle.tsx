'use client'

import { cn } from '@/lib/utils'

/**
 * One canonical on/off switch for the whole dashboard.
 *
 * Replaces the three divergent ad-hoc toggle geometries that had drifted
 * across pages (config `w-9 h-5`/knob `w-4`; siem-rules `w-8 h-4.5`/knob `w-3`
 * with a vertically off-centre `top-0.5`; feeds-sources a third), which read as
 * "inverted" and let the knob sit off-centre or graze the track edge.
 *
 * Correctness guarantees baked in here so no caller can regress them:
 *   - on = knob RIGHT + accent track; off = knob LEFT + muted track (standard).
 *   - perfect vertical centring via flex `items-center` (never a magic `top-`).
 *   - the knob can't overflow: the track pads both sides (`px-0.5`) and the knob
 *     travels exactly track-width − knob-width − 2·pad (`translate-x-4` on the
 *     w-9/h-5 track), so there's an equal 2px margin at rest and when thrown.
 *   - a single eased transition on colour + transform, honoured by the global
 *     reduce-motion rule.
 */
export function Toggle({
  checked,
  onChange,
  disabled = false,
  label,
  className,
}: {
  checked: boolean
  onChange: (next: boolean) => void
  disabled?: boolean
  /** Accessible name; also the native title. */
  label?: string
  className?: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation()
        if (!disabled) onChange(!checked)
      }}
      className={cn(
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full px-0.5',
        'transition-colors duration-200 outline-none',
        'focus-visible:ring-2 focus-visible:ring-safe/50 focus-visible:ring-offset-1 focus-visible:ring-offset-transparent',
        checked ? 'bg-safe' : 'bg-ink-600',
        disabled && 'opacity-40 cursor-not-allowed',
        className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          'h-4 w-4 rounded-full bg-white shadow-sm',
          'transition-transform duration-200 ease-out will-change-transform',
          checked ? 'translate-x-4' : 'translate-x-0',
        )}
      />
    </button>
  )
}

export default Toggle
