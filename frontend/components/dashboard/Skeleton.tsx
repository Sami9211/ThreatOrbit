'use client'

import { cn } from '@/lib/utils'

/** Loading placeholder block. Pulses via CSS (`animate-pulse`), which the
 *  global prefers-reduced-motion rule already freezes — no JS needed.
 *  Size it with width/height utility classes at the call site. */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn('animate-pulse rounded-md bg-white/[0.06]', className)} />
}

/** A column of row-shaped skeletons for list/table surfaces that are still
 *  waiting on their first API answer — shown instead of the empty state so a
 *  loading queue never flashes "no results" before the data arrives. */
export function SkeletonRows({ rows = 8, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('px-4 py-2 space-y-2', className)} aria-hidden role="status" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3">
          <Skeleton className="w-2 h-2 rounded-full shrink-0" />
          <Skeleton className="h-3.5 flex-1" />
          <Skeleton className="h-3.5 w-16 hidden md:block" />
          <Skeleton className="h-3.5 w-10" />
        </div>
      ))}
    </div>
  )
}
