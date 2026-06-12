'use client'

import { useCallback, useMemo, useRef, useState } from 'react'

/**
 * Dependency-free list virtualisation for long, uniform-height tables.
 *
 * Below `threshold` items it is a no-op (every row renders, zero behaviour
 * change). Above it, only the rows inside the scroll viewport (± overscan)
 * mount, with top/bottom spacer padding preserving the scrollbar geometry.
 *
 *   const { containerProps, visible, topPad, bottomPad, virtualized } =
 *     useWindowedRows(rows, { rowHeight: 56 })
 *   <div {...containerProps} className="flex-1 overflow-y-auto">
 *     {topPad > 0 && <div style={{ height: topPad }} />}
 *     {visible.map(({ item, index }) => …)}
 *     {bottomPad > 0 && <div style={{ height: bottomPad }} />}
 *   </div>
 */
export function useWindowedRows<T>(items: T[], opts: {
  rowHeight: number
  overscan?: number
  threshold?: number
}) {
  const { rowHeight, overscan = 12, threshold = 150 } = opts
  const [scrollTop, setScrollTop] = useState(0)
  const [viewport, setViewport] = useState(800)
  const frame = useRef<number | null>(null)

  const onScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget
    if (frame.current != null) return  // coalesce to one update per frame
    frame.current = requestAnimationFrame(() => {
      frame.current = null
      setScrollTop(el.scrollTop)
      setViewport(el.clientHeight || 800)
    })
  }, [])

  const virtualized = items.length > threshold
  const { visible, topPad, bottomPad } = useMemo(() => {
    if (!virtualized) {
      return {
        visible: items.map((item, index) => ({ item, index })),
        topPad: 0, bottomPad: 0,
      }
    }
    const start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan)
    const end = Math.min(items.length,
      Math.ceil((scrollTop + viewport) / rowHeight) + overscan)
    return {
      visible: items.slice(start, end).map((item, i) => ({ item, index: start + i })),
      topPad: start * rowHeight,
      bottomPad: (items.length - end) * rowHeight,
    }
  }, [items, virtualized, scrollTop, viewport, rowHeight, overscan])

  return {
    containerProps: virtualized ? { onScroll } : {},
    visible, topPad, bottomPad, virtualized,
  }
}
