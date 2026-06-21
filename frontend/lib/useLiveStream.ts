'use client'

import { useEffect, useRef } from 'react'
import { fetchStreamUrl } from '@/lib/api'

export type LiveEvent = { type: string; data: Record<string, unknown> }

/**
 * Subscribe to the dashboard's Server-Sent Events stream (real-time push).
 * Calls `onEvent` for every server event (notification, tick, alert.created,
 * case.created, …). Auto-reconnects via EventSource; also re-broadcasts each
 * event on `window` as `live:<type>` and a generic `live` event so any panel
 * can listen without prop-drilling. Falls back silently when unsupported or
 * unauthenticated (existing polling keeps working).
 */
export function useLiveStream(onEvent?: (e: LiveEvent) => void) {
  const cb = useRef(onEvent)
  cb.current = onEvent

  useEffect(() => {
    if (typeof window === 'undefined' || typeof EventSource === 'undefined') return

    let es: EventSource | null = null
    let closed = false

    const handle = (type: string) => (ev: MessageEvent) => {
      let data: Record<string, unknown> = {}
      try { data = ev.data ? JSON.parse(ev.data) : {} } catch { /* ignore */ }
      const detail: LiveEvent = { type, data }
      cb.current?.(detail)
      window.dispatchEvent(new CustomEvent('live', { detail }))
      window.dispatchEvent(new CustomEvent(`live:${type}`, { detail }))
    }

    // Named events the server emits, plus the default (unnamed) channel.
    const NAMED = ['notification', 'tick', 'alert.created', 'case.created',
      'incident.resolved', 'ioc.confirmed', 'playbook.completed', 'playbook.action']

    // Each connect mints a FRESH single-use ticket (so a reconnect can't reuse a
    // consumed one), then opens the EventSource with it.
    async function connect() {
      if (closed) return
      const url = await fetchStreamUrl()
      if (!url || closed) return
      es = new EventSource(url)
      NAMED.forEach((t) => es!.addEventListener(t, handle(t)))
      es.onmessage = handle('message')
      es.onerror = () => {
        // EventSource reconnects on its own; recreate only if fully closed (so we
        // mint a new ticket - the prior one is already consumed).
        if (es && es.readyState === EventSource.CLOSED && !closed) {
          es.close()
          setTimeout(connect, 3000)
        }
      }
    }
    connect()

    return () => { closed = true; es?.close() }
  }, [])
}
