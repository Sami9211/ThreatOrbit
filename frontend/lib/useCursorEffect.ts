/**
 * Persists whether the cursor particle effect is enabled.
 * Default: on. Stored in localStorage so it survives page reloads.
 */
'use client'

import { useState, useEffect, useCallback } from 'react'

const KEY = 'to-cursor-effect'

export function useCursorEffect(): [boolean, (v: boolean) => void] {
  const [enabled, setEnabled] = useState(false)

  useEffect(() => {
    const stored = localStorage.getItem(KEY)
    if (stored !== null) setEnabled(stored === 'on')
  }, [])

  const set = useCallback((v: boolean) => {
    setEnabled(v)
    localStorage.setItem(KEY, v ? 'on' : 'off')
  }, [])

  return [enabled, set]
}
