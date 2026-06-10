'use client'

import { useEffect, useState } from 'react'
import { fetchMyPermissions, type MyPermissions } from '@/lib/api'

// Module-level cache so every component shares one fetch per session.
let _cache: MyPermissions | null = null
let _inflight: Promise<MyPermissions> | null = null

/**
 * The current user's effective RBAC capabilities. `can('siem.write')` gates UI
 * controls so a viewer never sees buttons they can't use (the backend enforces
 * the same matrix regardless). Fails open-closed: while loading, `can()`
 * returns false, so controls appear only once a capability is confirmed.
 */
export function usePermissions() {
  const [perms, setPerms] = useState<MyPermissions | null>(_cache)

  useEffect(() => {
    if (_cache) { setPerms(_cache); return }
    _inflight = _inflight ?? fetchMyPermissions().then((p) => { _cache = p; return p })
    let active = true
    _inflight.then((p) => { if (active) setPerms(p) }).catch(() => {})
    return () => { active = false }
  }, [])

  return {
    role: perms?.role ?? null,
    permissions: perms?.permissions ?? [],
    loaded: perms !== null,
    can: (perm: string) => !!perms?.capabilities?.[perm],
  }
}

/** Clear the cached permissions (call on logout / role change). */
export function resetPermissions() {
  _cache = null
  _inflight = null
}
