'use client'

import { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { authLogin, authRegister, authMe, ApiError, TOKEN_KEY, USER_KEY, type User } from './api'

interface AuthCtx {
  user: User | null
  token: string | null
  loading: boolean
  login: (email: string, password: string, code?: string) => Promise<void>
  register: (body: { name: string; email: string; password: string; company?: string }) => Promise<{ pending: boolean; email?: string; message?: string }>
  completeSso: (token: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthCtx>({
  user: null, token: null, loading: true,
  login: async () => {}, register: async () => ({ pending: false }), completeSso: async () => {}, logout: () => {},
})

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser]   = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const stored = localStorage.getItem(TOKEN_KEY)
    if (!stored) { setLoading(false); return }
    setToken(stored)
    authMe()
      .then((u) => {
        setUser(u)
        localStorage.setItem(USER_KEY, JSON.stringify(u))
      })
      .catch((err) => {
        // Destroy the session only when the API definitively rejected the
        // token. A transient failure (network blip, API restart, 5xx) must
        // NOT log the operator out - fall back to the cached user and let the
        // next successful call re-validate.
        if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
          localStorage.removeItem(TOKEN_KEY)
          localStorage.removeItem(USER_KEY)
          setToken(null)
          return
        }
        const cached = localStorage.getItem(USER_KEY)
        if (cached) {
          try { setUser(JSON.parse(cached)) } catch { /* corrupt cache: stay signed out */ }
        }
      })
      .finally(() => setLoading(false))
  }, [])

  const storeSession = useCallback((tok: string, u: User) => {
    localStorage.setItem(TOKEN_KEY, tok)
    localStorage.setItem(USER_KEY, JSON.stringify(u))
    setToken(tok)
    setUser(u)
  }, [])

  const login = useCallback(async (email: string, password: string, code?: string) => {
    const { token: tok, user: u } = await authLogin(email, password, code)
    storeSession(tok, u)
  }, [storeSession])

  const register = useCallback(async (body: { name: string; email: string; password: string; company?: string }) => {
    const res = await authRegister(body)
    // Email-verification deployments return no session - the caller shows a
    // "check your email" state instead of proceeding to the dashboard.
    if (res.token && res.user) storeSession(res.token, res.user)
    return { pending: !!res.pending, email: res.email, message: res.message }
  }, [storeSession])

  // Complete an SSO sign-in: the backend handed us a session token in the URL
  // fragment; store it, then load the user with it.
  const completeSso = useCallback(async (tok: string) => {
    localStorage.setItem(TOKEN_KEY, tok)
    setToken(tok)
    const u = await authMe()
    storeSession(tok, u)
  }, [storeSession])

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    setToken(null)
    setUser(null)
  }, [])

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout, completeSso }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
