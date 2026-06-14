'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { motion } from 'framer-motion'
import { Mail, Lock, Eye, EyeOff, ArrowRight, Loader2, ShieldCheck, Github, AlertCircle, KeyRound } from 'lucide-react'
import { cn } from '@/lib/utils'
import Logo from '@/components/ui/Logo'
import { useAuth } from '@/lib/auth-context'
import { fetchSsoStatus, ssoLoginUrl } from '@/lib/api'

export default function LoginPage() {
  const router = useRouter()
  const { login, completeSso } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [remember, setRemember] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // TOTP step-up: shown when the account has MFA enrolled.
  const [mfaRequired, setMfaRequired] = useState(false)
  const [mfaCode, setMfaCode] = useState('')
  const [ssoOn, setSsoOn] = useState(false)

  // SSO: discover whether it's enabled, and complete a callback that handed us
  // a session token (or an error) back in the URL fragment.
  useEffect(() => {
    fetchSsoStatus().then((s) => setSsoOn(s.configured)).catch(() => {})
    const hash = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const tok = hash.get('sso_token')
    const err = hash.get('sso_error')
    if (tok) {
      history.replaceState(null, '', window.location.pathname)
      completeSso(tok).then(() => router.replace('/dashboard'))
        .catch(() => setError('Single sign-on succeeded but the session could not be established.'))
    } else if (err) {
      history.replaceState(null, '', window.location.pathname)
      setError(decodeURIComponent(err))
    }
  }, [completeSso, router])

  const emailValid = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)
  const canSubmit = emailValid && password.length > 0 && (!mfaRequired || mfaCode.length >= 6)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!canSubmit) return
    setSubmitting(true)
    setError(null)
    try {
      await login(email, password, mfaRequired ? mfaCode : undefined)
      router.push('/dashboard')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Login failed'
      if (msg === 'MFA code required') {
        // password verified - ask for the authenticator code
        setMfaRequired(true)
        setError(null)
      } else {
        setError(msg)
        if (msg.includes('MFA')) setMfaCode('')
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen bg-bg text-ink-100 relative overflow-hidden flex flex-col">
      {/* Ambient background */}
      <div className="fixed inset-0 pointer-events-none" aria-hidden>
        <div className="absolute -top-32 -left-24 w-[460px] h-[460px] rounded-full opacity-[0.10]" style={{ background: 'radial-gradient(circle, #FF2E97, transparent 70%)', filter: 'blur(60px)' }} />
        <div className="absolute bottom-0 -right-24 w-[520px] h-[520px] rounded-full opacity-[0.08]" style={{ background: 'radial-gradient(circle, #7A3CFF, transparent 70%)', filter: 'blur(60px)' }} />
      </div>

      <header className="relative z-10 max-w-6xl w-full mx-auto px-5 sm:px-6 py-6 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 group">
          <Logo size={28} className="transition-transform group-hover:scale-110" />
          <span className="font-display font-semibold text-lg">
            <span className="text-white">Threat</span>
            <span className="text-gradient-magenta">Orbit</span>
          </span>
        </Link>
        <p className="text-sm text-ink-400">
          New here?{' '}
          <Link href="/signup" className="text-magenta hover:underline font-medium">Create account</Link>
        </p>
      </header>

      <div className="relative z-10 flex-1 flex items-center justify-center px-5 py-10">
        <motion.div
          initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
          className="w-full max-w-md">
          <div className="glass border border-white/8 rounded-2xl p-7 sm:p-8">
            <div className="h-0.5 -mx-8 -mt-8 mb-7 bg-plasma rounded-t-2xl" />
            <h1 className="font-display text-2xl font-bold text-white mb-1">Welcome back</h1>
            <p className="text-sm text-ink-400 mb-6">Sign in to your ThreatOrbit workspace.</p>

            <form onSubmit={submit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-ink-300 mb-1.5">Work email</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-500" />
                  <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                    placeholder="jane@company.com"
                    className="w-full pl-10 pr-3 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 focus:ring-1 focus:ring-magenta/15 transition-colors placeholder-ink-600" />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-medium text-ink-300">Password</label>
                  <button type="button" className="text-[11px] text-ink-500 hover:text-magenta transition-colors">
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-500" />
                  <input type={showPw ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full pl-10 pr-10 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 focus:ring-1 focus:ring-magenta/15 transition-colors placeholder-ink-600" />
                  <button type="button" onClick={() => setShowPw((s) => !s)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-ink-500 hover:text-white transition-colors"
                    aria-label={showPw ? 'Hide password' : 'Show password'}>
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {mfaRequired && (
                <div>
                  <label className="block text-xs font-medium text-ink-300 mb-1.5">
                    Authenticator code
                  </label>
                  <div className="relative">
                    <ShieldCheck className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-safe" />
                    <input value={mfaCode} autoFocus inputMode="numeric" maxLength={6}
                      onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                      placeholder="6-digit code"
                      className="w-full pl-10 pr-3 py-2.5 rounded-xl bg-surface-2 border border-safe/25 text-sm font-mono tracking-[0.3em] text-ink-100 focus:outline-none focus:border-safe/50 focus:ring-1 focus:ring-safe/15 transition-colors placeholder-ink-600" />
                  </div>
                  <p className="text-[10px] text-ink-600 mt-1">
                    This account has two-factor authentication - enter the code from your authenticator app.
                  </p>
                </div>
              )}

              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)}
                  className="w-4 h-4 rounded accent-magenta" />
                <span className="text-xs text-ink-400">Keep me signed in</span>
              </label>

              {error && (
                <div role="alert" className="flex items-center gap-2 rounded-xl bg-threat/10 border border-threat/25 px-3 py-2.5 text-xs text-threat">
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  {error}
                </div>
              )}

              <button type="submit" disabled={!canSubmit || submitting}
                className={cn('w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold text-sm transition-all',
                  canSubmit && !submitting ? 'bg-plasma text-white hover:shadow-magenta-md hover:scale-[1.01]' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
                {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Signing in…</> : <>Sign in <ArrowRight className="w-4 h-4" /></>}
              </button>
            </form>

            <div className="flex items-center gap-3 my-5">
              <div className="flex-1 h-px bg-white/8" />
              <span className="text-[10px] text-ink-600 uppercase tracking-widest">or</span>
              <div className="flex-1 h-px bg-white/8" />
            </div>

            {ssoOn && (
              <a href={ssoLoginUrl()}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border border-violet/30 bg-violet/10 text-sm text-violet font-medium hover:bg-violet/15 transition-colors mb-2.5">
                <KeyRound className="w-4 h-4" /> Sign in with SSO
              </a>
            )}

            <button type="button" disabled
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border border-white/10 text-sm text-ink-500 cursor-not-allowed opacity-50">
              <Github className="w-4 h-4" /> Continue with GitHub
            </button>
          </div>

          <div className="flex items-center justify-center gap-2 text-[11px] text-ink-500 mt-5">
            <ShieldCheck className="w-3.5 h-3.5 text-safe" />
            Protected by end-to-end encryption
          </div>
        </motion.div>
      </div>
    </div>
  )
}
