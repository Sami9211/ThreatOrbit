'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { CheckCircle2, XCircle, Loader2, ShieldCheck } from 'lucide-react'
import { verifyEmail } from '@/lib/api'

type State = 'loading' | 'success' | 'error' | 'notoken'

export default function VerifyPage() {
  const [state, setState] = useState<State>('loading')
  const [email, setEmail] = useState<string | null>(null)
  const [message, setMessage] = useState('')

  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get('token')
    if (!token) { setState('notoken'); return }
    verifyEmail(token)
      .then((r) => { setEmail(r.email); setState('success') })
      .catch((e) => { setMessage(e instanceof Error ? e.message : 'Verification failed.'); setState('error') })
  }, [])

  return (
    <div className="min-h-screen bg-bg text-ink-100 flex items-center justify-center px-4 relative overflow-hidden">
      <div className="fixed inset-0 pointer-events-none" aria-hidden>
        <div className="absolute -top-32 -left-24 w-[480px] h-[480px] rounded-full opacity-[0.10]"
          style={{ background: 'radial-gradient(circle, #FF2E97, transparent 70%)', filter: 'blur(60px)' }} />
      </div>

      <div className="relative w-full max-w-md glass border border-white/8 rounded-2xl p-8 text-center">
        <div className="flex items-center justify-center gap-2 mb-6">
          <ShieldCheck className="w-5 h-5 text-plasma" />
          <span className="font-display font-bold text-white">ThreatOrbit</span>
        </div>

        {state === 'loading' && (
          <>
            <Loader2 className="w-8 h-8 text-ink-400 animate-spin mx-auto mb-4" />
            <p className="text-sm text-ink-400">Verifying your email…</p>
          </>
        )}

        {state === 'success' && (
          <>
            <div className="w-12 h-12 rounded-2xl bg-safe/15 flex items-center justify-center mx-auto mb-4">
              <CheckCircle2 className="w-6 h-6 text-safe" />
            </div>
            <h1 className="font-display text-xl font-bold text-white mb-1">Email verified</h1>
            <p className="text-sm text-ink-400 mb-6">
              {email ? <><span className="font-medium text-white break-all">{email}</span> is confirmed. </> : null}
              Your account is now active — you can sign in.
            </p>
            <Link href="/login"
              className="inline-block px-5 py-2.5 rounded-lg text-sm font-semibold bg-plasma text-white hover:opacity-90 transition-opacity">
              Sign in
            </Link>
          </>
        )}

        {(state === 'error' || state === 'notoken') && (
          <>
            <div className="w-12 h-12 rounded-2xl bg-threat/15 flex items-center justify-center mx-auto mb-4">
              <XCircle className="w-6 h-6 text-threat" />
            </div>
            <h1 className="font-display text-xl font-bold text-white mb-1">
              {state === 'notoken' ? 'No verification token' : 'Verification failed'}
            </h1>
            <p className="text-sm text-ink-400 mb-6">
              {state === 'notoken'
                ? 'This page needs a verification link from your signup email.'
                : (message || 'This verification link is invalid or has expired.')}
              {' '}You can request a new link from the sign-up page.
            </p>
            <div className="flex items-center justify-center gap-2">
              <Link href="/signup"
                className="px-4 py-2 rounded-lg text-sm font-medium bg-surface-2 border border-white/10 text-ink-300 hover:text-white transition-colors">
                Back to sign up
              </Link>
              <Link href="/login"
                className="px-4 py-2 rounded-lg text-sm font-semibold bg-plasma text-white hover:opacity-90 transition-opacity">
                Sign in
              </Link>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
