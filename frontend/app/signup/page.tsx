'use client'

import { useState, useMemo } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Check, ChevronRight, ChevronLeft, Eye, EyeOff, Star,
  Mail, Lock, User, Building2, ArrowRight, ShieldCheck, Loader2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import Logo from '@/components/ui/Logo'
import { PLANS, planById, type PlanId } from '@/lib/plans'
import { useAuth } from '@/lib/auth-context'

function strength(pw: string): { score: number; label: string; color: string } {
  let s = 0
  if (pw.length >= 8) s++
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++
  if (/\d/.test(pw)) s++
  if (/[^A-Za-z0-9]/.test(pw)) s++
  const map = [
    { label: 'Too short', color: '#FF4D6D' },
    { label: 'Weak', color: '#FF4D6D' },
    { label: 'Fair', color: '#FFB23E' },
    { label: 'Good', color: '#7A3CFF' },
    { label: 'Strong', color: '#34F5C5' },
  ]
  return { score: s, ...map[s] }
}

export default function SignUpPage() {
  const router = useRouter()
  const { register } = useAuth()
  const [step, setStep] = useState<1 | 2>(1)
  const [plan, setPlan] = useState<PlanId>('professional')
  const [annual, setAnnual] = useState(false)
  const [form, setForm] = useState({ name: '', email: '', company: '', password: '' })
  const [showPw, setShowPw] = useState(false)
  const [agree, setAgree] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const selected = planById[plan]
  const pw = strength(form.password)

  const priceText = useMemo(() => {
    if (selected.price === null) return 'Custom pricing'
    if (selected.price === 0) return 'Free forever'
    const p = annual ? Math.round(selected.price * 0.8) : selected.price
    return `£${p}/mo${annual ? ' · billed annually' : ''}`
  }, [selected, annual])

  const emailValid = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(form.email)
  const canSubmit = form.name.trim() && emailValid && form.password.length >= 8 && agree

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!canSubmit || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      await register({
        name: form.name.trim(),
        email: form.email.trim(),
        password: form.password,
        company: form.company.trim() || undefined,
      })
      router.push('/dashboard')
    } catch (err) {
      const msg = err instanceof Error ? err.message : ''
      setError(
        msg.includes('already exists') ? 'An account with that email already exists. Try signing in instead.'
        : msg.startsWith('HTTP') || msg.includes('fetch') ? 'Could not reach the ThreatOrbit API. Make sure the dashboard service is running, then try again.'
        : msg || 'Something went wrong creating your account. Please try again.',
      )
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen bg-bg text-ink-100 relative overflow-x-hidden">
      {/* Ambient background */}
      <div className="fixed inset-0 pointer-events-none" aria-hidden>
        <div className="absolute -top-32 -left-24 w-[480px] h-[480px] rounded-full opacity-[0.10]" style={{ background: 'radial-gradient(circle, #FF2E97, transparent 70%)', filter: 'blur(60px)' }} />
        <div className="absolute top-1/3 -right-24 w-[520px] h-[520px] rounded-full opacity-[0.08]" style={{ background: 'radial-gradient(circle, #7A3CFF, transparent 70%)', filter: 'blur(60px)' }} />
      </div>

      <div className="relative z-10 max-w-6xl mx-auto px-5 sm:px-6 py-6 sm:py-10">
        {/* Header */}
        <div className="flex items-center justify-between gap-3 mb-8">
          <Link href="/" className="flex items-center gap-2.5 group shrink-0">
            <Logo size={28} className="transition-transform group-hover:scale-110" />
            <span className="font-display font-semibold text-lg">
              <span className="text-white">Threat</span>
              <span className="text-gradient-magenta">Orbit</span>
            </span>
          </Link>
          <p className="text-sm text-ink-400 shrink-0">
            <span className="hidden sm:inline">Already have an account? </span>
            <Link href="/login" className="text-magenta hover:underline font-medium">Sign in</Link>
          </p>
        </div>

        {/* Step indicator */}
        <div className="flex items-center justify-center gap-3 mb-8">
          {[1, 2].map((n) => (
            <div key={n} className="flex items-center gap-3">
              <div className={cn('flex items-center gap-2 text-xs font-medium transition-colors',
                step >= n ? 'text-white' : 'text-ink-600')}>
                <span className={cn('w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold border transition-colors',
                  step > n ? 'bg-safe/15 border-safe/40 text-safe' :
                  step === n ? 'bg-magenta/15 border-magenta/40 text-magenta' :
                  'border-white/10 text-ink-600')}>
                  {step > n ? <Check className="w-3.5 h-3.5" /> : n}
                </span>
                {n === 1 ? 'Choose plan' : 'Create account'}
              </div>
              {n === 1 && <div className={cn('w-10 h-px', step > 1 ? 'bg-safe/40' : 'bg-white/10')} />}
            </div>
          ))}
        </div>

        <AnimatePresence mode="wait">
          {step === 1 ? (
            <motion.div key="plans"
              initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -16 }}
              transition={{ duration: 0.35 }}>
              <div className="text-center mb-7">
                <h1 className="font-display text-3xl sm:text-4xl font-bold text-white">Pick the plan that fits</h1>
                <p className="text-ink-400 mt-2">You can change or cancel anytime. No credit card needed to start.</p>
                {/* Annual toggle */}
                <button onClick={() => setAnnual((v) => !v)}
                  className="inline-flex items-center gap-2.5 mt-5 px-3 py-1.5 rounded-full border border-white/10 bg-surface-2 text-xs"
                  aria-pressed={annual}>
                  <span className={cn(!annual && 'text-white font-medium', annual && 'text-ink-500')}>Monthly</span>
                  <span className={cn('relative w-9 h-5 rounded-full transition-colors', annual ? 'bg-safe' : 'bg-ink-600')}>
                    <span className={cn('absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all', annual ? 'left-[18px]' : 'left-0.5')} />
                  </span>
                  <span className={cn(annual && 'text-white font-medium', !annual && 'text-ink-500')}>
                    Annual <span className="text-safe">−20%</span>
                  </span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {PLANS.map((p) => {
                  const active = plan === p.id
                  const displayPrice = p.price === null ? 'Custom' : p.price === 0 ? '£0' :
                    `£${annual ? Math.round(p.price * 0.8) : p.price}`
                  return (
                    <button key={p.id} onClick={() => setPlan(p.id)}
                      className={cn('relative text-left rounded-2xl border p-5 transition-all duration-300 flex flex-col',
                        active ? 'border-transparent bg-surface-2 ring-2 shadow-[0_12px_40px_rgba(0,0,0,0.5)]' : 'border-white/8 bg-surface/60 hover:border-white/15')}
                      style={active ? { boxShadow: `0 0 0 2px ${p.color}, 0 12px 40px rgba(0,0,0,0.5)` } : undefined}>
                      {p.badge && (
                        <span className="absolute -top-2.5 left-1/2 -translate-x-1/2 inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-magenta text-white text-[10px] font-bold whitespace-nowrap">
                          <Star className="w-2.5 h-2.5" /> {p.badge}
                        </span>
                      )}
                      <div className="flex items-center justify-between">
                        <p className="text-xs font-bold uppercase tracking-widest" style={{ color: p.color }}>{p.name}</p>
                        <span className={cn('w-5 h-5 rounded-full border flex items-center justify-center transition-colors',
                          active ? 'border-transparent' : 'border-white/15')}
                          style={active ? { background: p.color } : undefined}>
                          {active && <Check className="w-3 h-3 text-white" />}
                        </span>
                      </div>
                      <div className="flex items-end gap-1 mt-3 mb-1">
                        <span className="font-display text-3xl font-bold text-white leading-none">{displayPrice}</span>
                        {p.price !== null && p.price > 0 && <span className="text-xs text-ink-500 mb-1">/mo</span>}
                      </div>
                      <p className="text-[11px] text-ink-500">{p.users}</p>
                      <p className="text-xs text-ink-400 mt-3 leading-relaxed">{p.tagline}</p>
                      <div className="mt-4 space-y-1.5 flex-1">
                        {p.features.slice(0, 5).map((f) => (
                          <div key={f} className="flex items-start gap-2">
                            <Check className="w-3 h-3 mt-0.5 shrink-0" style={{ color: p.color }} />
                            <span className="text-[11px] text-ink-300 leading-snug">{f}</span>
                          </div>
                        ))}
                      </div>
                    </button>
                  )
                })}
              </div>

              <div className="flex items-center justify-between mt-8 flex-wrap gap-3">
                <Link href="/pricing" className="text-sm text-ink-400 hover:text-white transition-colors">
                  Compare all features →
                </Link>
                <button onClick={() => setStep(2)}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl bg-plasma text-white font-semibold text-sm hover:shadow-magenta-md hover:scale-[1.02] transition-all">
                  Continue with {selected.name}
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          ) : (
            <motion.div key="account"
              initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -16 }}
              transition={{ duration: 0.35 }}
              className="grid lg:grid-cols-[1fr_340px] gap-8 max-w-4xl mx-auto items-start">
              {/* Form */}
              <form onSubmit={submit} className="glass border border-white/8 rounded-2xl p-6 sm:p-8">
                <button type="button" onClick={() => setStep(1)}
                  className="flex items-center gap-1.5 text-xs text-ink-400 hover:text-white transition-colors mb-5">
                  <ChevronLeft className="w-3.5 h-3.5" /> Back to plans
                </button>
                <h1 className="font-display text-2xl font-bold text-white mb-1">Create your account</h1>
                <p className="text-sm text-ink-400 mb-6">Set up your ThreatOrbit workspace in seconds.</p>

                <div className="space-y-4">
                  <Input icon={User} label="Full name" value={form.name} placeholder="Jane Analyst"
                    onChange={(v) => setForm((f) => ({ ...f, name: v }))} />
                  <Input icon={Mail} label="Work email" type="email" value={form.email} placeholder="jane@company.com"
                    onChange={(v) => setForm((f) => ({ ...f, email: v }))}
                    valid={form.email ? emailValid : undefined} />
                  <Input icon={Building2} label="Company (optional)" value={form.company} placeholder="Acme Security Corp"
                    onChange={(v) => setForm((f) => ({ ...f, company: v }))} />

                  {/* Password */}
                  <div>
                    <label className="block text-xs font-medium text-ink-300 mb-1.5">Password</label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-500" />
                      <input
                        type={showPw ? 'text' : 'password'}
                        value={form.password}
                        onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                        placeholder="At least 8 characters"
                        className="w-full pl-10 pr-10 py-2.5 rounded-xl bg-surface-2 border border-white/8 text-sm text-ink-100 focus:outline-none focus:border-magenta/40 focus:ring-1 focus:ring-magenta/15 transition-colors placeholder-ink-600"
                      />
                      <button type="button" onClick={() => setShowPw((s) => !s)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-ink-500 hover:text-white transition-colors"
                        aria-label={showPw ? 'Hide password' : 'Show password'}>
                        {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    {form.password && (
                      <div className="flex items-center gap-2 mt-2">
                        <div className="flex-1 flex gap-1">
                          {[0, 1, 2, 3].map((i) => (
                            <span key={i} className="h-1 flex-1 rounded-full transition-colors"
                              style={{ background: i < pw.score ? pw.color : 'rgba(255,255,255,0.08)' }} />
                          ))}
                        </div>
                        <span className="text-[10px] font-medium" style={{ color: pw.color }}>{pw.label}</span>
                      </div>
                    )}
                  </div>

                  {/* Terms */}
                  <label className="flex items-start gap-2.5 cursor-pointer pt-1">
                    <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)}
                      className="mt-0.5 w-4 h-4 rounded accent-magenta shrink-0" />
                    <span className="text-[11px] text-ink-400 leading-relaxed">
                      I agree to the <Link href="/terms" className="text-magenta hover:underline">Terms of Service</Link> and{' '}
                      <Link href="/privacy" className="text-magenta hover:underline">Privacy Policy</Link>.
                    </span>
                  </label>
                </div>

                {error && (
                  <div className="mt-4 px-3.5 py-2.5 rounded-xl bg-threat/10 border border-threat/25 text-xs text-threat leading-relaxed" role="alert">
                    {error}
                  </div>
                )}

                <button type="submit" disabled={!canSubmit || submitting}
                  className={cn('w-full mt-6 flex items-center justify-center gap-2 py-3 rounded-xl font-semibold text-sm transition-all',
                    canSubmit && !submitting ? 'bg-plasma text-white hover:shadow-magenta-md hover:scale-[1.01]' : 'bg-surface-3 text-ink-600 cursor-not-allowed')}>
                  {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Creating workspace…</> : <>Create account <ArrowRight className="w-4 h-4" /></>}
                </button>

                <p className="text-center text-[11px] text-ink-600 mt-4">
                  By continuing you start a 14-day Professional trial. No charge until it ends.
                </p>
              </form>

              {/* Order summary */}
              <div className="glass border border-white/8 rounded-2xl p-6 lg:sticky lg:top-6">
                <p className="text-xs uppercase tracking-widest text-ink-500 font-semibold mb-4">Your plan</p>
                <div className="flex items-center justify-between mb-1">
                  <span className="font-display text-xl font-bold text-white">{selected.name}</span>
                  <span className="text-xs px-2 py-0.5 rounded-full" style={{ background: `${selected.color}1a`, color: selected.color }}>
                    {selected.users}
                  </span>
                </div>
                <p className="text-sm font-medium text-magenta mb-4">{priceText}</p>
                <p className="text-xs text-ink-400 leading-relaxed mb-4">{selected.tagline}</p>
                <div className="border-t border-white/5 pt-4 space-y-2">
                  {selected.features.map((f) => (
                    <div key={f} className="flex items-start gap-2">
                      <Check className="w-3.5 h-3.5 mt-0.5 shrink-0" style={{ color: selected.color }} />
                      <span className="text-xs text-ink-300">{f}</span>
                    </div>
                  ))}
                </div>
                <button onClick={() => setStep(1)} className="text-xs text-ink-400 hover:text-white transition-colors mt-4">
                  Change plan
                </button>
                <div className="mt-5 flex items-center gap-2 text-[11px] text-ink-500 border-t border-white/5 pt-4">
                  <ShieldCheck className="w-4 h-4 text-safe shrink-0" />
                  Encrypted in transit. SOC 2 Type II ready.
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}

function Input({ icon: Icon, label, value, onChange, placeholder, type = 'text', valid }: {
  icon: React.ElementType; label: string; value: string; onChange: (v: string) => void
  placeholder?: string; type?: string; valid?: boolean
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-ink-300 mb-1.5">{label}</label>
      <div className="relative">
        <Icon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-500" />
        <input type={type} value={value} placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)}
          className={cn('w-full pl-10 pr-10 py-2.5 rounded-xl bg-surface-2 border text-sm text-ink-100 focus:outline-none focus:ring-1 transition-colors placeholder-ink-600',
            valid === false ? 'border-threat/40 focus:border-threat/60 focus:ring-threat/15' : 'border-white/8 focus:border-magenta/40 focus:ring-magenta/15')} />
        {valid === true && <Check className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-safe" />}
      </div>
    </div>
  )
}
