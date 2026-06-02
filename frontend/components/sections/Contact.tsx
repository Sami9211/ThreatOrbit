'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Send, CheckCircle2, Mail, MessageSquare, Loader2, Check } from 'lucide-react'
import Reveal from '@/components/ui/Reveal'

const INTERESTS = ['Super SOC', 'CTI Library', 'SIEM + SOAR', 'General inquiry']

export default function Contact() {
  const [sent, setSent] = useState(false)
  const [sending, setSending] = useState(false)
  const [interest, setInterest] = useState(INTERESTS[0])
  const [form, setForm] = useState({ name: '', email: '', company: '', message: '' })

  const emailValid = /\S+@\S+\.\S+/.test(form.email)
  const valid = form.name.trim() && emailValid && form.message.trim()

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!valid || sending) return
    // No backend yet: simulate a send, then show success. Wire to an API route
    // or a service like Formspree to actually deliver the message.
    setSending(true)
    setTimeout(() => {
      setSending(false)
      setSent(true)
    }, 900)
  }

  return (
    <section id="contact" className="py-28 bg-surface-2 overflow-hidden">
      <div className="max-w-6xl mx-auto px-6 grid lg:grid-cols-2 gap-14 items-center">
        <Reveal variant="left">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/10 bg-white/3 mb-6">
            <Mail className="w-3 h-3 text-magenta" />
            <span className="text-xs text-ink-300 tracking-wide">Get in touch</span>
          </div>
          <h2 className="font-display text-4xl md:text-5xl font-bold text-white leading-tight mb-6">
            Let&apos;s talk about
            <br />
            <span className="text-gradient-magenta">your security stack.</span>
          </h2>
          <p className="text-ink-300 leading-relaxed mb-8">
            Tell us what you are running today and where the gaps are. Whether you want the full
            Super SOC or just one orbit, we will map ThreatOrbit to your environment.
          </p>
          <div className="space-y-4">
            <div className="flex items-center gap-3 text-sm text-ink-300">
              <MessageSquare className="w-4 h-4 text-magenta" />
              Prefer to chat? Use the assistant in the corner.
            </div>
            <div className="flex items-center gap-3 text-sm text-ink-300">
              <Mail className="w-4 h-4 text-magenta" />
              hello@threatorbit.io
            </div>
          </div>
        </Reveal>

        <Reveal variant="right">
          <div className="glass border border-white/8 rounded-3xl p-7 relative overflow-hidden">
            <div className="absolute inset-0 plasma-mesh opacity-30 pointer-events-none" />
            <AnimatePresence mode="wait">
              {sent ? (
                <motion.div
                  key="success"
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="relative text-center py-12"
                >
                  <CheckCircle2 className="w-14 h-14 text-safe mx-auto mb-5" strokeWidth={1.5} />
                  <h3 className="font-display text-2xl font-bold text-white mb-2">Message received</h3>
                  <p className="text-ink-400 text-sm max-w-xs mx-auto">
                    Thanks {form.name.split(' ')[0] || 'there'}. We will be in touch about{' '}
                    {interest.toLowerCase()} shortly.
                  </p>
                </motion.div>
              ) : (
                <motion.form
                  key="form"
                  onSubmit={submit}
                  className="relative space-y-4"
                  initial={{ opacity: 1 }}
                >
                  <div className="grid sm:grid-cols-2 gap-4">
                    <Field
                      label="Name"
                      value={form.name}
                      onChange={(v) => setForm({ ...form, name: v })}
                      placeholder="Jane Doe"
                      valid={!!form.name.trim()}
                    />
                    <Field
                      label="Work email"
                      type="email"
                      value={form.email}
                      onChange={(v) => setForm({ ...form, email: v })}
                      placeholder="jane@company.com"
                      valid={emailValid}
                      invalid={form.email.length > 3 && !emailValid}
                    />
                  </div>
                  <Field
                    label="Company"
                    value={form.company}
                    onChange={(v) => setForm({ ...form, company: v })}
                    placeholder="Acme Security"
                  />

                  <div>
                    <label className="block text-xs text-ink-400 mb-1.5">Interested in</label>
                    <div className="flex flex-wrap gap-2">
                      {INTERESTS.map((opt) => (
                        <button
                          key={opt}
                          type="button"
                          onClick={() => setInterest(opt)}
                          className={`px-3 py-1.5 rounded-lg text-xs border transition-colors ${
                            interest === opt
                              ? 'bg-magenta/15 border-magenta/40 text-white'
                              : 'border-white/10 text-ink-400 hover:text-white'
                          }`}
                        >
                          {opt}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs text-ink-400 mb-1.5">Message</label>
                    <textarea
                      value={form.message}
                      onChange={(e) => setForm({ ...form, message: e.target.value })}
                      rows={4}
                      placeholder="What are you trying to solve?"
                      className="w-full rounded-xl bg-white/3 border border-white/10 px-3.5 py-2.5 text-sm text-white placeholder:text-ink-600 focus:border-magenta/40 focus:outline-none transition-colors resize-none"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={!valid || sending}
                    className="w-full flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-plasma text-white font-semibold text-sm transition-all hover:shadow-magenta-md disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    {sending ? (
                      <>
                        Sending
                        <Loader2 className="w-4 h-4 animate-spin" />
                      </>
                    ) : (
                      <>
                        Send inquiry
                        <Send className="w-4 h-4" />
                      </>
                    )}
                  </button>
                </motion.form>
              )}
            </AnimatePresence>
          </div>
        </Reveal>
      </div>
    </section>
  )
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = 'text',
  valid = false,
  invalid = false,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  type?: string
  valid?: boolean
  invalid?: boolean
}) {
  return (
    <div>
      <label className="block text-xs text-ink-400 mb-1.5">{label}</label>
      <div className="relative">
        <input
          type={type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className={`w-full rounded-xl bg-white/3 border px-3.5 py-2.5 pr-9 text-sm text-white placeholder:text-ink-600 focus:outline-none transition-colors ${
            invalid
              ? 'border-threat/50 focus:border-threat/60'
              : 'border-white/10 focus:border-magenta/40'
          }`}
        />
        <AnimatePresence>
          {valid && (
            <motion.span
              initial={{ opacity: 0, scale: 0.6 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.6 }}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-safe"
            >
              <Check className="w-4 h-4" strokeWidth={2.5} />
            </motion.span>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
