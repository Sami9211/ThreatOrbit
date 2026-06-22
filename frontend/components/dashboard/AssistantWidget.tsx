'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useRouter } from 'next/navigation'
import { Sparkles, X, Send, Loader2, ArrowUpRight, ShieldCheck } from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchAssistantStatus, sendAssistantChat, type AssistantNav } from '@/lib/api'

interface Msg { role: 'user' | 'assistant'; text: string; navigations?: AssistantNav[]; tools?: string[] }

/**
 * Floating dashboard assistant. A security-bounded, read-only agent: it answers
 * questions about the platform's own data, reviews posture, recommends next
 * steps, and proposes which page to open (the user clicks - it never navigates
 * or acts on its own). Backed by /assistant/chat, which runs every tool under
 * the signed-in user and never exposes credentials.
 */
export default function AssistantWidget() {
  const router = useRouter()
  const [open, setOpen] = useState(false)
  const [mode, setMode] = useState<'ai' | 'basic' | null>(null)
  const [messages, setMessages] = useState<Msg[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetchAssistantStatus().then((s) => setMode(s.mode)).catch(() => {})
  }, [])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages, busy])

  const send = useCallback(() => {
    const text = input.trim()
    if (!text || busy) return
    const history = messages.slice(-6).map((m) => ({ role: m.role, text: m.text }))
    setMessages((prev) => [...prev, { role: 'user', text }])
    setInput('')
    setBusy(true)
    sendAssistantChat(text, history)
      .then((r) => setMessages((prev) => [...prev, {
        role: 'assistant', text: r.reply, navigations: r.navigations, tools: r.toolsUsed,
      }]))
      .catch((e) => setMessages((prev) => [...prev, {
        role: 'assistant',
        text: e instanceof Error && e.message.includes('429')
          ? 'I am getting a lot of questions at once - give me a moment.'
          : 'I could not reach the assistant service just now.',
      }]))
      .finally(() => setBusy(false))
  }, [input, busy, messages])

  const SUGGESTIONS = [
    "What's our security posture?",
    'Any open critical alerts?',
    'Top threat actors',
    'Where are attacks coming from?',
  ]

  return (
    <>
      {/* Launcher — a compact icon that expands to reveal the label on
          hover/focus (keeps the screen clear; full affordance on demand). */}
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label="Ask ThreatOrbit — open the security assistant"
        title="Ask ThreatOrbit"
        className={cn(
          'group fixed bottom-5 right-5 z-50 flex items-center gap-0 hover:gap-2 focus-visible:gap-2',
          'rounded-full p-3.5 hover:pr-5 focus-visible:pr-5 shadow-xl transition-all',
          'bg-plasma text-white hover:scale-105 hover:shadow-magenta-md',
          open && 'scale-0 opacity-0 pointer-events-none',
        )}>
        <Sparkles className="w-5 h-5 shrink-0" />
        <span className="max-w-0 group-hover:max-w-[160px] group-focus-visible:max-w-[160px] overflow-hidden whitespace-nowrap text-sm font-semibold transition-[max-width] duration-200 ease-out">
          Ask ThreatOrbit
        </span>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 24, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 24, scale: 0.96 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            className="fixed bottom-5 right-5 z-50 w-[min(420px,calc(100vw-2.5rem))] h-[min(600px,calc(100vh-2.5rem))] flex flex-col rounded-2xl border border-white/10 bg-[#0B0712]/98 backdrop-blur-xl shadow-2xl overflow-hidden">
            {/* Header */}
            <div className="flex items-center gap-2.5 px-4 py-3 border-b border-white/8 shrink-0 bg-gradient-to-r from-magenta/10 to-violet/10">
              <div className="p-1.5 rounded-lg bg-plasma/20 border border-magenta/25">
                <Sparkles className="w-4 h-4 text-magenta" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-white leading-tight">Security Assistant</p>
                <p className="text-[10px] text-ink-500 flex items-center gap-1">
                  <ShieldCheck className="w-2.5 h-2.5 text-safe" />
                  read-only · runs as you
                  {mode === 'basic' && <span className="text-amber"> · basic mode</span>}
                </p>
              </div>
              <button onClick={() => setOpen(false)} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/8 transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Conversation */}
            <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-4 space-y-3">
              {messages.length === 0 && (
                <div className="text-center py-6">
                  <p className="text-xs text-ink-400 mb-1">
                    Ask about your alerts, cases, threat intel, assets, or posture.
                  </p>
                  <p className="text-[10px] text-ink-600 mb-4">
                    I only read your platform data and propose where to look - I never change
                    anything or reveal credentials.
                  </p>
                  <div className="flex flex-col gap-1.5">
                    {SUGGESTIONS.map((s) => (
                      <button key={s} onClick={() => { setInput(s); setTimeout(send, 0) }}
                        className="text-left text-xs px-3 py-2 rounded-lg bg-white/4 border border-white/8 text-ink-300 hover:text-white hover:border-magenta/30 transition-colors">
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {messages.map((m, i) => (
                <div key={i} className={cn('flex', m.role === 'user' ? 'justify-end' : 'justify-start')}>
                  <div className={cn(
                    'max-w-[85%] rounded-2xl px-3.5 py-2.5 text-xs leading-relaxed',
                    m.role === 'user'
                      ? 'bg-plasma text-white rounded-br-sm'
                      : 'bg-white/5 border border-white/8 text-ink-200 rounded-bl-sm',
                  )}>
                    <p className="whitespace-pre-wrap">{m.text}</p>
                    {m.navigations && m.navigations.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {m.navigations.map((n, j) => (
                          <button key={j} onClick={() => { router.push(n.path); setOpen(false) }}
                            className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg bg-magenta/10 border border-magenta/25 text-magenta hover:bg-magenta/20 transition-colors">
                            {n.label} <ArrowUpRight className="w-2.5 h-2.5" />
                          </button>
                        ))}
                      </div>
                    )}
                    {m.tools && m.tools.length > 0 && (
                      <p className="mt-1.5 text-[9px] text-ink-600">
                        looked at: {Array.from(new Set(m.tools)).join(', ')}
                      </p>
                    )}
                  </div>
                </div>
              ))}
              {busy && (
                <div className="flex justify-start">
                  <div className="rounded-2xl rounded-bl-sm px-3.5 py-2.5 bg-white/5 border border-white/8">
                    <Loader2 className="w-3.5 h-3.5 text-magenta animate-spin" />
                  </div>
                </div>
              )}
            </div>

            {/* Composer */}
            <div className="border-t border-white/8 p-3 shrink-0">
              <div className="flex items-end gap-2">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
                  rows={1}
                  maxLength={2000}
                  placeholder="Ask about your security data…"
                  className="flex-1 resize-none max-h-24 px-3 py-2 rounded-xl bg-surface-2 border border-white/10 text-xs text-ink-100 placeholder-ink-600 focus:outline-none focus:border-magenta/40" />
                <button onClick={send} disabled={!input.trim() || busy}
                  className="p-2.5 rounded-xl bg-plasma text-white disabled:opacity-40 hover:shadow-magenta-sm transition-all shrink-0">
                  <Send className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
