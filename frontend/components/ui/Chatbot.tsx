'use client'

import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { MessageSquare, X, Send, Sparkles } from 'lucide-react'
import Logo from '@/components/ui/Logo'

type Msg = { from: 'bot' | 'user'; text: string }

/**
 * Orbit Assistant: a product-aware helper. The reply engine is rule-based
 * (keyword matching over a small knowledge base) so it works with no backend.
 * To make it a true AI assistant, swap `answer()` for a call to an API route
 * that proxies your LLM of choice.
 */
const KB: { keys: string[]; reply: string }[] = [
  {
    keys: ['price', 'pricing', 'cost', 'how much', 'plan'],
    reply:
      'ThreatOrbit comes in three tiers: the CTI Library is free and self-hosted, SIEM + SOAR is usage-based, and the full Super SOC is custom enterprise pricing. See the Pricing section, or I can point you to Contact sales.',
  },
  {
    keys: ['super soc', 'soc', 'everything', 'full'],
    reply:
      'The Super SOC is all three orbits in one: CTI (threat intel), SIEM (detection), and SOAR (automated response) around a single core. One platform, one API, one source of truth.',
  },
  {
    keys: ['cti', 'threat intel', 'intelligence', 'ioc', 'osint'],
    reply:
      'The CTI Library ingests indicators from five OSINT sources (OTX, abuse.ch, RSS, dark-web, social), enriches them with VirusTotal, and exports STIX 2.1. It can run completely on its own.',
  },
  {
    keys: ['siem', 'log', 'detect', 'anomaly'],
    reply:
      'The SIEM side parses Apache, syslog, Windows Event, and generic logs, then runs four detectors (pattern, statistical, ML, temporal) and returns consolidated anomaly reports.',
  },
  {
    keys: ['soar', 'automat', 'respond', 'response'],
    reply:
      'SOAR turns findings into action: results are bundled as STIX 2.1 and pushed straight to OpenCTI automatically, so detection becomes response without manual steps.',
  },
  {
    keys: ['opencti', 'stix', 'taxii'],
    reply:
      'ThreatOrbit integrates natively with OpenCTI over its GraphQL API. You can read indicators, check status, and push enriched STIX 2.1 bundles. TAXII and MISP export are on the roadmap.',
  },
  {
    keys: ['deploy', 'docker', 'install', 'setup', 'self-host'],
    reply:
      'Deployment is a single command: `docker compose up -d` brings up both APIs (ports 8000 and 8001). The frontend is a static Next.js export, so it hosts on any static platform — Netlify, Cloudflare Pages, Vercel, or your own CDN.',
  },
  {
    keys: ['api', 'key', 'auth', 'token'],
    reply:
      'Auth uses an X-API-Key header with two tiers: a standard user key for read access, and an admin key for write actions like fetch, STIX export, and OpenCTI push. The admin key falls back to the user key for single-key setups.',
  },
  {
    keys: ['contact', 'sales', 'demo', 'talk', 'human'],
    reply:
      'Happy to connect you. Scroll to the Contact section and send an inquiry, or email hello@threatorbit.io. For the Super SOC we usually start with a short demo.',
  },
  {
    keys: ['hi', 'hello', 'hey', 'help', 'start'],
    reply:
      'Hi, I am the Orbit Assistant. Ask me about the products (CTI, SIEM, SOAR, Super SOC), pricing, deployment, OpenCTI, or the API. What would you like to know?',
  },
]

function answer(input: string): string {
  const q = input.toLowerCase()
  let best: { score: number; reply: string } | null = null
  for (const entry of KB) {
    const score = entry.keys.reduce((s, k) => (q.includes(k) ? s + 1 : s), 0)
    if (score > 0 && (!best || score > best.score)) best = { score, reply: entry.reply }
  }
  return (
    best?.reply ??
    'Good question. I can help with our products (CTI, SIEM, SOAR, Super SOC), pricing, deployment, OpenCTI integration, and the API. Could you rephrase, or reach out via the Contact section for anything specific?'
  )
}

const SUGGESTIONS = ['What is the Super SOC?', 'How much does it cost?', 'How do I deploy it?']

export default function Chatbot() {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState('')
  const [msgs, setMsgs] = useState<Msg[]>([
    { from: 'bot', text: 'Hi, I am the Orbit Assistant. Ask me anything about ThreatOrbit.' },
  ])
  const [typing, setTyping] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [msgs, open, typing])

  const send = (text: string) => {
    const t = text.trim()
    if (!t || typing) return
    setMsgs((m) => [...m, { from: 'user', text: t }])
    setInput('')
    setTyping(true)
    setTimeout(() => {
      setTyping(false)
      setMsgs((m) => [...m, { from: 'bot', text: answer(t) }])
    }, 650)
  }

  return (
    <>
      {/* Launcher */}
      <motion.button
        onClick={() => setOpen((v) => !v)}
        initial={{ scale: 0, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ delay: 1, type: 'spring', stiffness: 200, damping: 18 }}
        whileHover={{ scale: 1.06 }}
        whileTap={{ scale: 0.94 }}
        className="fixed bottom-6 right-6 z-[80] w-14 h-14 rounded-full bg-plasma shadow-magenta-md flex items-center justify-center text-white"
        aria-label="Open assistant"
      >
        <AnimatePresence mode="wait">
          {open ? (
            <motion.span key="x" initial={{ rotate: -90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: 90, opacity: 0 }}>
              <X className="w-6 h-6" />
            </motion.span>
          ) : (
            <motion.span key="chat" initial={{ rotate: 90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: -90, opacity: 0 }}>
              <MessageSquare className="w-6 h-6" />
            </motion.span>
          )}
        </AnimatePresence>
      </motion.button>

      {/* Panel */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.96 }}
            transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
            className="fixed bottom-24 right-6 z-[80] w-[min(92vw,380px)] h-[540px] max-h-[75vh] rounded-3xl overflow-hidden glass border border-white/10 flex flex-col shadow-2xl"
          >
            {/* Header */}
            <div className="flex items-center gap-3 px-4 py-3.5 border-b border-white/8 bg-white/3">
              <Logo size={26} />
              <div className="flex-1">
                <div className="text-sm font-semibold text-white">Orbit Assistant</div>
                <div className="flex items-center gap-1.5 text-[10px] text-safe">
                  <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
                  Online
                </div>
              </div>
              <Sparkles className="w-4 h-4 text-amber" />
            </div>

            {/* Messages */}
            <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-4 space-y-3">
              {msgs.map((m, i) => (
                <div key={i} className={`flex ${m.from === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div
                    className={`max-w-[80%] rounded-2xl px-3.5 py-2.5 text-sm leading-relaxed ${
                      m.from === 'user'
                        ? 'bg-plasma text-white rounded-br-sm'
                        : 'bg-white/5 text-ink-200 border border-white/8 rounded-bl-sm'
                    }`}
                  >
                    {m.text}
                  </div>
                </div>
              ))}

              {typing && (
                <div className="flex justify-start">
                  <div className="bg-white/5 border border-white/8 rounded-2xl rounded-bl-sm px-3.5 py-3 flex items-center gap-1">
                    {[0, 1, 2].map((i) => (
                      <motion.span
                        key={i}
                        className="w-1.5 h-1.5 rounded-full bg-ink-300"
                        animate={{ opacity: [0.3, 1, 0.3], y: [0, -2, 0] }}
                        transition={{ duration: 0.9, repeat: Infinity, delay: i * 0.15 }}
                      />
                    ))}
                  </div>
                </div>
              )}

              {msgs.length <= 1 && !typing && (
                <div className="flex flex-wrap gap-2 pt-2">
                  {SUGGESTIONS.map((s) => (
                    <button
                      key={s}
                      onClick={() => send(s)}
                      className="text-[11px] px-3 py-1.5 rounded-full border border-white/10 text-ink-300 hover:text-white hover:border-magenta/30 transition-colors"
                    >
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Input */}
            <form
              onSubmit={(e) => {
                e.preventDefault()
                send(input)
              }}
              className="p-3 border-t border-white/8 flex items-center gap-2"
            >
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about ThreatOrbit..."
                className="flex-1 rounded-xl bg-white/5 border border-white/10 px-3.5 py-2.5 text-sm text-white placeholder:text-ink-600 focus:border-magenta/40 focus:outline-none transition-colors"
              />
              <button
                type="submit"
                className="w-10 h-10 rounded-xl bg-plasma text-white flex items-center justify-center shrink-0 hover:shadow-magenta-sm transition-shadow"
                aria-label="Send"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
