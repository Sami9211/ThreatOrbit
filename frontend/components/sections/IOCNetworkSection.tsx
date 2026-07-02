'use client'

import { useRef, useState, useEffect } from 'react'
import dynamic from 'next/dynamic'
import { motion, useInView, AnimatePresence } from 'framer-motion'
import { Network, Activity, RefreshCw } from 'lucide-react'
import { usePerfProfile } from '@/lib/usePerf'

import ScenePlaceholder from '@/components/effects/ScenePlaceholder'

const IOCNetworkScene = dynamic(() => import('@/components/effects/IOCNetworkScene'), {
  ssr: false,
  loading: () => <ScenePlaceholder />,
})
// Preload the IOCNetworkScene chunk before the section is reached so the user never
// waits seconds for the WebGL canvas to appear (same pattern as ScrollStory).
if (typeof window !== 'undefined') {
  const preload = () => import('@/components/effects/IOCNetworkScene')
  if (document.readyState === 'complete') {
    setTimeout(preload, 800)
  } else {
    window.addEventListener('load', () => setTimeout(preload, 800), { once: true })
  }
}


const IOC_TYPES = [
  { label: 'IP Address',   color: '#FF2E97', dot: 'bg-magenta'  },
  { label: 'Domain',       color: '#7A3CFF', dot: 'bg-violet'   },
  { label: 'File Hash',    color: '#FFB23E', dot: 'bg-amber'    },
  { label: 'Malicious URL',color: '#2DD4BF', dot: 'bg-teal'     },
  { label: 'Threat Actor', color: '#FF4D6D', dot: 'bg-threat'   },
]

const LIVE_EVENTS = [
  'New IP correlated - 3 domains linked',
  'Hash cluster merged - 7 samples',
  'Threat actor TTP mapped to 12 IOCs',
  'Domain DGA pattern detected - 18 children',
  'C2 infrastructure pivoted - 5 IPs',
  'Malware family attributed to actor',
  'URL redirect chain unrolled - depth 4',
  'AS correlation: 9 IPs same netblock',
]

export default function IOCNetworkSection() {
  const ref       = useRef<HTMLDivElement>(null)
  const inView    = useInView(ref, { once: true, margin: '-80px' })
  const liveRef   = useRef<HTMLDivElement>(null)
  const liveView  = useInView(liveRef, { margin: '-40px' })
  const { prefersReducedMotion } = usePerfProfile()

  const [eventIdx,   setEventIdx]   = useState(0)
  const [totalLinks, setTotalLinks] = useState(1284)
  const [totalNodes, setTotalNodes] = useState(847)

  useEffect(() => {
    if (prefersReducedMotion || !liveView) return
    const t = setInterval(() => {
      setEventIdx(i => (i + 1) % LIVE_EVENTS.length)
      setTotalLinks(n => n + Math.floor(Math.random() * 4 + 1))
      setTotalNodes(n => n + (Math.random() > 0.4 ? 1 : 0))
    }, 2400)
    return () => clearInterval(t)
  }, [prefersReducedMotion, liveView])

  return (
    <section ref={ref} className="relative py-28 bg-bg overflow-hidden">
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-0 w-[400px] h-[400px] rounded-full bg-violet/5 blur-[100px]" />
        <div className="absolute bottom-1/4 right-0 w-[350px] h-[350px] rounded-full bg-magenta/4 blur-[80px]" />
      </div>

      <div className="relative site-container">
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7 }}
          className="text-center mb-14"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-violet/20 bg-violet/5 mb-5">
            <Network className="w-3 h-3 text-violet" />
            <span className="text-xs text-violet tracking-wide">Threat Intelligence Graph</span>
          </div>
          <h2 className="font-display text-4xl md:text-5xl font-bold text-white leading-tight">
            Every IOC has a network.
            <br />
            <span className="text-gradient-magenta">ThreatOrbit maps it.</span>
          </h2>
          <p className="text-ink-400 mt-4 max-w-xl mx-auto text-sm">
            Indicators don&apos;t exist in isolation. IPs share infrastructure with domains. Hashes belong to
            malware families. Actors leave fingerprints across all of them.
          </p>
        </motion.div>

        <div ref={liveRef} className="grid lg:grid-cols-[1fr_1.6fr] gap-10 items-center">
          {/* Left stats + legend */}
          <motion.div
            initial={{ opacity: 0, x: -24 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.7, delay: 0.1 }}
            className="space-y-5"
          >
            {/* Counters */}
            <div className="grid grid-cols-2 gap-4">
              <div className="glass border border-white/8 rounded-2xl p-5">
                <div className="flex items-center gap-2 mb-2">
                  <Network className="w-4 h-4 text-violet" strokeWidth={1.5} />
                  <span className="text-[11px] text-ink-400 uppercase tracking-wider">Graph Nodes</span>
                </div>
                <div className="font-display text-2xl font-bold text-white tabular-nums">
                  {totalNodes.toLocaleString()}
                </div>
              </div>
              <div className="glass border border-white/8 rounded-2xl p-5">
                <div className="flex items-center gap-2 mb-2">
                  <Activity className="w-4 h-4 text-magenta" strokeWidth={1.5} />
                  <span className="text-[11px] text-ink-400 uppercase tracking-wider">Correlations</span>
                </div>
                <div className="font-display text-2xl font-bold text-magenta tabular-nums">
                  {totalLinks.toLocaleString()}
                </div>
              </div>
            </div>

            {/* Type legend */}
            <div className="glass border border-white/8 rounded-2xl p-5">
              <div className="text-[11px] text-ink-400 uppercase tracking-wider mb-4">IOC Type Legend</div>
              <div className="space-y-2.5">
                {IOC_TYPES.map(t => (
                  <div key={t.label} className="flex items-center gap-3">
                    <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${t.dot}`} />
                    <span className="text-sm text-ink-300 flex-1">{t.label}</span>
                    <span className="w-4 h-4 rounded-full opacity-60" style={{ background: t.color, boxShadow: `0 0 8px ${t.color}` }} />
                  </div>
                ))}
              </div>
            </div>

            {/* Live event feed */}
            <div className="glass border border-white/8 rounded-2xl p-5">
              <div className="flex items-center gap-2 mb-3">
                <span className="w-2 h-2 rounded-full bg-magenta animate-pulse" />
                <span className="text-[11px] text-ink-400 uppercase tracking-wider">Live Correlations</span>
              </div>
              <div className="h-8 overflow-hidden relative">
                <AnimatePresence mode="wait">
                  <motion.p
                    key={eventIdx}
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -12 }}
                    transition={{ duration: 0.4 }}
                    className="text-xs text-ink-300 font-mono absolute"
                  >
                    <RefreshCw className="inline w-3 h-3 mr-1.5 text-violet" />
                    {LIVE_EVENTS[eventIdx]}
                  </motion.p>
                </AnimatePresence>
              </div>
            </div>
          </motion.div>

          {/* 3D Network Graph */}
          <motion.div
            initial={{ opacity: 0, scale: 0.92 }}
            animate={inView ? { opacity: 1, scale: 1 } : {}}
            transition={{ duration: 0.9, delay: 0.15, ease: [0.22, 1, 0.36, 1] }}
            className="relative aspect-square w-full max-w-[520px] mx-auto"
          >
            <IOCNetworkScene />
          </motion.div>
        </div>
      </div>
    </section>
  )
}
