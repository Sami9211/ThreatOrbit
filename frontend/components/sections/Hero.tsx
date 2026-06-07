'use client'

import { useEffect, useRef, useState } from 'react'
import { motion, useScroll, useTransform, useMotionValue, useSpring, MotionValue } from 'framer-motion'
import { ArrowRight, Terminal, Shield, Zap } from 'lucide-react'
import dynamic from 'next/dynamic'
import MagneticButton from '@/components/ui/MagneticButton'
import CountUp from '@/components/ui/CountUp'

import ScenePlaceholder from '@/components/effects/ScenePlaceholder'

const HeroScene = dynamic(() => import('@/components/effects/HeroScene'), {
  ssr: false,
  loading: () => <ScenePlaceholder />,
})

const TERMINAL_LINES = [
  { text: '> Ingesting OSINT feeds...', color: 'text-magenta' },
  { text: '  [OTX] 1,247 IOCs synced', color: 'text-ink-300' },
  { text: '  [abuse.ch] 843 malware hashes', color: 'text-ink-300' },
  { text: '> Running anomaly detectors...', color: 'text-magenta' },
  { text: '  [ML] Baseline established', color: 'text-ink-300' },
  { text: '  [PATTERN] 3 threats flagged', color: 'text-threat' },
  { text: '> Pushing to OpenCTI...', color: 'text-magenta' },
  { text: '  [STIX 2.1] Bundle exported', color: 'text-safe' },
]

function TerminalWidget() {
  const [visibleLines, setVisibleLines] = useState(0)

  useEffect(() => {
    if (visibleLines >= TERMINAL_LINES.length) return
    const t = setTimeout(() => setVisibleLines((v) => v + 1), 420)
    return () => clearTimeout(t)
  }, [visibleLines])

  return (
    <div className="glass border border-white/8 rounded-xl p-4 font-mono text-xs leading-relaxed min-h-[190px]">
      <div className="flex items-center gap-1.5 mb-3">
        <span className="w-2.5 h-2.5 rounded-full bg-threat/80" />
        <span className="w-2.5 h-2.5 rounded-full bg-amber/80" />
        <span className="w-2.5 h-2.5 rounded-full bg-safe/80" />
        <span className="ml-2 text-ink-500 text-[10px]">threatorbit · threat_api</span>
      </div>
      {TERMINAL_LINES.slice(0, visibleLines).map((line, i) => (
        <div key={i} className={`${line.color} transition-opacity duration-300`}>
          {line.text}
        </div>
      ))}
      {visibleLines < TERMINAL_LINES.length && <span className="text-magenta cursor-blink" />}
    </div>
  )
}

// Floating 3D depth orb — shifts with cursor parallax at a given depth factor
function DepthOrb({
  cx, cy, size, color, depth, mouseX, mouseY,
}: {
  cx: string; cy: string; size: number; color: string; depth: number
  mouseX: MotionValue<number>
  mouseY: MotionValue<number>
}) {
  const x = useSpring(useTransform(mouseX, [-0.5, 0.5], [-depth, depth]), { stiffness: 80, damping: 20 })
  const y = useSpring(useTransform(mouseY, [-0.5, 0.5], [-depth * 0.6, depth * 0.6]), { stiffness: 80, damping: 20 })
  return (
    <motion.div
      className="absolute rounded-full pointer-events-none"
      style={{
        left: cx, top: cy,
        width: size, height: size,
        background: `radial-gradient(circle, ${color}22 0%, ${color}00 70%)`,
        filter: 'blur(2px)',
        x, y,
        translateX: '-50%',
        translateY: '-50%',
      }}
    />
  )
}

export default function Hero() {
  const sectionRef = useRef<HTMLElement>(null)
  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ['start start', 'end start'],
  })
  const contentY = useTransform(scrollYProgress, [0, 1], [0, 120])
  const contentOpacity = useTransform(scrollYProgress, [0, 0.7], [1, 0])
  const bgScale = useTransform(scrollYProgress, [0, 1], [1, 1.15])

  // Mouse tracking for 3D depth layers
  const mouseX = useMotionValue(0)
  const mouseY = useMotionValue(0)

  // Cache the section rect so we don't force a layout reflow on every mousemove
  // (reading getBoundingClientRect per-move is a known INP/jank source). We
  // refresh it on mount, resize, and scroll instead.
  const rectRef = useRef<DOMRect | null>(null)
  useEffect(() => {
    const measure = () => { rectRef.current = sectionRef.current?.getBoundingClientRect() ?? null }
    measure()
    window.addEventListener('resize', measure)
    window.addEventListener('scroll', measure, { passive: true })
    return () => {
      window.removeEventListener('resize', measure)
      window.removeEventListener('scroll', measure)
    }
  }, [])

  const handleMouseMove = (e: React.MouseEvent<HTMLElement>) => {
    const r = rectRef.current
    if (!r || r.width === 0) return
    mouseX.set((e.clientX - r.left) / r.width - 0.5)
    mouseY.set((e.clientY - r.top) / r.height - 0.5)
  }

  return (
    <section
      ref={sectionRef}
      className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden"
      onMouseMove={handleMouseMove}
    >
      {/* 3D floating geometry background — Three.js + bloom (decorative) */}
      <motion.div style={{ scale: bgScale }} className="absolute inset-0 z-0 opacity-85" aria-hidden>
        <HeroScene mouseX={mouseX} mouseY={mouseY} />
      </motion.div>

      {/* 3D depth orbs — each at different z-depth, parallaxes at different rates */}
      <DepthOrb cx="15%" cy="25%" size={320} color="#FF2E97" depth={28} mouseX={mouseX} mouseY={mouseY} />
      <DepthOrb cx="80%" cy="70%" size={260} color="#7A3CFF" depth={18} mouseX={mouseX} mouseY={mouseY} />
      <DepthOrb cx="65%" cy="20%" size={180} color="#FFB23E" depth={36} mouseX={mouseX} mouseY={mouseY} />
      <DepthOrb cx="20%" cy="75%" size={200} color="#2DD4BF" depth={22} mouseX={mouseX} mouseY={mouseY} />

      {/* Plasma vignettes */}
      <div className="absolute inset-0 bg-radial-magenta z-0 pointer-events-none" />
      <div className="absolute inset-0 bg-radial-violet z-0 pointer-events-none" />

      {/* Scan line */}
      <div className="scan-line z-10" />

      <motion.div
        style={{ y: contentY, opacity: contentOpacity }}
        className="relative z-10 max-w-7xl mx-auto px-6 py-28 grid lg:grid-cols-2 gap-16 items-center"
      >
        {/* Left */}
        <div>
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-magenta/20 bg-magenta/5 mb-7"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-magenta animate-pulse" />
            <span className="text-xs font-medium text-magenta tracking-wide">
              Enterprise Threat Intelligence Platform
            </span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 28 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2, ease: [0.22, 1, 0.36, 1] }}
            className="font-display text-5xl md:text-6xl xl:text-7xl font-bold leading-[1.08] tracking-tight text-white mb-6"
          >
            Detect.
            <br />
            <span className="text-gradient-animate">Analyze.</span>
            <br />
            Neutralize.
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.35 }}
            className="text-lg text-ink-300 max-w-lg leading-relaxed mb-10"
          >
            Ingest OSINT intelligence feeds, detect log anomalies with ML, and push enriched STIX
            bundles to OpenCTI, all through one unified API.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.45 }}
            className="flex flex-wrap gap-4"
          >
            <MagneticButton
              href="/signup"
              className="px-6 py-3 rounded-xl bg-plasma text-white font-semibold text-sm transition-shadow duration-300 hover:shadow-magenta-md"
            >
              Start for Free
              <ArrowRight className="w-4 h-4" />
            </MagneticButton>
            <MagneticButton
              href="/docs"
              className="px-6 py-3 rounded-xl glass border border-white/10 text-ink-200 font-medium text-sm hover:border-magenta/30 hover:text-white transition-colors duration-300"
            >
              <Terminal className="w-4 h-4" />
              View API Docs
            </MagneticButton>
          </motion.div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.7 }}
            className="flex items-center gap-6 mt-10"
          >
            {[
              { icon: Shield, label: 'STIX 2.1 native' },
              { icon: Zap, label: 'Sub-second analysis' },
              { icon: Terminal, label: 'Open API' },
            ].map(({ icon: Icon, label }) => (
              <div key={label} className="flex items-center gap-1.5 text-xs text-ink-400">
                <Icon className="w-3.5 h-3.5 text-magenta/60" strokeWidth={1.5} />
                {label}
              </div>
            ))}
          </motion.div>
        </div>

        {/* Right — floats toward camera relative to cursor */}
        <motion.div
          initial={{ opacity: 0, x: 40 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.9, delay: 0.4, ease: [0.22, 1, 0.36, 1] }}
          style={{
            x: useSpring(useTransform(mouseX, [-0.5, 0.5], [10, -10]), { stiffness: 100, damping: 25 }),
            y: useSpring(useTransform(mouseY, [-0.5, 0.5], [8, -8]),  { stiffness: 100, damping: 25 }),
          }}
          className="flex flex-col gap-4"
        >
          <TerminalWidget />

          <div className="grid grid-cols-3 gap-3">
            <StatCard value={2.1} suffix="M+" decimals={1} label="IOCs tracked" color="text-magenta" />
            <StatCard value={99.4} suffix="%" decimals={1} label="Detection rate" color="text-safe" />
            <StatCard value={50} prefix="<" suffix="ms" label="API latency" color="text-violet" />
          </div>
        </motion.div>
      </motion.div>

      {/* Scroll indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.2 }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2"
      >
        <span className="text-[10px] text-ink-500 tracking-widest uppercase">Scroll</span>
        <div className="w-px h-8 bg-gradient-to-b from-magenta/50 to-transparent animate-pulse" />
      </motion.div>
    </section>
  )
}

function StatCard({
  value,
  suffix,
  prefix,
  decimals,
  label,
  color,
}: {
  value: number
  suffix?: string
  prefix?: string
  decimals?: number
  label: string
  color: string
}) {
  return (
    <div className="glass border border-white/6 rounded-xl p-4 text-center">
      <div className={`font-display text-xl font-bold ${color}`}>
        <CountUp value={value} suffix={suffix} prefix={prefix} decimals={decimals} />
      </div>
      <div className="text-[10px] text-ink-500 mt-0.5">{label}</div>
    </div>
  )
}
