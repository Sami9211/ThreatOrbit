'use client'

import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import Logo from '@/components/ui/Logo'

/**
 * Brief brand intro shown once per session on first paint, then fades away.
 * Skips entirely under prefers-reduced-motion or if already shown this session.
 */
export default function Preloader() {
  const [show, setShow] = useState(false)

  // Decide whether to show (idempotent — safe under StrictMode double-invoke)
  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const seen = sessionStorage.getItem('to-intro')
    if (!reduce && !seen) setShow(true)
  }, [])

  // Hide timer lives in its own effect keyed on `show`, so a StrictMode
  // cleanup that clears the timeout always reschedules a fresh one.
  useEffect(() => {
    if (!show) return
    sessionStorage.setItem('to-intro', '1')
    const t = setTimeout(() => setShow(false), 1700)
    return () => clearTimeout(t)
  }, [show])

  return (
    <AnimatePresence>
      {show && (
        <motion.div
          className="fixed inset-0 z-[200] flex flex-col items-center justify-center bg-bg"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.6, ease: 'easeInOut' }}
        >
          <div className="absolute inset-0 plasma-mesh opacity-40 pointer-events-none" />
          <motion.div
            initial={{ scale: 0.6, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            className="relative"
          >
            <Logo size={84} />
          </motion.div>
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.5 }}
            className="mt-6 font-display font-semibold text-xl"
          >
            <span className="text-white">Threat</span>
            <span className="text-gradient-magenta">Orbit</span>
          </motion.div>
          <motion.div
            initial={{ scaleX: 0 }}
            animate={{ scaleX: 1 }}
            transition={{ delay: 0.3, duration: 1.1, ease: 'easeInOut' }}
            className="mt-5 h-px w-32 origin-left bg-gradient-to-r from-magenta via-violet to-amber"
          />
        </motion.div>
      )}
    </AnimatePresence>
  )
}
