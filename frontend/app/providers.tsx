'use client'

import { MotionConfig } from 'framer-motion'
import { AuthProvider } from '@/lib/auth-context'

export default function Providers({ children }: { children: React.ReactNode }) {
  // reducedMotion="user" makes every framer-motion animation in the app honor
  // the OS "reduce motion" setting automatically, so individual components
  // don't each need to branch on it (the CSS @media rule only covers CSS
  // animations/transitions, not framer's JS-driven ones).
  return (
    <MotionConfig reducedMotion="user">
      <AuthProvider>{children}</AuthProvider>
    </MotionConfig>
  )
}
