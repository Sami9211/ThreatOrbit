/**
 * Shared motion tokens + variants for the whole app.
 *
 * Before this, 84 files each hand-rolled their own framer-motion durations and
 * easings, so timings drifted and nothing was consistent. Import from here so
 * every animation shares one easing curve and a small duration scale, and the
 * "smooth animations everywhere" goal reads as one system rather than dozens of
 * one-offs.
 *
 * Reduced motion is handled globally by `<MotionConfig reducedMotion="user">`
 * at the app root (see app/providers.tsx). Per framer's accessibility model
 * that drops the *movement* (transform/layout — the vestibular
 * motion-sickness trigger) while keeping harmless opacity fades, so a user who
 * asks for reduced motion gets a still, non-moving fade rather than sliding
 * content — and individual components don't each need to branch on
 * `useReducedMotion()`.
 */
import type { Variants, Transition } from 'framer-motion'

/** One easing curve for the whole app: a soft easeOut that decelerates into
 *  place (reads as "premium/settled", never bouncy or linear). */
export const EASE = [0.22, 1, 0.36, 1] as const

/** Duration scale (seconds). Keep animations short — motion should feel
 *  responsive, not showy. */
export const DUR = {
  fast: 0.15,   // micro-interactions: hover, press, small toggles
  base: 0.25,   // the default for most enters/exits
  slow: 0.4,    // larger surfaces: drawers, page transitions
} as const

export const transition = (duration: number = DUR.base): Transition => ({
  duration, ease: EASE,
})

/** Fade + gentle rise — the default "content appears" animation. */
export const fadeInUp: Variants = {
  hidden: { opacity: 0, y: 8 },
  show: { opacity: 1, y: 0, transition: transition() },
}

/** Plain fade, no movement — for overlays/backdrops. */
export const fadeIn: Variants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: transition() },
}

/** Scale up from slightly small — for popovers, badges, modal cards. */
export const scaleIn: Variants = {
  hidden: { opacity: 0, scale: 0.96 },
  show: { opacity: 1, scale: 1, transition: transition() },
}

/** Right-side drawer slide-in. */
export const drawerRight: Variants = {
  hidden: { opacity: 0, x: '100%' },
  show: { opacity: 1, x: 0, transition: { duration: DUR.slow, ease: EASE } },
  exit: { opacity: 0, x: '100%', transition: { duration: DUR.base, ease: EASE } },
}

/** Stagger container: children animate in sequence. Pair with `listItem`. */
export const listContainer = (stagger = 0.04): Variants => ({
  hidden: {},
  show: { transition: { staggerChildren: stagger } },
})

export const listItem: Variants = {
  hidden: { opacity: 0, y: 6 },
  show: { opacity: 1, y: 0, transition: transition(DUR.fast) },
}

/** Per-route page enter (dashboard). Keyed remount replays it on navigation. */
export const pageEnter: Variants = {
  hidden: { opacity: 0, y: 6 },
  show: { opacity: 1, y: 0, transition: { duration: DUR.base, ease: EASE } },
}

/** Hover/press micro-interaction for cards and tiles: a subtle lift on hover,
 *  a slight settle on press. Spread onto a motion element:
 *  `<motion.div {...hoverLift}>`. The gesture transitions live inside the
 *  targets (not a top-level `transition` prop) so this composes with elements
 *  that set their own enter transition. */
export const hoverLift = {
  whileHover: { y: -2, transition: transition(DUR.fast) },
  whileTap: { scale: 0.98, transition: transition(DUR.fast) },
} as const
