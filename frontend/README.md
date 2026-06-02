# ThreatOrbit Frontend

Marketing site for the ThreatOrbit threat-intelligence platform. Built with
Next.js 14 (App Router), TypeScript, Tailwind, Framer Motion, and a
React-Three-Fiber 3D layer.

## Stack

| Concern        | Choice |
|----------------|--------|
| Framework      | Next.js 14 App Router, **static export** (`output: 'export'`) |
| Styling        | Tailwind CSS + a small `globals.css` design layer |
| Animation      | Framer Motion (scroll, springs, layout) |
| 3D / WebGL     | `three`, `@react-three/fiber`, `@react-three/drei`, `@react-three/postprocessing` |
| Icons          | `lucide-react` |
| Smooth scroll  | `lenis` |

Static export means `next build` writes plain HTML/CSS/JS to `out/`, hostable
on any static platform (Netlify, Cloudflare Pages, Vercel, a CDN). No Node
runtime is required in production.

## Develop

```bash
npm install
npm run dev        # http://localhost:3000
npm run build      # static export → out/
npx serve out      # preview the production build locally
```

> Note: a `next dev` server can occasionally serve a nested route unstyled
> after a `.next` wipe + restart (a dev-only CSS-injection quirk). The
> production build in `out/` is always correct — verify with `npx serve out`.

## Architecture

```
app/                 routes (home, docs/*, products/*, platform/*, legal)
  layout.tsx         root layout, fonts, metadata, skip-link, grain overlay
  page.tsx           homepage section composition
  icon.svg           orbit-mark favicon
  sitemap.ts         all routes
  robots.ts          crawl rules
  not-found.tsx      branded 404
components/
  sections/          one component per homepage section
  effects/           WebGL scenes + page-level effects (see below)
  layout/            Navbar, Footer, MegaMenu
  ui/                reusable bits (TiltCard, CountUp, Chatbot, …)
lib/
  usePerf.ts         shared perf/accessibility hooks
```

### 3D scenes (`components/effects/`)

| Scene            | Where        | What |
|------------------|--------------|------|
| `HeroScene`      | Hero         | Floating polyhedra + wireframes, drifting torus knot, starfield, bloom |
| `OrbitalScene`   | ScrollStory  | Three torus rings + hex prism, scroll-driven rotation, bloom |
| `ThreatGlobe`    | GlobalThreatMap | Wireframe globe, animated attack arcs, drag-to-rotate (OrbitControls), bloom |

All three are `dynamic(..., { ssr: false })` so three.js loads in a lazy
chunk **after** first paint — initial First Load JS stays ~170 kB.

### Performance & accessibility strategy

`lib/usePerf.ts` provides:

- `usePerfProfile()` → `{ prefersReducedMotion, isLowPower }`
- `useInViewport()` → `{ ref, visible }`

Every WebGL canvas uses these to:

- **Pause off-screen** — `frameloop` drops to `'demand'` when not visible.
- **Degrade on low-power devices** — fewer objects, no bloom, antialias off, capped DPR.
- **Respect reduced-motion** — autonomous animation freezes (scroll/drag still work).
- **Auto-adapt** — drei `AdaptiveDpr` + `PerformanceMonitor` lower resolution under load.

CSS-level: `prefers-reduced-motion` kills all transitions/animations site-wide,
`color-scheme: dark` keeps native form controls dark, `:focus-visible` rings
for keyboard users, and a skip-to-content link.

### Live-data sections

Several sections simulate live telemetry (client-only, paused off-screen):
streaming IOC feed (ThreatIntel), line-by-line log scanner (LogAnalysis),
rolling chart + ticking KPIs (DashboardPreview), cycling STIX flow (OpenCTI),
live attack counters (GlobalThreatMap). All seed from deterministic static
data to avoid hydration mismatch, then randomize after mount.

## Design system (Plasma Noir)

```
bg #0A0612   magenta #FF2E97   violet #7A3CFF   amber #FFB23E
teal #2DD4BF  threat #FF4D6D    safe #34F5C5
```

Fonts: Space Grotesk (display), Inter (body), JetBrains Mono (code).
