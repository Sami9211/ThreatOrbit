# ThreatOrbit Frontend

Marketing site **and operator dashboard** for the ThreatOrbit
threat-intelligence platform. Built with Next.js 16 (App Router), TypeScript,
Tailwind, Framer Motion, and a React-Three-Fiber 3D layer.

## Stack

| Concern        | Choice |
|----------------|--------|
| Framework      | Next.js 16 App Router, **Node SSR** (`next start`) |
| Styling        | Tailwind CSS 4 (CSS-first `@theme` in `globals.css`) + a small design layer |
| Animation      | Framer Motion (scroll, springs, layout) |
| 3D / WebGL     | `three`, `@react-three/fiber`, `@react-three/drei`, `@react-three/postprocessing` |
| Icons          | `lucide-react` |
| Smooth scroll  | `lenis` |

`next build` compiles the app to `.next` and `next start` serves it as a **Node
SSR server** (deployable on Vercel or any Node host). The security headers
(CSP, HSTS, X-Frame-Options, …) are applied by the Next server itself via
`next.config.mjs headers()` - so every host enforces them, not just a fronting
proxy. (This replaced the earlier `output: 'export'` static build, whose
`out/` bundle silently ignored `headers()`.)

## Develop

```bash
npm install
npm run dev        # http://localhost:3000 (dev server)
npm run build      # production build → .next
npm run start      # serve the SSR production build (next start)
```

## Test

```bash
npx tsc --noEmit         # typecheck (CI-enforced)
npm run lint             # eslint, errors CI-enforced (flat config,
                         #   eslint-config-next core-web-vitals + typescript)
npm run check:routes     # no dead internal links/anchors (CI-enforced)
npx playwright test      # e2e: auth, workflows, data-honesty fences,
                         #   axe-core a11y, responsive, self-health card
npm run check:live       # crawl every dashboard route against a RUNNING
                         #   stack (./linux-start.sh) and report console
                         #   errors, failed API calls, and body smells
```

The e2e suite runs against a production build plus the dashboard API - CI
boots both (see `.github/workflows/e2e.yml`); locally set `E2E_BASE_URL` to
point at an already-running instance, or let the `webServer` hook run
`next start` for you.

> Note: a `next dev` server can occasionally serve a nested route unstyled
> after a `.next` wipe + restart (a dev-only CSS-injection quirk). The
> production SSR build is always correct - verify with `npm run build && npm run start`.

## Architecture

```
app/                 routes (home, docs/*, products/*, platform/*, legal)
  layout.tsx         root layout, fonts, metadata, skip-link, grain overlay
  page.tsx           homepage section composition
  dashboard/         operator dashboard (see below)
  icon.svg           orbit-mark favicon
  sitemap.ts         all routes
  robots.ts          crawl rules
  not-found.tsx      branded 404
components/
  dashboard/         AuthGuard (JWT route protection for /dashboard/**)
  sections/          one component per homepage section
  effects/           WebGL scenes + page-level effects (see below)
  layout/            Navbar, Footer, MegaMenu
  ui/                reusable bits (TiltCard, CountUp, Chatbot, …)
lib/
  api.ts             typed Dashboard API client (JWT from localStorage,
                     automatic snake_case → camelCase response mapping)
  auth-context.tsx   login/session state backed by the Dashboard API
  usePerf.ts         shared perf/accessibility hooks
```

### Operator dashboard (`app/dashboard/**`)

30 pages - overview, the SOC command view, SIEM (queue/analytics/rules/
sources/hunt/entities/ATT&CK coverage), SOAR (cases/playbooks/integrations/
metrics), CTI (overview/actors/hunt), assets (inventory/network/vulns),
dark-web monitoring, feeds (overview/sources/import/imports), the IntelScope
scanner, the admin console, account settings, and config (general incl. the
live System Health card/API keys/users/data sources). Every page fetches
live data from the Dashboard API (`:8002`) on mount and falls back to built-in
deterministic demo data when the API is unreachable, so the dashboard
remains fully browsable even when the backend is down. Mutations (alert triage, rule toggles,
playbook runs, feed toggles, user role/status changes, API keys, IOC imports,
risk recompute, settings) persist via the API with optimistic UI and rollback
on failure. Point at a non-default API with `NEXT_PUBLIC_API_URL`.

### 3D scenes (`components/effects/`)

| Scene             | Where           | What |
|-------------------|-----------------|------|
| `HeroScene`       | Hero            | Floating polyhedra + wireframes, drifting torus knot, starfield, bloom |
| `OrbitalScene`    | ScrollStory     | A glowing **planet circled by rings of orbiting dots** (tilted dot-orbits + moons), scroll-driven rotation, bloom |
| `ThreatGlobe`     | GlobalThreatMap | Wireframe globe w/ lat-lon grid + pulsing city hotspots, animated attack arcs, drag-to-rotate (OrbitControls), bloom |
| `IOCNetworkScene` | IOCNetwork      | Clustered IOC graph - type-coloured nodes + correlation edges, slow auto-rotate, bloom |

All four are `dynamic(..., { ssr: false })` so three.js loads in a lazy
chunk **after** first paint - initial First Load JS stays ~176 kB.

### Performance & accessibility strategy

`lib/usePerf.ts` provides:

- `usePerfProfile()` → `{ prefersReducedMotion, isLowPower }`
- `useInViewport()` → `{ ref, visible }`

Every WebGL canvas uses these to:

- **Pause off-screen** - `frameloop` drops to `'demand'` when not visible.
- **Degrade on low-power devices** - fewer objects, no bloom, antialias off, capped DPR (≤1.5).
- **Runtime FPS degradation** - drei `PerformanceMonitor`'s `onDecline` drops a
  `degraded` flag that kills bloom and pins DPR to 1. This catches the case a
  static heuristic misses: a many-core laptop with a *weak GPU* (CPU cores ≠ GPU
  power). When bloom is off, emissive materials are brightened so shapes stay visible.
- **Respect reduced-motion** - autonomous animation freezes (scroll/drag still work).
- **Auto-adapt** - drei `AdaptiveDpr` + `PerformanceMonitor` lower resolution under load.

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
