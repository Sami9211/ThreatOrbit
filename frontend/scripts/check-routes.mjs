#!/usr/bin/env node
/**
 * Internal-route integrity gate — the "dead hyperlinks" guard.
 *
 * A static export ships every page as a file; a link to a route that does not
 * exist 404s silently in production and never shows up in `next build`. This
 * walks the App Router tree to learn the real set of routes, then scans every
 * navigation target in the codebase (`href="/…"`, `href={'/…'}`,
 * `` href={`/…`} ``, `href: '/…'`, `link: '/…'`, and `router.push('/…')`) and
 * fails if any of them points at a path that no page serves.
 *
 * Deliberately scoped to *navigation*: it ignores `path:` keys (those document
 * backend REST endpoints in the docs pages, not app routes), external URLs,
 * and bare anchors/queries. Template literals are validated on their literal
 * prefix (everything up to the first `${`, `?`, or `#`), which is enough to
 * catch a wrong base path while tolerating a dynamic query/segment.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative } from 'node:path'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const APP = join(ROOT, 'app')

/** Every route the App Router actually serves, derived from page.tsx files. */
function discoverRoutes(dir, base = '') {
  const routes = new Set()
  for (const name of readdirSync(dir)) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) {
      // Route groups "(marketing)" and parallel "@slot" segments don't add path.
      const seg = name.startsWith('(') && name.endsWith(')') ? '' : name.startsWith('@') ? '' : name
      const childBase = seg ? `${base}/${seg}` : base
      for (const r of discoverRoutes(full, childBase)) routes.add(r)
    } else if (/^page\.(tsx|ts|jsx|js)$/.test(name)) {
      routes.add(base === '' ? '/' : base)
    }
  }
  return routes
}

const ROUTES = discoverRoutes(APP)

/** Collect candidate source files. */
function sources(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.next' || name === 'scripts') continue
    const full = join(dir, name)
    if (statSync(full).isDirectory()) sources(full, acc)
    else if (/\.(tsx|ts|jsx|js)$/.test(name)) acc.push(full)
  }
  return acc
}

// Navigation targets only. `path:` is intentionally excluded (REST-API docs).
const PATTERNS = [
  /\bhref\s*=\s*"(\/[^"]*)"/g,
  /\bhref\s*=\s*'(\/[^']*)'/g,
  /\bhref\s*=\s*\{\s*"(\/[^"]*)"\s*\}/g,
  /\bhref\s*=\s*\{\s*'(\/[^']*)'\s*\}/g,
  /\bhref\s*=\s*\{\s*`(\/[^`]*)`\s*\}/g,
  /\b(?:href|link)\s*:\s*"(\/[^"]*)"/g,
  /\b(?:href|link)\s*:\s*'(\/[^']*)'/g,
  /\b(?:href|link)\s*:\s*`(\/[^`]*)`/g,
  /\.push\(\s*"(\/[^"]*)"/g,
  /\.push\(\s*'(\/[^']*)'/g,
  /\.push\(\s*`(\/[^`]*)`/g,
]

/** Reduce a raw target to the route it navigates to, or null to skip it. */
function toRoute(raw) {
  if (raw.startsWith('//')) return null          // protocol-relative external
  // Keep only the literal prefix: drop dynamic interpolation, query, and hash.
  let p = raw.split('${')[0].split('?')[0].split('#')[0]
  if (p === '') return null                       // pure anchor/query (e.g. "/#contact" → "/")? handled below
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1)
  return p === '' ? '/' : p
}

const failures = []
let checked = 0
for (const file of sources(ROOT === APP ? APP : ROOT)) {
  if (!file.startsWith(join(ROOT, 'app')) && !file.startsWith(join(ROOT, 'components')) && !file.startsWith(join(ROOT, 'lib'))) continue
  const text = readFileSync(file, 'utf8')
  const lines = text.split('\n')
  for (const re of PATTERNS) {
    re.lastIndex = 0
    let m
    while ((m = re.exec(text)) !== null) {
      const route = toRoute(m[1])
      if (route === null) continue
      checked++
      if (!ROUTES.has(route)) {
        const line = text.slice(0, m.index).split('\n').length
        failures.push(`${relative(ROOT, file)}:${line}  →  ${m[1]}  (resolves to ${route}, no such route)`)
      }
    }
  }
}

console.log(`Route integrity: ${ROUTES.size} routes discovered, ${checked} internal links checked.`)
if (failures.length) {
  console.error(`\nDead internal links (${failures.length}):`)
  for (const f of failures) console.error(`  ✗ ${f}`)
  console.error('\nFix the link or add the route. Known routes:')
  for (const r of [...ROUTES].sort()) console.error(`    ${r}`)
  process.exit(1)
}
console.log('No dead internal links.')
