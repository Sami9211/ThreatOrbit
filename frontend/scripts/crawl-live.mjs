// Live-mode dashboard crawl: visit every route, collect runtime problems.
import { chromium } from 'playwright'

const exe = process.env.PW_EXECUTABLE_PATH || '/opt/pw-browsers/chromium'
const BASE = 'http://localhost:3000'
const API = 'http://localhost:8002'

const ROUTES = [
  '/dashboard', '/dashboard/soc',
  '/dashboard/siem', '/dashboard/siem/rules', '/dashboard/siem/sources',
  '/dashboard/siem/hunt', '/dashboard/siem/entities', '/dashboard/siem/attack',
  '/dashboard/soar', '/dashboard/soar/playbooks', '/dashboard/soar/integrations',
  '/dashboard/soar/metrics',
  '/dashboard/cti', '/dashboard/cti/actors', '/dashboard/cti/hunt',
  '/dashboard/assets', '/dashboard/assets/network', '/dashboard/assets/vulns',
  '/dashboard/darkweb', '/dashboard/feeds', '/dashboard/feeds/sources',
  '/dashboard/feeds/import', '/dashboard/scanner',
  '/dashboard/config', '/dashboard/config/api', '/dashboard/config/users',
  '/dashboard/config/sources',
]

const { token, user } = await (await fetch(API + '/auth/login', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'admin@threatorbit.space', password: 'ChangeMe123!' }),
})).json()

const browser = await chromium.launch({ executablePath: exe })
const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 } })
const page = await ctx.newPage()
await page.addInitScript(([t, u]) => {
  localStorage.setItem('to_token', t)
  localStorage.setItem('to_user', JSON.stringify(u))
  localStorage.setItem('to-experience-mode', 'power')   // surface everything
}, [token, user])

const findings = []
let current = ''
page.on('pageerror', (e) => findings.push({ route: current, kind: 'pageerror', detail: String(e.message).slice(0, 200) }))
page.on('console', (m) => {
  const t = m.text()
  if (m.type() === 'error' && !/WebSocket|webpack-hmr|favicon/.test(t))
    findings.push({ route: current, kind: 'console', detail: t.slice(0, 200) })
})
page.on('response', (r) => {
  if (r.url().includes(':8002') && r.status() >= 400)
    findings.push({ route: current, kind: `http ${r.status()}`, detail: r.url().replace(API, '').slice(0, 140) })
})

for (const route of ROUTES) {
  current = route
  const before = findings.length
  try {
    // 'load' + a fixed settle beats 'networkidle': polling/SSE pages never go idle
    await page.goto(BASE + route, { waitUntil: 'load', timeout: 20000 })
  } catch {
    findings.push({ route, kind: 'nav-timeout', detail: 'page load exceeded 20s' })
  }
  await page.waitForTimeout(2500)   // let on-mount API fetches land
  const body = await page.locator('body').innerText().catch(() => '')
  for (const smell of ['undefined', 'NaN', '[object Object]']) {
    // whole-word-ish check to avoid false hits inside normal words
    const re = new RegExp(`(^|[\\s:>])${smell.replace(/[[\]]/g, '\\$&')}($|[\\s<.,)])`)
    if (re.test(body)) findings.push({ route, kind: 'body-smell', detail: smell })
  }
  // stream progress so partial output survives an interrupted run
  console.log(`${route}: ${findings.length - before} finding(s)`)
  for (const f of findings.slice(before)) console.log('  ' + JSON.stringify(f))
}

console.log(`\nTOTAL: ${findings.length} findings across ${ROUTES.length} routes`)
await browser.close()
process.exit(findings.length ? 1 : 0)
