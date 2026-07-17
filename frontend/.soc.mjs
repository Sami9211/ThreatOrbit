import { chromium } from 'playwright'
const OUT = '/tmp/claude-0/-home-user-ThreatOrbit-V2/25d048c0-5b53-5954-a35b-d9bfd0230f38/scratchpad'
const { token, user } = await (await fetch('http://127.0.0.1:8002/auth/login', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'admin@threatorbit.space', password: 'ChangeMe123!' }),
})).json()
const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' })
const page = await (await browser.newContext({ viewport: { width: 1440, height: 1000 } })).newPage()
await page.addInitScript(([t, u]) => {
  localStorage.setItem('to_token', t)
  localStorage.setItem('to_user', JSON.stringify(u))
  localStorage.setItem('to-experience-mode', 'power')
}, [token, user])
await page.goto('http://localhost:3000/dashboard/soc/', { waitUntil: 'load', timeout: 30000 })
await page.waitForTimeout(3500)
await page.screenshot({ path: `${OUT}/soc-${process.argv[2] || 'demo'}.png` })
console.log('shot taken')
await browser.close()
