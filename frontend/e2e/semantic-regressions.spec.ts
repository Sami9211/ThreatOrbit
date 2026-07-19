import { test, expect, ADMIN } from './fixtures'

/**
 * Semantic UX regression fence - the checks a structural crawl can't make.
 *
 * A dead-link / a11y crawl proves a page returns 200 and has a landmark; it
 * cannot prove that an *action carried its context*, that a hand-off actually
 * ran, or that a value is honestly labelled. Each test here pins a behavioural
 * guarantee this codebase makes - the kind of thing that silently rots when a
 * refactor drops a query-param handler or a provenance label.
 */
const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8002'

async function apiToken(request: any): Promise<string> {
  const r = await request.post(`${API}/auth/login`, {
    data: { email: ADMIN.email, password: ADMIN.password },
  })
  return (await r.json()).token
}

test.describe('Semantic guarantees a crawl would miss', () => {
  test('CVE → IntelScope hand-off pre-populates and auto-runs the scan', async ({ authedPage: page }) => {
    // The deep link a CVE surface builds: value + type=cve + run=1. A crawl
    // hitting /dashboard/scanner with no params never exercises the auto-run,
    // so this pins that the scanner honours it end-to-end.
    await page.goto('/dashboard/scanner?value=CVE-2024-3094&type=cve&run=1')
    // The query is pre-filled (cve isn't a UI tab, so the input keeps the
    // default url-type placeholder while carrying the CVE value)...
    await expect(page.getByPlaceholder('https://example.com/path'))
      .toHaveValue('CVE-2024-3094', { timeout: 20_000 })
    // ...and the scan actually ran: the result card only mounts once a scan
    // resolves, so its presence proves auto-run (not just a pre-filled form).
    await expect(page.getByText('Threat-Intel Record')).toBeVisible({ timeout: 20_000 })
  })

  test('ATT&CK ?technique=<id> opens that technique\'s coverage drawer', async ({ authedPage: page }) => {
    // Entity-risk technique badges deep-link here; the drawer must open on the
    // named technique, not just land on the matrix.
    await page.goto('/dashboard/siem/attack')
    const techId = page.getByText(/^T\d{4}(\.\d+)?$/).first()
    await expect(techId).toBeVisible({ timeout: 20_000 })
    const tid = (await techId.textContent())?.trim()
    test.skip(!tid, 'no ATT&CK techniques rendered')

    await page.goto(`/dashboard/siem/attack?technique=${tid}`)
    // The MITRE reference link lives ONLY in the technique drawer, so seeing it
    // proves the deep-link opened the right cell's detail.
    await expect(page.getByText('MITRE ATT&CK reference')).toBeVisible({ timeout: 15_000 })
  })

  test('a stored indicator scan classifies its provenance', async ({ authedPage: page, request }) => {
    // Provenance honesty (engine-derived vs feed/NVD): scanning a real stored
    // indicator must surface a Provenance classification, not just a raw source
    // string a reader could mistake for an authoritative feed.
    const token = await apiToken(request)
    const iocs = await (await request.get(`${API}/cti/iocs?limit=8`, {
      headers: { Authorization: `Bearer ${token}` },
    })).json()
    const ioc = (iocs.items ?? []).find((i: any) => i.type !== 'cve') ?? (iocs.items ?? [])[0]
    test.skip(!ioc, 'no indicators seeded')

    await page.goto(`/dashboard/scanner?value=${encodeURIComponent(ioc.value)}&run=1`)
    // Found record → the Threat-Intel card carries the Provenance row.
    await expect(page.getByText('Provenance')).toBeVisible({ timeout: 20_000 })
  })

  test('SOAR case detail renders the attack timeline from linked evidence', async ({ authedPage: page, request }) => {
    // The case investigation must visualise the merged attack timeline, not
    // just a flat evidence list. Pins that the /related timeline is rendered.
    const token = await apiToken(request)
    const headers = { Authorization: `Bearer ${token}` }
    const cases = await (await request.get(`${API}/soar/cases`, { headers })).json()
    const list = Array.isArray(cases) ? cases : cases.items ?? []
    test.skip(list.length === 0, 'no cases seeded')

    // Pick a case that genuinely has a merged /related timeline, so the test
    // exercises the render rather than racing an empty one.
    let target: any = null
    for (const c of list.slice(0, 10)) {
      const rel = await (await request.get(`${API}/soar/cases/${c.id}/related`, { headers })).json()
      if ((rel.timeline ?? []).length > 0) { target = c; break }
    }
    test.skip(!target, 'no seeded case has a linked-evidence timeline')

    await page.goto(`/dashboard/soar?case=${encodeURIComponent(target.id)}`)
    // The "Attack timeline" header renders only from a populated /related
    // timeline - a flat evidence list would not produce it.
    await expect(page.getByText('Attack timeline', { exact: false }).first())
      .toBeVisible({ timeout: 15_000 })
  })
})
