import { test, expect, ADMIN } from './fixtures'

/**
 * Contextual-navigation fence. Item-level actions must land on the specific
 * record they name - "open the SIEM module" is not an answer to "show me THIS
 * alert". Pins the two deep-link contracts cross-module links rely on:
 *   /dashboard/siem?alert=<id>  -> that alert's detail drawer is open
 *   /dashboard/soar?case=<id>   -> that case's detail panel is open
 */
const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8002'

async function apiToken(request: any): Promise<string> {
  const r = await request.post(`${API}/auth/login`, {
    data: { email: ADMIN.email, password: ADMIN.password },
  })
  return (await r.json()).token
}

test.describe('Deep links carry context', () => {
  test('?alert=<id> opens that alert\'s drawer on the SIEM page', async ({ authedPage: page, request }) => {
    const token = await apiToken(request)
    const alerts = await (await request.get(`${API}/siem/alerts?limit=1`, {
      headers: { Authorization: `Bearer ${token}` },
    })).json()
    const alert = alerts.items[0]
    test.skip(!alert, 'no alerts seeded')

    await page.goto(`/dashboard/siem?alert=${encodeURIComponent(alert.id)}`)
    // Queue row + opened drawer both render the title: >=2 occurrences proves
    // the DETAIL view is open, not just the list.
    await expect(page.getByText(alert.title).first()).toBeVisible({ timeout: 20_000 })
    await expect
      .poll(async () => page.getByText(alert.title).count(), { timeout: 15_000 })
      .toBeGreaterThanOrEqual(2)
  })

  test('?case=<id> opens that case\'s detail on the SOAR page', async ({ authedPage: page, request }) => {
    const token = await apiToken(request)
    const cases = await (await request.get(`${API}/soar/cases`, {
      headers: { Authorization: `Bearer ${token}` },
    })).json()
    const kase = Array.isArray(cases) ? cases[0] : cases.items?.[0]
    test.skip(!kase, 'no cases seeded')

    await page.goto(`/dashboard/soar?case=${encodeURIComponent(kase.id)}`)
    // Board card + opened detail panel both render the title.
    await expect(page.getByText(kase.title).first()).toBeVisible({ timeout: 20_000 })
    await expect
      .poll(async () => page.getByText(kase.title).count(), { timeout: 15_000 })
      .toBeGreaterThanOrEqual(2)
  })
})
