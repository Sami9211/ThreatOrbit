import { test, expect } from './fixtures'

/**
 * Regression fence for the systemic "seed-persists-on-empty" fabrication
 * (NETWORK_MAP §B8). Several pages used to keep a hardcoded demo array on
 * screen whenever the live API returned an EMPTY list - so a real, freshly
 * provisioned deployment showed fabricated rules / log sources / users / actors
 * as if they were real.
 *
 * Each test forces the relevant endpoint to return `[]` (a reachable API with
 * nothing ingested) and asserts the distinctive SEED value never appears. If
 * anyone reintroduces the `useState(SEED)` + `if (data.length > 0)` pattern,
 * these fail.
 */

// Scope stubs to the API host so we never intercept the frontend's own page
// navigation (which shares the `siem/rules` path fragment on :3000).
const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8002'

// Force an API endpoint to answer with an empty collection.
async function stubEmpty(page: import('@playwright/test').Page, path: string, body = '[]') {
  await page.route(`${API}${path}*`, (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body }))
}

test.describe('No seed data leaks on an empty (but reachable) API', () => {
  test('siem/rules shows no seed rule when /siem/rules is empty', async ({ authedPage: page }) => {
    await stubEmpty(page, '/siem/rules')
    await page.goto('/dashboard/siem/rules')
    await expect(page.getByRole('heading', { name: /Rules Engine/i })).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('Ransomware File Encryption Indicator')).toHaveCount(0)
  })

  test('siem/sources shows no seed source when /siem/sources is empty', async ({ authedPage: page }) => {
    await stubEmpty(page, '/siem/sources')
    await page.goto('/dashboard/siem/sources')
    await expect(page.getByRole('heading', { name: /Log Sources/i })).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('Windows Domain Controllers (6 hosts)')).toHaveCount(0)
  })

  test('config/users shows no seed user when /users is empty', async ({ authedPage: page }) => {
    await stubEmpty(page, '/users')
    await page.goto('/dashboard/config/users')
    await expect(page.getByRole('heading', { name: /Users .* Roles/i })).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('Priya Nair')).toHaveCount(0)
  })

  test('cti shows no seed actor when /cti/actors is empty', async ({ authedPage: page }) => {
    await stubEmpty(page, '/cti/actors')
    // Bias to Power mode (where the B8d seed lived); the assertion below is
    // mode-agnostic either way.
    await page.addInitScript(() => window.localStorage.setItem('to-experience-mode', 'power'))
    await page.goto('/dashboard/cti')
    await expect(page.getByRole('heading', { name: /Threat Intelligence/i }).first())
      .toBeVisible({ timeout: 20_000 })
    // The distinctive seed actor must never render on an empty store.
    await expect(page.getByText('Lazarus Group')).toHaveCount(0)
  })

  test('config/sources shows no "Connected" vendor with zero live sources (B1)', async ({ authedPage: page }) => {
    await stubEmpty(page, '/siem/sources')
    await page.goto('/dashboard/config/sources')
    // A catalogue card must be on screen before the badge assertion means anything.
    await expect(page.getByText('Amazon Web Services')).toBeVisible({ timeout: 20_000 })
    // With no live log sources, every vendor must resolve to "Not configured" -
    // the exact-cased "Connected" badge (the old fabricated state) never settles.
    await expect(page.getByText('Connected', { exact: true })).toHaveCount(0)
  })

  test('assets/network labels the example topology as illustrative (B7)', async ({ authedPage: page }) => {
    await page.goto('/dashboard/assets/network')
    await expect(page.getByRole('heading', { name: /Network Map/i })).toBeVisible({ timeout: 20_000 })
    // The seed firewalls/servers may render, but only under an explicit
    // "illustrative" banner so they can't be mistaken for discovered assets.
    await expect(page.getByText(/Illustrative topology/i)).toBeVisible({ timeout: 15_000 })
  })
})
