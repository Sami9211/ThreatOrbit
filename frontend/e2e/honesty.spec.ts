import type { Page } from '@playwright/test'
import { test, expect } from './fixtures'

/**
 * Data-honesty regression fences. Each of these surfaces used to render
 * hardcoded demo numbers as if they were live telemetry; they now compute
 * from real data. These specs pin the fixes so a fabricated value can't
 * silently come back.
 */

// Several surfaces only exist in Power mode; the toggle persists to
// localStorage, which init-scripts set before each navigation.
async function powerMode(page: Page) {
  await page.addInitScript(() => localStorage.setItem('to-experience-mode', 'power'))
}

test.describe('Data honesty fences', () => {
  test('SIEM header + analytics show computed trends, not demo strings', async ({ authedPage: page }) => {
    await powerMode(page)
    await page.goto('/dashboard/siem')
    await expect(page.getByText(/alert queue/i).first()).toBeVisible({ timeout: 20_000 })
    const body = () => page.locator('body')
    // The old static sub-annotations can never legitimately re-occur verbatim.
    await expect(body()).not.toContainText('↓ from 6m 04s')
    await expect(body()).not.toContainText('↑ from 19m 20s')
    await expect(body()).not.toContainText('↓ from 28% (7d)')
    // Computed annotations are present instead.
    await expect(body()).toContainText(/7d avg/)
    await expect(body()).toContainText(/in last hour/)

    // Analytics tab: the demo sparkline series ended in 2847 alerts/day.
    await page.getByRole('button', { name: /analytics/i }).click()
    await expect(page.getByText(/alert volume \(7d\)/i)).toBeVisible()
    await expect(body()).not.toContainText('2847')
  })

  test('alert-detail identity/host tabs show real UEBA, not invented directory data', async ({ authedPage: page }) => {
    await powerMode(page)
    await page.goto('/dashboard/siem')
    // open any alert row that carries a username (seeded brute-force alerts do)
    const row = page.getByText(/brute force/i).first()
    await expect(row).toBeVisible({ timeout: 20_000 })
    await row.click()
    await page.getByRole('button', { name: /^identity$/i }).click()
    const body = page.locator('body')
    await expect(body).toContainText(/UEBA Risk Score/i)
    await expect(body).toContainText(/Related Alerts/i)
    // the fabricated directory rows are gone for good
    await expect(body).not.toContainText('Department')
    await expect(body).not.toContainText('Kerberos')
    await page.getByRole('button', { name: /^host$/i }).click()
    await expect(body).toContainText(/Host Risk Score/i)
    await expect(body).not.toContainText('Windows 10 22H2')
    await expect(body).not.toContainText('3 critical, 7 high')
  })

  test('playbooks KPI strip is computed and success rate is a true percent', async ({ authedPage: page }) => {
    await powerMode(page)
    await page.goto('/dashboard/soar/playbooks')
    const body = page.locator('body')
    await expect(body).toContainText(/\d+ enabled/, { timeout: 20_000 })
    await expect(body).not.toContainText('Next: 17:00 UTC')
    await expect(body).not.toContainText('+1.3% from last month')
    // seeded playbooks have thousands of runs at ~90% success; the 100×
    // fraction/percent bug rendered this as "0.9%" — pin the sane range.
    // Poll: the value counts up from 0, so read it after it settles. The
    // success cell is hidden below the md breakpoint, so only assert when
    // it's rendered (the mobile project still runs the other fences).
    const successVisible = await page.getByText(/avg success rate/i)
      .isVisible().catch(() => false)
    if (successVisible) {
      await expect.poll(async () => {
        const text = await body.innerText()
        const m = text.match(/([\d.]+)%\s*\n*across [\d,]+ runs/)
        return m ? parseFloat(m[1]) : -1
      }, { timeout: 10_000 }).toBeGreaterThan(50)
    }
  })

  test('Config → API shows real key telemetry, no invented rate limit', async ({ authedPage: page }) => {
    await powerMode(page)
    await page.goto('/dashboard/config/api')
    const body = page.locator('body')
    await expect(body).toContainText(/Requests Today/i, { timeout: 20_000 })
    await expect(body).toContainText(/Revoked Keys/i)
    await expect(body).not.toContainText('1M/mo')
  })

  test('SOAR case board never flashes an empty state while loading', async ({ authedPage: page }) => {
    await powerMode(page)
    // Hold the cases response so the pending state is observable.
    await page.route('**/soar/cases*', async (route) => {
      await new Promise((r) => setTimeout(r, 2500))
      await route.continue()
    })
    await page.goto('/dashboard/soar')
    // While pending: skeletons, not "No cases".
    await expect(page.locator('[aria-label="Loading"]').first()).toBeVisible({ timeout: 10_000 })
    await expect(page.locator('body')).not.toContainText('No cases yet')
    // And it resolves to the real board.
    await expect(page.getByText(/case queue/i).first()).toBeVisible({ timeout: 20_000 })
  })
})
