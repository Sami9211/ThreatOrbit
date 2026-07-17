import { test, expect } from './fixtures'

/**
 * SOC console regression fence. Two failure modes are pinned:
 *  - with alerts present (CI runs the seeded demo API) the console must show
 *    the live work surface, never the "queue is empty" state;
 *  - the Intel Activity panel must render, so the console always reflects
 *    platform activity even when the SIEM side is quiet.
 */
test.describe('SOC console', () => {
  test('reflects the live queue when alerts exist', async ({ authedPage: page }) => {
    await page.goto('/dashboard/soc')
    await expect(page.getByText('SLA Breach Queue', { exact: false })).toBeVisible({ timeout: 20_000 })

    // Demo data seeds an open queue - the empty state must NOT be shown.
    await expect(page.getByText('The SIEM alert queue is empty.')).toHaveCount(0)

    // KPI strip carries real numbers (Open queue tile shows a digit, not "-").
    const openTile = page.locator('div', { hasText: /^Open queue/ }).last()
    await expect(openTile).not.toContainText('-')

    // The intel side renders alongside the alert queue.
    await expect(page.getByText('Intel Activity')).toBeVisible()
    await expect(page.getByText('Indicators tracked')).toBeVisible()
  })
})
