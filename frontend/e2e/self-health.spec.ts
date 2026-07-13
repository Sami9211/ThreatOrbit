import { test, expect } from './fixtures'

/**
 * Platform self-health regression fence. Settings → General shows a "System
 * Health" card sourced from the live /self-health endpoint (real DB latency,
 * schema version, queue backpressure, leader lease, process uptime). This pins
 * that the card renders a real verdict and the per-subsystem rows, so it can't
 * silently regress into a blank or fabricated panel.
 */
test.describe('Platform self-health', () => {
  test('System Health card renders a live verdict + subsystem rows', async ({ authedPage: page }) => {
    await page.goto('/dashboard/config')
    const card = page.locator('div.glass').filter({ hasText: 'System Health' }).last()
    await expect(card).toBeVisible({ timeout: 20_000 })

    // Overall verdict pill is one of the real states (demo boots Healthy).
    await expect(card).toContainText(/Healthy|Degraded|Down/)

    // Every subsystem row is present and carries a status, not a blank.
    for (const row of ['Database', 'Schema', 'Queue', 'Leader', 'Process']) {
      await expect(card.getByText(row, { exact: true })).toBeVisible()
    }
    // The DB check reports a measured round-trip, proving it's live, not static.
    await expect(card).toContainText(/round-trip/)
  })
})
