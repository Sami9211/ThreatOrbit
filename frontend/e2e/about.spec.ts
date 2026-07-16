import { test, expect } from './fixtures'

/**
 * About-this-deployment regression fence. Settings → General shows an "About
 * This Deployment" card sourced from the live /about endpoint (the product
 * version constant shipped in the build plus effective runtime posture). This
 * pins that the card shows the real values, not placeholders.
 */
test.describe('About this deployment', () => {
  test('About card renders live build identity + posture', async ({ authedPage: page }) => {
    await page.goto('/dashboard/config')
    const card = page.locator('div.glass').filter({ hasText: 'About This Deployment' }).last()
    await expect(card).toBeVisible({ timeout: 20_000 })

    // A semver-looking product version proves the endpoint answered.
    await expect(card).toContainText(/\d+\.\d+\.\d+/)

    for (const row of ['Version', 'API version', 'Schema version', 'Database', 'Data mode']) {
      await expect(card.getByText(row, { exact: true })).toBeVisible()
    }
    // Posture values come from the real config vocabulary.
    await expect(card).toContainText(/sqlite|postgres/)
    await expect(card).toContainText(/demo|live/)
  })
})
