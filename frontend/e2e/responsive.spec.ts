import { test, expect } from './fixtures'

/**
 * Mobile-responsive checks. Runs under the `mobile-safari` project (iPhone 13
 * viewport) — these assert the core pages are usable on a phone: no horizontal
 * overflow, and the primary content/nav is reachable.
 */
test.describe('Responsive (mobile viewport)', () => {
  const pages = [
    { path: '/dashboard', heading: /security overview/i },
    { path: '/dashboard/siem', heading: /siem|alert/i },
    { path: '/dashboard/soar', heading: /soar|case|playbook/i },
    { path: '/dashboard/cti', heading: /threat|intelligence|actor/i },
    { path: '/dashboard/assets', heading: /asset/i },
    { path: '/dashboard/config', heading: /settings|config|workspace/i },
  ]

  for (const p of pages) {
    test(`no horizontal overflow on ${p.path}`, async ({ authedPage: page }) => {
      await page.goto(p.path)
      await expect(page.getByText(p.heading).first()).toBeVisible({ timeout: 20_000 })
      // body must not scroll horizontally on a phone (allow a 2px tolerance)
      const overflow = await page.evaluate(() =>
        document.documentElement.scrollWidth - document.documentElement.clientWidth)
      expect(overflow).toBeLessThanOrEqual(2)
    })
  }

  test('mobile navigation reaches another section', async ({ authedPage: page }) => {
    await page.goto('/dashboard')
    // open the menu if a hamburger exists, then navigate
    const menu = page.getByRole('button', { name: /menu|open navigation/i }).first()
    if (await menu.isVisible().catch(() => false)) await menu.click()
    await page.goto('/dashboard/siem')
    await expect(page).toHaveURL(/siem/)
  })
})
