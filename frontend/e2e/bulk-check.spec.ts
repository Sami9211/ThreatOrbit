import { test, expect } from './fixtures'

/**
 * Bulk check: the L1 triage screen. An analyst pastes a firewall/proxy extract
 * and gets a verdict per line.
 *
 * The honesty rule matters as much as the mechanics here. A value this
 * deployment has never seen must never be presented as a pass - "not in intel"
 * is the absence of a record, not evidence the value is safe - and a domain
 * query that matched a URL hosted on it has to show WHICH indicator it hit, or
 * the verdict cannot be checked by the person acting on it.
 */

test.describe('Bulk indicator check', () => {
  test('every submitted line comes back, and unknowns are not called clean', async ({ authedPage: page }) => {
    await page.goto('/dashboard/scanner/bulk')

    const unknown = 'definitely-not-in-any-feed-8f21c.example'
    // Mixed separators and surrounding punctuation: analysts paste log extracts
    // and CSV columns, not tidy one-per-line lists.
    await page.locator('textarea').fill(`"${unknown}", 203.0.113.222\n198.51.100.9;`)
    await expect(page.getByText(/3 unique values parsed/)).toBeVisible()

    await page.getByRole('button', { name: /^Check/ }).click()
    await expect(page.locator('table')).toBeVisible({ timeout: 20_000 })

    // Misses are reported, not dropped: "checked and clean" must be
    // distinguishable from "not checked".
    await expect(page.locator('table tbody tr')).toHaveCount(3)
    await expect(page.getByRole('cell', { name: unknown })).toBeVisible()

    // The verdict for an unseen value, and the standing caveat about it.
    await expect(page.getByText('Not in intel').first()).toBeVisible()
    await expect(page.getByText(/is not a clean bill of health/)).toBeVisible()
    await expect(page.getByText(/absence of evidence, not evidence of absence/)).toBeVisible()

    // The summary tile names the same thing rather than implying a pass.
    await expect(page.getByText('no record either way')).toBeVisible()
  })

  test('an oversized paste is refused with the limit, not silently truncated', async ({ authedPage: page }) => {
    await page.goto('/dashboard/scanner/bulk')
    const tooMany = Array.from({ length: 1200 }, (_, i) => `host-${i}.example`).join('\n')
    await page.locator('textarea').fill(tooMany)

    await expect(page.getByText(/1,200 unique values parsed/)).toBeVisible()
    await expect(page.getByText(/Over the 1,000 limit/)).toBeVisible()
    // Refusing has to actually refuse - a disabled control, not a request that
    // quietly checks the first 1,000 and reports on those as if they were all.
    await expect(page.getByRole('button', { name: /^Check/ })).toBeDisabled()
  })
})
