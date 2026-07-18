import { test, expect } from './fixtures'

/**
 * IntelScope honesty + depth. The scanner must never fabricate intelligence:
 * an unknown value reads "unverified" (not clean, not malicious), provider
 * rows reflect what actually ran, and the Relations tab only shows records
 * that exist in this deployment's own stores.
 */

test.describe('IntelScope scanner', () => {
  test('unknown value scans to an honest unverified verdict', async ({ authedPage: page }) => {
    await page.goto('/dashboard/scanner/')
    // Scan an IP that no demo feed publishes (TEST-NET-3, documentation range).
    await page.getByRole('button', { name: 'IP', exact: true }).click()
    await page.getByPlaceholder('192.168.1.1').fill('203.0.113.222')
    await page.getByRole('button', { name: /^Scan$/ }).click()

    // Verdict pill: unverified - unknown is not proven clean.
    await expect(page.locator('span', { hasText: /^unverified$/ }).first())
      .toBeVisible({ timeout: 20_000 })
    await expect(page.getByText(/Unverified means/)).toBeVisible()

    // Result tabs are present.
    for (const tab of ['Details', 'Relations', 'Community', 'Sources']) {
      await expect(page.getByRole('tab', { name: new RegExp(tab) })).toBeVisible()
    }

    // Details: the TI store honestly reports no record (the copy appears in
    // the overview explainer AND the Details panel - both intended).
    await expect(page.getByText(/Not present in the ThreatOrbit intelligence store/).first())
      .toBeVisible()

    // Sources: the TI store row + honest per-provider availability. External
    // providers have no keys in e2e, so they must say "not configured".
    await page.getByRole('tab', { name: /Sources/ }).click()
    await expect(page.getByText('ThreatOrbit TI store')).toBeVisible()
    await expect(page.getByText('no record').first()).toBeVisible()
    await expect(page.getByText('not configured').first()).toBeVisible()

    // Community: no invented votes - analyst history only.
    await page.getByRole('tab', { name: /Community/ }).click()
    await expect(page.getByText(/reflects your own team's history|Scanned/)).toBeVisible()
  })

  test('hand-off deep link pre-populates and auto-runs the scan', async ({ authedPage: page }) => {
    // The CVE/threat-map "Look up in CTI scanner" contract: value + type in
    // the URL, run=1 starts the scan with zero extra clicks.
    await page.goto('/dashboard/scanner/?value=203.0.113.5&type=ip&run=1')
    await expect(page.getByPlaceholder('192.168.1.1')).toHaveValue('203.0.113.5')
    await expect(page.locator('span', { hasText: /^unverified$/ }).first())
      .toBeVisible({ timeout: 20_000 })
  })

  test('known demo indicator shows record, relations and deep links', async ({ authedPage: page }) => {
    // Find a real seeded IOC via the API the page itself uses, then scan it.
    const ioc = await page.evaluate(async () => {
      const token = localStorage.getItem('to_token')
      const res = await fetch('http://127.0.0.1:8002/cti/iocs?type=ip&limit=1', {
        headers: { Authorization: `Bearer ${token}` },
      })
      const body = await res.json()
      return body.items[0]?.value ?? null
    })
    test.skip(!ioc, 'no seeded ip IOC in this environment')

    await page.goto('/dashboard/scanner/')
    await page.getByRole('button', { name: 'IP', exact: true }).click()
    await page.getByPlaceholder('192.168.1.1').fill(ioc!)
    await page.getByRole('button', { name: /^Scan$/ }).click()

    // Details tab renders the real TI record.
    await expect(page.getByText('Threat-Intel Record')).toBeVisible({ timeout: 20_000 })
    await expect(page.getByText('Feed source').first()).toBeVisible()

    // Relations tab loads real stores (may be empty - but never errors, and
    // an empty state must say so explicitly rather than invent rows).
    await page.getByRole('tab', { name: /Relations/ }).click()
    await expect(
      page.getByText('SIEM Alerts').or(page.getByText('No Recorded Relations')),
    ).toBeVisible()
  })
})
