import type { Page } from '@playwright/test'
import { test, expect } from './fixtures'

/**
 * The core analyst value chain, end to end against the live stack - not just
 * "the page loads": triage an alert, escalate it into a SOAR case, see the
 * case appear on the board, and execute a playbook for real.
 */

async function powerMode(page: Page) {
  await page.addInitScript(() => localStorage.setItem('to-experience-mode', 'power'))
}

test.describe('Analyst workflow', () => {
  test('alert triage escalates into a SOAR case that appears on the board', async ({ authedPage: page }) => {
    await powerMode(page)
    await page.goto('/dashboard/siem')

    // Open an alert with rich context (seeded brute-force alerts always exist).
    const row = page.getByText(/brute force/i).first()
    await expect(row).toBeVisible({ timeout: 20_000 })
    await row.click()

    // Assign it - optimistic UI + PATCH to the API.
    await page.getByRole('button', { name: /assign to me/i }).click()
    await expect(page.getByText('Assigned to you')).toBeVisible()

    // Escalate into a case; the toast carries the real case id.
    await page.getByRole('button', { name: /create case/i }).click()
    const toast = page.getByText(/SOAR case .+ created from this alert/i)
    await expect(toast).toBeVisible({ timeout: 15_000 })
    const caseId = (await toast.innerText()).match(/case (\S+) created/i)?.[1]
    expect(caseId, 'toast must contain the created case id').toBeTruthy()

    // The case is genuinely on the SOAR board (served by the API, not local state).
    await page.goto('/dashboard/soar')
    await expect(page.getByText(caseId!).first()).toBeVisible({ timeout: 20_000 })
  })

  test('a playbook executes for real and the card records the run', async ({ authedPage: page }) => {
    await powerMode(page)
    await page.goto('/dashboard/soar/playbooks')
    await expect(page.getByText(/\d+ of \d+ playbooks/)).toBeVisible({ timeout: 20_000 })

    // Run the first enabled playbook; the engine executes every step and the
    // card flips its last-run stamp when the run lands.
    const run = page.getByRole('button', { name: /^run$/i }).first()
    await expect(run).toBeEnabled({ timeout: 10_000 })
    await run.click()
    await expect(page.getByText('Just now').first()).toBeVisible({ timeout: 30_000 })
  })
})
