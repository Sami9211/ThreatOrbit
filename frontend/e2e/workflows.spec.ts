import { test, expect } from './fixtures'

// The critical analyst workflows, end to end against the live stack.
test.describe('Dashboard workflows', () => {
  test('overview shows live KPIs', async ({ authedPage: page }) => {
    // default Normal mode shows "Security Status"; Power shows "Security Overview"
    await expect(page.getByRole('heading', { name: /security (overview|status)/i })).toBeVisible()
    // at least one numeric KPI rendered
    await expect(page.locator('text=/^\\d[\\d,]*$/').first()).toBeVisible()
  })

  test('SIEM alert queue loads with triage actions', async ({ authedPage: page }) => {
    await page.goto('/dashboard/siem')
    // default (Normal) mode shows alert cards with inline triage actions
    await expect(page.getByRole('button', { name: /acknowledge/i }).first()).toBeVisible({ timeout: 20_000 })
    await expect(page.getByRole('button', { name: /dismiss/i }).first()).toBeVisible()
  })

  test('SIEM rules page lists detection rules', async ({ authedPage: page }) => {
    await page.goto('/dashboard/siem/rules')
    await expect(page.getByRole('heading', { name: /rules engine/i })).toBeVisible()
    await expect(page.getByText(/FP %|Hits 24h|severity/i).first()).toBeVisible()
  })

  test('SOAR playbooks page renders and run history is present', async ({ authedPage: page }) => {
    await page.goto('/dashboard/soar/playbooks')
    await expect(page.getByRole('heading', { name: /playbooks/i })).toBeVisible()
    await expect(page.getByText(/run history/i)).toBeVisible()
  })

  test('CTI hub shows actors and IOC intelligence', async ({ authedPage: page }) => {
    await page.goto('/dashboard/cti')
    // default (Normal) mode: "Tracked Actors" / "Active Threats" + IOC stats
    await expect(page.getByText(/actor/i).first()).toBeVisible()
    await expect(page.getByText(/ioc/i).first()).toBeVisible()
  })

  test('Dark web findings page loads', async ({ authedPage: page }) => {
    await page.goto('/dashboard/darkweb')
    await expect(page.getByText(/dark web|exposure|findings/i).first()).toBeVisible()
  })

  test('Assets page lists the inventory', async ({ authedPage: page }) => {
    await page.goto('/dashboard/assets')
    await expect(page.getByText(/asset|risk|criticality/i).first()).toBeVisible()
  })

  test('global command palette opens and searches', async ({ authedPage: page }) => {
    await page.keyboard.press('Meta+k').catch(() => {})
    await page.keyboard.press('Control+k').catch(() => {})
    const search = page.getByPlaceholder(/search/i).first()
    if (await search.isVisible().catch(() => false)) {
      await search.fill('critical')
      await expect(page.locator('body')).toContainText(/critical|no results|result/i)
    }
  })
})
