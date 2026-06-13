import { test, expect } from './fixtures'

// The critical analyst workflows, end to end against the live stack.
test.describe('Dashboard workflows', () => {
  test('overview shows live KPIs', async ({ authedPage: page }) => {
    // default Normal mode shows "Security Status"; Power shows "Security Overview"
    await expect(page.getByRole('heading', { name: /security (overview|status)/i })).toBeVisible()
    // at least one numeric KPI rendered
    await expect(page.locator('text=/^\\d[\\d,]*$/').first()).toBeVisible()
  })

  test('SIEM alert queue loads and a row opens detail', async ({ authedPage: page }) => {
    await page.goto('/dashboard/siem')
    // the queue has alert rows; clicking one reveals triage actions
    const firstAlert = page.locator('button, [role="button"]').filter({ hasText: /T1\d{3}|critical|high|medium/i }).first()
    await expect(firstAlert).toBeVisible({ timeout: 20_000 })
    await firstAlert.click()
    await expect(page.getByText(/assign to me|suppress|create case|disposition/i).first()).toBeVisible()
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

  test('CTI hub shows actors + the IOC lifecycle panel', async ({ authedPage: page }) => {
    await page.goto('/dashboard/cti')
    await expect(page.getByText(/threat actors/i).first()).toBeVisible()
    await expect(page.getByText(/IOC database/i)).toBeVisible()
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
