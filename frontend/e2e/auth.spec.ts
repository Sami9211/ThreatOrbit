import { test, expect, login, ADMIN } from './fixtures'

test.describe('Authentication', () => {
  test('rejects bad credentials, accepts valid ones', async ({ page }) => {
    await page.goto('/login')
    await page.getByPlaceholder('jane@company.com').pressSequentially(ADMIN.email)
    await page.getByPlaceholder('••••••••').pressSequentially('definitely-wrong')
    await page.getByRole('button', { name: /sign in/i }).click()
    // stays on /login and surfaces an error
    await expect(page).toHaveURL(/\/login/)
    await expect(page.getByText(/invalid|incorrect|failed|credentials/i)).toBeVisible()
  })

  test('valid login reaches the dashboard', async ({ page }) => {
    await login(page)
    await expect(page).toHaveURL(/\/dashboard/)
    // default experience mode is Normal ("Security Status"); Power shows
    // "Security Overview" - accept either.
    await expect(page.getByRole('heading', { name: /security (overview|status)/i })).toBeVisible()
  })

  test('protected route redirects to login when unauthenticated', async ({ page }) => {
    await page.context().clearCookies()
    await page.goto('/dashboard/siem')
    await expect(page).toHaveURL(/\/login/, { timeout: 15_000 })
  })
})
