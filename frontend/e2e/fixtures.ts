import { test as base, expect, Page } from '@playwright/test'

// Demo-mode admin credentials (seeded by dashboard_api in demo mode).
export const ADMIN = {
  email: process.env.E2E_ADMIN_EMAIL || 'admin@threatorbit.space',
  password: process.env.E2E_ADMIN_PASSWORD || 'ChangeMe123!',
}

export async function login(page: Page, creds = ADMIN) {
  await page.goto('/login')
  await page.getByPlaceholder('jane@company.com').fill(creds.email)
  await page.getByPlaceholder('••••••••').fill(creds.password)
  await page.getByRole('button', { name: /sign in/i }).click()
  await page.waitForURL('**/dashboard', { timeout: 20_000 })
}

/** A test that starts already authenticated on the dashboard. */
export const test = base.extend<{ authedPage: Page }>({
  authedPage: async ({ page }, use) => {
    await login(page)
    await use(page)
  },
})

export { expect }
