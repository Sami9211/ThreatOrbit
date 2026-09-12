import { test as base, expect, Page } from '@playwright/test'

// Demo-mode admin credentials (seeded by dashboard_api in demo mode).
export const ADMIN = {
  email: process.env.E2E_ADMIN_EMAIL || 'admin@threatorbit.space',
  password: process.env.E2E_ADMIN_PASSWORD || 'ChangeMe123!',
}

export async function login(page: Page, creds = ADMIN) {
  await page.goto('/login')
  // Type key-by-key so React's controlled inputs reliably fire onChange and
  // enable the submit button - a plain fill() raced the disabled state on
  // WebKit/CI and left the button un-clickable.
  await page.getByPlaceholder('jane@company.com').pressSequentially(creds.email)
  await page.getByPlaceholder('••••••••').pressSequentially(creds.password)
  await page.getByRole('button', { name: /sign in/i }).click()
  // next.config has trailingSlash: true, so the app lands on /dashboard/ -
  // match with or without the trailing slash.
  await page.waitForURL(/\/dashboard\/?$/, { timeout: 20_000 })
  // ...and then wait for the dashboard to actually BE there. A URL change is
  // not a rendered page: the overview a11y check ran axe-core straight after
  // this and intermittently caught a half-built DOM on the slowest project,
  // failing CI on a violation that does not exist once the page settles (15/15
  // clean locally, three repeats). Every other test in that spec already waits
  // for a visible element before analysing; this makes `authedPage` mean what
  // its name says, for those tests and any future one.
  //
  // The heading differs by experience mode - "Security Status" in Normal,
  // "Security Overview" in Power - so match either rather than pinning a mode.
  await expect(
    page.getByRole('heading', { name: /security (status|overview)/i }).first(),
  ).toBeVisible({ timeout: 20_000 })
}

/** A test that starts already authenticated on the dashboard. */
export const test = base.extend<{ authedPage: Page }>({
  authedPage: async ({ page }, use) => {
    await login(page)
    await use(page)
  },
})

export { expect }
