import { defineConfig, devices } from '@playwright/test'

/**
 * E2E suite for the ThreatOrbit dashboard.
 *
 * Runs against a live stack: the dashboard API (:8002, seeded demo data) and
 * the static frontend served on :3000. In CI both are booted before the suite
 * (see .github/workflows/e2e.yml); locally, set E2E_BASE_URL to point at an
 * already-running instance, or let `webServer` serve the production export.
 *
 * Browsers are installed with `npx playwright install --with-deps chromium`.
 * Mobile projects exercise the responsive layouts on a phone viewport.
 */
const BASE_URL = process.env.E2E_BASE_URL || 'http://127.0.0.1:3000'

export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'desktop-chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile-safari', use: { ...devices['iPhone 13'] } },
  ],
  // Only serve the frontend when nothing external is supplied; the API is
  // expected to be running separately (CI boots it).
  webServer: process.env.E2E_BASE_URL ? undefined : {
    command: 'npm run start:e2e',
    url: BASE_URL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
