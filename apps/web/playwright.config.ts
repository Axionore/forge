import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for Forge E2E tests.
 * Run with: pnpm test:e2e
 *
 * Prerequisites for RBAC tests:
 * - API running on http://localhost:3000 with FORGE_ADMIN_TOKEN set
 * - Web dev server running on http://localhost:3001 (or update baseURL)
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:3001',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    // Add more browsers if needed for CI
  ],

  // Optional: webServer for automatic startup (uncomment when ready)
  // webServer: [
  //   {
  //     command: 'pnpm dev',
  //     url: 'http://localhost:3001',
  //     reuseExistingServer: !process.env.CI,
  //     timeout: 120 * 1000,
  //   },
  // ],
});