import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env.E2E_PORT || 4173);
const baseURL = process.env.E2E_BASE_URL || `http://127.0.0.1:${port}`;
const useMockServer = !process.env.E2E_BASE_URL;

export default defineConfig({
  testDir: './tests/e2e',
  testMatch: ['**/*.spec.ts'],
  testIgnore: ['**/support/**'],
  timeout: 30_000,
  expect: {
    timeout: 6_000,
  },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: 'tests/e2e/playwright-report' }],
  ],
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    locale: 'zh-CN',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: useMockServer
    ? {
        command: `node tests/e2e/mock-admin-server.cjs ${port}`,
        url: baseURL,
        reuseExistingServer: !process.env.CI,
        timeout: 60_000,
      }
    : undefined,
});
