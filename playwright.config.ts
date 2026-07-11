import { defineConfig, devices } from '@playwright/test';

const PORT = 4331;
const BASE = '/crypto-lab-vrf-gate/';

export default defineConfig({
  testDir: './e2e',
  // The VDF exhibit and beacon round run thousands of modular squarings in a
  // Web Worker; give each test room to finish that work before the axe scan.
  timeout: 120_000,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: `npm run preview -- --port ${PORT} --strictPort`,
    port: PORT,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
