import { defineConfig } from '@playwright/test';

/**
 * End-to-end tests against wp-env's site (`npm run env:start` first). Its
 * port is 8888 unless .wp-env.override.json says otherwise; WP_BASE_URL
 * overrides it here. Only HTTP requests, no browser.
 */
export default defineConfig({
    testDir: 'tests/e2e',
    timeout: 60_000,
    workers: 1,
    use: {
        baseURL: process.env.WP_BASE_URL ?? 'http://localhost:8888',
    },
});
