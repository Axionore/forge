import { test, expect } from '@playwright/test';

/**
 * E2E tests for the new RBAC Access page (/admin/access).
 *
 * These tests verify the full additive RBAC scaffolding delivered in the project:
 * - Principals management
 * - Roles with JSONB permissions
 * - Admin token issuance with one-time secret reveal (critical security UX)
 *
 * Prerequisites:
 *   1. Run `pnpm install` in apps/web (to get @playwright/test)
 *   2. Start the API: DATABASE_URL=... FORGE_ADMIN_TOKEN=... cargo run -p forge-api
 *   3. Start the web: cd apps/web && pnpm dev
 *   4. Run: pnpm test:e2e -- e2e/rbac-access.spec.ts
 *
 * The tests use a strong demo admin token. Update the constant below to match your FORGE_ADMIN_TOKEN.
 */

const ADMIN_TOKEN = 'rbac-demo-token-super-secure-1234567890ABCDEF';
const BASE_URL = 'http://localhost:3001';

test.describe('RBAC Access Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/access`);
    
    // Enter admin token (required for all actions)
    const tokenInput = page.getByPlaceholder(/forge_admin/i);
    await tokenInput.fill(ADMIN_TOKEN);
  });

  test('should load the RBAC access page with correct structure', async ({ page }) => {
    // Header
    await expect(page.getByText('Access & RBAC')).toBeVisible();
    await expect(page.getByText('OPERATOR AUTH')).toBeVisible();

    // Main sections
    await expect(page.getByText('Principals')).toBeVisible();
    await expect(page.getByText('Roles')).toBeVisible();
    await expect(page.getByText('Issued Admin Tokens')).toBeVisible();

    // Admin token input should be present
    await expect(page.getByPlaceholder(/forge_admin/i)).toBeVisible();

    // Take initial screenshot
    await page.screenshot({ path: 'e2e/screenshots/rbac-page-loaded.png', fullPage: true });
  });

  test('should create a new principal', async ({ page }) => {
    const principalName = `test-principal-${Date.now()}`;

    // Fill and submit principal form
    await page.getByPlaceholder('alice or ci-deployer').fill(principalName);
    await page.getByRole('button', { name: 'Create Principal' }).click();

    // Should appear in the list
    await expect(page.getByText(principalName)).toBeVisible();

    await page.screenshot({ path: 'e2e/screenshots/rbac-principal-created.png' });
  });

  test('should create a new role with permissions', async ({ page }) => {
    const roleName = `test-role-${Date.now()}`;

    await page.getByPlaceholder('Role name (e.g. deployer)').fill(roleName);
    await page.getByPlaceholder('Optional description').fill('E2E test role');

    // Update permissions JSON
    const permsTextarea = page.locator('textarea').filter({ hasText: /deployments:read/ });
    await permsTextarea.fill(JSON.stringify({
      "deployments:read": true,
      "secrets:read": true,
      "git-sources:write": true
    }, null, 2));

    await page.getByRole('button', { name: 'Create Role' }).click();

    await expect(page.getByText(roleName)).toBeVisible();
    await expect(page.getByText('E2E test role')).toBeVisible();

    await page.screenshot({ path: 'e2e/screenshots/rbac-role-created.png' });
  });

  test('should issue an admin token and show the one-time secret banner', async ({ page }) => {
    // First create a principal to select
    const principalName = `token-principal-${Date.now()}`;
    await page.getByPlaceholder('alice or ci-deployer').fill(principalName);
    await page.getByRole('button', { name: 'Create Principal' }).click();
    await expect(page.getByText(principalName)).toBeVisible();

    // Open the token issuance form and select the principal
    await page.getByLabel('PRINCIPAL').selectOption({ label: new RegExp(principalName) });
    await page.getByPlaceholder('ops team — staging').fill('Playwright E2E test token');

    // Issue the token
    await page.getByRole('button', { name: /Issue Admin Token/i }).click();

    // Critical assertion: the one-time amber banner must appear
    const oneTimeBanner = page.locator('text=One-time admin token — copy immediately');
    await expect(oneTimeBanner).toBeVisible();

    // The raw token should be visible in the banner (big monospace block)
    const tokenValue = page.locator('div').filter({ hasText: /at_[a-zA-Z0-9]{40,}/ }).first();
    await expect(tokenValue).toBeVisible();

    // Prefix should be shown
    await expect(page.locator('text=/at_[a-z0-9]{4,8}••••/')).toBeVisible();

    // Take screenshot of the hero one-time reveal experience
    await page.screenshot({ 
      path: 'e2e/screenshots/rbac-one-time-token-reveal.png', 
      fullPage: true 
    });

    // Dismiss the banner
    await page.getByRole('button', { name: 'Dismiss' }).click();
    await expect(oneTimeBanner).not.toBeVisible();
  });

  test('should list and allow revoking issued admin tokens', async ({ page }) => {
    // Create a principal
    const principalName = `revoke-principal-${Date.now()}`;
    await page.getByPlaceholder('alice or ci-deployer').fill(principalName);
    await page.getByRole('button', { name: 'Create Principal' }).click();

    // Issue a token
    await page.getByLabel('PRINCIPAL').selectOption({ label: new RegExp(principalName) });
    await page.getByRole('button', { name: /Issue Admin Token/i }).click();

    // Wait for banner and dismiss
    await expect(page.locator('text=One-time admin token')).toBeVisible();
    await page.getByRole('button', { name: 'Dismiss' }).click();

    // The token should now appear in the list
    const tokenRow = page.locator('div').filter({ hasText: /at_[a-z0-9]{4,8}••••/ }).first();
    await expect(tokenRow).toBeVisible();

    // Revoke it
    await page.getByRole('button', { name: 'Revoke' }).click();

    // Confirm dialog (Playwright auto-accepts by default in most cases, or handle it)
    // In real usage you may need page.on('dialog'...

    // After revoke, the row should show "revoked"
    await expect(page.locator('text=revoked')).toBeVisible({ timeout: 5000 });

    await page.screenshot({ path: 'e2e/screenshots/rbac-token-revoked.png' });
  });
});