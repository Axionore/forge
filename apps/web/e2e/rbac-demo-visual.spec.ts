import { test, expect } from '@playwright/test';

// Visual capture for the standalone RBAC demo HTML
// Run with: npx playwright test e2e/rbac-demo-visual.spec.ts --project=chromium

test('RBAC UI demo - full visual flow', async ({ page }) => {
  // Point to the served demo
  await page.goto('file:///home/iris/Documents/projects/forge/docs/rbac-ui-demo.html');

  // Initial load
  await expect(page.getByText('Access & RBAC')).toBeVisible();
  await page.screenshot({ path: 'e2e/screenshots/demo-01-loaded.png', fullPage: true });

  // Enter the real strong bootstrap admin token (from the clean DB launch)
  await page.getByPlaceholder(/forge_admin/i).fill('k36F6aNNWEjCtX46AY39uIDmP4as0bITjPrlUWjw9Bwdo37IX58SHn/yl+RJY0zQ');
  await page.waitForTimeout(1200); // slow down so user can watch the token being entered

  // Create a principal
  await page.getByPlaceholder('alice or ci-deployer').fill('playwright-tester');
  await page.getByRole('button', { name: 'Create Principal' }).click();
  await page.waitForTimeout(1200); // pause to observe the UI update
  await expect(page.getByText(/playwright-tester/).first()).toBeVisible();
  await page.screenshot({ path: 'e2e/screenshots/demo-02-principal-created.png' });

  // Create a role
  await page.getByPlaceholder('Role name (e.g. deployer)').fill('demo-operator');
  await page.getByPlaceholder('Optional description').fill('For E2E visual test');
  await page.getByRole('button', { name: 'Create Role' }).click();
  await page.waitForTimeout(1200);
  await expect(page.getByText('demo-operator')).toBeVisible();
  await page.screenshot({ path: 'e2e/screenshots/demo-03-role-created.png' });

  // Issue token (the key one-time banner moment)
  await page.getByLabel('PRINCIPAL').waitFor({ state: 'visible' });
  await page.waitForTimeout(800);
  await page.getByLabel('PRINCIPAL').selectOption({ label: /playwright-tester/ });
  await page.waitForTimeout(800);
  await page.getByPlaceholder('ops team — staging').fill('Playwright visual test token');
  await page.waitForTimeout(1200); // dramatic pause before clicking Issue
  await page.getByRole('button', { name: /Issue Admin Token/i }).click();

  // Assert the amber one-time reveal banner - this is the money shot
  await page.waitForTimeout(1500); // give the banner animation time to appear
  await expect(page.getByText('One-time admin token — copy immediately')).toBeVisible();
  await page.screenshot({ path: 'e2e/screenshots/demo-04-one-time-banner.png', fullPage: true });

  // Copy and dismiss
  await page.getByRole('button', { name: 'Copy secret' }).click();
  await page.getByRole('button', { name: 'Dismiss' }).click();

  // Final state with token in list
  await expect(page.getByText(/revoked|playwright-tester/)).toBeVisible();
  await page.screenshot({ path: 'e2e/screenshots/demo-05-final-state.png', fullPage: true });
});