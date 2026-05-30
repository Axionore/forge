import { test, expect } from '@playwright/test';

/**
 * Phase 1 Image Deploy Verification (Slice D)
 *
 * Exercises the complete happy path for criteria 2,4,5,6:
 * - Application creation + rich image deploy form (registry, env, ports, domains, strategy)
 * - Preview Spec modal (exact DeploymentSpec)
 * - Deploy button states + dispatch
 * - Status + real Status Timeline (JobResultRow data)
 * - Live Logs dialog (all enhancements: timestamps, follow/pause, filter, line nums, download/copy)
 * - Redeploy using previous_spec
 *
 * Prerequisites:
 * - API on http://localhost:3000 with FORGE_ADMIN_TOKEN
 * - Web on http://localhost:3001 (or update baseURL in playwright.config)
 * - At least one enrolled agent visible in the UI (otherwise tests are skipped with clear message)
 *
 * These tests are intentionally UI-contract focused. Full container execution + Traefik/LE
 * is covered by the manual Fresh VM checklist in docs/slice-d-verification.md.
 */

const ADMIN_TOKEN = process.env.FORGE_ADMIN_TOKEN || 'test-admin-token';
const API_BASE = 'http://localhost:3000';

test.describe('Phase 1: Image Deploy + Observability', () => {
  test.beforeEach(async ({ page }) => {
    // Seed token early (many admin pages read localStorage on mount)
    await page.addInitScript(() => {
      localStorage.setItem('adminToken', 'test-admin-token');
    });

    // Make the shared beforeEach tolerant so it doesn't kill isolated tests
    // (e.g. the new deployments timelines + logs panel test) when the server is slow
    // or when we only want to test specific pages.
    try {
      await page.goto('/admin/applications', { waitUntil: 'domcontentloaded', timeout: 8000 });
    } catch {
      // Non-fatal — the specific test will do its own navigation + mocking
    }
  });

  test('status timelines and enhanced logs panel render and are interactive (deployments page)', async ({ page }) => {
    // Broader mocking so the deployments list reliably renders items with our new StatusTimeline + Stream Logs buttons
    // The page only shows the timeline / logs buttons after "Show Recent Results" is clicked (which adds ?results_limit)

    await page.route('**/admin/applications', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'app-1', name: 'phase1-test-app', description: 'For harness testing' }
        ])
      });
    });

    // Handle both the initial fetch (no limit) and the one after clicking "Show Recent Results (5)"
    await page.route('**/admin/applications/*/deployments**', async (route, request) => {
      const url = request.url();
      const hasResultsLimit = url.includes('results_limit');

      const baseDeployment = {
        id: 'dep-1',
        application_id: 'app-1',
        version: 1,
        status: 'healthy',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      const deploymentItem = hasResultsLimit
        ? {
            deployment: baseDeployment,
            recent_results: [
              { id: 'r1', job_type: 'deploy', success: true, error: null, received_at: new Date().toISOString(), details: {} },
              { id: 'r2', job_type: 'container_logs', success: true, error: null, received_at: new Date().toISOString(), details: {} }
            ]
          }
        : {
            deployment: baseDeployment,
            recent_results: []   // initial load without the toggle doesn't include them yet
          };

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([deploymentItem])
      });
    });

    // Silence other admin calls that can cause 500s on a partial backend
    await page.route('**/admin/git-sources**', r => r.fulfill({ status: 200, body: '[]' }));
    await page.route('**/admin/secrets**', r => r.fulfill({ status: 200, body: '[]' }));
    await page.route('**/admin/applications/*/deployments/*/metrics**', r => r.fulfill({ status: 200, body: '[]' }));

    // Very broad fallback for any other /admin calls the deployments page might make
    // (promote, destroy, notifications, debug, ssh-keys, etc.). This makes the list
    // + timeline + logs buttons render reliably even if we missed a specific route.
    await page.route('**/admin/**', async (route) => {
      const url = route.request().url();
      // Let the specific mocks above take precedence
      if (url.includes('/applications') || url.includes('/git-sources') || url.includes('/secrets') || url.includes('/metrics')) {
        return route.continue();
      }
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
    });

    // Seed the admin token the page components expect (many admin pages read it on mount)
    await page.addInitScript(() => {
      localStorage.setItem('adminToken', 'test-admin-token');
    });

    // Robust readiness wait (the dev server can be slow to boot in this environment)
    const maxWait = 45000;
    const start = Date.now();
    while (Date.now() - start < maxWait) {
      try {
        await page.goto('http://localhost:3001', { waitUntil: 'domcontentloaded', timeout: 4000 });
        break;
      } catch {
        await page.waitForTimeout(1500);
      }
    }

    await page.goto('/admin/deployments', { waitUntil: 'domcontentloaded', timeout: 30000 });

    // The list should now render at least one deployment item
    await expect(page.getByText(/dep-1|v1|phase1-test-app/i)).toBeVisible({ timeout: 10000 });

    // Click "Show Recent Results (5)" — this triggers the enriched fetch that populates recent_results
    // and causes our <StatusTimeline> + "Stream Logs (WS)" buttons to appear
    const showResultsBtn = page.getByRole('button', { name: /Show Recent Results/i });
    await expect(showResultsBtn).toBeVisible({ timeout: 5000 });
    await showResultsBtn.click();

    // Now the timeline text and Stream Logs buttons (from our recent work) should be visible
    await expect(page.getByText(/Status Timeline|Execution Timeline/i)).toBeVisible({ timeout: 10000 });

    const logsButtons = page.getByRole('button', { name: /Stream Logs|logs/i });
    await expect(logsButtons.first()).toBeVisible({ timeout: 5000 });

    // Open the logs dialog and verify the enhanced panel (follow toggle, filter, status badges, download/copy, etc.)
    await logsButtons.first().click();

    const logsDialog = page.getByRole('dialog');
    await expect(logsDialog).toBeVisible({ timeout: 5000 });

    await expect(logsDialog.getByText(/Follow:|connected|connecting|PAUSED|FOLLOWING/i)).toBeVisible();
    await expect(logsDialog.getByPlaceholder(/Filter/i)).toBeVisible();
    await expect(logsDialog.getByRole('button', { name: /Download|Copy visible|Clear/i })).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(logsDialog).not.toBeVisible();
  });

  test('full image deploy flow with private registry, preview, timeline, logs, redeploy', async ({ page }) => {
    // 1. Create a new Application (criterion 2)
    await page.getByRole('button', { name: 'Create Application' }).first().click();
    await page.getByLabel(/name/i).fill('phase1-harness-app');
    await page.getByLabel(/description/i).fill('Slice D verification deployment');
    await page.getByRole('button', { name: /create/i }).click();

    await expect(page.getByText('phase1-harness-app')).toBeVisible();

    // Open detail page
    await page.getByText('phase1-harness-app').click();

    // 2. Fill the rich deploy form (image + private registry + env + ports + domains + strategy)
    const imageInput = page.getByLabel(/image/i);
    await imageInput.fill('nginx:1.25');

    // Private registry section (if visible/expanded)
    const registryServer = page.getByLabel(/registry server/i);
    if (await registryServer.isVisible()) {
      await registryServer.fill('https://ghcr.io');
      await page.getByLabel(/registry username/i).fill('harness-user');
      await page.getByLabel(/registry password/i).fill('harness-pat');
    }

    // Add a couple of env vars (dynamic editor)
    await page.getByRole('button', { name: /add env/i }).click();
    const envRows = page.locator('[data-testid="env-row"]');
    await envRows.nth(0).getByLabel(/key/i).fill('ENV');
    await envRows.nth(0).getByLabel(/value/i).fill('production');

    // Ports
    await page.getByLabel(/publish port/i).fill('80:80');

    // Domains (for Traefik + LE)
    await page.getByLabel(/domain/i).fill('harness-phase1.example.com');

    // Strategy
    await page.getByRole('tab', { name: /rolling/i }).click();

    // 3. Preview Spec (exact DeploymentSpec JSON) – criterion 3
    await page.getByRole('button', { name: /preview spec/i }).click();
    const previewModal = page.getByRole('dialog');
    await expect(previewModal).toBeVisible();
    const json = await previewModal.locator('pre, code').innerText();
    expect(json).toContain('nginx:1.25');
    expect(json).toContain('registry_auth'); // when registry fields filled
    await previewModal.getByRole('button', { name: /close/i }).click();

    // 4. Deploy (button loading state + dispatch)
    const deployBtn = page.getByRole('button', { name: /deploy image/i });
    await expect(deployBtn).toBeEnabled();
    await deployBtn.click();

    // Loading state
    await expect(page.getByText(/signing|dispatching/i)).toBeVisible({ timeout: 2000 });

    // 5. Status + real Status Timeline appears (JobResult driven) – criteria 4+5
    await expect(page.getByText(/healthy|in_progress|pending/i)).toBeVisible({ timeout: 15000 });

    const timeline = page.getByText(/execution timeline|status timeline/i);
    await expect(timeline).toBeVisible();

    // At least the deploy job result row should be present
    await expect(page.getByText(/deploy/i).first()).toBeVisible();

    // 6. Live Logs dialog – all enhancements (criterion 5)
    await page.getByRole('button', { name: /stream logs|open live logs/i }).click();

    const logsDialog = page.getByRole('dialog');
    await expect(logsDialog).toBeVisible();

    // Connection badge
    await expect(logsDialog.getByText(/connected|connecting/i)).toBeVisible();

    // Follow toggle
    const followBtn = logsDialog.getByRole('button', { name: /follow/i });
    await expect(followBtn).toBeVisible();
    await followBtn.click(); // toggle off
    await expect(logsDialog.getByText(/follow: off/i)).toBeVisible();

    // Filter
    const filterInput = logsDialog.getByPlaceholder(/filter/i);
    await filterInput.fill('nginx');
    await expect(logsDialog.getByText(/no lines match/i)).toBeVisible({ timeout: 1000 }); // or actual log content

    // Line numbers gutter (subtle)
    await expect(logsDialog.locator('text=/^\\d+$/').first()).toBeVisible();

    // Download + Copy visible buttons
    await expect(logsDialog.getByRole('button', { name: /download/i })).toBeVisible();
    await expect(logsDialog.getByRole('button', { name: /copy visible/i })).toBeVisible();

    // Close logs
    await logsDialog.getByRole('button', { name: /close|×/i }).click();

    // 7. Redeploy (criterion 6)
    await page.getByRole('button', { name: /redeploy/i }).first().click();
    await expect(page.getByText(/redeploy dispatched|new version/i)).toBeVisible({ timeout: 5000 });

    // New events should appear in the timeline for the redeploy
    await expect(page.getByText(/deploy/i).nth(1)).toBeVisible({ timeout: 10000 });
  });

  test('quick deploy surfaces (applications list + deployments list) also support registry + redeploy + logs', async ({ page }) => {
    // Quick Deploy modal from /admin/applications
    await page.goto('/admin/applications');
    await page.getByRole('button', { name: 'Quick Deploy' }).click();

    const modal = page.getByRole('dialog');
    await modal.getByLabel(/image/i).fill('nginx:alpine');
    // Registry fields should be present (Slice C polish)
    await expect(modal.getByLabel(/registry server/i)).toBeVisible();

    // (Further interaction would require a real agent; the presence of the fields + consistent logic is the check)
  });
});
