import { expect, test } from '@playwright/test';
import { ADDRESS, KEY_A, KEY_B } from '../../packages/test-fixtures/src/fixtures.js';
test('tenant login, collection, evidence export, module status, responsive view and logout', async ({
  page,
}) => {
  await page.goto('/');
  await page.getByLabel('Tenant API key').fill(KEY_A);
  await page.getByRole('button', { name: 'Continue to workspace' }).click();
  await expect(page.getByRole('heading', { name: 'Your cryptographic landscape.' })).toBeVisible();
  await expect(page).toHaveURL(/\/dashboard$/);
  expect(await page.evaluate(() => document.cookie)).not.toContain(KEY_A);
  await page.getByLabel('EVM account address').fill(ADDRESS);
  await page.getByRole('button', { name: 'Run assessment' }).click();
  await expect(page.getByRole('button', { name: 'Inspect' }).first()).toBeVisible();
  await page.screenshot({ path: 'test-results/console-desktop.png', fullPage: true });
  await page.getByRole('button', { name: 'Inspect' }).first().click();
  await expect(page.getByRole('heading', { name: 'Evidence explorer' })).toBeVisible();
  await expect(page).toHaveURL(/\/findings\?assessment=/);
  const downloadPath = await page.getByRole('link', { name: 'Export JSON' }).getAttribute('href');
  await page.reload();
  await expect(page.getByRole('link', { name: 'Export JSON' })).toHaveAttribute(
    'href',
    downloadPath!,
  );
  const exported = await page.request.get(downloadPath!);
  expect(exported.ok()).toBe(true);
  expect((await exported.json()).observation.address).toBe(ADDRESS);
  await expect(page.getByText(/DEMONSTRATION DATA/)).toBeVisible();
  for (const view of ['CBOM', 'QBOM', 'CPM', 'Trust Graph', 'Reports']) {
    await page.getByRole('button', { name: view, exact: true }).click();
    await expect(
      page.getByRole('heading', {
        name: view === 'CPM' ? 'Continuous cryptographic posture' : view,
        exact: true,
      }),
    ).toBeVisible();
  }
  const report = await page.request.get('/api/reports');
  expect(report.ok()).toBe(true);
  expect((await report.json()).assessmentCount).toBeGreaterThan(0);
  await page.getByRole('button', { name: 'Settings' }).click();
  await expect(page.getByText('planned', { exact: true })).toHaveCount(10);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Overview' }).click();
  await page.screenshot({ path: 'test-results/console-mobile.png', fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Open your console' })).toBeVisible();
  await page.getByLabel('Tenant API key').fill(KEY_B);
  await page.getByRole('button', { name: 'Continue to workspace' }).click();
  await expect(page.getByText('Your evidence starts here')).toBeVisible();
  expect((await page.request.get(downloadPath!)).status()).toBe(404);
});
test('rejects cross-origin mutations and incorrect keys', async ({ page }) => {
  await page.goto('/');
  const response = await page.request.post('/api/session', {
    headers: { origin: 'https://untrusted.example' },
    form: { key: KEY_A },
  });
  expect(response.status()).toBe(403);
  await page.getByLabel('Tenant API key').fill('invalid-key-with-at-least-32-characters');
  await page.getByRole('button', { name: 'Continue to workspace' }).click();
  await expect(page.getByRole('main').getByRole('alert')).toHaveText('API key was not accepted');
});

test('all prescribed console routes require a session and support direct navigation', async ({
  page,
}) => {
  const routes = [
    ['/dashboard', 'Your cryptographic landscape.'],
    ['/inventory', 'Every observation, in context.'],
    ['/cbom', 'Know the cryptographic dependencies.'],
    ['/qbom', 'Plan from verified evidence.'],
    ['/posture', 'Trace posture and change.'],
    ['/trust-graph', 'Explore observed relationships.'],
    ['/findings', 'Findings you can trace.'],
    ['/migrations', 'Migration readiness.'],
    ['/reports', 'Intelligence you can share.'],
    ['/settings', 'Workspace configuration.'],
  ] as const;
  for (const [path] of routes) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: 'Open your console' })).toBeVisible();
  }
  await page.getByLabel('Tenant API key').fill(KEY_B);
  await page.getByRole('button', { name: 'Continue to workspace' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  for (const [path, heading] of routes) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
    await expect(page.locator('nav [aria-current="page"]')).toHaveCount(1);
  }
  await page.goBack();
  await expect(page).toHaveURL(/\/reports$/);
  await expect(page.getByRole('heading', { name: 'Intelligence you can share.' })).toBeVisible();
});
