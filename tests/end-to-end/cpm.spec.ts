import { test, expect } from '@playwright/test';
test('CPM schedule, persisted worker health, lifecycle and migration readiness', async ({
  page,
}) => {
  await page.goto('/');
  await page.getByLabel('Tenant API key').fill('browser-admin-fixture-at-least-32-characters');
  await page.getByRole('button', { name: 'Continue to workspace' }).click();
  await page.getByLabel('EVM account address').fill(`0x${'33'.repeat(20)}`);
  await page.getByRole('button', { name: 'Run assessment' }).click();
  await expect(page.getByRole('button', { name: 'Inspect' }).first()).toBeVisible();
  await page.getByRole('button', { name: 'CPM', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Continuous cryptographic posture' }),
  ).toBeVisible();
  await expect(page.getByText('No monitoring schedule for this asset.')).toBeVisible();
  await page.getByLabel('Assessment frequency').selectOption('60');
  await page.getByRole('button', { name: 'Schedule monitoring', exact: true }).click();
  await expect(page.getByText('Monitoring schedule created', { exact: true })).toBeVisible();
  await expect
    .poll(
      async () => {
        await page.getByRole('button', { name: 'Refresh', exact: true }).click();
        return page.getByText('succeeded', { exact: true }).count();
      },
      { timeout: 15000 },
    )
    .toBe(1);
  const finding = page
    .locator('article.finding')
    .filter({ has: page.getByText('Authorization scheme needs discovery', { exact: true }) });
  await finding.getByText('Manage finding', { exact: true }).click();
  await finding
    .getByLabel('Reason', { exact: true })
    .fill('Administrator reviewed available authorization evidence');
  await finding.getByRole('button', { name: 'Record transition' }).click();
  await expect(finding.getByText(/acknowledged/)).toBeVisible();
  await page.getByRole('button', { name: 'Pause monitoring', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Resume monitoring' })).toBeVisible();
  await page.screenshot({ path: 'test-results/cpm-desktop.png', fullPage: true });
  const csrf = await page.request.post('/api/cpm/monitoring', {
    headers: { origin: 'https://untrusted.example' },
    data: {},
  });
  expect(csrf.status()).toBe(403);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: 'test-results/cpm-mobile.png', fullPage: true });
  await page.getByRole('button', { name: 'Migrations', exact: true }).click();
  await page.getByLabel('Goal', { exact: true }).selectOption('cryptographic-migration');
  await page.getByLabel('Acceptance criterion').selectOption('signature_algorithm');
  await page.getByLabel('Expected value').fill('ML-DSA');
  await page.getByRole('button', { name: 'Assess migration readiness' }).click();
  await expect(page.getByText('TECHNICALLY_BLOCKED', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.getByLabel('Tenant API key').fill('browser-analyst-fixture-at-least-32-characters');
  await page.getByRole('button', { name: 'Continue to workspace' }).click();
  await page.getByRole('button', { name: 'CPM', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Record transition' })).toHaveCount(0);
});
