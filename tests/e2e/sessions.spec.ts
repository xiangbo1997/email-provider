import { expect, test } from '@playwright/test';

import { installAdminApiMock } from './support/admin-mock';

test.describe('Recent Sessions', () => {
  test.beforeEach(async ({ context }) => {
    await context.addCookies([
      {
        name: 'email_provider_admin_csrf',
        value: 'csrf-e2e',
        domain: '127.0.0.1',
        path: '/',
        httpOnly: false,
        secure: false,
        sameSite: 'Lax',
      },
    ]);
  });

  test('按状态筛选会话', async ({ page }) => {
    const mocks = await installAdminApiMock(page, {
      authenticated: true,
      sessions: [
        {
          session_id: 'sess-1',
          state: 'failed',
          provider: 'applemail',
          email: 'failed@example.com',
          purpose: 'signup',
          error_code: 'TIMEOUT',
          error_message: 'poll timeout',
        },
        {
          session_id: 'sess-2',
          state: 'leased',
          provider: 'luckmail',
          email: 'ok@example.com',
          purpose: 'bind',
        },
      ],
    });

    await page.goto('/admin');

    await page.getByTestId('session-filter-state').selectOption('failed');

    await expect.poll(() => mocks.calls.lastSessionQuery.state).toBe('failed');
    await expect(page.getByTestId('session-list')).toContainText('failed@example.com');
    await expect(page.getByTestId('session-list')).not.toContainText('ok@example.com');
    await expect(page.getByTestId('summary-session-failed')).toHaveText('1');
  });
});
