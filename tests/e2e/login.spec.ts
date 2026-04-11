import { expect, test } from '@playwright/test';

import { installAdminApiMock } from './support/admin-mock';

function json(status: number, payload: unknown) {
  return {
    status,
    contentType: 'application/json; charset=utf-8',
    body: JSON.stringify(payload),
  };
}

test.describe('Admin Login', () => {
  test('登录失败时展示错误消息', async ({ page }) => {
    await page.route('**/api/admin/auth/me', async (route) => {
      await route.fulfill(json(401, { detail: { code: 'UNAUTHORIZED', message: 'admin login required' } }));
    });

    await page.route('**/api/admin/auth/login', async (route) => {
      await route.fulfill(json(401, { detail: { code: 'INVALID_ADMIN_CREDENTIALS', message: 'invalid username or password' } }));
    });

    await page.goto('/admin/login');
    await page.getByTestId('login-username').fill('wrong-user');
    await page.getByTestId('login-password').fill('wrong-pass');
    await page.getByTestId('login-submit').click();

    await expect(page.getByTestId('login-error')).toBeVisible();
    await expect(page.getByTestId('login-error')).toContainText('invalid username or password');
  });

  test('登录成功后跳转控制台并加载身份', async ({ page }) => {
    await installAdminApiMock(page, { authenticated: false, username: 'ops-admin' });

    await page.goto('/admin/login');
    await page.getByTestId('login-username').fill('ops-admin');
    await page.getByTestId('login-password').fill('correct-password');
    await page.getByTestId('login-submit').click();

    await expect(page).toHaveURL(/\/admin$/);
    await expect(page.getByTestId('admin-identity')).toContainText('ops-admin');
    await expect(page.getByTestId('summary-config-total')).toHaveText('1');
  });
});
