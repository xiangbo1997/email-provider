import { expect, test } from '@playwright/test';

import { installAdminApiMock } from './support/admin-mock';

test.describe('Admin Dashboard', () => {
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

  test('加载配置摘要与会话面板', async ({ page }) => {
    await installAdminApiMock(page, { authenticated: true });

    await page.goto('/admin');

    await expect(page.getByTestId('admin-shell')).toBeVisible();
    await expect(page.getByTestId('summary-config-total')).toHaveText('1');
    await expect(page.getByTestId('config-list')).toContainText('default-applemail');
    await expect(page.getByTestId('session-list')).toContainText('demo@example.com');
    await expect(page.getByTestId('provider-guide-name')).toContainText('applemail');
  });

  test('新建配置请求携带 CSRF，且无前端 API Key 存储字段', async ({ page }) => {
    const mocks = await installAdminApiMock(page, { authenticated: true });

    await page.goto('/admin');

    await page.getByTestId('config-create-button').click();
    await page.getByTestId('config-name-input').fill('new-provider-config');
    await page.getByTestId('config-provider-select').selectOption('applemail');
    await page.getByTestId('config-description-input').fill('created by e2e');
    await page.getByTestId('config-save').click();

    await expect.poll(() => mocks.calls.lastWriteCsrfHeader).toBe('csrf-e2e');
    await expect.poll(() => Boolean(mocks.calls.lastCreatePayload)).toBeTruthy();

    const payload = mocks.calls.lastCreatePayload || {};
    expect(payload).not.toHaveProperty('api_key');
    expect(payload).not.toHaveProperty('apiKey');
    expect(payload).not.toHaveProperty('x_api_key');

    const storageKeys = await page.evaluate(() => {
      const keys = [...Object.keys(window.localStorage), ...Object.keys(window.sessionStorage)];
      return keys.filter((key) => /api[_-]?key/i.test(key));
    });
    expect(storageKeys).toEqual([]);
  });

  test('provider 说明渲染为纯文本，避免注入执行', async ({ page }) => {
    await installAdminApiMock(page, {
      authenticated: true,
      catalog: [
        {
          name: 'xss-provider',
          description: '<img src=x onerror=alert(1)>description',
          fields: [{ key: 'token', label: '<script>alert(1)</script>', secret: true }],
          example_extra: { token: '<svg onload=alert(1)>' },
        },
      ],
      configs: [
        {
          id: 1,
          name: 'xss-config',
          provider: 'xss-provider',
          enabled: true,
          description: 'xss check',
          extra: { token: 'demo' },
        },
      ],
    });

    await page.goto('/admin');

    await expect(page.getByTestId('provider-guide-name')).toContainText('xss-provider');
    await expect(page.locator('#providerGuide img')).toHaveCount(0);
    await expect(page.locator('#providerGuide script')).toHaveCount(0);
    await expect(page.getByTestId('provider-example-json')).toContainText('<svg onload=alert(1)>');
  });
});
