import { Page, Route } from '@playwright/test';

type Dict = Record<string, unknown>;

type ProviderField = {
  key: string;
  label?: string;
  secret?: boolean;
  multiline?: boolean;
};

type ProviderCatalogItem = {
  name: string;
  description?: string;
  fields?: ProviderField[];
  example_extra?: Dict;
};

type ProviderConfigItem = {
  id: number;
  name: string;
  provider: string;
  enabled: boolean;
  description?: string;
  proxy?: string | null;
  proxy_masked?: string;
  proxy_configured?: boolean;
  extra?: Dict;
  last_validation_ok?: boolean | null;
};

type RecentSessionItem = {
  session_id: string;
  state: string;
  provider: string;
  email: string;
  purpose?: string;
  created_at?: string;
  expires_at?: string;
  error_code?: string;
  error_message?: string;
};

export type AdminMockOptions = {
  authenticated?: boolean;
  username?: string;
  csrfToken?: string;
  requireCsrf?: boolean;
  catalog?: ProviderCatalogItem[];
  configs?: ProviderConfigItem[];
  sessions?: RecentSessionItem[];
};

export type AdminMockHandles = {
  state: {
    authenticated: boolean;
    username: string;
    csrfToken: string;
    catalog: ProviderCatalogItem[];
    configs: ProviderConfigItem[];
    sessions: RecentSessionItem[];
  };
  calls: {
    lastCreatePayload: Dict | null;
    lastUpdatePayload: Dict | null;
    lastWriteCsrfHeader: string;
    lastSessionQuery: Record<string, string>;
  };
};

function fulfillJson(route: Route, status: number, payload: unknown) {
  return route.fulfill({
    status,
    contentType: 'application/json; charset=utf-8',
    body: JSON.stringify(payload),
  });
}

function parseJsonBody(route: Route): Dict {
  try {
    return (route.request().postDataJSON() || {}) as Dict;
  } catch (_error) {
    return {};
  }
}

function parseId(url: string): number | null {
  const match = /\/provider-configs\/(\d+)/.exec(url);
  if (!match) return null;
  const id = Number(match[1]);
  return Number.isFinite(id) ? id : null;
}

function sanitizeConfigSummary(item: ProviderConfigItem): ProviderConfigItem {
  return {
    id: item.id,
    name: item.name,
    provider: item.provider,
    enabled: item.enabled,
    description: item.description || '',
    proxy_masked: item.proxy ? '***' : '',
    proxy_configured: Boolean(item.proxy),
    last_validation_ok: item.last_validation_ok ?? null,
    extra: item.extra || {},
  };
}

export async function installAdminApiMock(page: Page, options: AdminMockOptions = {}): Promise<AdminMockHandles> {
  const state = {
    authenticated: options.authenticated ?? true,
    username: options.username || 'admin',
    csrfToken: options.csrfToken || 'csrf-e2e',
    catalog:
      options.catalog ||
      [
        {
          name: 'applemail',
          description: 'Apple Mail provider',
          fields: [
            { key: 'token', label: 'Token', secret: true },
            { key: 'mailbox', label: 'Mailbox' },
          ],
          example_extra: { token: 'demo-token', mailbox: 'demo-mailbox' },
        },
        {
          name: 'luckmail',
          description: 'LuckMail provider',
          fields: [{ key: 'api_key', label: 'API Key', secret: true }],
          example_extra: { api_key: 'lk-demo' },
        },
      ],
    configs:
      options.configs ||
      [
        {
          id: 1,
          name: 'default-applemail',
          provider: 'applemail',
          enabled: true,
          description: '默认配置',
          proxy: null,
          proxy_configured: false,
          proxy_masked: '',
          extra: { token: '***', mailbox: 'default' },
          last_validation_ok: true,
        },
      ],
    sessions:
      options.sessions ||
      [
        {
          session_id: 'sess-001',
          state: 'leased',
          provider: 'applemail',
          email: 'demo@example.com',
          purpose: 'signup',
          created_at: '2026-04-11T10:00:00Z',
          expires_at: '2026-04-11T10:10:00Z',
        },
      ],
  };

  const calls = {
    lastCreatePayload: null as Dict | null,
    lastUpdatePayload: null as Dict | null,
    lastWriteCsrfHeader: '',
    lastSessionQuery: {} as Record<string, string>,
  };

  const requireCsrf = options.requireCsrf ?? true;

  const ensureCsrf = (route: Route): boolean => {
    const header = route.request().headers()['x-csrf-token'] || '';
    calls.lastWriteCsrfHeader = header;
    if (!requireCsrf) return true;
    return header === state.csrfToken;
  };

  await page.route('**/api/admin/auth/login', async (route) => {
    const body = parseJsonBody(route);
    if (!body.username || !body.password) {
      await fulfillJson(route, 400, { detail: { code: 'BAD_REQUEST', message: 'username/password required' } });
      return;
    }
    state.authenticated = true;
    await fulfillJson(route, 200, { ok: true, username: state.username });
  });

  await page.route('**/api/admin/auth/logout', async (route) => {
    state.authenticated = false;
    await fulfillJson(route, 200, { ok: true });
  });

  await page.route('**/api/admin/auth/me', async (route) => {
    if (!state.authenticated) {
      await fulfillJson(route, 401, { detail: { code: 'UNAUTHORIZED', message: 'admin login required' } });
      return;
    }
    await fulfillJson(route, 200, { username: state.username });
  });

  await page.route('**/api/admin/provider-catalog', async (route) => {
    await fulfillJson(route, 200, { providers: state.catalog });
  });

  await page.route(/.*\/api\/admin\/provider-configs\/\d+\/validate(?:\?.*)?$/, async (route) => {
    if (!ensureCsrf(route)) {
      await fulfillJson(route, 403, { detail: { code: 'CSRF_FAILED', message: 'invalid csrf token' } });
      return;
    }
    const id = parseId(route.request().url());
    const target = state.configs.find((it) => it.id === id);
    if (!target) {
      await fulfillJson(route, 404, { detail: { code: 'NOT_FOUND', message: 'config not found' } });
      return;
    }
    target.last_validation_ok = true;
    await fulfillJson(route, 200, {
      id,
      validation: {
        ok: true,
        message: 'mock validation success',
      },
    });
  });

  await page.route(/.*\/api\/admin\/provider-configs\/\d+(?:\?.*)?$/, async (route) => {
    const req = route.request();
    const id = parseId(req.url());
    const method = req.method().toUpperCase();
    const index = state.configs.findIndex((it) => it.id === id);

    if (method === 'GET') {
      if (index < 0) {
        await fulfillJson(route, 404, { detail: { code: 'NOT_FOUND', message: 'config not found' } });
        return;
      }
      await fulfillJson(route, 200, state.configs[index]);
      return;
    }

    if (method === 'PUT') {
      if (!ensureCsrf(route)) {
        await fulfillJson(route, 403, { detail: { code: 'CSRF_FAILED', message: 'invalid csrf token' } });
        return;
      }
      if (index < 0) {
        await fulfillJson(route, 404, { detail: { code: 'NOT_FOUND', message: 'config not found' } });
        return;
      }
      const body = parseJsonBody(route);
      calls.lastUpdatePayload = body;
      state.configs[index] = {
        ...state.configs[index],
        ...(body as ProviderConfigItem),
      };
      await fulfillJson(route, 200, state.configs[index]);
      return;
    }

    if (method === 'DELETE') {
      if (!ensureCsrf(route)) {
        await fulfillJson(route, 403, { detail: { code: 'CSRF_FAILED', message: 'invalid csrf token' } });
        return;
      }
      if (index >= 0) {
        state.configs.splice(index, 1);
      }
      await fulfillJson(route, 200, { ok: true });
      return;
    }

    await fulfillJson(route, 405, { detail: { code: 'METHOD_NOT_ALLOWED', message: 'method not supported' } });
  });

  await page.route(/.*\/api\/admin\/provider-configs(?:\?.*)?$/, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();

    if (method === 'GET') {
      const url = new URL(req.url());
      const q = (url.searchParams.get('q') || '').toLowerCase();
      const provider = url.searchParams.get('provider') || '';
      const enabledRaw = url.searchParams.get('enabled');
      const enabled = enabledRaw === 'true' ? true : enabledRaw === 'false' ? false : null;
      const items = state.configs
        .filter((it) => {
          if (provider && it.provider !== provider) return false;
          if (enabled !== null && it.enabled !== enabled) return false;
          if (!q) return true;
          return `${it.name} ${it.description || ''}`.toLowerCase().includes(q);
        })
        .map(sanitizeConfigSummary);
      await fulfillJson(route, 200, { items });
      return;
    }

    if (method === 'POST') {
      if (!ensureCsrf(route)) {
        await fulfillJson(route, 403, { detail: { code: 'CSRF_FAILED', message: 'invalid csrf token' } });
        return;
      }
      const body = parseJsonBody(route);
      calls.lastCreatePayload = body;
      const id = state.configs.length ? Math.max(...state.configs.map((it) => it.id)) + 1 : 1;
      const saved: ProviderConfigItem = {
        id,
        name: String(body.name || ''),
        provider: String(body.provider || ''),
        enabled: Boolean(body.enabled ?? true),
        description: String(body.description || ''),
        proxy: (body.proxy as string | null) || null,
        proxy_configured: Boolean(body.proxy),
        proxy_masked: body.proxy ? '***' : '',
        extra: (body.extra as Dict) || {},
        last_validation_ok: null,
      };
      state.configs.unshift(saved);
      await fulfillJson(route, 200, saved);
      return;
    }

    await fulfillJson(route, 405, { detail: { code: 'METHOD_NOT_ALLOWED', message: 'method not supported' } });
  });

  await page.route('**/api/admin/recent-sessions**', async (route) => {
    const reqUrl = new URL(route.request().url());
    const provider = reqUrl.searchParams.get('provider') || '';
    const stateFilter = reqUrl.searchParams.get('state') || '';
    calls.lastSessionQuery = {
      provider,
      state: stateFilter,
    };

    const items = state.sessions.filter((it) => {
      if (provider && it.provider !== provider) return false;
      if (stateFilter && it.state !== stateFilter) return false;
      return true;
    });

    await fulfillJson(route, 200, { items });
  });

  return { state, calls };
}
