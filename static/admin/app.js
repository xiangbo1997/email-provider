const PAGE = document.body?.dataset?.page || "";

const state = {
  me: null,
  catalog: [],
  configs: [],
  selectedConfigId: null,
  selectedConfig: null,
  sessions: [],
  usingAdvancedJson: false,
};

function getCookie(name) {
  const prefix = `${name}=`;
  const chunks = document.cookie ? document.cookie.split(";") : [];
  for (const raw of chunks) {
    const item = raw.trim();
    if (item.startsWith(prefix)) {
      return decodeURIComponent(item.slice(prefix.length));
    }
  }
  return "";
}

function csrfToken() {
  return getCookie("email_provider_admin_csrf");
}

function isWriteMethod(method) {
  const m = String(method || "GET").toUpperCase();
  return ["POST", "PUT", "PATCH", "DELETE"].includes(m);
}

async function fetchJson(url, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const headers = {
    ...(options.headers || {}),
  };

  if (!headers["Content-Type"] && options.body && typeof options.body === "string") {
    headers["Content-Type"] = "application/json";
  }

  if (isWriteMethod(method)) {
    const token = csrfToken();
    if (token) {
      headers["X-CSRF-Token"] = token;
    }
  }

  const response = await fetch(url, {
    ...options,
    method,
    headers,
    credentials: "include",
  });

  const text = await response.text();
  let payload = {};
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (_error) {
      payload = { message: text };
    }
  }

  if (!response.ok) {
    const err = new Error(payload?.detail?.message || payload?.message || `HTTP ${response.status}`);
    err.status = response.status;
    err.payload = payload;
    throw err;
  }

  return payload;
}

function toast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.textContent = message;
  container.appendChild(node);
  setTimeout(() => {
    node.classList.add("closing");
    setTimeout(() => node.remove(), 180);
  }, 2800);
}

function toPrettyJson(value) {
  return JSON.stringify(value || {}, null, 2);
}

function parseJsonOrThrow(text) {
  const raw = String(text || "").trim();
  if (!raw) return {};
  return JSON.parse(raw);
}

function getProviderSpec(provider) {
  return state.catalog.find((item) => item.name === provider) || null;
}

function setFormStatus(message, tone = "muted") {
  const el = document.getElementById("formStatus");
  if (!el) return;
  el.className = tone === "danger" ? "hint danger-text" : "hint";
  el.textContent = message;
}

function maskProxyText(item) {
  if (item.proxy_masked) return item.proxy_masked;
  if (item.proxy_configured === true) return "代理：已配置";
  if (item.proxy_configured === false) return "代理：未配置";
  return "代理：未知";
}

function renderSummary() {
  const total = state.configs.length;
  const enabled = state.configs.filter((it) => Boolean(it.enabled)).length;
  const sessions = state.sessions.length;
  const failed = state.sessions.filter((it) => String(it.state || "").toLowerCase() === "failed").length;

  const set = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.textContent = String(value);
  };

  set("summaryConfigTotal", total);
  set("summaryConfigEnabled", enabled);
  set("summarySessionRecent", sessions);
  set("summarySessionFailed", failed);
}

function renderProviderGuide(providerName) {
  const root = document.getElementById("providerGuide");
  if (!root) return;
  root.innerHTML = "";

  const spec = getProviderSpec(providerName);
  if (!spec) {
    root.innerHTML = '<div class="empty">暂无 provider 说明。</div>';
    return;
  }

  const card = document.createElement("article");
  card.className = "guide-card";

  const chip = document.createElement("div");
  chip.className = "chip";
  chip.setAttribute("data-testid", "provider-guide-name");
  chip.textContent = String(spec.name || "");
  card.appendChild(chip);

  const title = document.createElement("h3");
  title.textContent = spec.description || "暂无描述";
  card.appendChild(title);

  const fieldsWrap = document.createElement("div");
  fieldsWrap.className = "guide-fields";
  const fields = Array.isArray(spec.fields) ? spec.fields : [];
  if (!fields.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "该 provider 无额外字段。";
    fieldsWrap.appendChild(empty);
  } else {
    for (const field of fields) {
      const fieldNode = document.createElement("div");
      fieldNode.className = "guide-field";
      fieldNode.setAttribute("data-testid", `provider-guide-field-${field.key}`);

      const keyNode = document.createElement("strong");
      keyNode.textContent = String(field.key || "");
      fieldNode.appendChild(keyNode);

      const flags = [];
      if (field.secret) flags.push("secret");
      if (field.multiline) flags.push("multiline");
      const flagText = flags.length ? ` · ${flags.join(" / ")}` : "";

      const labelNode = document.createElement("div");
      labelNode.className = "muted";
      labelNode.textContent = `${field.label || ""}${flagText}`;
      fieldNode.appendChild(labelNode);
      fieldsWrap.appendChild(fieldNode);
    }
  }
  card.appendChild(fieldsWrap);

  const example = document.createElement("pre");
  example.className = "inline-json";
  example.setAttribute("data-testid", "provider-example-json");
  example.textContent = toPrettyJson(spec.example_extra || {});
  card.appendChild(example);

  root.appendChild(card);
}

function applyProviderOptions(selectNode, placeholder = "全部 provider") {
  if (!selectNode) return;
  selectNode.innerHTML = "";
  const empty = document.createElement("option");
  empty.value = "";
  empty.textContent = placeholder;
  selectNode.appendChild(empty);
  for (const item of state.catalog) {
    const option = document.createElement("option");
    option.value = String(item.name || "");
    option.textContent = String(item.name || "");
    selectNode.appendChild(option);
  }
}

function clearProviderFilters() {
  const providerFilter = document.getElementById("configProviderFilter");
  const sessionProviderFilter = document.getElementById("sessionProviderFilter");
  applyProviderOptions(providerFilter, "全部 provider");
  applyProviderOptions(sessionProviderFilter, "全部 provider");
}

function renderConfigList() {
  const root = document.getElementById("configList");
  if (!root) return;
  root.innerHTML = "";

  if (!state.configs.length) {
    root.innerHTML = '<div class="empty">暂无配置，请点击“新建”。</div>';
    return;
  }

  const template = document.getElementById("configCardTemplate");
  for (const item of state.configs) {
    const node = template.content.firstElementChild.cloneNode(true);
    node.querySelector(".config-name").textContent = item.name || `#${item.id}`;
    node.querySelector(".config-meta").textContent = [
      item.provider || "unknown",
      item.enabled ? "enabled" : "disabled",
      maskProxyText(item),
      item.last_validation_ok === true ? "校验通过" : item.last_validation_ok === false ? "校验失败" : "未校验",
    ].join(" · ");

    node.setAttribute("data-testid", `config-card-${item.id}`);
    if (item.id === state.selectedConfigId) {
      node.classList.add("active");
    }

    node.addEventListener("click", async () => {
      try {
        await loadConfigDetail(item.id);
      } catch (error) {
        toast(`加载配置失败: ${error.message}`, "danger");
      }
    });
    root.appendChild(node);
  }
}

function renderSessionList() {
  const root = document.getElementById("sessionList");
  if (!root) return;
  root.innerHTML = "";

  if (!state.sessions.length) {
    root.innerHTML = '<div class="empty">暂无会话记录。</div>';
    return;
  }

  for (const item of state.sessions) {
    const card = document.createElement("article");
    card.className = "session-card";
    card.setAttribute("data-testid", `session-card-${item.session_id}`);
    const chipDanger = String(item.state || "").toLowerCase() === "failed";
    const chip = document.createElement("div");
    chip.className = `chip ${chipDanger ? "danger" : ""}`.trim();
    chip.textContent = String(item.state || "unknown");
    card.appendChild(chip);

    const title = document.createElement("h3");
    title.textContent = `${item.email || "(no email)"} · ${item.provider || "unknown"}`;
    card.appendChild(title);

    const createMetaLine = (text) => {
      const div = document.createElement("div");
      div.className = "muted";
      div.textContent = text;
      return div;
    };
    card.appendChild(createMetaLine(`purpose: ${item.purpose || "-"}`));
    card.appendChild(createMetaLine(`created: ${item.created_at || "-"}`));
    card.appendChild(createMetaLine(`expires: ${item.expires_at || "-"}`));
    if (item.error_message) {
      card.appendChild(createMetaLine(`error: ${item.error_code || "-"} · ${item.error_message}`));
    }
    root.appendChild(card);
  }
}

function fillProviderFields(providerName, extra = {}) {
  const container = document.getElementById("providerFieldsContainer");
  if (!container) return;
  container.innerHTML = "";

  const spec = getProviderSpec(providerName);
  const fields = spec?.fields || [];

  for (const field of fields) {
    const row = document.createElement("label");
    row.className = "provider-field";
    row.setAttribute("data-testid", `config-field-${field.key}`);

    const title = document.createElement("span");
    title.textContent = field.label || field.key;

    let input;
    if (field.multiline) {
      input = document.createElement("textarea");
      input.rows = 4;
    } else {
      input = document.createElement("input");
      input.type = field.secret ? "password" : "text";
    }
    input.value = extra?.[field.key] != null ? String(extra[field.key]) : "";
    input.dataset.extraKey = field.key;

    row.appendChild(title);

    if (field.secret) {
      const wrapper = document.createElement("div");
      wrapper.className = "input-with-action";
      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "ghost";
      toggle.textContent = "显示";
      toggle.setAttribute("data-testid", `config-secret-toggle-${field.key}`);
      toggle.addEventListener("click", () => {
        const nextIsPassword = input.type !== "password";
        input.type = nextIsPassword ? "password" : "text";
        toggle.textContent = nextIsPassword ? "显示" : "隐藏";
      });
      wrapper.appendChild(input);
      wrapper.appendChild(toggle);
      row.appendChild(wrapper);
    } else {
      row.appendChild(input);
    }

    container.appendChild(row);
  }
}

function getFormProvider() {
  return document.getElementById("providerSelect")?.value || "";
}

function collectExtraFromForm() {
  if (state.usingAdvancedJson) {
    return parseJsonOrThrow(document.getElementById("extraJsonInput")?.value || "{}");
  }
  const container = document.getElementById("providerFieldsContainer");
  const out = {};
  if (!container) return out;
  container.querySelectorAll("[data-extra-key]").forEach((input) => {
    const key = input.dataset.extraKey;
    out[key] = input.value;
  });
  return out;
}

function renderEditor(config) {
  const normalized = config || {};
  state.selectedConfig = normalized;

  const setVal = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.value = value ?? "";
  };

  const setChecked = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.checked = Boolean(value);
  };

  setVal("configIdInput", normalized.id || "");
  setVal("configNameInput", normalized.name || "");
  setVal("descriptionInput", normalized.description || "");
  setVal("proxyInput", normalized.proxy || "");
  setChecked("enabledCheckbox", normalized.enabled ?? true);

  const providerSelect = document.getElementById("providerSelect");
  if (providerSelect) {
    providerSelect.innerHTML = "";
    for (const item of state.catalog) {
      const option = document.createElement("option");
      option.value = String(item.name || "");
      option.textContent = String(item.name || "");
      providerSelect.appendChild(option);
    }
    providerSelect.value = normalized.provider || state.catalog[0]?.name || "";
  }

  const extra = normalized.extra || {};
  fillProviderFields(getFormProvider(), extra);
  const extraJson = document.getElementById("extraJsonInput");
  if (extraJson) {
    extraJson.value = toPrettyJson(extra);
  }

  renderProviderGuide(getFormProvider());
  renderConfigList();
}

function composeConfigPayload() {
  return {
    name: String(document.getElementById("configNameInput")?.value || "").trim(),
    provider: getFormProvider(),
    enabled: Boolean(document.getElementById("enabledCheckbox")?.checked),
    description: String(document.getElementById("descriptionInput")?.value || "").trim(),
    proxy: String(document.getElementById("proxyInput")?.value || "").trim() || null,
    extra: collectExtraFromForm(),
  };
}

function buildQuery(baseUrl, pairs) {
  const url = new URL(baseUrl, window.location.origin);
  for (const [key, value] of pairs) {
    if (value === undefined || value === null || value === "") continue;
    url.searchParams.set(key, String(value));
  }
  return `${url.pathname}${url.search}`;
}

async function loadMe() {
  const me = await fetchJson("/api/admin/auth/me");
  state.me = me;
  const node = document.getElementById("adminIdentity");
  if (node) node.textContent = me.username || me.user || "admin";
}

async function loadCatalog() {
  const payload = await fetchJson("/api/admin/provider-catalog");
  const providers = payload.providers || payload.items || payload.data || [];
  state.catalog = Array.isArray(providers) ? providers : [];
  clearProviderFilters();
}

async function loadConfigSummaries() {
  const q = document.getElementById("configSearchInput")?.value || "";
  const provider = document.getElementById("configProviderFilter")?.value || "";
  const enabled = document.getElementById("configEnabledFilter")?.value || "";
  const url = buildQuery("/api/admin/provider-configs", [["q", q], ["provider", provider], ["enabled", enabled], ["limit", 200]]);
  const payload = await fetchJson(url);
  const items = payload.items || payload.configs || payload.data || payload.results || [];
  state.configs = Array.isArray(items) ? items : [];
  renderConfigList();
}

async function loadConfigDetail(configId) {
  const payload = await fetchJson(`/api/admin/provider-configs/${configId}`);
  const detail = payload.item || payload.config || payload.data || payload;
  state.selectedConfigId = detail.id;
  renderEditor(detail);
  setFormStatus(`已加载配置 ${detail.name || detail.id}`);
}

async function loadSessions() {
  const provider = document.getElementById("sessionProviderFilter")?.value || "";
  const stateFilter = document.getElementById("sessionStateFilter")?.value || "";
  const url = buildQuery("/api/admin/recent-sessions", [["provider", provider], ["state", stateFilter], ["limit", 30]]);
  const payload = await fetchJson(url);
  const items = payload.items || payload.sessions || payload.data || [];
  state.sessions = Array.isArray(items) ? items : [];
  renderSessionList();
  renderSummary();
}

async function refreshAll() {
  await loadCatalog();
  await loadConfigSummaries();
  if (state.selectedConfigId) {
    await loadConfigDetail(state.selectedConfigId);
  } else if (state.configs[0]) {
    await loadConfigDetail(state.configs[0].id);
  } else {
    renderEditor({ provider: state.catalog[0]?.name || "", extra: {} });
  }
  await loadSessions();
  renderSummary();
}

async function onSaveConfig() {
  const payload = composeConfigPayload();
  if (!payload.name) {
    throw new Error("配置名称不能为空");
  }
  if (!payload.provider) {
    throw new Error("请选择 provider");
  }

  const id = String(document.getElementById("configIdInput")?.value || "").trim();
  const method = id ? "PUT" : "POST";
  const url = id ? `/api/admin/provider-configs/${id}` : "/api/admin/provider-configs";

  const saved = await fetchJson(url, {
    method,
    body: JSON.stringify(payload),
  });

  state.selectedConfigId = saved.id;
  await loadConfigSummaries();
  await loadConfigDetail(saved.id);
  setFormStatus(`已保存配置 ${saved.name}`);
  toast("配置保存成功", "success");
}

async function onValidateConfig() {
  const id = String(document.getElementById("configIdInput")?.value || "").trim();
  if (!id) {
    throw new Error("请先保存配置再校验");
  }
  const res = await fetchJson(`/api/admin/provider-configs/${id}/validate`, { method: "POST" });
  await loadConfigSummaries();
  await loadConfigDetail(res.id || id);
  const ok = res?.validation?.ok === true;
  setFormStatus(`校验${ok ? "通过" : "失败"}: ${res?.validation?.message || "-"}`, ok ? "muted" : "danger");
}

async function onDeleteConfig() {
  const id = String(document.getElementById("configIdInput")?.value || "").trim();
  if (!id) {
    throw new Error("当前没有可删除配置");
  }
  const name = document.getElementById("configNameInput")?.value || `#${id}`;
  if (!window.confirm(`确定删除配置 ${name} 吗？`)) return;
  await fetchJson(`/api/admin/provider-configs/${id}`, { method: "DELETE" });
  state.selectedConfigId = null;
  await loadConfigSummaries();
  if (state.configs[0]) {
    await loadConfigDetail(state.configs[0].id);
  } else {
    renderEditor({ provider: state.catalog[0]?.name || "", extra: {} });
  }
  setFormStatus(`已删除配置 ${name}`);
  toast("删除成功", "success");
}

function bindDashboardEvents() {
  document.getElementById("providerSelect")?.addEventListener("change", () => {
    const provider = getFormProvider();
    fillProviderFields(provider, {});
    renderProviderGuide(provider);
    const spec = getProviderSpec(provider);
    if (!state.usingAdvancedJson) {
      const extraJson = document.getElementById("extraJsonInput");
      if (extraJson) {
        extraJson.value = toPrettyJson(spec?.example_extra || {});
      }
    }
  });

  document.getElementById("advancedJsonToggle")?.addEventListener("change", (event) => {
    state.usingAdvancedJson = event.target.checked;
    const editor = document.getElementById("extraJsonInput");
    if (editor) {
      editor.classList.toggle("hidden", !state.usingAdvancedJson);
      if (state.usingAdvancedJson) {
        editor.value = toPrettyJson(collectExtraFromForm());
      }
    }
  });

  document.getElementById("toggleProxyBtn")?.addEventListener("click", () => {
    const input = document.getElementById("proxyInput");
    const btn = document.getElementById("toggleProxyBtn");
    if (!input || !btn) return;
    const nextPassword = input.type !== "password";
    input.type = nextPassword ? "password" : "text";
    btn.textContent = nextPassword ? "显示" : "隐藏";
  });

  document.getElementById("fillTemplateBtn")?.addEventListener("click", () => {
    const spec = getProviderSpec(getFormProvider());
    const tpl = spec?.example_extra || {};
    const editor = document.getElementById("extraJsonInput");
    if (editor) editor.value = toPrettyJson(tpl);
    fillProviderFields(getFormProvider(), tpl);
    toast("已填充模板", "info");
  });

  document.getElementById("newConfigBtn")?.addEventListener("click", () => {
    state.selectedConfigId = null;
    renderEditor({
      name: "",
      provider: state.catalog[0]?.name || "",
      enabled: true,
      description: "",
      proxy: "",
      extra: getProviderSpec(state.catalog[0]?.name || "")?.example_extra || {},
    });
    setFormStatus("已切换到新建模式");
  });

  document.getElementById("saveConfigBtn")?.addEventListener("click", async () => {
    try {
      await onSaveConfig();
    } catch (error) {
      setFormStatus(`保存失败: ${error.message}`, "danger");
    }
  });

  document.getElementById("validateConfigBtn")?.addEventListener("click", async () => {
    try {
      await onValidateConfig();
    } catch (error) {
      setFormStatus(`校验失败: ${error.message}`, "danger");
    }
  });

  document.getElementById("deleteConfigBtn")?.addEventListener("click", async () => {
    try {
      await onDeleteConfig();
    } catch (error) {
      setFormStatus(`删除失败: ${error.message}`, "danger");
    }
  });

  document.getElementById("configSearchInput")?.addEventListener("input", () => {
    clearTimeout(window.__cfgSearchTimer);
    window.__cfgSearchTimer = setTimeout(() => {
      loadConfigSummaries().catch((error) => toast(`加载配置失败: ${error.message}`, "danger"));
    }, 260);
  });

  document.getElementById("configProviderFilter")?.addEventListener("change", () => {
    loadConfigSummaries().catch((error) => toast(`加载配置失败: ${error.message}`, "danger"));
  });

  document.getElementById("configEnabledFilter")?.addEventListener("change", () => {
    loadConfigSummaries().catch((error) => toast(`加载配置失败: ${error.message}`, "danger"));
  });

  document.getElementById("sessionProviderFilter")?.addEventListener("change", () => {
    loadSessions().catch((error) => toast(`加载会话失败: ${error.message}`, "danger"));
  });

  document.getElementById("sessionStateFilter")?.addEventListener("change", () => {
    loadSessions().catch((error) => toast(`加载会话失败: ${error.message}`, "danger"));
  });

  document.getElementById("refreshSessionsBtn")?.addEventListener("click", () => {
    loadSessions().catch((error) => toast(`加载会话失败: ${error.message}`, "danger"));
  });

  document.getElementById("refreshAllBtn")?.addEventListener("click", () => {
    refreshAll().catch((error) => toast(`刷新失败: ${error.message}`, "danger"));
  });

  document.getElementById("logoutBtn")?.addEventListener("click", async () => {
    try {
      await fetchJson("/api/admin/auth/logout", { method: "POST" });
    } catch (_error) {
      // ignore
    }
    window.location.href = "/admin/login";
  });
}

function bindLoginEvents() {
  const form = document.getElementById("loginForm");
  const err = document.getElementById("loginError");
  const submitBtn = document.getElementById("loginSubmitBtn");

  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (err) {
      err.classList.add("hidden");
      err.textContent = "";
    }

    const username = String(document.getElementById("usernameInput")?.value || "").trim();
    const password = String(document.getElementById("passwordInput")?.value || "");
    if (!username || !password) {
      if (err) {
        err.textContent = "请输入用户名和密码";
        err.classList.remove("hidden");
      }
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "登录中...";
    try {
      await fetchJson("/api/admin/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      window.location.href = "/admin";
    } catch (error) {
      if (err) {
        err.textContent = error.message || "登录失败";
        err.classList.remove("hidden");
      }
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "登录";
    }
  });
}

async function bootLogin() {
  try {
    await fetchJson("/api/admin/auth/me");
    window.location.href = "/admin";
    return;
  } catch (_err) {
    // ignore
  }
  bindLoginEvents();
}

async function bootDashboard() {
  bindDashboardEvents();
  try {
    await loadMe();
  } catch (_error) {
    window.location.href = "/admin/login";
    return;
  }

  try {
    await refreshAll();
    setFormStatus("数据已加载");
  } catch (error) {
    toast(`初始化失败: ${error.message}`, "danger");
    setFormStatus(`初始化失败: ${error.message}`, "danger");
  }
}

if (PAGE === "login") {
  bootLogin();
} else if (PAGE === "dashboard") {
  bootDashboard();
}
