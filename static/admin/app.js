const storageKey = "email_provider_admin_api_key";

const state = {
  apiKey: sessionStorage.getItem(storageKey) || "",
  catalog: [],
  configs: [],
  selectedConfigId: null,
};

const el = {
  apiKeyInput: document.getElementById("apiKeyInput"),
  saveApiKeyBtn: document.getElementById("saveApiKeyBtn"),
  clearApiKeyBtn: document.getElementById("clearApiKeyBtn"),
  authStatus: document.getElementById("authStatus"),
  configList: document.getElementById("configList"),
  refreshConfigsBtn: document.getElementById("refreshConfigsBtn"),
  newConfigBtn: document.getElementById("newConfigBtn"),
  fillTemplateBtn: document.getElementById("fillTemplateBtn"),
  saveConfigBtn: document.getElementById("saveConfigBtn"),
  validateConfigBtn: document.getElementById("validateConfigBtn"),
  deleteConfigBtn: document.getElementById("deleteConfigBtn"),
  providerGuide: document.getElementById("providerGuide"),
  sessionList: document.getElementById("sessionList"),
  refreshSessionsBtn: document.getElementById("refreshSessionsBtn"),
  configIdInput: document.getElementById("configIdInput"),
  configNameInput: document.getElementById("configNameInput"),
  providerSelect: document.getElementById("providerSelect"),
  enabledCheckbox: document.getElementById("enabledCheckbox"),
  proxyInput: document.getElementById("proxyInput"),
  descriptionInput: document.getElementById("descriptionInput"),
  extraJsonInput: document.getElementById("extraJsonInput"),
  formStatus: document.getElementById("formStatus"),
  configCardTemplate: document.getElementById("configCardTemplate"),
};

function authHeaders() {
  const headers = { "Content-Type": "application/json" };
  if (state.apiKey) {
    headers.Authorization = `Bearer ${state.apiKey}`;
  }
  return headers;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      ...authHeaders(),
      ...(options.headers || {}),
    },
  });

  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch (_error) {
    payload = { message: text };
  }
  if (!response.ok) {
    const message = payload?.detail?.message || payload?.message || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return payload;
}

function setStatus(message, tone = "muted") {
  el.formStatus.textContent = message;
  el.formStatus.className = tone === "danger" ? "hint danger-text" : "hint";
}

function setAuthStatus(message) {
  el.authStatus.textContent = message;
}

function safeParseJson(text) {
  const raw = String(text || "").trim();
  if (!raw) return {};
  return JSON.parse(raw);
}

function prettyJson(value) {
  return JSON.stringify(value || {}, null, 2);
}

function selectedProviderSpec() {
  return state.catalog.find((item) => item.name === el.providerSelect.value) || null;
}

function resetForm(prefill = {}) {
  el.configIdInput.value = prefill.id || "";
  el.configNameInput.value = prefill.name || "";
  el.providerSelect.value = prefill.provider || state.catalog[0]?.name || "";
  el.enabledCheckbox.checked = prefill.enabled ?? true;
  el.proxyInput.value = prefill.proxy || "";
  el.descriptionInput.value = prefill.description || "";
  el.extraJsonInput.value = prettyJson(prefill.extra || {});
  state.selectedConfigId = prefill.id || null;
  renderProviderGuide();
}

function renderConfigList() {
  el.configList.innerHTML = "";
  if (!state.configs.length) {
    el.configList.innerHTML = '<div class="empty">还没有保存的 provider 配置。</div>';
    return;
  }

  for (const item of state.configs) {
    const node = el.configCardTemplate.content.firstElementChild.cloneNode(true);
    node.querySelector(".config-name").textContent = item.name;
    node.querySelector(".config-meta").textContent = `${item.provider} · ${item.enabled ? "enabled" : "disabled"} · ${item.proxy || "no proxy"}`;
    if (item.id === state.selectedConfigId) {
      node.classList.add("active");
    }
    node.addEventListener("click", () => {
      state.selectedConfigId = item.id;
      resetForm(item);
      renderConfigList();
      setStatus(`已加载配置 ${item.name}`);
    });
    el.configList.appendChild(node);
  }
}

function renderProviderSelect() {
  el.providerSelect.innerHTML = "";
  for (const item of state.catalog) {
    const option = document.createElement("option");
    option.value = item.name;
    option.textContent = item.name;
    el.providerSelect.appendChild(option);
  }
}

function renderProviderGuide() {
  const spec = selectedProviderSpec();
  if (!spec) {
    el.providerGuide.innerHTML = '<div class="empty">没有 provider 信息。</div>';
    return;
  }

  const fields = (spec.fields || [])
    .map((field) => {
      const flags = [];
      if (field.secret) flags.push("secret");
      if (field.multiline) flags.push("multiline");
      const flagText = flags.length ? ` · ${flags.join(" / ")}` : "";
      return `
        <div class="guide-field">
          <strong>${field.key}</strong>
          <div class="muted">${field.label || ""}${flagText}</div>
        </div>
      `;
    })
    .join("");

  el.providerGuide.innerHTML = `
    <article class="guide-card">
      <div class="chip">${spec.name}</div>
      <h3>${spec.description || "没有额外说明"}</h3>
      <div class="guide-fields">
        ${fields || '<div class="muted">这个 provider 当前没有额外字段。</div>'}
      </div>
      <pre class="inline-json">${prettyJson(spec.example_extra || {})}</pre>
    </article>
  `;
}

function renderSessions(items) {
  el.sessionList.innerHTML = "";
  if (!items.length) {
    el.sessionList.innerHTML = '<div class="empty">还没有邮箱会话记录。</div>';
    return;
  }

  for (const item of items) {
    const card = document.createElement("article");
    card.className = "session-card";
    const chipClass = item.state === "failed" ? "chip danger" : "chip";
    const errorBlock = item.error_message
      ? `<div class="muted">error: ${item.error_code || "-"} · ${item.error_message}</div>`
      : "";
    card.innerHTML = `
      <div class="${chipClass}">${item.state}</div>
      <h3>${item.email || "(no email)"} · ${item.provider}</h3>
      <div class="muted">purpose: ${item.purpose || "-"}</div>
      <div class="muted">created: ${item.created_at}</div>
      <div class="muted">expires: ${item.expires_at}</div>
      ${errorBlock}
    `;
    el.sessionList.appendChild(card);
  }
}

async function loadCatalog() {
  const payload = await fetchJson("/api/admin/provider-catalog");
  state.catalog = payload.providers || [];
  renderProviderSelect();
  if (!el.providerSelect.value && state.catalog[0]) {
    el.providerSelect.value = state.catalog[0].name;
  }
  renderProviderGuide();
}

async function loadConfigs() {
  const payload = await fetchJson("/api/admin/provider-configs");
  state.configs = payload.items || [];
  renderConfigList();
}

async function loadSessions() {
  const payload = await fetchJson("/api/admin/recent-sessions?limit=20");
  renderSessions(payload.items || []);
}

async function refreshAll() {
  if (!state.apiKey) {
    setAuthStatus("请先输入 API Key");
    return;
  }
  try {
    await loadCatalog();
    await loadConfigs();
    await loadSessions();
    setAuthStatus("API Key 有效，数据已刷新");
  } catch (error) {
    setAuthStatus(`加载失败: ${error.message}`);
  }
}

function currentPayload() {
  return {
    name: el.configNameInput.value.trim(),
    provider: el.providerSelect.value,
    enabled: el.enabledCheckbox.checked,
    proxy: el.proxyInput.value.trim() || null,
    description: el.descriptionInput.value.trim(),
    extra: safeParseJson(el.extraJsonInput.value),
  };
}

async function saveCurrentConfig() {
  const payload = currentPayload();
  if (!payload.name) {
    throw new Error("配置名称不能为空");
  }

  const configId = el.configIdInput.value.trim();
  const method = configId ? "PUT" : "POST";
  const url = configId
    ? `/api/admin/provider-configs/${configId}`
    : "/api/admin/provider-configs";

  const saved = await fetchJson(url, {
    method,
    body: JSON.stringify(payload),
  });
  state.selectedConfigId = saved.id;
  await loadConfigs();
  resetForm(saved);
  renderConfigList();
  setStatus(`已保存配置 ${saved.name}`);
}

async function validateCurrentConfig() {
  const configId = el.configIdInput.value.trim();
  if (!configId) {
    throw new Error("请先保存配置，再执行校验");
  }
  const result = await fetchJson(`/api/admin/provider-configs/${configId}/validate`, {
    method: "POST",
  });
  await loadConfigs();
  resetForm(result);
  renderConfigList();
  const ok = result.validation?.ok ? "通过" : "失败";
  setStatus(`校验${ok}: ${result.validation?.message || "-"}`, result.validation?.ok ? "muted" : "danger");
}

async function deleteCurrentConfig() {
  const configId = el.configIdInput.value.trim();
  if (!configId) {
    throw new Error("当前没有可删除的配置");
  }
  const currentName = el.configNameInput.value.trim() || `#${configId}`;
  const confirmed = window.confirm(`确定删除配置 ${currentName} 吗？`);
  if (!confirmed) return;
  await fetchJson(`/api/admin/provider-configs/${configId}`, { method: "DELETE" });
  resetForm({});
  await loadConfigs();
  setStatus(`已删除配置 ${currentName}`);
}

function fillTemplate() {
  const spec = selectedProviderSpec();
  el.extraJsonInput.value = prettyJson(spec?.example_extra || {});
  setStatus(`已填充 ${spec?.name || ""} 模板`);
}

function bindEvents() {
  el.saveApiKeyBtn.addEventListener("click", async () => {
    state.apiKey = el.apiKeyInput.value.trim();
    sessionStorage.setItem(storageKey, state.apiKey);
    await refreshAll();
  });

  el.clearApiKeyBtn.addEventListener("click", () => {
    state.apiKey = "";
    el.apiKeyInput.value = "";
    sessionStorage.removeItem(storageKey);
    setAuthStatus("API Key 已清除，只保存在当前浏览器标签页");
  });

  el.providerSelect.addEventListener("change", renderProviderGuide);
  el.refreshConfigsBtn.addEventListener("click", loadConfigs);
  el.refreshSessionsBtn.addEventListener("click", loadSessions);
  el.newConfigBtn.addEventListener("click", () => {
    resetForm({ provider: el.providerSelect.value || state.catalog[0]?.name });
    setStatus("已切换到新建模式");
  });
  el.fillTemplateBtn.addEventListener("click", fillTemplate);

  el.saveConfigBtn.addEventListener("click", async () => {
    try {
      await saveCurrentConfig();
    } catch (error) {
      setStatus(`保存失败: ${error.message}`, "danger");
    }
  });

  el.validateConfigBtn.addEventListener("click", async () => {
    try {
      await validateCurrentConfig();
    } catch (error) {
      setStatus(`校验失败: ${error.message}`, "danger");
    }
  });

  el.deleteConfigBtn.addEventListener("click", async () => {
    try {
      await deleteCurrentConfig();
    } catch (error) {
      setStatus(`删除失败: ${error.message}`, "danger");
    }
  });
}

async function boot() {
  bindEvents();
  el.apiKeyInput.value = state.apiKey;
  if (!state.apiKey) {
    resetForm({});
    renderProviderGuide();
    return;
  }
  await refreshAll();
  resetForm({});
}

boot().catch((error) => {
  setAuthStatus(`初始化失败: ${error.message}`);
});
