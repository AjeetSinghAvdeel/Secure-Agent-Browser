const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const BYPASS_TTL_MS = 2 * 60 * 1000;
const SAFE_NOTIFY_TTL_MS = 15000;
const AUTH_NOTIFY_TTL_MS = 15000;

const pendingByTab = new Map();
const pendingScanIdByTab = new Map();
const bypassByTab = new Map();
const safeNotifyCache = new Map();
const pendingResultByTab = new Map();
let lastAuthNotifyAt = 0;

function isLocalDashboardUrl(url) {
  try {
    const parsed = new URL(url);
    return (
      (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") &&
      ["8080", "5173", "4173", "3000"].includes(parsed.port || "")
    );
  } catch (_) {
    return false;
  }
}

function shouldSkip(url) {
  return (
    !url ||
    isLocalDashboardUrl(url) ||
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("view-source:") ||
    url.startsWith("devtools://")
  );
}

function markBypass(tabId, url) {
  bypassByTab.set(tabId, {
    url,
    expiresAt: Date.now() + BYPASS_TTL_MS,
  });
}

function consumeBypass(tabId, url) {
  const entry = bypassByTab.get(tabId);
  if (!entry) return false;
  if (Date.now() > entry.expiresAt) {
    bypassByTab.delete(tabId);
    return false;
  }
  if (entry.url === url) {
    bypassByTab.delete(tabId);
    return true;
  }
  return false;
}

function getStoredToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["token"], (result) => {
      resolve(result?.token || null);
    });
  });
}

function setStoredToken(token) {
  return new Promise((resolve) => {
    if (token) {
      chrome.storage.local.set({ token }, () => resolve());
      return;
    }
    chrome.storage.local.remove(["token"], () => resolve());
  });
}

function clearStoredToken() {
  return new Promise((resolve) => {
    chrome.storage.local.remove(["token"], () => resolve());
  });
}

function normalizeApiBaseUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return DEFAULT_API_BASE_URL;
  return raw.replace(/\/+$/, "");
}

async function getApiBaseUrl() {
  const storedBaseUrl = await new Promise((resolve) => {
    chrome.storage.local.get(["apiBaseUrl"], (result) => {
      resolve(result?.apiBaseUrl || null);
    });
  });
  if (storedBaseUrl) {
    return normalizeApiBaseUrl(storedBaseUrl);
  }

  const tabs = await chrome.tabs.query({});
  const dashboardTabs = tabs.filter((tab) => tab.id && isLocalDashboardUrl(tab.url || ""));
  for (const tab of dashboardTabs) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => window.localStorage.getItem("secureagent_api_base_url"),
      });
      const discoveredBaseUrl = results?.[0]?.result;
      if (discoveredBaseUrl) {
        const normalized = normalizeApiBaseUrl(discoveredBaseUrl);
        await new Promise((resolve) => {
          chrome.storage.local.set({ apiBaseUrl: normalized }, () => resolve());
        });
        return normalized;
      }
    } catch (_) {
      // ignore tabs where script injection is not available
    }
  }

  return DEFAULT_API_BASE_URL;
}

async function syncTokenFromDashboardTabs() {
  const tabs = await chrome.tabs.query({});
  const dashboardTabs = tabs.filter((tab) => tab.id && isLocalDashboardUrl(tab.url || ""));
  for (const tab of dashboardTabs) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => window.localStorage.getItem("secureagent_token"),
      });
      const token = results?.[0]?.result;
      if (token) {
        await setStoredToken(token);
        return token;
      }
    } catch (_) {
      // ignore tabs where script injection is not available
    }
  }
  return null;
}

function notifyAuthRequired() {
  const now = Date.now();
  if (now - lastAuthNotifyAt < AUTH_NOTIFY_TTL_MS) return;
  lastAuthNotifyAt = now;

  try {
    chrome.notifications.create(`secureagent-auth-${now}`, {
      type: "basic",
      iconUrl: "icons/secureagent-128.png",
      title: "SecureAgent requires login",
      message: "Login in the SecureAgent dashboard to enable protected scanning.",
      priority: 1,
    });
  } catch (_) {
    // ignore notification failures
  }
}

async function collectPageContext(tabId) {
  for (let attempt = 0; attempt < 6; attempt += 1) {
    try {
      const response = await chrome.tabs.sendMessage(tabId, {
        type: "SECUREAGENT_COLLECT_PAGE_CONTEXT",
      });
      if (response?.pageContext) {
        return response.pageContext;
      }
    } catch (_) {
      // content script may not be ready on the first pass
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  return null;
}

async function analyzeUrl(url, tabId) {
  let token = await getStoredToken();
  if (!token) {
    token = await syncTokenFromDashboardTabs();
  }
  if (!token) {
    return null;
  }

  const apiBaseUrl = await getApiBaseUrl();
  const pageContext = typeof tabId === "number" ? await collectPageContext(tabId) : null;
  let res = await fetch(`${apiBaseUrl}/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ url, page_context: pageContext }),
  });
  if (res.status === 401) {
    const refreshedToken = await syncTokenFromDashboardTabs();
    if (refreshedToken && refreshedToken !== token) {
      token = refreshedToken;
      res = await fetch(`${apiBaseUrl}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ url, page_context: pageContext }),
      });
    }
  }
  if (res.status === 401) {
    await clearStoredToken();
    throw new Error("SecureAgent requires login");
  }
  if (!res.ok) {
    throw new Error(`SecureAgent API error: ${res.status}`);
  }
  return res.json();
}

async function callAuthenticatedApi(url, payload) {
  let token = await getStoredToken();
  if (!token) {
    token = await syncTokenFromDashboardTabs();
  }
  if (!token) {
    throw new Error("SecureAgent requires login");
  }

  let res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload || {}),
  });

  if (res.status === 401) {
    const refreshedToken = await syncTokenFromDashboardTabs();
    if (refreshedToken && refreshedToken !== token) {
      token = refreshedToken;
      res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(payload || {}),
      });
    }
  }

  if (res.status === 401) {
    await clearStoredToken();
    throw new Error("SecureAgent requires login");
  }

  if (!res.ok) {
    let detail = "";
    try {
      const data = await res.json();
      detail = data?.detail ? `: ${data.detail}` : "";
    } catch (_) {
      // ignore parse failures
    }
    throw new Error(`SecureAgent API error: ${res.status}${detail}`);
  }

  return res.json();
}

chrome.runtime.onStartup?.addListener(() => {
  void syncTokenFromDashboardTabs();
  void getApiBaseUrl();
});

chrome.runtime.onInstalled?.addListener(() => {
  void syncTokenFromDashboardTabs();
  void getApiBaseUrl();
});

function toWarningUrl(result, url, mode) {
  const params = new URLSearchParams({
    mode,
    url,
    risk: String(result?.risk ?? 0),
    indicators: JSON.stringify(result?.indicators ?? []),
    explanation: String(result?.explanation ?? "No explanation available."),
  });
  return chrome.runtime.getURL(`warning.html?${params.toString()}`);
}

function maybeNotifySafe(url, risk) {
  const key = String(url || "");
  const now = Date.now();
  const last = safeNotifyCache.get(key) || 0;
  if (now - last < SAFE_NOTIFY_TTL_MS) return;
  safeNotifyCache.set(key, now);

  try {
    let hostname = "";
    try {
      hostname = new URL(url).hostname;
    } catch (_) {
      hostname = url;
    }
    chrome.notifications.create(`secureagent-safe-${now}`, {
      type: "basic",
      iconUrl: "icons/secureagent-128.png",
      title: "SecureAgent | Safe Site",
      message: `${hostname} is verified safe (Risk: ${Number(risk || 0)})`,
      priority: 0,
    });
  } catch (_) {
    // ignore notification failures so browsing flow is unaffected
  }
}

function sendResultToTab(tabId, result) {
  if (typeof tabId !== "number" || tabId < 0) return;
  const payload = {
    type: "SECUREAGENT_RESULT",
    decision: String(result?.decision || "WARN").toUpperCase(),
    risk: Number(result?.risk ?? 0),
    url: String(result?.url || ""),
    explanation: String(result?.explanation || ""),
    attack_type: String(result?.attack_type || ""),
    indicators: Array.isArray(result?.indicators) ? result.indicators : [],
    reason: String(result?.reason || ""),
  };

  pendingResultByTab.set(tabId, payload);

  // Try immediate delivery.
  chrome.tabs.sendMessage(tabId, payload, () => {
    void chrome.runtime.lastError;
  });

  // Retry after a short delay to handle pages where content script attaches later.
  setTimeout(() => {
    chrome.tabs.sendMessage(tabId, payload, () => {
      void chrome.runtime.lastError;
    });
  }, 500);
}

function scheduleScan(details) {
  const { tabId, url } = details;
  const pendingUrl = pendingByTab.get(tabId);
  if (pendingUrl && pendingUrl === url) {
    return;
  }

  const scanId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  pendingByTab.set(tabId, url);
  pendingScanIdByTab.set(tabId, scanId);

  (async () => {
    try {
      const result = await analyzeUrl(url, tabId);
      if (!result) {
        return;
      }
      if (pendingScanIdByTab.get(tabId) !== scanId) {
        return;
      }
      const tab = await chrome.tabs.get(tabId).catch(() => null);
      if (!tab?.id || String(tab.url || "") !== String(url || "")) {
        return;
      }
      sendResultToTab(tabId, result);
    } catch (error) {
      console.error("SecureAgent scan failed", error);
      // Fail-open for normal navigation when scanner is unavailable.
    } finally {
      if (pendingScanIdByTab.get(tabId) === scanId) {
        pendingByTab.delete(tabId);
        pendingScanIdByTab.delete(tabId);
      }
    }
  })();
}

chrome.webNavigation.onCommitted.addListener(
  function (details) {
    if (details.frameId !== 0) {
      return;
    }

    const { tabId, url } = details;
    if (tabId < 0 || shouldSkip(url)) {
      return;
    }

    if (consumeBypass(tabId, url)) {
      return;
    }

    scheduleScan(details);
  }
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "SECUREAGENT_CONTENT_READY") {
    const tabId = sender?.tab?.id;
    if (typeof tabId === "number") {
      const payload = pendingResultByTab.get(tabId);
      if (payload) {
        chrome.tabs.sendMessage(tabId, payload, () => {
          void chrome.runtime.lastError;
        });
      }
      sendResponse({ ok: true });
      return true;
    }
    sendResponse({ ok: false });
    return true;
  }

  if (message?.type === "SECUREAGENT_PROCEED") {
    const tabId = sender?.tab?.id;
    const targetUrl = String(message?.url || "");
    if (typeof tabId === "number" && targetUrl) {
      markBypass(tabId, targetUrl);
      chrome.tabs.update(tabId, { url: targetUrl });
      sendResponse({ ok: true });
      return true;
    }
    sendResponse({ ok: false });
    return true;
  }

  if (message?.type === "SECUREAGENT_GOBACK") {
    const tabId = sender?.tab?.id;
    if (typeof tabId === "number") {
      chrome.tabs.goBack(tabId, () => {
        if (chrome.runtime.lastError) {
          chrome.tabs.update(tabId, { url: "about:blank" });
        }
        sendResponse({ ok: true });
      });
      return true;
    }
    sendResponse({ ok: false });
    return true;
  }

  if (message?.type === "SECUREAGENT_EVALUATE_ACTION") {
    getApiBaseUrl()
      .then((apiBaseUrl) => callAuthenticatedApi(`${apiBaseUrl}/evaluate_action`, message.payload))
      .then((data) => sendResponse({ ok: true, data }))
      .catch((error) => sendResponse({ ok: false, error: String(error?.message || error) }));
    return true;
  }

  if (message?.type === "SECUREAGENT_REQUEST_PLAN") {
    getApiBaseUrl()
      .then((apiBaseUrl) => callAuthenticatedApi(`${apiBaseUrl}/agent/plan`, message.payload))
      .then((data) => sendResponse({ ok: true, data }))
      .catch((error) => sendResponse({ ok: false, error: String(error?.message || error) }));
    return true;
  }

  if (message?.type === "SECUREAGENT_LOG_CONFIRMATION") {
    getApiBaseUrl()
      .then((apiBaseUrl) => callAuthenticatedApi(`${apiBaseUrl}/action_confirmation`, message.payload))
      .then((data) => sendResponse({ ok: true, data }))
      .catch((error) => sendResponse({ ok: false, error: String(error?.message || error) }));
    return true;
  }

  if (message?.type === "SECUREAGENT_SYNC_AUTH") {
    syncTokenFromDashboardTabs()
      .then((token) => sendResponse({ ok: true, data: { tokenPresent: Boolean(token) } }))
      .catch((error) => sendResponse({ ok: false, error: String(error?.message || error) }));
    return true;
  }

  return false;
});
