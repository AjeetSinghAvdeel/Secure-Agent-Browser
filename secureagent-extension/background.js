const API_URL = "http://localhost:8000/scan";
const BYPASS_TTL_MS = 2 * 60 * 1000;
const SAFE_NOTIFY_TTL_MS = 15000;
const AUTH_NOTIFY_TTL_MS = 15000;

const pendingByTab = new Map();
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

async function analyzeUrl(url) {
  let token = await getStoredToken();
  if (!token) {
    token = await syncTokenFromDashboardTabs();
  }
  if (!token) {
    notifyAuthRequired();
    return null;
  }

  const res = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ url }),
  });
  if (res.status === 401) {
    await clearStoredToken();
    notifyAuthRequired();
    throw new Error("SecureAgent requires login");
  }
  if (!res.ok) {
    throw new Error(`SecureAgent API error: ${res.status}`);
  }
  return res.json();
}

chrome.runtime.onStartup?.addListener(() => {
  void syncTokenFromDashboardTabs();
});

chrome.runtime.onInstalled?.addListener(() => {
  void syncTokenFromDashboardTabs();
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

  pendingByTab.set(tabId, url);

  (async () => {
    try {
      const result = await analyzeUrl(url);
      if (!result) {
        return;
      }
      const decision = String(result?.decision || "WARN").toUpperCase();

      if (decision === "BLOCK" || decision === "WARN") {
        const warningPage = toWarningUrl(
          result,
          url,
          decision === "BLOCK" ? "block" : "warn"
        );
        await chrome.tabs.update(tabId, { url: warningPage });
        return;
      }

      if (decision === "ALLOW") {
        sendResultToTab(tabId, result);
        maybeNotifySafe(url, result?.risk);
      }

      // SAFE: no redirect needed.
    } catch (error) {
      console.error("SecureAgent scan failed", error);
      // Fail-open for normal navigation when scanner is unavailable.
    } finally {
      pendingByTab.delete(tabId);
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

  return false;
});
