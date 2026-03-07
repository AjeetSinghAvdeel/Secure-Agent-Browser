const API_URL = "http://localhost:8000/analyze_url";
const BYPASS_TTL_MS = 2 * 60 * 1000;

const pendingByTab = new Map();
const bypassByTab = new Map();

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

async function analyzeUrl(url) {
  const res = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) {
    throw new Error(`SecureAgent API error: ${res.status}`);
  }
  return res.json();
}

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

async function handleNavigation(details) {
  const { tabId, frameId, url } = details;
  if (frameId !== 0 || tabId < 0 || shouldSkip(url)) return;
  if (consumeBypass(tabId, url)) return;

  const inflight = pendingByTab.get(tabId);
  if (inflight && inflight.url === url) return;

  const request = (async () => {
    try {
      const result = await analyzeUrl(url);
      const decision = String(result?.decision || "WARN").toUpperCase();

      if (decision === "ALLOW") {
        return;
      }

      if (decision === "WARN") {
        const warningUrl = toWarningUrl(result, url, "warn");
        await chrome.tabs.update(tabId, { url: warningUrl });
        return;
      }

      if (decision === "BLOCK") {
        const warningUrl = toWarningUrl(result, url, "block");
        await chrome.tabs.update(tabId, { url: warningUrl });
      }
    } catch (error) {
      console.error("SecureAgent analyze failure", error);
    } finally {
      pendingByTab.delete(tabId);
    }
  })();

  pendingByTab.set(tabId, { url, request });
}

chrome.webNavigation.onCommitted.addListener(handleNavigation);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
