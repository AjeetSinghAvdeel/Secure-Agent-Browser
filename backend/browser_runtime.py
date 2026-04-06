from __future__ import annotations

import os
import time
from typing import Any, Dict

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.options import Options


JS_PROBE = """
(() => {
  if (window.__secureAgentProbeInstalled) return;
  window.__secureAgentProbeInstalled = true;

  const getDomain = (url) => {
    try { return new URL(url, location.href).hostname; } catch { return ""; }
  };

  const excerpt = (value) => String(value || "").replace(/\\s+/g, " ").trim().slice(0, 4000);

  window.__secureAgentSignals = {
    domMutations: 0,
    suspiciousOverlays: 0,
    clickInterceptors: 0,
    eventHijacks: 0,
    hiddenClickableCount: 0,
    overlappingCount: 0,
    iframeCount: 0,
    transparentIframeRatio: 0,
    detectedPatterns: [],
    network: []
  };

  const mark = (pattern) => {
    if (!window.__secureAgentSignals.detectedPatterns.includes(pattern)) {
      window.__secureAgentSignals.detectedPatterns.push(pattern);
    }
  };

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        window.__secureAgentSignals.domMutations += mutation.addedNodes.length;
      }
    }
    if (mutations.some((m) => m.addedNodes.length > 0)) {
      mark("mutation_ui_injection");
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  const originalAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, listener, options) {
    if (["click", "submit", "beforeinput"].includes(String(type || "").toLowerCase())) {
      window.__secureAgentSignals.eventHijacks++;
      mark("event_hijacking");
    }
    return originalAddEventListener.call(this, type, listener, options);
  };

  const originalFetch = window.fetch;
  window.fetch = function(...args) {
    const url = args[0]?.url || args[0];
    window.__secureAgentSignals.network.push({
      type: "fetch",
      url: String(url || ""),
      domain: getDomain(url),
      method: args[1]?.method || "GET",
      crossOrigin: getDomain(url) !== location.hostname
    });
    return originalFetch.apply(this, args);
  };

  const originalXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this.__secureAgentUrl = url;
    this.__secureAgentMethod = method;
    return originalXHROpen.call(this, method, url, ...rest);
  };

  const originalXHRSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(body) {
    window.__secureAgentSignals.network.push({
      type: "xhr",
      url: String(this.__secureAgentUrl || ""),
      domain: getDomain(this.__secureAgentUrl),
      method: this.__secureAgentMethod || "GET",
      crossOrigin: getDomain(this.__secureAgentUrl) !== location.hostname
    });
    return originalXHRSend.call(this, body);
  };

  const scanUi = () => {
    const signals = window.__secureAgentSignals;
    let overlays = 0;
    let hiddenClickables = 0;
    let overlapping = 0;
    let iframeCount = 0;
    let transparentIframes = 0;

    const clickables = document.querySelectorAll(
      'button, a, input, textarea, select, [role="button"], [onclick], iframe, form'
    );

    clickables.forEach((element) => {
      const style = window.getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      const area = Math.max(0, rect.width * rect.height);
      const viewportArea = Math.max(1, window.innerWidth * window.innerHeight);
      const areaRatio = area / viewportArea;
      const zIndex = Number(style.zIndex || 0);
      const opacity = Number.parseFloat(style.opacity || "1");
      const clickable = ["BUTTON", "A", "INPUT", "TEXTAREA", "SELECT"].includes(element.tagName) || element.getAttribute("role") === "button";

      if (
        ["fixed", "absolute", "sticky"].includes(String(style.position || "").toLowerCase()) &&
        zIndex >= 1000 &&
        (opacity < 0.2 || areaRatio >= 0.2)
      ) {
        overlays++;
        mark("hidden_overlays");
      }

      if (
        clickable &&
        (
          style.opacity === "0" ||
          style.display === "none" ||
          style.visibility === "hidden" ||
          rect.width < 6 ||
          rect.height < 6
        )
      ) {
        hiddenClickables++;
        mark("invisible_clickable_area");
      }

      if (element.tagName === "IFRAME") {
        iframeCount++;
        if (opacity < 0.1 || (zIndex >= 1000 && areaRatio >= 0.15)) {
          transparentIframes++;
          mark("clickjacking_iframe");
        }
      }

      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;
      if (rect.width > 24 && rect.height > 24 && centerX > 0 && centerY > 0) {
        const topElement = document.elementFromPoint(centerX, centerY);
        if (topElement && topElement !== element && !element.contains(topElement)) {
          overlapping++;
          mark("overlapping_elements");
        }
      }
    });

    signals.suspiciousOverlays = overlays;
    signals.hiddenClickableCount = hiddenClickables;
    signals.overlappingCount = overlapping;
    signals.iframeCount = iframeCount;
    signals.transparentIframeRatio = iframeCount > 0 ? transparentIframes / iframeCount : 0;
  };

  scanUi();
  setInterval(scanUi, 1500);

  window.__secureAgentSnapshot = () => ({
    title: document.title || "",
    text: excerpt(document.body?.innerText || ""),
    html: document.documentElement?.outerHTML || "",
    url: location.href,
    signals: window.__secureAgentSignals
  });
})();
"""


def _truthy_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def browser_runtime_enabled() -> bool:
    return _truthy_env("SECUREAGENT_ENABLE_BROWSER_RUNTIME", True)


def collect_browser_artifacts(url: str) -> Dict[str, Any]:
    if not browser_runtime_enabled():
        raise RuntimeError("Browser runtime disabled")

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1440,1200")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

    driver = None
    start = time.perf_counter()
    try:
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(float(os.getenv("SECUREAGENT_BROWSER_TIMEOUT_SECONDS", "10")))
        driver.get(url)
        driver.execute_script(JS_PROBE)
        time.sleep(float(os.getenv("SECUREAGENT_BROWSER_SETTLE_SECONDS", "2.5")))
        snapshot = driver.execute_script(
            "return typeof window.__secureAgentSnapshot === 'function' ? window.__secureAgentSnapshot() : null;"
        ) or {}

        html = str(snapshot.get("html") or driver.page_source or "")
        text = str(snapshot.get("text") or "")
        signals = snapshot.get("signals") or {}
        duration_ms = round((time.perf_counter() - start) * 1000.0, 3)

        return {
            "mode": "browser",
            "html": html,
            "page_text": text,
            "page_title": str(snapshot.get("title") or ""),
            "current_url": str(snapshot.get("url") or url),
            "page_context": {
                "detected_patterns": list(signals.get("detectedPatterns") or []),
                "hidden_clickable_count": int(signals.get("hiddenClickableCount") or 0),
                "overlapping_count": int(signals.get("overlappingCount") or 0),
                "iframe_count": int(signals.get("iframeCount") or 0),
                "transparent_iframe_ratio": float(signals.get("transparentIframeRatio") or 0.0),
                "mutation_count": int(signals.get("domMutations") or 0),
                "script_injection_count": 0,
                "suspicious_event_hook_count": int(signals.get("eventHijacks") or 0),
                "browser_network": list(signals.get("network") or []),
                "page_text_excerpt": text,
            },
            "runtime_behavior": {
                "dom_mutations": int(signals.get("domMutations") or 0),
                "suspicious_overlays": int(signals.get("suspiciousOverlays") or 0),
                "click_interceptors": int(signals.get("clickInterceptors") or 0),
                "event_hijacks": int(signals.get("eventHijacks") or 0),
                "network_requests": list(signals.get("network") or []),
                "runtime_ms": duration_ms,
            },
        }
    except WebDriverException as exc:
        raise RuntimeError(f"Browser runtime unavailable: {exc}") from exc
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
