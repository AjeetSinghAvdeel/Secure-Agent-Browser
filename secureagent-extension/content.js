const allowedReplayClicks = new WeakSet();
const allowedReplayForms = new WeakSet();
const bypassedInputs = new WeakSet();
const uiMutationState = {
  mutationCount: 0,
  lastInjectedAt: 0,
  scriptInjectionCount: 0,
  suspiciousEventHookCount: 0,
};
const pageDecisionOverlayState = {
  acknowledgedUrl: "",
};
let currentAuthToken = null;
let authStateReady = false;

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

function shouldEnforceProtection() {
  return authStateReady && Boolean(currentAuthToken) && !isLocalDashboardUrl(window.location.href);
}

function isSecureAgentUiElement(element) {
  if (!(element instanceof Element)) return false;
  return Boolean(
    element.closest(
      [
        "#secureagent-toast-host",
        "#secureagent-confirmation-host",
        "#secureagent-page-decision-host",
        "#secureagent-banner",
        "#secureagent-agent-simulator",
      ].join(", ")
    )
  );
}

function textDensity(value) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, 280);
}

function isClickableElement(element) {
  if (!(element instanceof Element)) return false;
  const tag = (element.tagName || "").toLowerCase();
  if (["button", "a", "input"].includes(tag)) return true;
  if (element.getAttribute("role") === "button") return true;
  const onclick = element.getAttribute("onclick");
  return Boolean(onclick);
}

function getElementArea(rect) {
  return Math.max(0, rect.width) * Math.max(0, rect.height);
}

function isLikelyOverlayElement(element, style, rect) {
  if (!(element instanceof Element)) return false;
  const position = String(style.position || "").toLowerCase();
  const zIndex = Number(style.zIndex || 0);
  const opacity = Number.parseFloat(style.opacity || "1");
  const viewportArea = Math.max(1, window.innerWidth * window.innerHeight);
  const areaRatio = getElementArea(rect) / viewportArea;

  return (
    ["fixed", "absolute", "sticky"].includes(position) &&
    zIndex >= 1000 &&
    (opacity < 0.2 || areaRatio >= 0.2)
  );
}

function collectPageContext() {
  const clickables = Array.from(
    document.querySelectorAll(
      'button, a, input, textarea, select, [role="button"], [onclick], iframe, form'
    )
  );
  const detectedPatterns = new Set();
  let overlappingCount = 0;
  let hiddenClickableCount = 0;
  let iframeCount = 0;
  let transparentIframeCount = 0;

  clickables.forEach((element) => {
    if (!(element instanceof Element)) return;
    if (isSecureAgentUiElement(element)) return;
    const style = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    const clickable = isClickableElement(element);
    const text = textDensity(element.textContent || element.getAttribute("aria-label") || "");

    if (
      clickable &&
      (style.opacity === "0" ||
        style.display === "none" ||
        style.visibility === "hidden" ||
        rect.width < 6 ||
        rect.height < 6)
    ) {
      hiddenClickableCount += 1;
      detectedPatterns.add("invisible_clickable_area");
    }

    if (Number(style.zIndex || 0) >= 9999) {
      detectedPatterns.add("z_index_abuse");
    }

    if (parseFloat(style.fontSize || "16") <= 8) {
      detectedPatterns.add("tiny_font");
    }

    if (clickable && ["div", "span"].includes((element.tagName || "").toLowerCase()) && text) {
      detectedPatterns.add("fake_buttons");
    }

    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    if (rect.width > 24 && rect.height > 24 && centerX > 0 && centerY > 0) {
      const topElement = document.elementFromPoint(centerX, centerY);
      if (topElement && topElement !== element && !element.contains(topElement)) {
        const topRect = topElement.getBoundingClientRect?.();
        const topStyle = window.getComputedStyle(topElement);
        const topArea = topRect ? getElementArea(topRect) : 0;
        const currentArea = Math.max(1, getElementArea(rect));
        const coverRatio = topArea / currentArea;

        if (
          topRect &&
          isLikelyOverlayElement(topElement, topStyle, topRect) &&
          coverRatio >= 0.6
        ) {
          overlappingCount += 1;
          detectedPatterns.add("overlapping_elements");
          if (clickable) {
            detectedPatterns.add("hidden_overlays");
          }
        }
      }
    }

    if (element instanceof HTMLIFrameElement) {
      iframeCount += 1;
      const iframeArea = getElementArea(rect);
      const viewportArea = Math.max(1, window.innerWidth * window.innerHeight);
      const iframeAreaRatio = iframeArea / viewportArea;
      const isTransparent = Number.parseFloat(style.opacity || "1") < 0.1;
      const isElevatedFrame =
        ["fixed", "absolute"].includes(String(style.position || "").toLowerCase()) &&
        Number(style.zIndex || 0) >= 1000 &&
        iframeAreaRatio >= 0.15;

      if (isTransparent || isElevatedFrame) {
        transparentIframeCount += 1;
        detectedPatterns.add("clickjacking_iframe");
        if (isTransparent) {
          detectedPatterns.add("opacity_clickjacking");
        }
      }
    }
  });

  document.querySelectorAll("form").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) return;
    if (isSecureAgentUiElement(form)) return;
    const passwordField = form.querySelector('input[type="password"]');
    const formText = textDensity(form.textContent || "");
    if (passwordField && /(verify|urgent|confirm|suspended|identity)/i.test(formText)) {
      detectedPatterns.add("misleading_forms");
    }
  });

  if (uiMutationState.mutationCount > 0) {
    detectedPatterns.add("mutation_ui_injection");
  }
  if (uiMutationState.scriptInjectionCount > 0) {
    detectedPatterns.add("script_injection");
  }
  if (uiMutationState.suspiciousEventHookCount > 0) {
    detectedPatterns.add("event_hijacking");
  }

  return {
    detected_patterns: Array.from(detectedPatterns),
    hidden_clickable_count: hiddenClickableCount,
    overlapping_count: overlappingCount,
    iframe_count: iframeCount,
    transparent_iframe_ratio:
      iframeCount > 0 ? transparentIframeCount / iframeCount : 0,
    mutation_count: uiMutationState.mutationCount,
    script_injection_count: uiMutationState.scriptInjectionCount,
    suspicious_event_hook_count: uiMutationState.suspiciousEventHookCount,
    last_injected_at: uiMutationState.lastInjectedAt || null,
    page_text_excerpt: textDensity(document.body?.innerText || ""),
  };
}

function startUiMutationObserver() {
  if (!document.documentElement) {
    window.addEventListener("DOMContentLoaded", startUiMutationObserver, { once: true });
    return;
  }

  const observer = new MutationObserver((mutations) => {
    let suspicious = false;
    for (const mutation of mutations) {
      mutation.addedNodes.forEach((node) => {
        if (!(node instanceof Element)) return;
        if (isSecureAgentUiElement(node)) return;
        const style = window.getComputedStyle(node);
        const rect = node.getBoundingClientRect?.();
        if (node.tagName === "SCRIPT") {
          uiMutationState.scriptInjectionCount += 1;
          suspicious = true;
        }
        if (rect && isLikelyOverlayElement(node, style, rect)) {
          suspicious = true;
        }
      });
    }

    if (suspicious) {
      uiMutationState.mutationCount += 1;
      uiMutationState.lastInjectedAt = Date.now();
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
}

const nativeAddEventListener = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function patchedAddEventListener(type, listener, options) {
  const targetName = this instanceof Element ? this.tagName : this === document ? "DOCUMENT" : "";
  if (
    ["submit", "beforeinput"].includes(String(type || "").toLowerCase()) &&
    (this === document || this === window || targetName === "BODY")
  ) {
    uiMutationState.suspiciousEventHookCount += 1;
  }
  return nativeAddEventListener.call(this, type, listener, options);
};

function getStoredToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["token"], (result) => {
      const token = result?.token || null;
      currentAuthToken = token;
      authStateReady = true;
      resolve(token);
    });
  });
}

function setStoredToken(token) {
  return new Promise((resolve) => {
    currentAuthToken = token || null;
    authStateReady = true;
    if (token) {
      chrome.storage.local.set({ token }, () => resolve());
      return;
    }
    chrome.storage.local.remove(["token"], () => resolve());
  });
}

void getStoredToken();
void syncAuthFromDashboard();

function ensureToastHost() {
  let host = document.getElementById("secureagent-toast-host");
  if (host) return host;

  host = document.createElement("div");
  host.id = "secureagent-toast-host";
  host.style.position = "fixed";
  host.style.top = "20px";
  host.style.right = "20px";
  host.style.zIndex = "999999";
  host.style.display = "flex";
  host.style.flexDirection = "column";
  host.style.gap = "12px";
  host.style.maxWidth = "min(90vw, 420px)";
  document.documentElement.appendChild(host);
  return host;
}

function ensureConfirmationHost() {
  let host = document.getElementById("secureagent-confirmation-host");
  if (host) return host;

  host = document.createElement("div");
  host.id = "secureagent-confirmation-host";
  host.style.position = "fixed";
  host.style.inset = "0";
  host.style.zIndex = "1000000";
  host.style.display = "none";
  host.style.alignItems = "center";
  host.style.justifyContent = "center";
  host.style.background = "rgba(2, 6, 23, 0.68)";
  host.style.backdropFilter = "blur(8px)";
  document.documentElement.appendChild(host);
  return host;
}

function ensureDecisionOverlayHost() {
  let host = document.getElementById("secureagent-page-decision-host");
  if (host) return host;

  host = document.createElement("div");
  host.id = "secureagent-page-decision-host";
  host.style.position = "fixed";
  host.style.inset = "0";
  host.style.zIndex = "999998";
  host.style.display = "none";
  host.style.alignItems = "center";
  host.style.justifyContent = "center";
  host.style.background = "rgba(2, 6, 23, 0.55)";
  host.style.backdropFilter = "blur(8px)";
  document.documentElement.appendChild(host);
  return host;
}

function showMediationToast(result, title) {
  const host = ensureToastHost();
  const toast = document.createElement("div");
  const decision = String(result?.decision || "WARN").toUpperCase();
  const palette =
    decision === "BLOCK"
      ? {
          border: "rgba(248, 113, 113, 0.45)",
          bg: "linear-gradient(135deg, rgba(127,29,29,.96), rgba(69,10,10,.96))",
        }
      : decision === "WARN"
      ? {
          border: "rgba(251, 191, 36, 0.45)",
          bg: "linear-gradient(135deg, rgba(120,53,15,.96), rgba(69,26,3,.96))",
        }
      : {
          border: "rgba(74, 222, 128, 0.45)",
          bg: "linear-gradient(135deg, rgba(21,128,61,.96), rgba(20,83,45,.96))",
        };

  toast.style.border = `1px solid ${palette.border}`;
  toast.style.background = palette.bg;
  toast.style.color = "white";
  toast.style.borderRadius = "16px";
  toast.style.padding = "14px 16px";
  toast.style.boxShadow = "0 14px 32px rgba(15,23,42,.35)";
  toast.style.backdropFilter = "blur(8px)";
  toast.style.fontFamily = "Inter, Arial, sans-serif";
  toast.style.transform = "translateY(-6px)";
  toast.style.opacity = "0";
  toast.style.transition = "opacity 180ms ease, transform 180ms ease";

  toast.innerHTML = `
    <div style="font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;opacity:.9;">
      ${title || "SecureAgent Action Review"}
    </div>
    <div style="font-size:15px;font-weight:700;margin-top:6px;">
      ${decision}
    </div>
    <div style="font-size:13px;line-height:1.45;opacity:.92;margin-top:4px;">
      ${String(result?.reason || "No reason provided")}
    </div>
    <div style="font-size:12px;opacity:.8;margin-top:8px;">
      Risk ${Number(result?.risk || 0)}${result?.attack_type ? ` • ${result.attack_type}` : ""}
    </div>
  `;

  host.appendChild(toast);
  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
  });

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(-6px)";
    setTimeout(() => toast.remove(), 220);
  }, 4500);
}

function emitAuditEvent(result) {
  window.dispatchEvent(
    new CustomEvent("secureagent:action-audit", {
      detail: result,
    })
  );
  window.postMessage(
    {
      type: "SECUREAGENT_ACTION_AUDIT",
      detail: result,
    },
    "*"
  );
}

function sendRuntimeMessage(message) {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!response?.ok) {
          reject(new Error(response?.error || "SecureAgent request failed"));
          return;
        }
        resolve(response.data);
      });
    } catch (error) {
      reject(error);
    }
  });
}

async function syncAuthFromDashboard() {
  try {
    await sendRuntimeMessage({ type: "SECUREAGENT_SYNC_AUTH" });
    await getStoredToken();
  } catch (_) {
    // best-effort only
  }
}

async function evaluatePageAction(action, actionContext = {}) {
  try {
    const result = await sendRuntimeMessage({
      type: "SECUREAGENT_EVALUATE_ACTION",
      payload: {
        url: window.location.href,
        action,
        action_context: actionContext,
      },
    });
    emitAuditEvent(result);
    return result;
  } catch (error) {
    if (String(error?.message || error).includes("requires login")) {
      await syncAuthFromDashboard();
      if (currentAuthToken) {
        return evaluatePageAction(action, actionContext);
      }
      await setStoredToken(null);
      showMediationToast(
        {
          decision: "WARN",
          reason: "SecureAgent requires login",
          risk: 0,
        },
        "SecureAgent Authentication"
      );
    }
    throw error;
  }
}

async function requestAgentPlan(userGoal) {
  return sendRuntimeMessage({
    type: "SECUREAGENT_REQUEST_PLAN",
    payload: {
      url: window.location.href,
      user_goal: userGoal,
      page_context: collectPageContext(),
    },
  });
}

async function logConfirmationDecision(action, actionContext, decision, reason) {
  try {
    await sendRuntimeMessage({
      type: "SECUREAGENT_LOG_CONFIRMATION",
      payload: {
        url: window.location.href,
        action,
        action_context: actionContext,
        decision,
        reason,
      },
    });
  } catch (error) {
    console.error("SecureAgent confirmation logging failed", error);
  }
}

function requestUserConfirmation(result, actionContext = {}) {
  return new Promise((resolve) => {
    const host = ensureConfirmationHost();
    host.innerHTML = "";
    host.style.display = "flex";

    const panel = document.createElement("div");
    panel.style.width = "min(92vw, 480px)";
    panel.style.borderRadius = "20px";
    panel.style.border = "1px solid rgba(251, 191, 36, 0.35)";
    panel.style.background = "linear-gradient(180deg, rgba(15,23,42,.98), rgba(30,41,59,.98))";
    panel.style.color = "#f8fafc";
    panel.style.padding = "22px";
    panel.style.boxShadow = "0 26px 60px rgba(2,6,23,.45)";
    panel.style.fontFamily = "Inter, Arial, sans-serif";

    const target = String(actionContext?.target_text || actionContext?.action || "this action");
    panel.innerHTML = `
      <div style="font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#fbbf24;">
        SecureAgent Confirmation
      </div>
      <div style="font-size:22px;font-weight:800;margin-top:10px;">
        Sensitive action requires approval
      </div>
      <div style="font-size:14px;line-height:1.6;color:#cbd5e1;margin-top:10px;">
        ${String(result?.reason || "This action needs explicit approval before execution.")}
      </div>
      <div style="margin-top:16px;padding:14px;border-radius:14px;background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.18);">
        <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;">Target</div>
        <div style="font-size:15px;font-weight:600;margin-top:6px;">${target}</div>
        <div style="font-size:12px;color:#94a3b8;margin-top:8px;">Risk ${Number(result?.risk || 0)}${result?.attack_type ? ` • ${result.attack_type}` : ""}</div>
      </div>
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:18px;">
        <button id="secureagent-confirm-deny" type="button" style="border:0;border-radius:12px;padding:12px 16px;background:#334155;color:#fff;font-weight:700;cursor:pointer;">Deny</button>
        <button id="secureagent-confirm-allow" type="button" style="border:0;border-radius:12px;padding:12px 16px;background:#f59e0b;color:#111827;font-weight:800;cursor:pointer;">Approve</button>
      </div>
    `;

    host.appendChild(panel);
    const close = (approved) => {
      host.style.display = "none";
      host.innerHTML = "";
      resolve(Boolean(approved));
    };
    panel.querySelector("#secureagent-confirm-deny")?.addEventListener("click", () => close(false));
    panel.querySelector("#secureagent-confirm-allow")?.addEventListener("click", () => close(true));
  });
}

function textSnippet(value) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, 140);
}

function getElementLabel(element) {
  if (!element) return "";
  const aria = element.getAttribute?.("aria-label");
  const title = element.getAttribute?.("title");
  const placeholder = element.getAttribute?.("placeholder");
  const text = element.textContent;
  return textSnippet(aria || title || placeholder || text || "");
}

function buildActionContext(action, element, extra = {}) {
  const form = element?.closest?.("form") || null;
  return {
    source: extra.source || "user",
    target_text: getElementLabel(element),
    element_tag: element?.tagName || "",
    element_name: element?.getAttribute?.("name") || "",
    element_id: element?.id || "",
    input_type: element?.getAttribute?.("type") || "",
    form_action: form?.getAttribute?.("action") || "",
    form_id: form?.id || "",
    current_path: window.location.pathname,
    action,
    page_context: collectPageContext(),
    ...extra,
  };
}

function isTextEntryTarget(target) {
  if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) {
    return false;
  }

  if (target instanceof HTMLTextAreaElement) {
    return true;
  }

  const type = (target.type || "text").toLowerCase();
  return ["text", "search", "email", "url", "tel", "password"].includes(type);
}

function applyInputMutation(target, event) {
  const start = target.selectionStart ?? target.value.length;
  const end = target.selectionEnd ?? target.value.length;
  const inputType = String(event.inputType || "");
  const data = event.data ?? "";

  if (inputType.startsWith("delete")) {
    if (start === end) {
      if (inputType === "deleteContentBackward" && start > 0) {
        target.setRangeText("", start - 1, end, "end");
      } else if (inputType === "deleteContentForward" && end < target.value.length) {
        target.setRangeText("", start, end + 1, "start");
      } else {
        target.setRangeText("", start, end, "start");
      }
    } else {
      target.setRangeText("", start, end, "start");
    }
  } else if (typeof data === "string") {
    target.setRangeText(data, start, end, "end");
  } else {
    return false;
  }

  bypassedInputs.add(target);
  target.dispatchEvent(new Event("input", { bubbles: true }));
  setTimeout(() => bypassedInputs.delete(target), 0);
  return true;
}

function resolveSimulationTarget(selector, action) {
  const candidates = Array.from(document.querySelectorAll(selector));
  if (candidates.length === 0) return null;

  if (action === "enter_text") {
    return candidates.find((candidate) => isTextEntryTarget(candidate)) || null;
  }

  if (action === "submit_form") {
    return (
      candidates.find((candidate) => candidate instanceof HTMLFormElement) ||
      candidates.find((candidate) => candidate.closest?.("form")) ||
      null
    );
  }

  if (action === "click_button") {
    return candidates.find((candidate) => candidate instanceof HTMLElement) || null;
  }

  return candidates[0] || null;
}

function handleDecisionFeedback(result, options = {}) {
  if (!result) return;
  const decision = String(result.decision || "WARN").toUpperCase();
  if (decision === "ALLOW" && !options.showAllow) return;
  if (decision === "REQUIRE_CONFIRMATION" && !options.showConfirmation) return;
  showMediationToast(result, options.title);
  if (decision === "BLOCK" && options.useAlert) {
    window.alert("SecureAgent blocked this action: " + String(result.reason || "Unknown reason"));
  }
}

function hidePageDecisionOverlay() {
  const host = document.getElementById("secureagent-page-decision-host");
  if (!host) return;
  host.innerHTML = "";
  host.style.display = "none";
}

function showPageDecisionOverlay(message) {
  const decision = String(message?.decision || "WARN").toUpperCase();
  if (pageDecisionOverlayState.acknowledgedUrl === window.location.href) {
    return;
  }
  if (decision === "ALLOW") {
    hidePageDecisionOverlay();
    return;
  }

  const host = ensureDecisionOverlayHost();
  host.innerHTML = "";
  host.style.display = "flex";

  const panel = document.createElement("div");
  const accent =
    decision === "BLOCK"
      ? { border: "rgba(248, 113, 113, 0.4)", bg: "rgba(127,29,29,.92)", action: "Continue Anyway" }
      : { border: "rgba(251, 191, 36, 0.4)", bg: "rgba(120,53,15,.92)", action: "Acknowledge Warning" };
  panel.style.width = "min(92vw, 560px)";
  panel.style.borderRadius = "20px";
  panel.style.border = `1px solid ${accent.border}`;
  panel.style.background = "linear-gradient(180deg, rgba(15,23,42,.98), rgba(30,41,59,.98))";
  panel.style.color = "#f8fafc";
  panel.style.padding = "24px";
  panel.style.boxShadow = "0 26px 60px rgba(2,6,23,.45)";
  panel.style.fontFamily = "Inter, Arial, sans-serif";

  const indicatorLines = Array.isArray(message?.indicators) ? message.indicators.slice(0, 6) : [];
  panel.innerHTML = `
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;">
      <div>
        <div style="font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:${decision === "BLOCK" ? "#fca5a5" : "#fcd34d"};">
          SecureAgent Scan Result
        </div>
        <div style="font-size:28px;font-weight:800;margin-top:8px;">
          ${decision}
        </div>
        <div style="font-size:14px;line-height:1.6;color:#cbd5e1;margin-top:8px;">
          ${String(message?.reason || message?.explanation || "Potentially unsafe page detected.")}
        </div>
      </div>
      <div style="padding:8px 12px;border-radius:999px;background:${accent.bg};font-size:13px;font-weight:800;">
        Risk ${Number(message?.risk || 0)}
      </div>
    </div>
    <div style="margin-top:16px;padding:14px;border-radius:14px;background:rgba(15,23,42,.65);border:1px solid rgba(148,163,184,.18);">
      <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;">Attack Type</div>
      <div style="font-size:16px;font-weight:700;margin-top:6px;">${String(message?.attack_type || "Suspicious Content")}</div>
      ${
        indicatorLines.length > 0
          ? `<div style="margin-top:12px;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;">Indicators</div>
             <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px;">
               ${indicatorLines.map((item) => `<span style="padding:6px 10px;border-radius:999px;border:1px solid rgba(148,163,184,.18);background:rgba(30,41,59,.9);font-size:12px;">${String(item).replace(/_/g, " ")}</span>`).join("")}
             </div>`
          : ""
      }
    </div>
    <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:18px;">
      <button id="secureagent-overlay-dismiss" type="button" style="border:0;border-radius:12px;padding:12px 16px;background:#334155;color:#fff;font-weight:700;cursor:pointer;">Dismiss</button>
      <button id="secureagent-overlay-proceed" type="button" style="border:0;border-radius:12px;padding:12px 16px;background:${decision === "BLOCK" ? "#b91c1c" : "#f59e0b"};color:#fff;font-weight:800;cursor:pointer;">${decision === "BLOCK" ? "Override And Continue" : accent.action}</button>
    </div>
  `;

  host.appendChild(panel);
  panel.querySelector("#secureagent-overlay-dismiss")?.addEventListener("click", () => {
    pageDecisionOverlayState.acknowledgedUrl = window.location.href;
    hidePageDecisionOverlay();
  });
  panel.querySelector("#secureagent-overlay-proceed")?.addEventListener("click", () => {
    pageDecisionOverlayState.acknowledgedUrl = window.location.href;
    hidePageDecisionOverlay();
  });
}

async function resolveExecutionDecision(action, actionContext, result, options = {}) {
  const decision = String(result?.decision || "WARN").toUpperCase();
  handleDecisionFeedback(result, {
    ...options,
    showConfirmation: true,
  });

  if (decision === "BLOCK") {
    return false;
  }

  if (decision === "REQUIRE_CONFIRMATION") {
    const approved = await requestUserConfirmation(result, actionContext);
    await logConfirmationDecision(
      action,
      actionContext,
      approved ? "ALLOW" : "BLOCK",
      approved ? "User approved confirmation prompt" : "User denied confirmation prompt"
    );
    if (!approved) {
      showMediationToast(
        {
          decision: "BLOCK",
          reason: "User denied SecureAgent confirmation",
          risk: Number(result?.risk || 0),
          attack_type: result?.attack_type || "",
        },
        "SecureAgent Confirmation"
      );
      return false;
    }
  }

  return true;
}

window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  if (event.data?.type !== "SECURE_AGENT_AUTH") return;
  void setStoredToken(event.data?.token || null);
});

startUiMutationObserver();

document.addEventListener(
  "click",
  (event) => {
    if (!shouldEnforceProtection()) return;
    const target = event.target;
    if (!(target instanceof Element)) return;
    if (isSecureAgentUiElement(target)) return;

    const button = target.closest('button, input[type="button"], input[type="submit"]');
    if (!button) return;

    if (allowedReplayClicks.has(button)) {
      allowedReplayClicks.delete(button);
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();

    const actionContext = buildActionContext("click_button", button);
    void (async () => {
      try {
        const result = await evaluatePageAction("click_button", actionContext);
        const shouldProceed = await resolveExecutionDecision("click_button", actionContext, result, {
          useAlert: result.decision === "BLOCK",
        });
        if (!shouldProceed) {
          return;
        }

        allowedReplayClicks.add(button);
        button.click();
      } catch (error) {
        console.error("SecureAgent click mediation failed", error);
        showMediationToast(
          {
            decision: "BLOCK",
            reason: String(error?.message || "Click mediation failed"),
            risk: 0,
          },
          "SecureAgent Click Blocked"
        );
      }
    })();
  },
  true
);

document.addEventListener(
  "submit",
  (event) => {
    if (!shouldEnforceProtection()) return;
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (isSecureAgentUiElement(form)) return;

    if (allowedReplayForms.has(form)) {
      allowedReplayForms.delete(form);
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();

    const submitter = event.submitter instanceof Element ? event.submitter : form;
    const actionContext = buildActionContext("submit_form", submitter, {
      fields: Array.from(form.elements)
        .filter((item) => item instanceof HTMLInputElement || item instanceof HTMLTextAreaElement)
        .map((item) => ({
          name: item.name || item.id || "",
          type: item.type || item.tagName.toLowerCase(),
        })),
    });

    void (async () => {
      try {
        const result = await evaluatePageAction("submit_form", actionContext);
        const shouldProceed = await resolveExecutionDecision("submit_form", actionContext, result, {
          useAlert: result.decision === "BLOCK",
        });
        if (!shouldProceed) {
          return;
        }

        allowedReplayForms.add(form);
        if (typeof form.requestSubmit === "function") {
          form.requestSubmit();
        } else {
          form.submit();
        }
      } catch (error) {
        console.error("SecureAgent form mediation failed", error);
        showMediationToast(
          {
            decision: "BLOCK",
            reason: String(error?.message || "Form mediation failed"),
            risk: 0,
          },
          "SecureAgent Submission Blocked"
        );
      }
    })();
  },
  true
);

document.addEventListener(
  "beforeinput",
  (event) => {
    if (!shouldEnforceProtection()) return;
    const target = event.target;
    if (!isTextEntryTarget(target)) return;
    if (isSecureAgentUiElement(target)) return;
    if (bypassedInputs.has(target)) return;

    const inputType = String(event.inputType || "");
    const hasSupportedMutation =
      inputType.startsWith("delete") || typeof event.data === "string";
    if (!hasSupportedMutation) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    const actionContext = buildActionContext("enter_text", target, {
      input_type: target.type || "text",
      proposed_text: textSnippet(event.data || inputType),
    });

    void (async () => {
      try {
        const result = await evaluatePageAction("enter_text", actionContext);
        const shouldProceed = await resolveExecutionDecision("enter_text", actionContext, result, {
          useAlert: result.decision === "BLOCK",
        });
        if (!shouldProceed) {
          return;
        }

        applyInputMutation(target, event);
      } catch (error) {
        console.error("SecureAgent input mediation failed", error);
        showMediationToast(
          {
            decision: "BLOCK",
            reason: String(error?.message || "Text entry mediation failed"),
            risk: 0,
          },
          "SecureAgent Input Blocked"
        );
      }
    })();
  },
  true
);

async function runSimulatedAgentAction(message) {
  const selector = String(message?.selector || "");
  const action = String(message?.action || "").toLowerCase();
  const value = String(message?.value || "");
  if (!selector || !action) return;

  const target = resolveSimulationTarget(selector, action);
  if (!(target instanceof Element)) {
    showMediationToast(
      {
        decision: "WARN",
        reason: `Simulator target not found for selector: ${selector}`,
        risk: 0,
      },
      "SecureAgent Simulator"
    );
    return;
  }

  if (action === "enter_text" && !isTextEntryTarget(target)) {
    showMediationToast(
      {
        decision: "WARN",
        reason: "Simulator could not find a text input that matches this scenario.",
        risk: 0,
      },
      "SecureAgent Agent Simulator"
    );
    return;
  }

  if (action === "enter_text" && isTextEntryTarget(target)) {
    const actionContext = buildActionContext("enter_text", target, {
      source: "agent_simulator",
      proposed_text: textSnippet(value),
    });
    const result = await evaluatePageAction("enter_text", actionContext);
    const shouldProceed = await resolveExecutionDecision("enter_text", actionContext, result, {
      title: "SecureAgent Agent Simulator",
      showAllow: true,
    });
    if (!shouldProceed) return;
    target.focus();
    target.value = value;
    target.dispatchEvent(new Event("input", { bubbles: true }));
    target.dispatchEvent(new Event("change", { bubbles: true }));
    return;
  }

  if (action === "click_button") {
    const actionContext = buildActionContext("click_button", target, {
      source: "agent_simulator",
    });
    const result = await evaluatePageAction("click_button", actionContext);
    const shouldProceed = await resolveExecutionDecision("click_button", actionContext, result, {
      title: "SecureAgent Agent Simulator",
      showAllow: true,
    });
    if (!shouldProceed) return;
    if (!(target instanceof HTMLElement)) {
      showMediationToast(
        {
          decision: "WARN",
          reason: "Simulator target is not clickable in the current page state.",
          risk: 0,
        },
        "SecureAgent Agent Simulator"
      );
      return;
    }
    target.click();
    return;
  }

  if (action === "submit_form") {
    const form =
      target instanceof HTMLFormElement ? target : target.closest?.("form");
    if (!(form instanceof HTMLFormElement)) {
      showMediationToast(
        {
          decision: "WARN",
          reason: "Simulator could not find a form to submit on this page.",
          risk: 0,
        },
        "SecureAgent Agent Simulator"
      );
      return;
    }

    const actionContext = buildActionContext("submit_form", form, {
      source: "agent_simulator",
      fields: Array.from(form.elements)
        .filter((item) => item instanceof HTMLInputElement || item instanceof HTMLTextAreaElement)
        .map((item) => ({
          name: item.name || item.id || "",
          type: item.type || item.tagName.toLowerCase(),
        })),
    });
    const result = await evaluatePageAction("submit_form", actionContext);
    const shouldProceed = await resolveExecutionDecision("submit_form", actionContext, result, {
      title: "SecureAgent Agent Simulator",
      showAllow: true,
    });
    if (!shouldProceed) return;
    try {
      if (typeof form.requestSubmit === "function") {
        form.requestSubmit();
      } else {
        form.submit();
      }
    } catch (error) {
      showMediationToast(
        {
          decision: "WARN",
          reason: String(error?.message || "Form submission could not be completed."),
          risk: 0,
        },
        "SecureAgent Agent Simulator"
      );
    }
    return;
  }

  showMediationToast(
    {
      decision: "WARN",
      reason: `Unsupported simulator action: ${action}`,
      risk: 0,
    },
    "SecureAgent Agent Simulator"
  );
}

async function runProtectedAgentGoal(userGoal) {
  const plan = await requestAgentPlan(userGoal);
  handleDecisionFeedback(
    {
      decision: plan?.validation?.decision || "WARN",
      reason: plan?.validation?.reason || "No validation reason provided",
      risk: plan?.scan_result?.risk || 0,
      attack_type: plan?.scan_result?.attack_type || "Unknown",
    },
    {
      title: "SecureAgent LLM Agent",
      showAllow: true,
    }
  );

  if (String(plan?.validation?.decision || "").toUpperCase() === "BLOCK") {
    return plan;
  }

  const proposed = plan?.agent_plan?.proposed_action || {};
  window.postMessage(
    {
      type: "SECUREAGENT_SIMULATE_AGENT_ACTION",
      action:
        proposed.type === "type"
          ? "enter_text"
          : proposed.type === "click"
          ? "click_button"
          : proposed.type,
      selector: proposed.target === "input" ? "input, textarea" : "button, [role='button'], a",
      value: proposed.value || "",
    },
    "*"
  );
  return plan;
}

window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data.type !== "SECUREAGENT_SIMULATE_AGENT_ACTION") return;

  void runSimulatedAgentAction(data).catch((error) => {
    console.error("SecureAgent simulator action failed", error);
    showMediationToast(
      {
        decision: "WARN",
        reason: String(error?.message || "Agent simulator action failed unexpectedly"),
        risk: 0,
      },
      String(error?.message || "").includes("requires login")
        ? "SecureAgent Authentication"
        : "SecureAgent Agent Simulator"
    );
  });
});

window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data.type !== "SECUREAGENT_RUN_AGENT") return;

  void runProtectedAgentGoal(String(data.userGoal || "")).catch((error) => {
    console.error("SecureAgent protected agent failed", error);
    showMediationToast(
      {
        decision: "WARN",
        reason: "Protected agent planning failed",
        risk: 0,
      },
      "SecureAgent LLM Agent"
    );
  });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "SECUREAGENT_COLLECT_PAGE_CONTEXT") {
    sendResponse({ ok: true, pageContext: collectPageContext() });
    return true;
  }
  if (!message || message.type !== "SECUREAGENT_RESULT") return;
  if (message.url && String(message.url) !== String(window.location.href)) {
    return;
  }

  if (String(message.decision || "").toUpperCase() !== "ALLOW") {
    showPageDecisionOverlay(message);
    return;
  }
  hidePageDecisionOverlay();
});

chrome.runtime.sendMessage({ type: "SECUREAGENT_CONTENT_READY" }, () => {
  void chrome.runtime.lastError;
});
