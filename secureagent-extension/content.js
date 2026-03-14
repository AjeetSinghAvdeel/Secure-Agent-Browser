const ACTION_API_URL = "http://localhost:8000/evaluate_action";

const allowedReplayClicks = new WeakSet();
const allowedReplayForms = new WeakSet();
const bypassedInputs = new WeakSet();

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

async function evaluatePageAction(action, actionContext = {}) {
  const response = await fetch(ACTION_API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: window.location.href,
      action,
      action_context: actionContext,
    }),
  });

  if (!response.ok) {
    throw new Error(`SecureAgent action API error: ${response.status}`);
  }

  const result = await response.json();
  emitAuditEvent(result);
  return result;
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

function handleDecisionFeedback(result, options = {}) {
  if (!result) return;
  const decision = String(result.decision || "WARN").toUpperCase();
  if (decision === "ALLOW" && !options.showAllow) return;
  showMediationToast(result, options.title);
  if (decision === "BLOCK" && options.useAlert) {
    window.alert("SecureAgent blocked this action: " + String(result.reason || "Unknown reason"));
  }
}

document.addEventListener(
  "click",
  (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;

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
        handleDecisionFeedback(result, { useAlert: result.decision === "BLOCK" });
        if (String(result.decision || "").toUpperCase() === "BLOCK") {
          return;
        }

        allowedReplayClicks.add(button);
        button.click();
      } catch (error) {
        console.error("SecureAgent click mediation failed", error);
        allowedReplayClicks.add(button);
        button.click();
      }
    })();
  },
  true
);

document.addEventListener(
  "submit",
  (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

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
        handleDecisionFeedback(result, { useAlert: result.decision === "BLOCK" });
        if (String(result.decision || "").toUpperCase() === "BLOCK") {
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
        allowedReplayForms.add(form);
        if (typeof form.requestSubmit === "function") {
          form.requestSubmit();
        } else {
          form.submit();
        }
      }
    })();
  },
  true
);

document.addEventListener(
  "beforeinput",
  (event) => {
    const target = event.target;
    if (!isTextEntryTarget(target)) return;
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
        handleDecisionFeedback(result, { useAlert: result.decision === "BLOCK" });
        if (String(result.decision || "").toUpperCase() === "BLOCK") {
          return;
        }

        applyInputMutation(target, event);
      } catch (error) {
        console.error("SecureAgent input mediation failed", error);
        applyInputMutation(target, event);
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

  const target = document.querySelector(selector);
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

  if (action === "enter_text" && isTextEntryTarget(target)) {
    const actionContext = buildActionContext("enter_text", target, {
      source: "agent_simulator",
      proposed_text: textSnippet(value),
    });
    const result = await evaluatePageAction("enter_text", actionContext);
    handleDecisionFeedback(result, {
      title: "SecureAgent Agent Simulator",
      showAllow: true,
    });
    if (String(result.decision || "").toUpperCase() === "BLOCK") return;
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
    handleDecisionFeedback(result, {
      title: "SecureAgent Agent Simulator",
      showAllow: true,
    });
    if (String(result.decision || "").toUpperCase() === "BLOCK") return;
    if (target instanceof HTMLElement) {
      target.click();
    }
    return;
  }

  if (action === "submit_form") {
    const form =
      target instanceof HTMLFormElement ? target : target.closest?.("form");
    if (!(form instanceof HTMLFormElement)) return;

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
    handleDecisionFeedback(result, {
      title: "SecureAgent Agent Simulator",
      showAllow: true,
    });
    if (String(result.decision || "").toUpperCase() === "BLOCK") return;
    if (typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else {
      form.submit();
    }
  }
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
        reason: "Agent simulator action failed unexpectedly",
        risk: 0,
      },
      "SecureAgent Agent Simulator"
    );
  });
});

chrome.runtime.onMessage.addListener((message) => {
  if (!message || message.type !== "SECUREAGENT_RESULT") return;
  if (String(message.decision || "").toUpperCase() !== "ALLOW") return;

  const existing = document.getElementById("secureagent-banner");
  if (existing) return;

  const logoUrl = chrome.runtime.getURL("icons/secureagent.svg");
  let host = "this site";
  try {
    host = window.location.hostname || "this site";
  } catch (_) {
    // ignore
  }

  const banner = document.createElement("div");
  banner.id = "secureagent-banner";
  banner.style.position = "fixed";
  banner.style.top = "12px";
  banner.style.left = "50%";
  banner.style.transform = "translateX(-50%)";
  banner.style.zIndex = "999999";
  banner.style.display = "flex";
  banner.style.alignItems = "center";
  banner.style.gap = "10px";
  banner.style.padding = "10px 14px";
  banner.style.borderRadius = "999px";
  banner.style.border = "1px solid rgba(110, 231, 183, 0.45)";
  banner.style.background = "linear-gradient(135deg, #065f46 0%, #047857 100%)";
  banner.style.color = "white";
  banner.style.fontSize = "13px";
  banner.style.fontWeight = "600";
  banner.style.fontFamily = "Inter, Arial, sans-serif";
  banner.style.boxShadow = "0 10px 28px rgba(6, 95, 70, 0.42)";
  banner.style.backdropFilter = "blur(6px)";
  banner.style.maxWidth = "min(92vw, 920px)";
  banner.style.whiteSpace = "nowrap";
  banner.style.overflow = "hidden";
  banner.style.textOverflow = "ellipsis";
  banner.style.transition = "opacity 220ms ease, transform 220ms ease";

  banner.innerHTML = `
    <img src="${logoUrl}" alt="SecureAgent" style="width:18px;height:18px;display:block;filter: drop-shadow(0 1px 1px rgba(0,0,0,.35));" />
    <span style="opacity:.96;">SecureAgent verified <strong>${host}</strong> as safe</span>
    <span style="padding:2px 8px;border-radius:999px;background:rgba(255,255,255,.2);font-size:12px;font-weight:700;">
      Risk ${Number(message.risk || 0)}
    </span>
  `;

  document.documentElement.prepend(banner);

  setTimeout(() => {
    banner.style.opacity = "0";
    banner.style.transform = "translateX(-50%) translateY(-6px)";
    setTimeout(() => banner.remove(), 240);
  }, 6000);
});

chrome.runtime.sendMessage({ type: "SECUREAGENT_CONTENT_READY" }, () => {
  void chrome.runtime.lastError;
});
