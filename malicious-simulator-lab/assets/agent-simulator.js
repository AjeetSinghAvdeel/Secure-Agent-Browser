(function () {
  const scenario = window.secureAgentScenario || null;
  if (!scenario || !Array.isArray(scenario.actions)) return;

  const panel = document.createElement("aside");
  panel.style.position = "fixed";
  panel.style.right = "18px";
  panel.style.bottom = "18px";
  panel.style.zIndex = "99999";
  panel.style.width = "min(92vw, 340px)";
  panel.style.border = "1px solid rgba(148,163,184,.22)";
  panel.style.borderRadius = "18px";
  panel.style.background = "linear-gradient(180deg, rgba(15,23,42,.96), rgba(2,6,23,.96))";
  panel.style.color = "#e2e8f0";
  panel.style.padding = "16px";
  panel.style.boxShadow = "0 18px 40px rgba(15,23,42,.45)";
  panel.style.fontFamily = "Inter, system-ui, sans-serif";

  panel.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
      <div>
        <div style="font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#93c5fd;font-weight:800;">
          Agent Simulator
        </div>
        <div style="font-size:16px;font-weight:700;margin-top:4px;">
          ${String(scenario.title || "Scenario")}
        </div>
      </div>
      <div style="font-size:11px;padding:4px 8px;border-radius:999px;background:rgba(148,163,184,.14);">
        SecureAgent
      </div>
    </div>
    <p style="margin:10px 0 14px;font-size:12px;line-height:1.5;color:#cbd5e1;">
      Trigger simulated agent actions. SecureAgent should approve safe actions and stop risky ones.
    </p>
    <div id="secureagent-sim-actions" style="display:grid;gap:8px;"></div>
    <div id="secureagent-sim-status" style="margin-top:12px;padding:10px 12px;border-radius:12px;background:rgba(15,23,42,.7);font-size:12px;color:#cbd5e1;">
      Waiting for simulated agent action...
    </div>
  `;

  const actionContainer = panel.querySelector("#secureagent-sim-actions");
  const status = panel.querySelector("#secureagent-sim-status");

  scenario.actions.forEach((action) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = String(action.label || action.action);
    button.style.width = "100%";
    button.style.textAlign = "left";
    button.style.padding = "10px 12px";
    button.style.borderRadius = "12px";
    button.style.border = "1px solid rgba(148,163,184,.18)";
    button.style.background = "rgba(30,41,59,.92)";
    button.style.color = "#f8fafc";
    button.style.fontWeight = "600";
    button.style.cursor = "pointer";
    button.addEventListener("click", () => {
      status.textContent = `Running ${action.action} on ${action.selector}...`;
      window.postMessage(
        {
          type: "SECUREAGENT_SIMULATE_AGENT_ACTION",
          action: action.action,
          selector: action.selector,
          value: action.value || "",
        },
        "*"
      );
    });
    actionContainer.appendChild(button);
  });

  window.addEventListener("secureagent:action-audit", (event) => {
    const detail = event.detail || {};
    const decision = String(detail.decision || "WARN").toUpperCase();
    const targetText = detail.action_context?.target_text
      ? ` on "${detail.action_context.target_text}"`
      : "";
    status.textContent =
      `${decision}: ${detail.action}${targetText} • ${detail.reason || "No reason provided"}`;
  });

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    if (event.data?.type !== "SECUREAGENT_ACTION_AUDIT") return;
    const detail = event.data?.detail || {};
    const decision = String(detail.decision || "WARN").toUpperCase();
    const targetText = detail.action_context?.target_text
      ? ` on "${detail.action_context.target_text}"`
      : "";
    status.textContent =
      `${decision}: ${detail.action}${targetText} • ${detail.reason || "No reason provided"}`;
  });

  document.addEventListener("DOMContentLoaded", () => {
    document.body.appendChild(panel);
  });
})();
