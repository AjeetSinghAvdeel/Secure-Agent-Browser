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

// Handshake so background can resend latest scan result if initial message was too early.
chrome.runtime.sendMessage({ type: "SECUREAGENT_CONTENT_READY" }, () => {
  void chrome.runtime.lastError;
});
