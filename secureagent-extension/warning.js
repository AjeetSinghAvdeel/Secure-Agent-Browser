function getParams() {
  const params = new URLSearchParams(window.location.search);
  const mode = params.get("mode") || "warn";
  const url = params.get("url") || "";
  const risk = Number(params.get("risk") || 0);
  const explanation = params.get("explanation") || "No explanation available.";
  let indicators = [];

  try {
    indicators = JSON.parse(params.get("indicators") || "[]");
  } catch (_) {
    indicators = [];
  }

  return {
    mode: mode.toLowerCase(),
    url,
    risk,
    explanation,
    indicators: Array.isArray(indicators) ? indicators : [],
  };
}

function render() {
  const data = getParams();

  const subtitle = document.getElementById("subtitle");
  const risk = document.getElementById("risk");
  const indicators = document.getElementById("indicators");
  const explanation = document.getElementById("explanation");
  const url = document.getElementById("url");
  const proceed = document.getElementById("proceed");
  const goBack = document.getElementById("goBack");

  if (!subtitle || !risk || !indicators || !explanation || !url || !proceed || !goBack) {
    return;
  }

  const isBlock = data.mode === "block";
  subtitle.textContent = isBlock
    ? "Access has been blocked due to high risk."
    : "This page may be unsafe. Review before continuing.";

  risk.textContent = `${data.risk}/100`;
  risk.className = `value ${isBlock ? "risk-block" : "risk-warn"}`;
  explanation.textContent = data.explanation;
  url.textContent = data.url ? `Target URL: ${data.url}` : "";

  indicators.innerHTML = "";
  if (data.indicators.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No explicit indicators returned.";
    indicators.appendChild(li);
  } else {
    data.indicators.forEach((item) => {
      const li = document.createElement("li");
      li.textContent = String(item).replace(/_/g, " ");
      indicators.appendChild(li);
    });
  }

  if (isBlock) {
    proceed.classList.add("blocked");
  }

  proceed.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "SECUREAGENT_PROCEED", url: data.url });
  });

  goBack.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "SECUREAGENT_GOBACK" });
  });
}

render();
