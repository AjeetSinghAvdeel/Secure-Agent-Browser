from bs4 import BeautifulSoup
from urllib.parse import urlparse
from risk import calculate_risk
from ml_model import predict_attack
from llm_reasoner import analyze_intent


BRAND_DOMAINS = {
    "google": ["google.com", "accounts.google.com"],
    "github": ["github.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "microsoft": ["microsoft.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
}

INJECTION_KEYWORDS = [
    "ignore previous",
    "ignore all",
    "act as system",
    "admin mode",
    "override",
    "send password",
    "reveal secret",
    "root access",
    "bypass security",
    "dump database",
]

HIDDEN_STYLES = [
    "display:none",
    "visibility:hidden",
    "opacity:0",
    "font-size:0",
    "left:-9999px",
]


# -------------------------------
# HTML Processing
# -------------------------------
def extract_text(html):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = soup.get_text(separator=" ").lower()
    return soup, text


def detect_injection(text):
    return [w for w in INJECTION_KEYWORDS if w in text]


def detect_hidden(soup):
    hidden = []
    for tag in soup.find_all(style=True):
        style = tag.get("style", "").replace(" ", "").lower()
        for rule in HIDDEN_STYLES:
            if rule in style:
                hidden.append("Hidden element detected")
                break
        if (
            ("position:fixed" in style or "position:absolute" in style)
            and "opacity:0" in style
        ):
            hidden.append("Possible clickjacking overlay detected")

    for iframe in soup.find_all("iframe"):
        style = iframe.get("style", "").lower()
        if "display:none" in style or "opacity:0" in style:
            hidden.append("Hidden iframe detected (clickjacking)")
    return hidden


def detect_phishing(soup, page_url, text):
    findings = []
    parsed = urlparse(page_url)
    domain = parsed.netloc.lower()

    has_password_form = any(
        f.find("input", {"type": "password"})
        for f in soup.find_all("form")
    )

    if not has_password_form:
        return []

    for brand, allowed_domains in BRAND_DOMAINS.items():
        if brand in text and not any(domain.endswith(d) for d in allowed_domains):
            findings.append(
                f"Possible phishing: impersonates {brand} on {domain}"
            )
    return findings


# -------------------------------
# Runtime Behavior Analysis
# -------------------------------
def analyze_behavior(behavior):
    risk = 0
    reasons = []

    if not behavior:
        return 0, []

    if behavior.get("domMutations", 0) > 20:
        risk += 15
        reasons.append("High runtime DOM mutation volume detected")

    if behavior.get("suspiciousOverlays", 0) > 2:
        risk += 25
        reasons.append("Suspicious runtime UI overlays detected")

    if behavior.get("clickInterceptors", 0) > 0:
        risk += 15
        reasons.append("Click interception behavior detected")

    if behavior.get("eventHijacks", 0) > 3:
        risk += 15
        reasons.append("User interaction hijacking detected")

    return risk, reasons


# -------------------------------
# 🔥 Network Behavior Analysis (STEP 4)
# -------------------------------
def analyze_network(network, page_url):
    risk = 0
    reasons = []

    if not network:
        return 0, []

    page_domain = urlparse(page_url).netloc.lower()

    for req in network:
        req_domain = (req.get("domain") or "").lower()
        method = req.get("method", "").upper()

        if not req_domain:
            continue

        # Cross-origin POSTs are HIGH risk
        if req_domain != page_domain and method in ("POST", "PUT", "BEACON"):
            risk += 30
            reasons.append(
                f"Cross-origin data exfiltration attempt to {req_domain}"
            )

        # Credential keywords in URL
        url = (req.get("url") or "").lower()
        if any(k in url for k in ["password", "token", "session", "auth"]):
            risk += 25
            reasons.append(
                f"Sensitive data transmission detected ({method})"
            )

    return risk, reasons


# -------------------------------
# Main Scanner
# -------------------------------
def scan_page(payload, page_url=None):
    html = payload.get("html", "")
    behavior = payload.get("behavior", {})
    network = payload.get("network", [])

    soup, text = extract_text(html)

    injection = detect_injection(text)
    hidden = detect_hidden(soup)
    phishing = detect_phishing(soup, page_url or "", text)

    ml_result = predict_attack(text)
    llm_result, llm_reasons = analyze_intent(text)

    behavior_risk, behavior_reasons = analyze_behavior(behavior)
    network_risk, network_reasons = analyze_network(network, page_url or "")

    base_risk, reasons, confidence, decision = calculate_risk(
        injection,
        hidden,
        phishing,
        ml_result,
        llm_result,
        behavior_risk=behavior_risk + network_risk,
        behavior_findings=behavior_reasons + network_reasons,
    )

    return {
        "injection": injection,
        "hidden": hidden,
        "phishing": phishing,
        "ml_result": ml_result,
        "llm_result": llm_result,
        "behavior": behavior,
        "network": network,
        "risk": base_risk,
        "confidence": confidence,
        "reasons": reasons + llm_reasons,
        "decision": decision,
    }
