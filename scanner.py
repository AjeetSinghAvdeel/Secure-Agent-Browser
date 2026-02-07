from bs4 import BeautifulSoup
from risk import calculate_risk
from ml_model import predict_attack
from llm_reasoner import analyze_intent   # NEW


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
    "dump database"
]

HIDDEN_STYLES = [
    "display:none",
    "visibility:hidden",
    "opacity:0",
    "font-size:0",
    "left:-9999px"
]


def extract_text(html):

    soup = BeautifulSoup(html, "html.parser")

    # Remove script/style noise
    for tag in soup(["script", "style"]):
        tag.decompose()

    text = soup.get_text().lower()

    return soup, text


# -------------------------------
# Injection Detection
# -------------------------------

def detect_injection(text):

    matches = []

    for w in INJECTION_KEYWORDS:
        if w in text:
            matches.append(w)

    return matches


# -------------------------------
# Hidden / Clickjacking Detection
# -------------------------------

def detect_hidden(soup):

    hidden = []

    for tag in soup.find_all(style=True):

        style = tag.get("style", "").replace(" ", "").lower()

        for rule in HIDDEN_STYLES:
            if rule in style:
                hidden.append("Hidden element detected")
                break

        if ("position:fixed" in style or "position:absolute" in style):
            if "opacity:0" in style or "z-index" in style:
                hidden.append("Possible clickjacking overlay detected")


    for iframe in soup.find_all("iframe"):

        style = iframe.get("style", "").lower()

        if "display:none" in style or "opacity:0" in style:
            hidden.append("Hidden iframe detected (clickjacking)")


    return hidden


# -------------------------------
# Phishing Detection
# -------------------------------

def detect_phishing(soup):

    forms = []

    for form in soup.find_all("form"):

        if form.find("input", {"type": "password"}):
            forms.append("Suspicious login form detected")

    return forms


# -------------------------------
# Main Scanner
# -------------------------------

def scan_page(html):

    soup, text = extract_text(html)

    injection = detect_injection(text)
    hidden = detect_hidden(soup)
    phishing = detect_phishing(soup)

    # -------------------------------
    # ML Detection
    # -------------------------------

    ml_result = predict_attack(text)   # 1 = attack, 0 = safe


    # -------------------------------
    # LLM Reasoning (NEW)
    # -------------------------------

    llm_result, llm_reasons = analyze_intent(text)


    # Risk evaluation
    score, reasons = calculate_risk(
        injection,
        hidden,
        phishing,
        ml_result,
        llm_result      # NEW
    )

    return {
        "injection": injection,
        "hidden": hidden,
        "phishing": phishing,
        "ml_result": ml_result,
        "llm_result": llm_result,
        "llm_reasons": llm_reasons,
        "risk": score,
        "reasons": reasons + llm_reasons
    }
