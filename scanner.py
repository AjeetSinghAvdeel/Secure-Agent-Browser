from bs4 import BeautifulSoup
from risk import calculate_risk


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

    # remove script/style noise
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
# Hidden Content Detection
# -------------------------------

def detect_hidden(soup):

    hidden = []

    for tag in soup.find_all(style=True):

        style = tag["style"].replace(" ", "").lower()

        for rule in HIDDEN_STYLES:
            if rule in style:
                hidden.append(str(tag)[:120])
                break

    return hidden


# -------------------------------
# Phishing Detection
# -------------------------------

def detect_phishing(soup):

    forms = []

    for form in soup.find_all("form"):

        if form.find("input", {"type": "password"}):
            forms.append(str(form)[:200])

    return forms


# -------------------------------
# Main Scanner
# -------------------------------

def scan_page(html):

    soup, text = extract_text(html)

    injection = detect_injection(text)
    hidden = detect_hidden(soup)
    phishing = detect_phishing(soup)

    # Send full lists to risk engine
    score, reasons = calculate_risk(injection, hidden, phishing)

    return {
        "injection": injection,
        "hidden": hidden,
        "phishing": phishing,
        "risk": score,
        "reasons": reasons
    }
