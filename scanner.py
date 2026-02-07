from bs4 import BeautifulSoup
from risk import calculate_risk


# Dangerous phrases
INJECTION_KEYWORDS = [
    "ignore previous",
    "act as system",
    "admin mode",
    "override",
    "send password",
    "reveal secret"
]

# Hidden styles
HIDDEN_STYLES = [
    "display:none",
    "visibility:hidden",
    "opacity:0",
    "font-size:0",
    "left:-9999px"
]


def extract_text(html):

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text().lower()

    return soup, text


def detect_injection(text):

    found = []

    for word in INJECTION_KEYWORDS:
        if word in text:
            found.append(word)

    return found


def detect_hidden(soup):

    hidden = []

    for tag in soup.find_all(style=True):

        style = tag["style"].replace(" ", "").lower()

        for rule in HIDDEN_STYLES:
            if rule in style:
                hidden.append(str(tag)[:100])

    return hidden


def detect_phishing(soup):

    forms = []

    for form in soup.find_all("form"):

        if form.find("input", {"type": "password"}):
            forms.append(str(form)[:150])

    return forms


def scan_page(html):

    soup, text = extract_text(html)

    injection = detect_injection(text)
    hidden = detect_hidden(soup)
    phishing = detect_phishing(soup)

    score, reasons = calculate_risk(
        injection, hidden, phishing
    )

    return {
        "injection": injection,
        "hidden": hidden,
        "phishing": phishing,
        "risk": score,
        "reasons": reasons
    }