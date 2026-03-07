"""Deterministic domain trust scoring for SecureAgent."""

from __future__ import annotations

from urllib.parse import urlparse


def extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower()


def calculate_domain_trust(url: str) -> int:
    trust = 100
    domain = extract_domain(url)

    # suspicious TLDs
    suspicious_tlds = [
        ".xyz",
        ".top",
        ".gq",
        ".tk",
        ".ml",
        ".cf",
        ".click",
        ".work",
    ]

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            trust -= 30
            break

    # HTTP instead of HTTPS
    if str(url).startswith("http://"):
        trust -= 15

    # long random domains
    if len(domain) > 30:
        trust -= 10

    # many hyphens (phishing indicator)
    if domain.count("-") > 3:
        trust -= 10

    # numeric heavy domains
    digits = sum(c.isdigit() for c in domain)
    if digits > 5:
        trust -= 10

    trust = max(0, min(100, trust))
    return trust

