"""Domain intelligence utilities for URL trust scoring."""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

import tldextract

SUSPICIOUS_TLDS = {"xyz", "top", "click", "ru", "tk"}
PHISHING_KEYWORDS = {"login", "verify", "secure", "update", "account", "password"}
IP_ADDRESS_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _extract_host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").lower()


def _is_ip_address(host: str) -> bool:
    if not IP_ADDRESS_PATTERN.fullmatch(host):
        return False
    octets = host.split(".")
    return all(0 <= int(octet) <= 255 for octet in octets)


def analyze_url(url: str) -> Dict[str, object]:
    """
    Analyze a URL and compute trust information.

    Returns:
        {
          "trust_score": int (0-100),
          "risk_penalty": float (0-1),
          "flags": list[str]
        }
    """
    flags: List[str] = []
    penalty = 0.0
    lowered_url = url.lower()
    host = _extract_host(url)

    extracted = tldextract.extract(host)
    tld = extracted.suffix.lower()

    if tld in SUSPICIOUS_TLDS:
        flags.append("suspicious_tld")
        penalty += 0.25

    if any(keyword in lowered_url for keyword in PHISHING_KEYWORDS):
        flags.append("phishing_keyword")
        penalty += 0.25

    if _is_ip_address(host):
        flags.append("ip_address_url")
        penalty += 0.30

    if len(extracted.subdomain) > 30:
        flags.append("long_subdomain")
        penalty += 0.20

    penalty = min(1.0, penalty)
    trust_score = max(0, min(100, round((1.0 - penalty) * 100)))

    return {
        "trust_score": trust_score,
        "risk_penalty": round(penalty, 3),
        "flags": flags,
    }


def analyze_domain(url: str) -> Dict[str, object]:
    """Backward-compatible public API for domain analysis."""
    return analyze_url(url)


if __name__ == "__main__":
    test_urls = [
        "https://example.com",
        "http://192.168.1.10/login",
        "https://secure-verify-account-update.top/signin",
        "http://this.is.a.very.long.subdomain.structure.that.looks.suspicious.example.com",
        "http://bank-login-alert.xyz/verify",
        "https://github.com",
    ]

    for test_url in test_urls:
        print(f"URL: {test_url}")
        print(analyze_url(test_url))
        print("-" * 60)
