"""Domain intelligence utilities for URL trust scoring."""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

import tldextract
from domain_intelligence import calculate_domain_trust

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
    lowered_url = url.lower()
    host = _extract_host(url)
    extracted = tldextract.extract(host)

    if any(host.endswith(f".{tld}") or host == tld for tld in SUSPICIOUS_TLDS):
        flags.append("suspicious_tld")

    if any(keyword in lowered_url for keyword in PHISHING_KEYWORDS):
        flags.append("phishing_keyword")

    if _is_ip_address(host):
        flags.append("ip_address_url")

    if len(host) > 30:
        flags.append("long_subdomain")
    if host.count("-") > 3:
        flags.append("many_hyphens")
    if sum(c.isdigit() for c in host) > 5:
        flags.append("numeric_heavy_domain")
    if str(url).startswith("http://"):
        flags.append("no_https")

    trust_score = calculate_domain_trust(url)
    penalty = round((100 - trust_score) / 100.0, 3)

    return {
        "trust_score": trust_score,
        "risk_penalty": penalty,
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
