from __future__ import annotations

from time import time
from typing import Any, Dict, Optional

import requests

URLHAUS_LOOKUP_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/text_recent/"
PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.csv"
TIMEOUT = 6
FEED_CACHE_TTL_SECONDS = 600
_FEED_CACHE: Dict[str, Dict[str, Any]] = {}


def _check_urlhaus(url: str) -> Optional[Dict[str, Any]]:
    try:
        res = requests.post(
            URLHAUS_LOOKUP_URL,
            data={"url": url},
            timeout=TIMEOUT,
            headers={"User-Agent": "SecureAgent Threat Intel"},
        )
        if not res.ok:
            return None
        payload = res.json()
        status = str(payload.get("query_status", "")).lower()
        if status == "ok":
            threat = payload.get("threat") or payload.get("url_status") or "malicious_url"
            return {"threat": str(threat), "confidence": 0.9}
    except Exception:
        return None
    return None


def _check_feed(feed_url: str, url: str, threat: str, confidence: float) -> Optional[Dict[str, Any]]:
    target = url.strip().lower()
    if not target:
        return None

    now = time()
    cached = _FEED_CACHE.get(feed_url)
    if cached and now - float(cached.get("updated_at", 0)) <= FEED_CACHE_TTL_SECONDS:
        if target in str(cached.get("text", "")).lower():
            return {"threat": threat, "confidence": confidence}
        return None

    try:
        res = requests.get(
            feed_url,
            timeout=TIMEOUT,
            headers={"User-Agent": "SecureAgent Threat Intel"},
        )
        if not res.ok:
            return None
        text = res.text or ""
        _FEED_CACHE[feed_url] = {"updated_at": now, "text": text}
        if target in text.lower():
            return {"threat": threat, "confidence": confidence}
    except Exception:
        return None
    return None


def _check_phishtank(url: str) -> Optional[Dict[str, Any]]:
    return _check_feed(
        PHISHTANK_FEED_URL,
        url,
        threat="phishing",
        confidence=0.9,
    )


def check_threat_intel(url: str) -> Optional[Dict[str, Any]]:
    """
    Best-effort malicious URL lookup against public threat-intel sources.
    Returns a threat dict when a match is found, else None.
    """
    target = (url or "").strip()
    if not target or target.startswith("/attacks/"):
        return None

    return (
        _check_urlhaus(target)
        or _check_feed(URLHAUS_FEED_URL, target, "malware", 0.9)
        or _check_phishtank(target)
    )
