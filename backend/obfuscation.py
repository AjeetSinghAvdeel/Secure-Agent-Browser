"""Obfuscation detection utilities for webpage content analysis."""

from __future__ import annotations

import re
from typing import Dict, List

# Long base64-like blob candidates (heuristic pre-filter).
BASE64_CANDIDATE_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
# Long hexadecimal payload candidates.
HEX_PAYLOAD_PATTERN = re.compile(r"\b(?:0x)?[A-Fa-f0-9]{40,}\b")
# Hidden element/style indicators.
DISPLAY_NONE_PATTERN = re.compile(r"display\s*:\s*none", re.IGNORECASE)
VISIBILITY_HIDDEN_PATTERN = re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE)
OPACITY_ZERO_PATTERN = re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.IGNORECASE)
HIDDEN_ATTR_PATTERN = re.compile(r"<[^>]*\bhidden\b[^>]*>", re.IGNORECASE)
# Suspicious Unicode ranges commonly used for visual spoofing/obfuscation.
SUSPICIOUS_UNICODE_PATTERN = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]"
)


def analyze_obfuscation(content: str) -> Dict[str, object]:
    """
    Analyze webpage content for obfuscation indicators.

    Returns:
        {
          "obfuscation_score": float (0-1),
          "hidden_elements_detected": bool,
          "flags": list[str]
        }
    """
    flags: List[str] = []
    penalty = 0.0

    has_base64_blob = _has_base64_blob(content)
    has_hex_payload = bool(HEX_PAYLOAD_PATTERN.search(content))
    has_hidden_dom = any(
        (
            DISPLAY_NONE_PATTERN.search(content),
            VISIBILITY_HIDDEN_PATTERN.search(content),
            OPACITY_ZERO_PATTERN.search(content),
            HIDDEN_ATTR_PATTERN.search(content),
        )
    )
    has_suspicious_unicode = bool(SUSPICIOUS_UNICODE_PATTERN.search(content))

    if has_base64_blob:
        flags.append("base64_blob")
        penalty += 0.30

    if has_hex_payload:
        flags.append("hex_payload")
        penalty += 0.25

    if has_hidden_dom:
        flags.append("hidden_dom_element")
        penalty += 0.25

    if has_suspicious_unicode:
        flags.append("suspicious_unicode")
        penalty += 0.20

    penalty = min(1.0, penalty)

    return {
        "obfuscation_score": round(penalty, 3),
        "hidden_elements_detected": has_hidden_dom,
        "flags": flags,
    }


def _has_base64_blob(content: str) -> bool:
    for match in BASE64_CANDIDATE_PATTERN.finditer(content):
        blob = match.group(0)
        core = blob.rstrip("=")

        # Reject payloads that do not look encoded (e.g., long hex-like tokens).
        has_mixed_alnum = any(c.isdigit() for c in core) and any(c.isalpha() for c in core)
        has_base64_symbols = "+" in core or "/" in core
        if not (has_mixed_alnum or has_base64_symbols):
            continue

        # Base64 strings are typically aligned to 4-char blocks.
        if len(blob) % 4 != 0:
            continue

        return True
    return False


if __name__ == "__main__":
    samples = [
        (
            "clean_html",
            "<html><body><h1>Welcome</h1><p>No suspicious content here.</p></body></html>",
        ),
        (
            "base64_and_hidden",
            (
                "<div style='display:none'>"
                "QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l"
                "</div>"
            ),
        ),
        (
            "hex_and_unicode",
            (
                "<script>var x='deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';</script>"
                "Normal text\u200bwith zero-width char."
            ),
        ),
        (
            "hidden_attribute",
            "<span hidden>Do not show</span><p>Visible text</p>",
        ),
    ]

    for name, sample in samples:
        print(f"Sample: {name}")
        print(analyze_obfuscation(sample))
        print("-" * 60)
