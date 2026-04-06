from __future__ import annotations

import re
from typing import Any, Dict, List


BUTTON_DIV_PATTERN = re.compile(
    r"<(?:div|span|a)[^>]*(?:role=['\"]button['\"]|onclick=|cursor\s*:\s*pointer)[^>]*>",
    re.IGNORECASE,
)
OVERLAY_PATTERN = re.compile(
    r"(position\s*:\s*(?:fixed|absolute)[^>]{0,160}(?:z-index\s*:\s*[7-9]\d{2,}|opacity\s*:\s*0(?:\.0+)?))",
    re.IGNORECASE,
)
IFRAME_PATTERN = re.compile(r"<iframe\b[^>]*>", re.IGNORECASE)
OPACITY_ZERO_PATTERN = re.compile(r"opacity\s*:\s*0(?:\.0+)?", re.IGNORECASE)
DISPLAY_NONE_PATTERN = re.compile(r"display\s*:\s*none", re.IGNORECASE)
TINY_FONT_PATTERN = re.compile(r"font-size\s*:\s*([0-7](?:\.\d+)?)px", re.IGNORECASE)
HIGH_Z_INDEX_PATTERN = re.compile(r"z-index\s*:\s*([1-9]\d{3,})", re.IGNORECASE)
POINTER_EVENTS_PATTERN = re.compile(r"pointer-events\s*:\s*auto", re.IGNORECASE)
PASSWORD_FORM_PATTERN = re.compile(r"<form\b[\s\S]*?type=['\"]password['\"]", re.IGNORECASE)
OFFSCREEN_PATTERN = re.compile(r"(left|top)\s*:\s*-?\d{3,}px", re.IGNORECASE)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"createelement\(\s*['\"]script['\"]\s*\)|appendchild\(\s*script\s*\)",
    re.IGNORECASE,
)
DOM_INJECTION_PATTERN = re.compile(
    r"createelement\(\s*['\"]div['\"]\s*\)|appendchild\(\s*overlay\s*\)|settimeout\s*\(",
    re.IGNORECASE,
)
EVENT_HIJACK_PATTERN = re.compile(
    r"document\.addeventlistener\(\s*['\"](click|submit|beforeinput)['\"]",
    re.IGNORECASE,
)


def _normalize_pattern(pattern: str) -> str:
    return pattern.strip().lower().replace(" ", "_")


def analyze_ui_deception(
    html: str,
    page_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    content = html or ""
    context = page_context or {}
    patterns: List[str] = []
    evidence: List[str] = []
    score = 0.0

    fake_button_hits = len(BUTTON_DIV_PATTERN.findall(content))
    misleading_form_hits = 1 if PASSWORD_FORM_PATTERN.search(content) else 0
    overlay_hits = len(OVERLAY_PATTERN.findall(content))
    iframe_hits = len(IFRAME_PATTERN.findall(content))
    hidden_clickable_hits = 0
    z_index_abuse_hits = len(HIGH_Z_INDEX_PATTERN.findall(content))
    tiny_font_hits = len(TINY_FONT_PATTERN.findall(content))

    if fake_button_hits:
        patterns.append("fake_buttons")
        score += min(0.24, 0.08 * fake_button_hits)
        evidence.append(f"fake_button_hits={fake_button_hits}")
    if misleading_form_hits:
        patterns.append("misleading_forms")
        score += 0.18
        evidence.append("password_form_detected")
    if overlay_hits:
        patterns.append("hidden_overlays")
        score += min(0.24, 0.08 * overlay_hits)
        evidence.append(f"overlay_hits={overlay_hits}")
    if iframe_hits and (overlay_hits or OPACITY_ZERO_PATTERN.search(content)):
        patterns.append("clickjacking_iframe")
        score += min(0.25, 0.1 * iframe_hits)
        evidence.append(f"iframe_hits={iframe_hits}")
    if z_index_abuse_hits:
        patterns.append("z_index_abuse")
        score += min(0.16, 0.04 * z_index_abuse_hits)
        evidence.append(f"z_index_hits={z_index_abuse_hits}")
    if tiny_font_hits:
        patterns.append("tiny_font")
        score += min(0.12, 0.03 * tiny_font_hits)
        evidence.append(f"tiny_font_hits={tiny_font_hits}")

    if SCRIPT_INJECTION_PATTERN.search(content):
        patterns.append("script_injection")
        score += 0.22
        evidence.append("script_injection_pattern")

    if DOM_INJECTION_PATTERN.search(content):
        patterns.append("dynamic_ui_injection")
        score += 0.16
        evidence.append("dom_injection_pattern")

    if EVENT_HIJACK_PATTERN.search(content):
        patterns.append("event_hijacking")
        score += 0.14
        evidence.append("event_hijack_pattern")

    style_hits = sum(
        1
        for matched in (
            OPACITY_ZERO_PATTERN.search(content),
            DISPLAY_NONE_PATTERN.search(content),
            OFFSCREEN_PATTERN.search(content),
        )
        if matched
    )
    if style_hits and POINTER_EVENTS_PATTERN.search(content):
        hidden_clickable_hits += 1

    dom_patterns = [
        _normalize_pattern(item)
        for item in context.get("detected_patterns", [])
        if str(item).strip()
    ]

    if dom_patterns:
        if "fake_buttons" in dom_patterns:
            patterns.append("fake_buttons")
            score += 0.16
        if "misleading_forms" in dom_patterns:
            patterns.append("misleading_forms")
            score += 0.16
        if {"hidden_overlays", "invisible_clickable_area", "overlapping_elements"}.intersection(dom_patterns):
            patterns.append("hidden_overlays")
            score += 0.18
        if {"clickjacking_iframe", "opacity_clickjacking"}.intersection(dom_patterns):
            patterns.append("clickjacking_iframe")
            score += 0.20
        if "z_index_abuse" in dom_patterns:
            patterns.append("z_index_abuse")
            score += 0.12
        if "mutation_ui_injection" in dom_patterns:
            patterns.append("dynamic_ui_injection")
            score += 0.12

    hidden_clickable_hits += int(context.get("hidden_clickable_count", 0) or 0)
    if hidden_clickable_hits:
        patterns.append("invisible_clickable_area")
        score += min(0.2, 0.05 * hidden_clickable_hits)
        evidence.append(f"hidden_clickable_hits={hidden_clickable_hits}")

    overlapping_count = int(context.get("overlapping_count", 0) or 0)
    if overlapping_count:
        patterns.append("overlapping_elements")
        score += min(0.18, 0.04 * overlapping_count)
        evidence.append(f"overlapping_hits={overlapping_count}")

    mutation_count = int(context.get("mutation_count", 0) or 0)
    if mutation_count:
        patterns.append("mutation_ui_injection")
        score += min(0.18, 0.02 * mutation_count)
        evidence.append(f"mutation_count={mutation_count}")

    script_injection_count = int(context.get("script_injection_count", 0) or 0)
    if script_injection_count:
        patterns.append("script_injection")
        score += min(0.24, 0.08 * script_injection_count)
        evidence.append(f"script_injection_count={script_injection_count}")

    event_hook_count = int(context.get("suspicious_event_hook_count", 0) or 0)
    if event_hook_count:
        patterns.append("event_hijacking")
        score += min(0.15, 0.03 * event_hook_count)
        evidence.append(f"event_hook_count={event_hook_count}")

    iframe_count = int(context.get("iframe_count", 0) or 0)
    if iframe_count and float(context.get("transparent_iframe_ratio", 0) or 0) > 0:
        patterns.append("opacity_clickjacking")
        score += 0.18
        evidence.append(f"transparent_iframes={iframe_count}")

    normalized_patterns: List[str] = []
    seen = set()
    for pattern in patterns:
        if pattern not in seen:
            seen.add(pattern)
            normalized_patterns.append(pattern)

    return {
        "ui_risk_score": round(min(1.0, score), 4),
        "detected_patterns": normalized_patterns,
        "evidence": evidence,
    }
