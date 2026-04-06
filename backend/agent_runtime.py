from __future__ import annotations

import re
from typing import Any, Dict, List


AUTH_PATTERNS = ("log in", "login", "sign in", "authenticate", "account")
DOWNLOAD_PATTERNS = ("download", "install", "save file", "attachment")
CLICK_PATTERNS = ("click", "continue", "open", "view", "proceed", "allow")
SENSITIVE_PATTERNS = ("password", "otp", "token", "credential", "secret", "verify your account")


def _normalize_text(value: str) -> str:
    return " ".join(str(value or "").lower().split())


def extract_page_instructions(page_text: str) -> List[str]:
    lowered = _normalize_text(page_text)
    instructions: List[str] = []

    if any(token in lowered for token in AUTH_PATTERNS):
        instructions.append("authenticate")
    if any(token in lowered for token in DOWNLOAD_PATTERNS):
        instructions.append("download")
    if any(token in lowered for token in CLICK_PATTERNS):
        instructions.append("click")
    if any(token in lowered for token in SENSITIVE_PATTERNS):
        instructions.append("submit_sensitive_data")

    return instructions


def detect_goal_conflict(user_goal: str, page_text: str) -> Dict[str, Any]:
    goal = _normalize_text(user_goal)
    instructions = extract_page_instructions(page_text)

    goal_intents = {
        "authenticate": any(token in goal for token in ("login", "sign in", "authenticate", "account")),
        "download": any(token in goal for token in ("download", "save", "install")),
        "click": any(token in goal for token in ("click", "open", "continue", "view")),
        "submit_sensitive_data": any(
            token in goal for token in ("password", "otp", "credential", "verify account", "secret")
        ),
    }

    conflicts = [intent for intent in instructions if not goal_intents.get(intent, False)]
    return {
        "page_instructions": instructions,
        "goal_conflict": bool(conflicts),
        "conflicts": conflicts,
    }


def summarize_goal(user_goal: str) -> Dict[str, Any]:
    goal = _normalize_text(user_goal)
    return {
        "read_only": any(token in goal for token in ("read", "review", "inspect", "analyze", "summarize")),
        "authenticate": any(token in goal for token in ("login", "sign in", "authenticate")),
        "download": any(token in goal for token in ("download", "install", "save")),
        "fill_form": any(token in goal for token in ("fill", "enter", "type", "submit")),
        "click_cta": any(token in goal for token in ("click", "open", "continue", "view")),
        "contains_sensitive": any(token in goal for token in ("password", "otp", "token", "credential")),
    }


def infer_page_surfaces(page_text: str, page_context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    lowered = _normalize_text(page_text)
    context = page_context or {}
    detected_patterns = {
        str(item).strip().lower()
        for item in context.get("detected_patterns", []) or []
        if str(item).strip()
    }
    network = context.get("browser_network", []) or []
    cross_origin_requests = [
        item for item in network if bool(item.get("crossOrigin"))
    ]

    button_labels = re.findall(
        r"\b(continue|verify|allow|sign in|log in|submit|download|open)\b",
        lowered,
    )

    return {
        "has_form": "<form" in lowered or "input" in lowered,
        "has_password": "password" in lowered,
        "has_email_field": "email" in lowered,
        "has_download": any(token in lowered for token in DOWNLOAD_PATTERNS),
        "has_verification_language": any(token in lowered for token in ("verify", "suspended", "urgent", "confirm your identity")),
        "button_labels": sorted(set(button_labels)),
        "detected_patterns": sorted(detected_patterns),
        "cross_origin_requests": len(cross_origin_requests),
        "runtime_manipulation": bool(
            detected_patterns.intersection(
                {
                    "hidden_overlays",
                    "clickjacking_iframe",
                    "opacity_clickjacking",
                    "mutation_ui_injection",
                    "dynamic_ui_injection",
                    "event_hijacking",
                }
            )
        ),
    }


class MockWebAgent:
    def plan(
        self,
        *,
        user_goal: str,
        page_text: str,
        page_url: str,
        page_context: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        goal_summary = summarize_goal(user_goal)
        surfaces = infer_page_surfaces(page_text, page_context)
        page_instructions = extract_page_instructions(page_text)

        if goal_summary["read_only"]:
            action = {"type": "navigate", "target": page_url, "mode": "read_only"}
            rationale = "Goal is informational, so the safest plan is non-interactive browsing."
        elif surfaces["has_password"] and (goal_summary["authenticate"] or goal_summary["fill_form"]):
            action = {
                "type": "type",
                "target": "input[type='password'], input[type='email'], input, textarea",
                "value": "USER_PROVIDED_SECRET",
                "requires_confirmation": True,
            }
            rationale = "The page exposes credential inputs, so any typing plan must be treated as sensitive."
        elif surfaces["has_download"] and goal_summary["download"]:
            action = {
                "type": "click",
                "target": "a[download], button, a",
                "requires_confirmation": True,
            }
            rationale = "The goal includes a download, so the plan proposes a guarded click on a download surface."
        elif goal_summary["fill_form"] and surfaces["has_form"]:
            action = {
                "type": "type",
                "target": "input, textarea",
                "value": user_goal[:160],
            }
            rationale = "The page exposes an editable form, so the plan proposes controlled text entry."
        else:
            action = {"type": "click", "target": "button, [role='button'], a"}
            rationale = "The plan falls back to a bounded click action on visible controls."

        return {
            "provider": "secureagent-heuristic-planner",
            "user_goal": str(user_goal or "").strip(),
            "page_url": page_url,
            "page_instructions": page_instructions,
            "goal_summary": goal_summary,
            "page_surfaces": surfaces,
            "proposed_action": action,
            "reasoning": rationale,
            "safety_checks": [
                "Compare page instructions against the user goal before executing.",
                "Treat credential entry, downloads, and verification flows as sensitive.",
                "Escalate when runtime UI manipulation or cross-origin traffic is present.",
            ],
        }
