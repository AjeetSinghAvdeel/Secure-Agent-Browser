from __future__ import annotations

from typing import Any, Iterable


def evaluate_action(
    action: str,
    indicators: Iterable[str],
    risk: float,
    *,
    page_decision: str = "ALLOW",
    attack_type: str = "Suspicious Content",
    action_context: dict[str, Any] | None = None,
) -> dict[str, str]:
    normalized = {str(item).strip().lower() for item in indicators}
    expanded = normalized | {item.replace("_", " ") for item in normalized}
    action_name = str(action or "").strip().lower()
    page_policy = str(page_decision or "ALLOW").upper()
    context = action_context or {}
    target_text = str(context.get("target_text") or "").strip().lower()
    input_type = str(context.get("input_type") or "").strip().lower()
    form_action = str(context.get("form_action") or "").strip().lower()
    sensitive_submission = any(
        token in f"{target_text} {form_action}" for token in ("verify", "login", "password", "otp")
    ) or input_type in {"password", "email"}

    if page_policy == "BLOCK" or float(risk) >= 0.8:
        return {
            "decision": "BLOCK",
            "reason": "High risk webpage",
        }

    if (
        "prompt injection" in expanded
        and action_name in {"submit_form", "enter_text"}
    ):
        return {
            "decision": "BLOCK",
            "reason": "Prompt injection may manipulate agent",
        }

    if attack_type == "Prompt Injection" and action_name == "click_button":
        return {
            "decision": "WARN",
            "reason": "This page contains prompt injection indicators",
        }

    if (
        "phishing_keyword" in normalized
        or "phishing_intent" in expanded
        or "credential_request" in expanded
    ) and action_name == "submit_form":
        return {
            "decision": "BLOCK" if sensitive_submission else "WARN",
            "reason": "Possible credential harvesting",
        }

    if page_policy == "WARN" and action_name in {"submit_form", "enter_text"}:
        return {
            "decision": "WARN",
            "reason": "Page risk is elevated, review before continuing",
        }

    return {
        "decision": "ALLOW",
        "reason": "Action appears safe",
    }
