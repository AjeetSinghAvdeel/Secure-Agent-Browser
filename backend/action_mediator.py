from __future__ import annotations

from typing import Any, Iterable
try:
    import policy_engine
except Exception:  # pragma: no cover - package import fallback
    from . import policy_engine  # type: ignore


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
    raw_action_name = str(action or "").strip().lower()
    action_aliases = {
        "click": "click_button",
        "type": "enter_text",
        "navigate": "navigate",
    }
    action_name = action_aliases.get(raw_action_name, raw_action_name)
    page_policy = str(page_decision or "ALLOW").upper()
    context = action_context or {}
    target_text = str(context.get("target_text") or "").strip().lower()
    input_type = str(context.get("input_type") or "").strip().lower()
    form_action = str(context.get("form_action") or "").strip().lower()
    user_goal = str(context.get("user_goal") or "").strip().lower()
    intent_text = f"{target_text} {form_action}".strip()
    sensitive_submission = any(
        token in intent_text for token in ("verify", "login", "password", "otp")
    ) or input_type in {"password", "email"}
    sensitive_approval = any(
        token in intent_text for token in ("approve access", "export data", "connect wallet", "grant access")
    )
    action_policy = policy_engine.evaluate_action_policy(
        risk_score=risk,
        action=action_name,
        input_type=input_type,
        target_text=target_text,
    )

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
    ) and action_name in {"submit_form", "enter_text"}:
        return {
            "decision": "BLOCK" if sensitive_submission else "WARN",
            "reason": "Possible credential harvesting",
        }

    if user_goal and "submit_sensitive_data" not in user_goal and sensitive_submission:
        return {
            "decision": "WARN",
            "reason": "Sensitive submission does not clearly match the user goal",
        }

    if sensitive_approval and not any(token in user_goal for token in ("approve", "grant access", "export", "wallet")):
        return {
            "decision": "WARN" if page_policy in {"ALLOW", "WARN"} else "BLOCK",
            "reason": "High-impact approval action does not match the current user goal",
        }

    if page_policy == "WARN" and action_name in {"submit_form", "enter_text"}:
        return {
            "decision": "WARN",
            "reason": "Page risk is elevated, review before continuing",
        }

    if action_policy["decision"] == "REQUIRE_CONFIRMATION":
        return {
            "decision": "REQUIRE_CONFIRMATION",
            "reason": action_policy["reason"],
        }

    if action_policy["decision"] == "WARN":
        return {
            "decision": "WARN",
            "reason": action_policy["reason"],
        }

    return {
        "decision": "ALLOW",
        "reason": "Action appears safe",
    }
