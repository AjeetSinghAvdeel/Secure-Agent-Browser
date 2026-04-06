"""Policy-as-code engine for risk response decisions."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml

DEFAULT_POLICY_MODE = "balanced"
POLICY_DIR = Path(__file__).resolve().parent / "policies"
ALLOWED_DECISIONS = ("ALLOW", "WARN", "REQUIRE_CONFIRMATION", "BLOCK")


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _normalize_risk(risk_score: float) -> float:
    """
    Normalize risk score into [0, 1].
    Supports both normalized (0-1) and percent-like (0-100) inputs.
    """
    risk = float(risk_score)
    if risk > 1.0:
        risk = risk / 100.0
    return _clamp01(risk)


def load_policy(policy_mode: str = DEFAULT_POLICY_MODE) -> Dict[str, float]:
    """
    Load policy thresholds from YAML for the selected mode.
    """
    mode = (policy_mode or DEFAULT_POLICY_MODE).strip().lower()
    policy_path = POLICY_DIR / f"{mode}.yaml"

    if not policy_path.exists():
        raise ValueError(
            f"Unknown policy mode '{policy_mode}'. "
            f"Expected one of: strict, balanced, research."
        )

    with policy_path.open("r", encoding="utf-8") as f:
        policy = yaml.safe_load(f) or {}

    if "block_if_risk_above" not in policy or "warn_if_risk_above" not in policy:
        raise ValueError(f"Policy file '{policy_path.name}' is missing required keys.")

    block_threshold = _clamp01(policy["block_if_risk_above"])
    warn_threshold = _clamp01(policy["warn_if_risk_above"])

    if warn_threshold >= block_threshold:
        raise ValueError(
            f"Invalid policy '{policy_path.name}': warn_if_risk_above must be lower "
            "than block_if_risk_above."
        )

    return {
        "block_if_risk_above": block_threshold,
        "warn_if_risk_above": warn_threshold,
    }


def evaluate_risk_policy(
    risk_score: float,
    policy_mode: str = DEFAULT_POLICY_MODE,
    *,
    signal_details: list[Dict[str, Any]] | None = None,
    attack_type: str = "",
    is_local_simulation: bool = False,
    is_trusted_domain: bool = False,
    has_threat_intel: bool = False,
) -> Dict[str, str]:
    """
    Evaluate risk score against a selected policy.

    Returns:
        {
          "decision": "ALLOW | WARN | BLOCK",
          "policy_mode": "...",
          "reason": "..."
        }
    """
    risk = _normalize_risk(risk_score)
    mode = (policy_mode or DEFAULT_POLICY_MODE).strip().lower()
    risk_percent = int(round(risk * 100))
    policy = load_policy(mode)
    warn_threshold = int(round(policy["warn_if_risk_above"] * 100))
    block_threshold = int(round(policy["block_if_risk_above"] * 100))
    details = list(signal_details or [])
    high_or_critical = [
        signal
        for signal in details
        if str(signal.get("severity", "")).lower() in {"high", "critical"}
    ]
    critical = [
        signal
        for signal in details
        if str(signal.get("severity", "")).lower() == "critical"
    ]
    attack = str(attack_type or "").strip().lower()

    elevated_ui_attack = attack in {"clickjacking", "dynamic script attack"} and len(high_or_critical) >= 2

    if critical or (
        elevated_ui_attack and (not is_trusted_domain or has_threat_intel or risk_percent >= warn_threshold)
    ):
        return {
            "decision": "BLOCK" if risk_percent >= max(55, warn_threshold) else "WARN",
            "policy_mode": mode,
            "reason": (
                "High-severity attack signals override the base threshold evaluation."
            ),
        }

    if is_local_simulation and len(high_or_critical) >= 2 and risk_percent >= max(30, warn_threshold - 10):
        return {
            "decision": "WARN",
            "policy_mode": mode,
            "reason": "Local simulator page contains multiple high-severity attack indicators.",
        }

    if risk_percent >= block_threshold:
        decision = "BLOCK"
        reason = (
            f"Risk score {risk_percent} exceeds block threshold {block_threshold} "
            f"for '{mode}' policy."
        )
    elif risk_percent >= warn_threshold:
        decision = "WARN"
        reason = (
            f"Risk score {risk_percent} exceeds warn threshold {warn_threshold} "
            f"for '{mode}' policy."
        )
    else:
        decision = "ALLOW"
        reason = (
            f"Risk score {risk_percent} is below warn threshold {warn_threshold} "
            f"for '{mode}' policy."
        )

    return {
        "decision": decision,
        "policy_mode": mode,
        "reason": reason,
    }


def evaluate_action_policy(
    *,
    risk_score: float,
    action: str,
    input_type: str = "",
    target_text: str = "",
) -> Dict[str, str]:
    risk = _normalize_risk(risk_score)
    risk_percent = int(round(risk * 100))
    action_name = str(action or "").strip().lower()
    input_kind = str(input_type or "").strip().lower()
    label = f"{target_text} {input_kind}".lower()
    sensitive = input_kind in {"password", "email"} or any(
        token in label for token in ("password", "otp", "verify", "code", "token")
    )
    high_risk_action = action_name in {"submit_form", "enter_text", "type"} and risk_percent >= 55

    if risk_percent >= 80:
        return {
            "decision": "BLOCK",
            "reason": f"Action blocked because risk score {risk_percent} exceeds 80.",
        }

    if sensitive or high_risk_action:
        return {
            "decision": "REQUIRE_CONFIRMATION",
            "reason": "Sensitive or high-risk action requires explicit user confirmation.",
        }

    if risk_percent >= 50:
        return {
            "decision": "WARN",
            "reason": f"Action is elevated risk because score {risk_percent} exceeds 50.",
        }

    return {
        "decision": "ALLOW",
        "reason": "Action is within acceptable policy limits.",
    }


def evaluate_action(
    action: Dict[str, Any],
    scan_result: Dict[str, Any],
    policy_mode: str = DEFAULT_POLICY_MODE,
) -> Dict[str, str]:
    """
    Backward-compatible wrapper used by API flow.
    Reads risk from scan result and applies selected policy mode.
    """
    _ = action  # Action-specific controls can be layered here later.
    risk_score = scan_result.get("risk", 0)
    return evaluate_risk_policy(risk_score=risk_score, policy_mode=policy_mode)


if __name__ == "__main__":
    test_cases = [
        ("strict", 0.2),
        ("strict", 0.4),
        ("strict", 0.8),
        ("balanced", 0.55),
        ("research", 0.85),
        ("research", 0.95),
    ]

    for mode, risk in test_cases:
        result = evaluate_risk_policy(risk_score=risk, policy_mode=mode)
        print(f"mode={mode}, risk={risk:.2f} -> {result}")
