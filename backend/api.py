from __future__ import annotations

from datetime import datetime, timezone
from html import unescape
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

import os

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    import domain_intel
    import explainability
    import llm_reasoner
    import ml_model
    import obfuscation
    import policy_engine
    import risk
    import scanner
    import threat_intel
    from action_mediator import evaluate_action as evaluate_mediated_action
    from auth import router as auth_router
    from auth_middleware import AuthenticatedUser, get_current_user, require_roles
    from metrics import get_tracker, MetricsTracker
except Exception:  # pragma: no cover - package import fallback
    from . import domain_intel, explainability, llm_reasoner, ml_model, obfuscation, policy_engine, risk, scanner, threat_intel  # type: ignore
    from .action_mediator import evaluate_action as evaluate_mediated_action  # type: ignore
    from .auth import router as auth_router  # type: ignore
    from .auth_middleware import AuthenticatedUser, get_current_user, require_roles  # type: ignore
    from .metrics import get_tracker, MetricsTracker  # type: ignore

try:
    from firebase_admin import firestore
    from firebase_client import db
except Exception:  # pragma: no cover - optional in local/dev setups
    try:
        from firebase_admin import firestore
        from .firebase_client import db  # type: ignore
    except Exception:
        firestore = None
        db = None

try:
    from google.api_core.exceptions import FailedPrecondition
except Exception:  # pragma: no cover - optional in local/dev setups
    FailedPrecondition = Exception

app = FastAPI(title="SecureAgent Backend")

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "SECUREAGENT_CORS_ORIGINS",
        ",".join(
            [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "http://localhost:4173",
                "http://127.0.0.1:4173",
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://localhost:8080",
                "http://127.0.0.1:8080",
            ]
        ),
    ).split(",")
    if origin.strip()
]

LOCAL_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$"

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=LOCAL_ORIGIN_REGEX,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth_router)


# ============================================================================
# Startup Event Handler - Initializes all subsystems on server start
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """
    Initialize all SecureAgent subsystems when the uvicorn server starts.
    This ensures metrics tracking, task success measurement, and optional
    Firebase persistence are ready without requiring additional commands.
    """
    try:
        # Initialize metrics tracker
        tracker = get_tracker()
        print(f"✓ Metrics tracker initialized (TP=0, FP=0, TN=0, FN=0)")
    except Exception as e:
        print(f"⚠ Metrics initialization warning: {e}")
    
    try:
        # Initialize Firebase metrics (optional, gracefully degrades if unavailable)
        from firebase_metrics import setup_metrics_persistence
        setup_metrics_persistence()
        print("✓ Firebase metrics persistence initialized (optional)")
    except Exception:
        print("⊘ Firebase metrics not available (optional, continuing without cloud persistence)")
    
    try:
        # Initialize task success harness
        from task_success_harness import TaskSuccessHarness
        harness = TaskSuccessHarness()
        harness.register_default_scenarios()
        print("✓ Task success measurement harness initialized")
    except Exception as e:
        print(f"⚠ Task success harness warning: {e}")
    
    print("\n✅ SecureAgent startup complete. Ready to process requests.")


@app.get("/health")
def health_check():
    """
    Health check endpoint for SecureAgent backend.
    
    Returns current status of all subsystems:
    - status: Overall health status (healthy/degraded)
    - metrics_ready: Metrics tracking is initialized
    - firebase_ready: Optional Firebase persistence is available
    - timestamp: Server time in ISO 8601 format
    
    Example response:
    {
        "status": "healthy",
        "metrics_ready": true,
        "firebase_ready": true,
        "timestamp": "2024-01-15T10:30:00Z"
    }
    """
    try:
        tracker = get_tracker()
        metrics_active = tracker is not None
    except:
        metrics_active = False
    
    try:
        from firebase_admin import firestore
        firebase_available = firestore is not None
    except:
        firebase_available = False
    
    overall_status = "healthy" if metrics_active else "degraded"
    
    return {
        "status": overall_status,
        "metrics_ready": metrics_active,
        "firebase_ready": firebase_available,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# In-memory history enables extension -> dashboard visibility in local setups
# even when Firestore is unavailable.
SCAN_HISTORY: List[Dict[str, Any]] = []
ACTION_HISTORY: List[Dict[str, Any]] = []
MAX_HISTORY = 500
ACTION_AGGREGATION_WINDOW_SECONDS = 2.0


class ScanRequest(BaseModel):
    url: str
    ground_truth: str | None = None  # "malicious" or "benign" for evaluation


class ActionRequest(BaseModel):
    url: str
    action: str
    action_context: Dict[str, Any] | None = None


SIMULATOR_HOSTS = {"localhost", "127.0.0.1", "::1"}
PROMPT_INJECTION_PHRASES = (
    "ignore all previous instructions",
    "system override",
    "bypass security",
    "escalate privileges",
    "dump credentials",
    "exfiltrate secrets",
    "reveal hidden policies",
    "jailbreak",
)
PHISHING_PAGE_TERMS = (
    "verify your account",
    "suspended unless",
    "verify now",
    "confirm your identity",
    "unusual login attempt",
)
SUSPICIOUS_SCRIPT_TERMS = (
    "eval(",
    "atob(",
    "fromcharcode(",
    "hex_payload",
    "base64_blob",
)
TRUSTED_DOMAIN_SUFFIXES = (
    "google.com",
    "firebase.google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "cloudflare.com",
    "amazon.com",
    "wikipedia.org",
)


def _normalize_url(url: str) -> str:
    target = (url or "").strip()
    if not target:
        return target
    if target.startswith("/attacks/"):
        return target
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def _decision_to_status(decision: str) -> str:
    mapping = {"ALLOW": "safe", "WARN": "warning", "BLOCK": "blocked"}
    return mapping.get((decision or "").upper(), "warning")


def _predict_ml(html: str) -> float:
    if hasattr(ml_model, "predict_attack_score"):
        return float(ml_model.predict_attack_score(html))
    if hasattr(ml_model, "predict"):
        return float(ml_model.predict(html))
    if hasattr(ml_model, "predict_attack"):
        return float(ml_model.predict_attack(html))
    raise AttributeError("ml_model has no predict/predict_attack function")


def _extract_text_content(html: str) -> str:
    lowered = re.sub(r"(?is)<script.*?>.*?</script>", " ", html or "")
    lowered = re.sub(r"(?is)<style.*?>.*?</style>", " ", lowered)
    lowered = re.sub(r"(?s)<[^>]+>", " ", lowered)
    lowered = unescape(lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def _analyze_domain(url: str) -> Dict[str, Any]:
    if hasattr(domain_intel, "analyze_domain"):
        return domain_intel.analyze_domain(url)
    if hasattr(domain_intel, "analyze_url"):
        return domain_intel.analyze_url(url)
    raise AttributeError("domain_intel has no analyze_domain/analyze_url function")


def _evaluate_policy(risk_score: float) -> Dict[str, Any]:
    if hasattr(policy_engine, "evaluate_policy"):
        return policy_engine.evaluate_policy(risk_score)
    if hasattr(policy_engine, "evaluate_risk_policy"):
        return policy_engine.evaluate_risk_policy(risk_score)
    raise AttributeError("policy_engine has no evaluate_policy/evaluate_risk_policy")


def _semantic_signal(html: str) -> Dict[str, Any]:
    text = (html or "").lower()
    flags: List[str] = []
    score = 0.0

    if any(phrase in text for phrase in PROMPT_INJECTION_PHRASES):
        flags.append("prompt_injection_pattern")
        score += 0.45

    if any(term in text for term in PHISHING_PAGE_TERMS):
        flags.append("phishing_content_pattern")
        score += 0.35

    has_password_form = "<form" in text and "password" in text
    has_phish_context = (
        any(term in text for term in PHISHING_PAGE_TERMS)
        or "verify" in text
        or "suspend" in text
        or "urgent" in text
    )
    if has_password_form and has_phish_context:
        flags.append("credential_harvest_form")
        score += 0.20

    if any(term in text for term in SUSPICIOUS_SCRIPT_TERMS):
        flags.append("obfuscated_script_pattern")
        score += 0.25

    return {"score": min(1.0, round(score, 3)), "flags": flags}


def _host_context(url: str) -> Dict[str, Any]:
    host = (urlparse(url).hostname or "").lower()
    is_trusted = any(
        host == suffix or host.endswith(f".{suffix}")
        for suffix in TRUSTED_DOMAIN_SUFFIXES
    )
    return {"host": host, "is_trusted": is_trusted}


def _contextualize_flags(
    semantic_flags: List[str],
    obfuscation_flags: List[str],
    *,
    is_trusted: bool,
    has_intel: bool,
    domain_flags: List[str],
) -> Dict[str, List[str]]:
    # On trusted domains with no threat-intel hit, suppress noisy generic indicators.
    if not is_trusted or has_intel:
        return {
            "semantic_flags": semantic_flags,
            "obfuscation_flags": obfuscation_flags,
        }

    refined_semantic = [
        f for f in semantic_flags
        if f in {"prompt_injection_pattern", "credential_harvest_form"}
    ]
    suspicious_domain_present = bool(
        set(domain_flags).intersection(
            {"suspicious_tld", "ip_address_url", "many_hyphens", "numeric_heavy_domain"}
        )
    )
    refined_obfuscation = [
        f for f in obfuscation_flags
        if f in {"base64_blob", "hex_payload"} or suspicious_domain_present
    ]
    return {
        "semantic_flags": refined_semantic,
        "obfuscation_flags": refined_obfuscation,
    }


def _local_simulation_domain_adjustment(url: str, domain_data: Dict[str, Any]) -> Dict[str, Any]:
    adjusted = dict(domain_data)
    flags = list(adjusted.get("flags", []))
    host = (urlparse(url).hostname or "").lower()

    if host in SIMULATOR_HOSTS:
        penalty = max(float(adjusted.get("risk_penalty", 0.0)), 0.20)
        adjusted["risk_penalty"] = round(min(1.0, penalty), 3)
        flags.append("local_simulation_host")
        adjusted["trust_score"] = max(0, min(100, round((1.0 - adjusted["risk_penalty"]) * 100)))

    adjusted["flags"] = flags
    return adjusted


def _apply_signal_boosts(
    risk_data: Dict[str, Any],
    domain_flags: List[str],
    obfuscation_flags: List[str],
    semantic_flags: List[str],
    intel: Dict[str, Any] | None,
    *,
    is_trusted: bool,
) -> Dict[str, Any]:
    total = int(risk_data.get("risk_percent", round(float(risk_data.get("total_risk", 0.0)) * 100)))
    bonus = 0

    if "prompt_injection_pattern" in semantic_flags and "hidden_dom_element" in obfuscation_flags:
        bonus += 8
    if "credential_harvest_form" in semantic_flags and "phishing_keyword" in domain_flags:
        bonus += 10
    if intel:
        bonus += min(10, int(round(float(intel.get("confidence", 0.9)) * 10)))

    if is_trusted and not intel and "prompt_injection_pattern" not in semantic_flags:
        bonus = min(bonus, 4)

    adjusted = max(0, min(100, total + bonus))
    risk_data["risk_percent"] = adjusted
    risk_data["total_risk"] = round(adjusted / 100.0, 4)
    risk_data["confidence"] = adjusted
    return risk_data


def _classify_attack(indicators: List[str]) -> str:
    lowered = [str(item).lower() for item in indicators]

    if any("prompt" in item and "inject" in item for item in lowered):
        return "Prompt Injection"
    if any("phishing" in item or "credential_harvest" in item for item in lowered):
        return "Phishing"
    if any(
        token in item
        for item in lowered
        for token in ("base64", "hex", "unicode", "hidden", "obfuscat")
    ):
        return "Obfuscation"
    if any("threat_intel" in item for item in lowered):
        return "Known Threat"
    return "Suspicious Content"


def _signal_confidence(signal_type: str) -> str:
    mapping = {
        "prompt_injection": "high",
        "prompt_injection_pattern": "high",
        "credential_request": "high",
        "credential_harvest_form": "high",
        "phishing_intent": "high",
        "phishing_content_pattern": "high",
        "threat_intel_phishing": "critical",
        "threat_intel_malware": "critical",
        "threat_intel_malicious_url": "critical",
        "hidden_dom_element": "medium",
        "hex_payload": "medium",
        "base64_blob": "low",
        "obfuscated_script_pattern": "medium",
        "suspicious_unicode": "medium",
        "phishing_keyword": "medium",
    }
    return mapping.get(signal_type, "low")


def _signal_severity(signal_type: str) -> str:
    confidence = _signal_confidence(signal_type)
    if confidence == "critical":
        return "critical"
    if signal_type in {
        "prompt_injection",
        "prompt_injection_pattern",
        "credential_harvest_form",
        "credential_request",
    }:
        return "critical"
    if confidence == "high":
        return "high"
    if confidence == "medium":
        return "medium"
    return "low"


def _build_signal_details(indicators: List[str]) -> List[Dict[str, str]]:
    details: List[Dict[str, str]] = []
    seen: set[str] = set()

    for signal in indicators:
        signal_type = str(signal)
        if signal_type in seen:
            continue
        seen.add(signal_type)
        details.append(
            {
                "type": signal_type,
                "confidence": _signal_confidence(signal_type),
                "severity": _signal_severity(signal_type),
            }
        )

    return details


def _audit_target(entry: Dict[str, Any]) -> str:
    context = entry.get("action_context", {}) or {}
    return str(context.get("target_text") or entry.get("url") or "").strip().lower()


def _aggregate_action_audit(payload: Dict[str, Any]) -> Dict[str, Any]:
    with_timestamp = {
        **payload,
        "timestamp": payload.get("timestamp")
        or datetime.now(timezone.utc).isoformat(),
    }
    current_ts = datetime.fromisoformat(
        str(with_timestamp["timestamp"]).replace("Z", "+00:00")
    )

    if ACTION_HISTORY:
        latest = ACTION_HISTORY[0]
        latest_ts = datetime.fromisoformat(
            str(latest.get("timestamp", "")).replace("Z", "+00:00")
        )
        delta = (current_ts - latest_ts).total_seconds()
        same_action = str(latest.get("action", "")).lower() == str(
            with_timestamp.get("action", "")
        ).lower()
        same_target = _audit_target(latest) == _audit_target(with_timestamp)
        same_user = str(latest.get("user_id", "")) == str(with_timestamp.get("user_id", ""))
        if same_action and same_target and same_user and 0 <= delta < ACTION_AGGREGATION_WINDOW_SECONDS:
            latest["count"] = int(latest.get("count", 1)) + 1
            latest["timestamp"] = with_timestamp["timestamp"]
            latest["decision"] = with_timestamp.get("decision", latest.get("decision"))
            latest["reason"] = with_timestamp.get("reason", latest.get("reason"))
            latest["risk"] = with_timestamp.get("risk", latest.get("risk"))
            latest["attack_type"] = with_timestamp.get(
                "attack_type", latest.get("attack_type")
            )
            latest["page_decision"] = with_timestamp.get(
                "page_decision", latest.get("page_decision")
            )
            return latest

    with_timestamp["count"] = int(with_timestamp.get("count", 1) or 1)
    ACTION_HISTORY.insert(0, with_timestamp)
    if len(ACTION_HISTORY) > MAX_HISTORY:
        del ACTION_HISTORY[MAX_HISTORY:]
    return with_timestamp


def _persist_action_audit(payload: Dict[str, Any]) -> None:
    with_timestamp = _aggregate_action_audit(payload)

    if not db or not firestore:
        return

    try:
        db.collection("agent_actions").add(
            {
                "user_id": with_timestamp.get("user_id"),
                "url": with_timestamp.get("url"),
                "action": with_timestamp.get("action"),
                "target": str(
                    (with_timestamp.get("action_context", {}) or {}).get("target_text")
                    or with_timestamp.get("url")
                    or ""
                ),
                "action_context": with_timestamp.get("action_context", {}),
                "decision": with_timestamp.get("decision"),
                "reason": with_timestamp.get("reason"),
                "risk": int(with_timestamp.get("risk", 0)),
                "count": int(with_timestamp.get("count", 1)),
                "page_decision": with_timestamp.get("page_decision"),
                "attack_type": with_timestamp.get("attack_type"),
                "indicators": with_timestamp.get("indicators", []),
                "timestamp": firestore.SERVER_TIMESTAMP,
            }
        )
    except Exception:
        pass


def _build_explanation(
    ml_score: float,
    domain_flags: List[str],
    obfuscation_flags: List[str],
    risk_data: Dict[str, Any],
    decision: str,
) -> Dict[str, Any]:
    domain_flag_map = {flag: True for flag in domain_flags}
    obfuscation_flag_map = {
        "hidden_dom": "hidden_dom_element" in obfuscation_flags,
        "obfuscated_js": "hex_payload" in obfuscation_flags,
        "base64_encoded": "base64_blob" in obfuscation_flags,
        "evasion_techniques": bool(obfuscation_flags),
        "unicode_tricks": "suspicious_unicode" in obfuscation_flags,
    }
    policy_payload = {
        "policy_violated": decision in {"WARN", "BLOCK"},
        "violated_policy": "risk_threshold",
    }
    return explainability.generate_explanation(
        ml_score=ml_score,
        domain_flags=domain_flag_map,
        obfuscation_flags=obfuscation_flag_map,
        risk_data=risk_data,
        policy_decision=policy_payload,
    )


def _persist_scan(url: str, payload: Dict[str, Any]) -> None:
    with_timestamp = {
        **payload,
        "timestamp": payload.get("timestamp")
        or datetime.now(timezone.utc).isoformat(),
    }
    SCAN_HISTORY.insert(0, with_timestamp)
    if len(SCAN_HISTORY) > MAX_HISTORY:
        del SCAN_HISTORY[MAX_HISTORY:]

    if not db or not firestore:
        return

    try:
        db.collection("scans").add(
            {
                "user_id": with_timestamp.get("user_id"),
                "url": url,
                "risk": int(with_timestamp.get("risk", 0)),
                "risk_score": float(with_timestamp.get("risk_score", 0.0)),
                "domain_trust": float(with_timestamp.get("trust", 0)),
                "decision": with_timestamp.get("decision", "WARN"),
                "signals": with_timestamp.get("signal_details", []),
                "ai_analysis": with_timestamp.get("analysis", {}),
                "status": _decision_to_status(str(with_timestamp.get("decision", "WARN"))),
                "details": {
                    "reasons": with_timestamp.get("indicators", []),
                    "signal_details": with_timestamp.get("signal_details", []),
                    "summary": with_timestamp.get("explanation", ""),
                    "attack_type": with_timestamp.get("attack_type"),
                    "analysis": with_timestamp.get("analysis"),
                },
                "policy": {
                    "decision": with_timestamp.get("decision", "WARN"),
                    "reason": with_timestamp.get("reason", "Policy threshold evaluation"),
                },
                "actionType": with_timestamp.get("actionType"),
                "action_log": with_timestamp.get("action_log"),
                "attack_type": with_timestamp.get("attack_type"),
                "timestamp": firestore.SERVER_TIMESTAMP,
            }
        )
    except Exception:
        pass


def _run_pipeline(target_url: str) -> Dict[str, Any]:
    # 1. Fetch webpage content
    html = scanner.fetch_page_content(target_url)

    # 2. Threat intelligence lookup
    intel = threat_intel.check_threat_intel(target_url)

    # 3. Run ML detection
    ml_score = _predict_ml(html)
    host_ctx = _host_context(target_url)
    semantic_data = _semantic_signal(html)
    page_text = _extract_text_content(html)
    llm_data = llm_reasoner.detect_malicious_intent(page_text)
    semantic_score = max(
        float(ml_score),
        float(semantic_data["score"]),
        float(llm_data["score"]),
    )

    # 4. Domain intelligence
    domain_data = _analyze_domain(target_url)
    domain_data = _local_simulation_domain_adjustment(target_url, domain_data)

    # 5. Obfuscation detection
    obfuscation_data = obfuscation.analyze_obfuscation(html)

    # 7. Policy decision
    domain_flags = list(domain_data.get("flags", []))
    semantic_flags = list(semantic_data.get("flags", []))
    semantic_flags.extend([str(flag) for flag in llm_data.get("flags", [])])
    if intel and intel.get("threat"):
        domain_flags.append(f"threat_intel_{intel['threat']}")

    obfuscation_flags = list(obfuscation_data.get("flags", []))
    refined = _contextualize_flags(
        semantic_flags=semantic_flags,
        obfuscation_flags=obfuscation_flags,
        is_trusted=bool(host_ctx["is_trusted"]),
        has_intel=bool(intel),
        domain_flags=domain_flags,
    )
    semantic_flags = refined["semantic_flags"]
    obfuscation_flags = refined["obfuscation_flags"]

    indicators = [
        *domain_flags,
        *semantic_flags,
        *obfuscation_flags,
    ]
    signal_details = _build_signal_details(indicators)
    domain_trust = float(domain_data["trust_score"])
    dom_suspicion_score = float(domain_data["risk_penalty"])
    obfuscation_score = float(obfuscation_data["obfuscation_score"])
    threat_intel_score = min(
        1.0,
        (float(intel.get("confidence", 0.0)) if intel else 0.0)
        + (float(llm_data.get("score", 0.0)) * 0.35),
    )

    # 6. Calculate risk
    risk_data = _apply_signal_boosts(
        risk_data=risk.calculate_risk(
            ml_score,
            dom_suspicion_score,
            obfuscation_score,
            threat_intel_score,
            domain_trust=domain_trust,
            signals=signal_details,
        ),
        domain_flags=domain_flags,
        obfuscation_flags=obfuscation_flags,
        semantic_flags=semantic_flags,
        intel=intel,
        is_trusted=bool(host_ctx["is_trusted"]),
    )
    policy = _evaluate_policy(risk_data["total_risk"])

    # 8. Explanation
    explanation = _build_explanation(
        ml_score=max(float(ml_score), semantic_score),
        domain_flags=domain_flags + semantic_flags,
        obfuscation_flags=obfuscation_flags,
        risk_data=risk_data,
        decision=str(policy.get("decision", "WARN")),
    )

    attack_type = _classify_attack(indicators)
    if llm_data.get("attack_type") and llm_data.get("attack_type") != "Suspicious Content":
        attack_type = str(llm_data["attack_type"])

    explanation_reasons = list(explanation.get("reasons", []))
    if domain_trust >= 90:
        explanation_reasons.append("Domain reputation high")
    elif domain_trust >= 75:
        explanation_reasons.append("Domain reputation moderately high")

    analysis = {
        "title": "AI ANALYSIS",
        "summary": explanation["summary"],
        "key_findings": explanation_reasons[:6],
        "policy_decision": policy["decision"],
    }

    return {
        "url": target_url,
        "risk": int(risk_data["risk_percent"]),
        "risk_score": round(float(risk_data["total_risk"]), 4),
        "decision": policy["decision"],
        "reason": policy.get("reason", "Policy threshold evaluation"),
        "trust": domain_data["trust_score"],
        "indicators": indicators,
        "signal_details": signal_details,
        "attack_type": attack_type,
        "explanation": explanation["summary"],
        "explanation_reasons": explanation_reasons,
        "analysis": analysis,
        "llm": llm_data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _serialize_firestore_doc(doc: Any) -> Dict[str, Any]:
    return {"id": doc.id, **(doc.to_dict() or {})}


def _sort_by_timestamp_desc(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def sort_key(record: Dict[str, Any]) -> float:
        raw = record.get("timestamp") or record.get("time")
        if hasattr(raw, "timestamp"):
            try:
                return float(raw.timestamp())
            except Exception:
                return 0.0
        if hasattr(raw, "to_datetime"):
            try:
                return float(raw.to_datetime().timestamp())
            except Exception:
                return 0.0
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0

    return sorted(records, key=sort_key, reverse=True)


def _read_scans_for_user(user_id: str, limit: int) -> List[Dict[str, Any]]:
    capped = max(1, min(limit, MAX_HISTORY))
    if db and firestore:
        try:
            docs = (
                db.collection("scans")
                .where("user_id", "==", user_id)
                .order_by("timestamp", direction=firestore.Query.DESCENDING)
                .limit(capped)
                .stream()
            )
            return [_serialize_firestore_doc(doc) for doc in docs]
        except FailedPrecondition:
            docs = (
                db.collection("scans")
                .where("user_id", "==", user_id)
                .limit(capped)
                .stream()
            )
            return _sort_by_timestamp_desc([_serialize_firestore_doc(doc) for doc in docs])[:capped]
    return [scan for scan in SCAN_HISTORY if scan.get("user_id") == user_id][:capped]


def _read_actions_for_user(user_id: str, limit: int) -> List[Dict[str, Any]]:
    capped = max(1, min(limit, MAX_HISTORY))
    if db and firestore:
        try:
            docs = (
                db.collection("agent_actions")
                .where("user_id", "==", user_id)
                .order_by("timestamp", direction=firestore.Query.DESCENDING)
                .limit(capped)
                .stream()
            )
            return [_serialize_firestore_doc(doc) for doc in docs]
        except FailedPrecondition:
            docs = (
                db.collection("agent_actions")
                .where("user_id", "==", user_id)
                .limit(capped)
                .stream()
            )
            return _sort_by_timestamp_desc([_serialize_firestore_doc(doc) for doc in docs])[:capped]
    return [action for action in ACTION_HISTORY if action.get("user_id") == user_id][:capped]


def _read_all_scans(limit: int) -> List[Dict[str, Any]]:
    capped = max(1, min(limit, MAX_HISTORY))
    if db and firestore:
        docs = (
            db.collection("scans")
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .limit(capped)
            .stream()
        )
        return [_serialize_firestore_doc(doc) for doc in docs]
    return SCAN_HISTORY[:capped]


def _build_research_analytics(limit: int) -> Dict[str, Any]:
    scans = _read_all_scans(limit)
    totals = {"ALLOW": 0, "WARN": 0, "BLOCK": 0}
    attacks: Dict[str, int] = {}
    for scan in scans:
        decision = str(scan.get("decision") or (scan.get("policy") or {}).get("decision") or "WARN")
        if decision in totals:
            totals[decision] += 1
        attack_type = str(scan.get("attack_type") or (scan.get("details") or {}).get("attack_type") or "Unknown")
        attacks[attack_type] = attacks.get(attack_type, 0) + 1
    return {
        "total_scans": len(scans),
        "decisions": totals,
        "attack_types": attacks,
    }


@app.get("/")
def root() -> Dict[str, str]:
    return {"status": "SecureAgent API running"}


@app.get("/scan_history")
def scan_history(
    limit: int = 100,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    return {"scans": _read_scans_for_user(user.id, limit)}


@app.get("/action_history")
def action_history(
    limit: int = 100,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    return {"actions": _read_actions_for_user(user.id, limit)}


@app.get("/scans")
def list_scans(
    limit: int = 100,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    return {"scans": _read_scans_for_user(user.id, limit)}


@app.get("/scans/my")
def list_my_scans(
    limit: int = 100,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    return {"scans": _read_scans_for_user(user.id, limit)}


@app.get("/admin/all_scans")
def admin_all_scans(
    limit: int = 100,
    user: AuthenticatedUser = Depends(require_roles("admin")),
) -> Dict[str, Any]:
    return {"scans": _read_all_scans(limit), "requested_by": user.id}


@app.get("/research/analytics")
def research_analytics(
    limit: int = 500,
    user: AuthenticatedUser = Depends(require_roles("admin", "researcher")),
) -> Dict[str, Any]:
    return {"analytics": _build_research_analytics(limit), "requested_by": user.id}


@app.post("/analyze_url")
def analyze_url(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    target_url = _normalize_url(req.url)
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing URL")

    try:
        response = _run_pipeline(target_url)
        response["user_id"] = user.id
        
        # Update metrics if ground truth is provided
        if req.ground_truth and req.ground_truth.lower() in ("malicious", "benign"):
            tracker = get_tracker()
            metrics_update = tracker.update_metrics(
                risk_score=float(response.get("risk_score", 0.0)),
                ground_truth=req.ground_truth.lower(),  # type: ignore
                url=target_url,
                confidence=float(response.get("confidence", 1.0)),
                attack_type=response.get("attack_type"),
                indicators=response.get("indicators", []),
                analysis_details={
                    "has_phishing_patterns": "phishing" in str(response.get("indicators", [])).lower(),
                    "has_injection_patterns": "injection" in str(response.get("indicators", [])).lower(),
                    "obfuscated": any(
                        term in str(response.get("indicators", [])).lower()
                        for term in ["base64", "hex", "obfuscation"]
                    ),
                    "is_trusted_domain": response.get("trust", 0) > 70,
                },
            )
            response["metrics_update"] = metrics_update
        
        background_tasks.add_task(_persist_scan, target_url, response)
        return response
    except scanner.ScanPipelineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc


@app.post("/evaluate_action")
def evaluate_action_endpoint(
    req: ActionRequest,
    background_tasks: BackgroundTasks,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    target_url = _normalize_url(req.url)
    action_name = str(req.action or "").strip().lower()
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing URL")
    if not action_name:
        raise HTTPException(status_code=400, detail="Missing action")

    try:
        scan_result = _run_pipeline(target_url)
        normalized_risk = float(scan_result.get("risk_score", 0.0))
        indicators = list(scan_result.get("indicators", []))
        action_context = req.action_context or {}
        mediation = evaluate_mediated_action(
            action=action_name,
            indicators=indicators,
            risk=normalized_risk,
            page_decision=str(scan_result.get("decision", "WARN")),
            attack_type=str(scan_result.get("attack_type", "Suspicious Content")),
            action_context=action_context,
        )

        response = {
            "user_id": user.id,
            "url": target_url,
            "action": action_name,
            "action_context": action_context,
            "decision": mediation["decision"],
            "reason": mediation["reason"],
            "risk": int(scan_result.get("risk", 0)),
            "attack_type": scan_result.get("attack_type", "Suspicious Content"),
            "indicators": indicators,
            "signal_details": scan_result.get("signal_details", []),
            "trust": scan_result.get("trust"),
            "explanation": scan_result.get("explanation"),
            "analysis": scan_result.get("analysis"),
            "page_decision": scan_result.get("decision", "WARN"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actionType": action_name,
        }

        response["action_log"] = {
            "actionType": action_name,
            "decision": response["decision"],
            "reason": response["reason"],
        }
        background_tasks.add_task(_persist_action_audit, response)

        if response["decision"] in {"BLOCK", "WARN"}:
            background_tasks.add_task(_persist_scan, target_url, response)

        return response
    except scanner.ScanPipelineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Action evaluation failed: {exc}") from exc


@app.post("/scan")
def scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    return analyze_url(req, background_tasks, user)


@app.get("/metrics")
def get_metrics(user: AuthenticatedUser = Depends(get_current_user)) -> Dict[str, Any]:
    """
    GET /metrics
    
    Returns computed metrics for threat detection system evaluation.
    
    Response includes:
    - Confusion matrix (TP, FP, TN, FN)
    - Precision, Recall, F1 Score
    - False Positive/Negative Rates
    - Accuracy and Specificity
    - Current timestamp and sample counts
    
    Example response:
    {
        "timestamp": "2026-03-20T10:30:00+00:00",
        "precision": 0.92,
        "recall": 0.88,
        "f1_score": 0.90,
        "false_positive_rate": 0.03,
        "false_negative_rate": 0.12,
        "accuracy": 0.95,
        "specificity": 0.97,
        "confusion_matrix": {
            "tp": 230,
            "fp": 20,
            "tn": 500,
            "fn": 30,
            "total": 780
        }
    }
    """
    tracker = get_tracker()
    metrics = tracker.compute_metrics()
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **metrics,
        "user_id": user.id,
    }


@app.get("/metrics/snapshot")
def get_metrics_snapshot(user: AuthenticatedUser = Depends(get_current_user)) -> Dict[str, Any]:
    """
    GET /metrics/snapshot
    
    Returns timestamped metrics snapshot and adds to history.
    
    Example response:
    {
        "timestamp": "2026-03-20T10:30:00+00:00",
        "tp": 230,
        "fp": 20,
        "tn": 500,
        "fn": 30,
        "precision": 0.92,
        "recall": 0.88,
        "f1_score": 0.90,
        "false_positive_rate": 0.03,
        "false_negative_rate": 0.12,
        "accuracy": 0.95,
        "specificity": 0.97
    }
    """
    tracker = get_tracker()
    snapshot = tracker.get_metrics_snapshot()
    
    from dataclasses import asdict
    return {
        **asdict(snapshot),
        "user_id": user.id,
    }


@app.get("/metrics/error-analysis")
def get_error_analysis(user: AuthenticatedUser = Depends(get_current_user)) -> Dict[str, Any]:
    """
    GET /metrics/error-analysis
    
    Returns comprehensive error analysis and improvement suggestions.
    
    Response includes:
    - Error distribution (FP and FN counts)
    - Top domains with errors
    - Missed attack types
    - Most common false positive indicators
    - Actionable improvement suggestions
    
    Example response:
    {
        "error_distribution": {
            "false_positives": 20,
            "false_negatives": 30,
            "total_errors": 50,
            "error_rate": 0.064
        },
        "top_error_domains": [
            ["github.com", 5],
            ["example.com", 4]
        ],
        "missed_attack_types": [
            ["Prompt Injection", 12],
            ["Phishing", 8]
        ],
        "top_false_positive_indicators": [
            ["phishing_content_pattern", 7],
            ["suspicious_keyword", 5]
        ],
        "improvement_suggestions": [
            "Phishing patterns account for 40%+ FPs...",
            "50%+ FNs are injection attacks..."
        ]
    }
    """
    tracker = get_tracker()
    analysis = tracker.get_error_analysis()
    
    return {
        **analysis,
        "user_id": user.id,
    }


@app.get("/errors")
def get_misclassifications(
    error_type: str | None = None,
    domain: str | None = None,
    tag: str | None = None,
    limit: int = 100,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    GET /errors
    
    Returns all misclassifications (False Positives and False Negatives).
    
    Query parameters:
    - error_type: "FP" for false positives, "FN" for false negatives, or null for all
    - domain: Filter by domain substring
    - tag: Filter by tag (phishing, injection, obfuscation, trusted_domain)
    - limit: Maximum records to return (default: 100)
    
    Example request:
    GET /errors?error_type=FP&domain=github&limit=50
    
    Example response:
    {
        "timestamp": "2026-03-20T10:30:00+00:00",
        "error_type": "FP",
        "domain_filter": "github",
        "total_returned": 3,
        "errors": [
            {
                "id": "err_000001",
                "timestamp": "2026-03-20T10:15:00+00:00",
                "url": "https://github-mirror-site.com/login",
                "predicted_label": "malicious",
                "actual_label": "benign",
                "risk_score": 75,
                "confidence": 0.92,
                "attack_type": "Phishing",
                "indicators": ["phishing_content_pattern", "credential_harvest_form"],
                "reason": "Incorrectly flagged as Phishing. Indicators: phishing_content_pattern, credential_harvest_form",
                "domain": "github-mirror-site.com",
                "tags": ["phishing"]
            }
        ]
    }
    """
    tracker = get_tracker()
    errors = tracker.get_misclassifications(
        error_type=error_type,
        domain=domain,
        tag=tag,
        limit=limit,
    )
    
    from dataclasses import asdict
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_type": error_type or "all",
        "domain_filter": domain,
        "tag_filter": tag,
        "total_returned": len(errors),
        "errors": [asdict(e) for e in errors],
        "user_id": user.id,
    }


@app.post("/metrics/reset")
def reset_metrics(user: AuthenticatedUser = Depends(require_roles("admin"))) -> Dict[str, str]:
    """
    POST /metrics/reset
    
    Admin-only endpoint to reset all metrics to zero.
    
    Requires: Admin role
    
    Example response:
    {
        "status": "success",
        "message": "All metrics reset to zero",
        "timestamp": "2026-03-20T10:30:00+00:00"
    }
    """
    tracker = get_tracker()
    tracker.reset_metrics()
    
    return {
        "status": "success",
        "message": "All metrics reset to zero",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metrics/export")
def export_metrics(user: AuthenticatedUser = Depends(require_roles("admin"))) -> Dict[str, Any]:
    """
    GET /metrics/export
    
    Admin-only endpoint to export all metrics to JSON format.
    
    Requires: Admin role
    
    Returns full metrics with history and misclassifications.
    """
    tracker = get_tracker()
    metrics = tracker.compute_metrics()
    snapshot = tracker.get_metrics_snapshot()
    analysis = tracker.get_error_analysis()
    
    from dataclasses import asdict
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        "snapshot": asdict(snapshot),
        "error_analysis": analysis,
        "history_snapshots": [asdict(s) for s in tracker.history[-10:]],  # Last 10
        "misclassification_count": len(tracker.misclassifications),
        "user_id": user.id,
    }
