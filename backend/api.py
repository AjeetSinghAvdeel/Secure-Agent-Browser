from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import domain_intel
import explainability
import ml_model
import obfuscation
import policy_engine
import risk
import scanner
import threat_intel

try:
    from firebase_admin import firestore
    from firebase_client import db
except Exception:  # pragma: no cover - optional in local/dev setups
    firestore = None
    db = None

app = FastAPI(title="SecureAgent Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory history enables extension -> dashboard visibility in local setups
# even when Firestore is unavailable.
SCAN_HISTORY: List[Dict[str, Any]] = []
MAX_HISTORY = 500


class ScanRequest(BaseModel):
    url: str


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
    if hasattr(ml_model, "predict"):
        return float(ml_model.predict(html))
    if hasattr(ml_model, "predict_attack"):
        return float(ml_model.predict_attack(html))
    raise AttributeError("ml_model has no predict/predict_attack function")


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
    total = float(risk_data.get("total_risk", 0.0))

    if len(obfuscation_flags) >= 2:
        total += 0.15
    if "prompt_injection_pattern" in semantic_flags:
        total += 0.20
    if "credential_harvest_form" in semantic_flags:
        total += 0.10
    if "phishing_content_pattern" in semantic_flags:
        total += 0.10
    if "phishing_keyword" in domain_flags:
        total += 0.10
    if intel:
        total += min(0.30, 0.20 * float(intel.get("confidence", 0.9)))

    # Trusted domains should not be escalated by weak heuristic-only signals.
    if is_trusted and not intel:
        if "prompt_injection_pattern" not in semantic_flags:
            total = min(
                total,
                float(risk_data.get("total_risk", 0.0)) + 0.06,
            )

    risk_data["total_risk"] = round(min(1.0, total), 4)
    return risk_data


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
                "url": url,
                "risk": int(with_timestamp.get("risk", 0)),
                "status": _decision_to_status(str(with_timestamp.get("decision", "WARN"))),
                "details": {
                    "reasons": with_timestamp.get("indicators", []),
                    "summary": with_timestamp.get("explanation", ""),
                },
                "policy": {
                    "decision": with_timestamp.get("decision", "WARN"),
                    "reason": "Policy threshold evaluation",
                },
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
    semantic_score = max(float(ml_score), float(semantic_data["score"]))

    # 4. Domain intelligence
    domain_data = _analyze_domain(target_url)
    domain_data = _local_simulation_domain_adjustment(target_url, domain_data)

    # 5. Obfuscation detection
    obfuscation_data = obfuscation.analyze_obfuscation(html)

    # 6. Calculate risk
    risk_data = risk.calculate_risk(
        ml_score,
        semantic_score,
        float(domain_data["risk_penalty"]),
        float(obfuscation_data["obfuscation_score"]),
    )

    # 7. Policy decision
    domain_flags = list(domain_data.get("flags", []))
    semantic_flags = list(semantic_data.get("flags", []))
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

    risk_data = _apply_signal_boosts(
        risk_data=risk_data,
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

    return {
        "url": target_url,
        "risk": round(float(risk_data["total_risk"]) * 100),
        "decision": policy["decision"],
        "trust": domain_data["trust_score"],
        "indicators": [
            *domain_flags,
            *semantic_flags,
            *obfuscation_flags,
        ],
        "explanation": explanation["summary"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
def root() -> Dict[str, str]:
    return {"status": "SecureAgent API running"}


@app.get("/scan_history")
def scan_history(limit: int = 100) -> Dict[str, Any]:
    capped = max(1, min(limit, MAX_HISTORY))
    return {"scans": SCAN_HISTORY[:capped]}


@app.post("/analyze_url")
def analyze_url(req: ScanRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    target_url = _normalize_url(req.url)
    if not target_url:
        raise HTTPException(status_code=400, detail="Missing URL")

    try:
        response = _run_pipeline(target_url)
        background_tasks.add_task(_persist_scan, target_url, response)
        return response
    except scanner.ScanPipelineError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc


@app.post("/scan")
def scan(req: ScanRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    return analyze_url(req, background_tasks)
