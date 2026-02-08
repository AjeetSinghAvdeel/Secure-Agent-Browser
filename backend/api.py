from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import os
import numpy as np

from bot import get_html
from scanner import scan_page
from firebase_client import db
from firebase_admin import firestore
from policy_engine import evaluate_action


# ----------------------------
# Utils
# ----------------------------

def sanitize(obj):
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize(v) for v in obj]
    elif isinstance(obj, np.generic):
        return obj.item()
    else:
        return obj


def normalize_url(url: str):
    # Absolute file path support
    if url.startswith("file://"):
        return url

    # Resolve local attack files correctly
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(base_dir, ".."))

    local_path = os.path.join(project_root, url)

    if os.path.exists(local_path):
        return "file://" + local_path

    return url


# ----------------------------
# App
# ----------------------------

app = FastAPI(title="Secure Agent API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # dev only
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


@app.get("/")
def root():
    return {"status": "Secure Agent API running"}


@app.post("/scan")
def scan(req: ScanRequest):
    driver = None

    try:
        # ----------------------------
        # Normalize URL
        # ----------------------------
        url = normalize_url(req.url)

        # ----------------------------
        # Load Page + Scan
        # ----------------------------
        driver, payload = get_html(url)
        raw_result = scan_page(payload, page_url=req.url)
        result = sanitize(raw_result)

        # ----------------------------
        # Risk → Status
        # ----------------------------
        risk = int(result["risk"])
        status = (
            "safe" if risk < 40 else
            "warning" if risk < 70 else
            "blocked"
        )

        # ----------------------------
        # 🔐 SIMULATED AGENT ACTION
        # ----------------------------
        from agent import infer_agent_action

        agent_action = infer_agent_action(result)
        policy = evaluate_action(agent_action, result)

        # ----------------------------
        # 🧠 POLICY EVALUATION
        # ----------------------------
        policy = evaluate_action(agent_action, result)

        # ----------------------------
        # 🔹 Firestore write (SINGLE SOURCE)
        # ----------------------------
        db.collection("scans").add({
            "url": req.url,
            "risk": risk,
            "status": status,
            "details": result,
            "agent_action": agent_action,
            "policy": policy,
            "timestamp": firestore.SERVER_TIMESTAMP
        })

        # ----------------------------
        # API Response
        # ----------------------------
        return {
            "url": req.url,
            "risk": risk,
            "status": status,
            "policy": policy,
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        print("🚨 Scan failed:", e)
        return {"error": "Scan failed", "message": str(e)}

    finally:
        if driver:
            driver.quit()
