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
    if os.path.exists(url):
        return "file://" + os.path.abspath(url)
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
        url = normalize_url(req.url)

        driver, payload = get_html(url)
        raw_result = scan_page(payload, page_url=req.url)
        result = sanitize(raw_result)

        risk = int(result["risk"])
        status = (
            "safe" if risk < 40 else
            "warning" if risk < 70 else
            "blocked"
        )

        # 🔹 Firestore write (Sentinel ONLY here)
        db.collection("scans").add({
            "url": req.url,
            "risk": risk,
            "status": status,
            "details": result,
            "timestamp": firestore.SERVER_TIMESTAMP
        })

        # 🔹 API response (JSON-safe)
        return {
            "url": req.url,
            "risk": risk,
            "status": status,
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        print("🚨 Scan failed:", e)
        return {"error": "Scan failed", "message": str(e)}

    finally:
        if driver:
            driver.quit()
