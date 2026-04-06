from __future__ import annotations

import os
from pathlib import Path

import firebase_admin
from firebase_admin import credentials, firestore


def _resolve_credentials_path() -> Path:
    configured = os.getenv("SECUREAGENT_FIREBASE_CREDENTIALS", "firebase_key.json").strip()
    candidate = Path(configured)
    if not candidate.is_absolute():
        candidate = Path(__file__).resolve().parent / candidate
    return candidate


db = None

try:
    credentials_path = _resolve_credentials_path()
    if credentials_path.exists():
        cred = credentials.Certificate(str(credentials_path))
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        db = firestore.client()
except Exception:
    db = None
