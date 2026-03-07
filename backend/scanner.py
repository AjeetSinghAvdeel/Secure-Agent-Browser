from __future__ import annotations

from pathlib import Path

import requests

BACKEND_DIR = Path(__file__).resolve().parent
BACKEND_ATTACKS_DIR = BACKEND_DIR / "attacks"
ROOT_ATTACKS_DIR = BACKEND_DIR.parent / "attacks"


class ScanPipelineError(Exception):
    pass


def _load_attack_file(url: str) -> str:
    filename = Path(url).name
    for base_dir in (BACKEND_ATTACKS_DIR, ROOT_ATTACKS_DIR):
        candidate = (base_dir / filename).resolve()
        if candidate.parent == base_dir.resolve() and candidate.exists():
            return candidate.read_text(encoding="utf-8", errors="ignore")
    raise ScanPipelineError(f"Attack file not found for path: {url}")


def fetch_page_content(url: str) -> str:
    """
    Fetch webpage HTML content.

    Required behavior:
    - Use requests.get
    - Browser-like User-Agent header
    - timeout=10, allow_redirects=True
    - Return empty string on request failures
    """
    target = (url or "").strip()
    if not target:
        return ""

    if target.startswith("/attacks/"):
        try:
            return _load_attack_file(target)
        except Exception:
            return ""

    if not target.startswith(("http://", "https://")):
        return ""

    try:
        response = requests.get(
            target,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
            allow_redirects=True,
        )
        response.raise_for_status()
        return response.text or ""
    except Exception:
        return ""
