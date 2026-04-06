from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import requests

try:
    import browser_runtime
except Exception:  # pragma: no cover - package import fallback
    from . import browser_runtime  # type: ignore

BACKEND_DIR = Path(__file__).resolve().parent
SIMULATOR_PAGES_DIR = BACKEND_DIR.parent / "malicious-simulator-lab" / "pages"
BENCHMARK_PAGES_DIR = BACKEND_DIR.parent / "benchmark-fixtures" / "pages"


class ScanPipelineError(Exception):
    pass


def _load_attack_file(url: str) -> str:
    filename = Path(url).name
    candidate = (SIMULATOR_PAGES_DIR / filename).resolve()
    if candidate.parent == SIMULATOR_PAGES_DIR.resolve() and candidate.exists():
        return candidate.read_text(encoding="utf-8", errors="ignore")
    raise ScanPipelineError(f"Attack file not found for path: {url}")


def _load_benchmark_file(url: str) -> str:
    filename = Path(url).name
    candidate = (BENCHMARK_PAGES_DIR / filename).resolve()
    if candidate.parent == BENCHMARK_PAGES_DIR.resolve() and candidate.exists():
        return candidate.read_text(encoding="utf-8", errors="ignore")
    raise ScanPipelineError(f"Benchmark fixture not found for path: {url}")


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

    if target.startswith("/malicious-simulator-lab/pages/"):
        try:
            return _load_attack_file(target)
        except Exception:
            return ""

    if target.startswith("/benchmark-fixtures/pages/"):
        try:
            return _load_benchmark_file(target)
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


def fetch_page_artifacts(url: str, *, prefer_browser_runtime: bool = True) -> Dict[str, Any]:
    target = (url or "").strip()
    if not target:
        return {
            "mode": "none",
            "html": "",
            "page_text": "",
            "page_context": {},
            "runtime_behavior": {},
        }

    if target.startswith("/malicious-simulator-lab/pages/"):
        html = fetch_page_content(target)
        return {
            "mode": "fixture",
            "html": html,
            "page_text": "",
            "page_context": {},
            "runtime_behavior": {},
        }

    if target.startswith("/benchmark-fixtures/pages/"):
        html = fetch_page_content(target)
        return {
            "mode": "benchmark_fixture",
            "html": html,
            "page_text": "",
            "page_context": {},
            "runtime_behavior": {},
        }

    if target.startswith(("http://", "https://")):
        if not prefer_browser_runtime:
            html = fetch_page_content(target)
            return {
                "mode": "http",
                "html": html,
                "page_text": "",
                "page_context": {},
                "runtime_behavior": {},
            }
        try:
            return browser_runtime.collect_browser_artifacts(target)
        except Exception as exc:
            html = fetch_page_content(target)
            return {
                "mode": "http",
                "html": html,
                "page_text": "",
                "page_context": {
                    "browser_runtime_error": str(exc),
                },
                "runtime_behavior": {
                    "browser_runtime_error": str(exc),
                },
            }

    return {
        "mode": "none",
        "html": "",
        "page_text": "",
        "page_context": {},
        "runtime_behavior": {},
    }
