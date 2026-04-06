from __future__ import annotations

from collections import defaultdict, deque
from threading import Lock
from typing import Any, Deque, Dict, Iterable, List


def _safe_average(values: Iterable[float]) -> float:
    bucket = [float(value) for value in values]
    if not bucket:
        return 0.0
    return round(sum(bucket) / len(bucket), 3)


def _safe_max(values: Iterable[float]) -> float:
    bucket = [float(value) for value in values]
    if not bucket:
        return 0.0
    return round(max(bucket), 3)


class PerformanceTracker:
    def __init__(self, max_records: int = 500) -> None:
        self._records: Deque[Dict[str, Any]] = deque(maxlen=max_records)
        self._lock = Lock()

    def record(
        self,
        *,
        pipeline_ms: float,
        dom_ms: float,
        ml_ms: float,
        policy_ms: float,
        action: str | None = None,
        url: str | None = None,
    ) -> Dict[str, Any]:
        record = {
            "pipeline_ms": round(float(pipeline_ms), 3),
            "dom_ms": round(float(dom_ms), 3),
            "ml_ms": round(float(ml_ms), 3),
            "policy_ms": round(float(policy_ms), 3),
            "action": str(action or "scan"),
            "url": str(url or ""),
        }
        with self._lock:
            self._records.append(record)
        return record

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._records)

    def summary(self) -> Dict[str, Any]:
        records = self.snapshot()
        pipelines = [item["pipeline_ms"] for item in records]
        doms = [item["dom_ms"] for item in records]
        mls = [item["ml_ms"] for item in records]
        policies = [item["policy_ms"] for item in records]

        per_action: Dict[str, List[float]] = defaultdict(list)
        for item in records:
            per_action[str(item.get("action") or "scan")].append(float(item["pipeline_ms"]))

        return {
            "avg_latency_ms": _safe_average(pipelines),
            "max_latency_ms": _safe_max(pipelines),
            "breakdown": {
                "dom": _safe_average(doms),
                "ml": _safe_average(mls),
                "policy": _safe_average(policies),
            },
            "per_action_overhead_ms": {
                action: {
                    "avg": _safe_average(values),
                    "max": _safe_max(values),
                }
                for action, values in sorted(per_action.items())
            },
            "recent_samples": records[-20:],
            "optimizations": [
                "Caching: cache fetched page content and derived DOM/UI heuristics per URL to avoid rescanning identical pages.",
                "Async processing: move expensive enrichment, persistence, and secondary analysis off the request path with background workers.",
                "Batching: batch repeated scans or agent actions for the same origin and coalesce duplicate UI mutation events.",
            ],
            "sample_count": len(records),
        }


_tracker = PerformanceTracker()


def get_performance_tracker() -> PerformanceTracker:
    return _tracker
