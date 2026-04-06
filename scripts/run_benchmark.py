from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    os.environ.setdefault("SECUREAGENT_ENABLE_BROWSER_RUNTIME", "false")
    repo_root = Path(__file__).resolve().parent.parent
    backend_dir = repo_root / "backend"
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    import api  # type: ignore
    import stress_suite  # type: ignore

    report = api._run_benchmark_report()
    stress = stress_suite.run_stress_suite()
    exported = api._export_benchmark_artifacts(report, stress)

    metrics = report.get("metrics", {})
    print("SecureAgent benchmark completed.")
    print(f"Pages: {report.get('dataset', {}).get('page_count', 0)}")
    print(f"Tasks: {report.get('dataset', {}).get('task_count', 0)}")
    print(f"Precision: {metrics.get('precision', 0.0):.4f}")
    print(f"Recall: {metrics.get('recall', 0.0):.4f}")
    print(f"F1: {metrics.get('f1_score', 0.0):.4f}")
    print(f"Avg latency: {metrics.get('avg_latency_ms', 0.0):.3f} ms")
    print(f"Stress p95 latency: {stress.get('summary', {}).get('p95_latency_ms', 0.0):.3f} ms")
    print(f"Artifacts: {exported['export_dir']}")
    print(f"Latest: {exported['latest_dir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
