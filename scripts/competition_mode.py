from __future__ import annotations

import os
import sys
from pathlib import Path


DEMO_FLOW = [
    "1. Log in and open the dashboard benchmark panel to establish baseline metrics.",
    "2. Scan a benign benchmark page and show low-friction ALLOW behavior.",
    "3. Open a phishing or fake OAuth page and demonstrate blocked password or approval actions.",
    "4. Run /agent/execute on a malicious page to show multi-step agent protection with mediation.",
    "5. Show the stress and benchmark exports in benchmark-results/latest as evidence for judges.",
]


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

    competition_note = "\n".join(
        [
            "# Competition Mode",
            "",
            "This run produced the current benchmark, stress, and summary artifacts for the hackathon demo.",
            "",
            "## Demo Flow",
            "",
            *[f"- {item}" for item in DEMO_FLOW],
            "",
            "## Key Metrics",
            "",
            f"- Precision: {report.get('metrics', {}).get('precision', 0.0):.4f}",
            f"- Recall: {report.get('metrics', {}).get('recall', 0.0):.4f}",
            f"- F1 Score: {report.get('metrics', {}).get('f1_score', 0.0):.4f}",
            f"- Benign Task Success: {report.get('metrics', {}).get('task_success_rate_benign', 0.0):.4f}",
            f"- Malicious Task Stop: {report.get('metrics', {}).get('malicious_task_stop_rate', 0.0):.4f}",
            f"- Stress P95 Latency: {stress.get('summary', {}).get('p95_latency_ms', 0.0):.3f} ms",
            "",
        ]
    )
    latest_dir = Path(exported["latest_dir"])
    (latest_dir / "COMPETITION_MODE.md").write_text(competition_note, encoding="utf-8")

    print("SecureAgent competition mode completed.")
    print(f"Artifacts: {exported['export_dir']}")
    print(f"Latest: {exported['latest_dir']}")
    print("Demo flow:")
    for item in DEMO_FLOW:
        print(item)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
