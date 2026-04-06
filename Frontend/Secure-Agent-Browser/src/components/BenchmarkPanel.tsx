import { useEffect, useState } from "react";
import { FlaskConical, ShieldAlert, TimerReset, CheckCircle2 } from "lucide-react";

import { apiFetch } from "@/lib/api";
import { useAuth } from "@/context/AuthContext";

type BenchmarkReport = {
  metrics: {
    precision: number;
    recall: number;
    f1_score: number;
    false_positive_rate: number;
    avg_latency_ms: number;
    task_success_rate_benign: number;
    malicious_task_stop_rate: number;
  };
  dataset: {
    page_count: number;
    task_count: number;
    attack_types: string[];
  };
};

export default function BenchmarkPanel() {
  const { token } = useAuth();
  const [report, setReport] = useState<BenchmarkReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;

    let cancelled = false;

    void (async () => {
      try {
        const response = await apiFetch(
          "/benchmark/report",
          { method: "GET" },
          token
        );
        if (!response.ok) {
          throw new Error(`Benchmark report failed: ${response.status}`);
        }
        const payload = (await response.json()) as BenchmarkReport;
        if (!cancelled) {
          setReport(payload);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Benchmark unavailable");
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <section className="glass rounded-2xl overflow-hidden mb-8">
      <div className="border-b border-border px-5 py-4 flex items-center gap-3">
        <FlaskConical className="h-5 w-5 text-primary" />
        <div>
          <h2 className="text-base font-semibold">Judge Pack Metrics</h2>
          <p className="text-[11px] font-mono text-muted-foreground">
            Reproducible internal benchmark aligned to the problem statement and export flow
          </p>
        </div>
      </div>

      {report ? (
        <div className="p-5 space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "F1 Score", value: `${(report.metrics.f1_score * 100).toFixed(1)}%`, icon: ShieldAlert },
              { label: "Precision", value: `${(report.metrics.precision * 100).toFixed(1)}%`, icon: CheckCircle2 },
              { label: "Benign Task Success", value: `${(report.metrics.task_success_rate_benign * 100).toFixed(1)}%`, icon: CheckCircle2 },
              { label: "Avg Latency", value: `${report.metrics.avg_latency_ms.toFixed(1)}ms`, icon: TimerReset },
            ].map((item) => (
              <div key={item.label} className="rounded-xl border border-border/70 bg-background/30 p-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[11px] font-mono uppercase tracking-wide text-muted-foreground">{item.label}</p>
                  <item.icon className="h-4 w-4 text-primary" />
                </div>
                <p className="text-2xl font-bold">{item.value}</p>
              </div>
            ))}
          </div>

          <div className="grid gap-3 md:grid-cols-[1.2fr_0.8fr]">
            <div className="rounded-xl border border-border/70 bg-background/25 p-4">
              <p className="text-[11px] font-mono uppercase tracking-wide text-muted-foreground mb-2">
                Attack Coverage
              </p>
              <div className="flex flex-wrap gap-2">
                {report.dataset.attack_types.map((attackType) => (
                  <span
                    key={attackType}
                    className="rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs text-primary"
                  >
                    {attackType}
                  </span>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-border/70 bg-background/25 p-4">
              <p className="text-[11px] font-mono uppercase tracking-wide text-muted-foreground mb-2">
                Dataset
              </p>
              <p className="text-sm text-foreground/90">
                {report.dataset.page_count} benchmark pages and {report.dataset.task_count} mediated tasks.
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                False positive rate: {(report.metrics.false_positive_rate * 100).toFixed(1)}%
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                Malicious task stop rate: {(report.metrics.malicious_task_stop_rate * 100).toFixed(1)}%
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                Use `POST /benchmark/export` or `python3 scripts/competition_mode.py` before the final demo.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="px-5 py-5 text-sm text-muted-foreground">
          {error || "Generating benchmark report..."}
        </div>
      )}
    </section>
  );
}
