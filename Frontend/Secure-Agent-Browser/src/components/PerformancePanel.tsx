import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";
import { Gauge, TimerReset } from "lucide-react";

type Breakdown = {
  dom: number;
  ml: number;
  policy: number;
};

type RecentSample = {
  action: string;
  pipeline_ms: number;
  dom_ms: number;
  ml_ms: number;
  policy_ms: number;
};

type PerformanceData = {
  avg_latency_ms: number;
  max_latency_ms: number;
  breakdown: Breakdown;
  per_action_overhead_ms?: Record<string, { avg: number; max: number }>;
  recent_samples?: RecentSample[];
};

interface PerformancePanelProps {
  performance: PerformanceData | null;
}

const PerformancePanel = ({ performance }: PerformancePanelProps) => {
  const trend = (performance?.recent_samples || []).map((sample, index) => ({
    name: `${index + 1}`,
    total: sample.pipeline_ms,
  }));

  const breakdown = performance
    ? [
        { name: "DOM", value: performance.breakdown.dom },
        { name: "ML", value: performance.breakdown.ml },
        { name: "Policy", value: performance.breakdown.policy },
      ]
    : [];

  return (
    <section className="glass rounded-2xl p-6 mb-8">
      <div className="flex items-center justify-between gap-4 mb-6">
        <div>
          <p className="text-xs text-muted-foreground font-mono mb-1">
            PERFORMANCE
          </p>
          <h2 className="text-xl font-semibold">Pipeline Latency</h2>
        </div>
        <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-mono text-primary">
          <Gauge className="w-3.5 h-3.5" />
          Graph idea: stack DOM, ML, and policy timings over scans
        </div>
      </div>

      {!performance ? (
        <div className="rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground">
          No performance samples yet.
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="rounded-xl border border-border/60 bg-background/40 p-4">
              <p className="text-xs text-muted-foreground font-mono mb-1">AVG LATENCY</p>
              <p className="text-3xl font-bold font-mono">{performance.avg_latency_ms.toFixed(1)}ms</p>
            </div>
            <div className="rounded-xl border border-border/60 bg-background/40 p-4">
              <p className="text-xs text-muted-foreground font-mono mb-1">MAX LATENCY</p>
              <p className="text-3xl font-bold font-mono">{performance.max_latency_ms.toFixed(1)}ms</p>
            </div>
            <div className="rounded-xl border border-border/60 bg-background/40 p-4">
              <p className="text-xs text-muted-foreground font-mono mb-1">HOT PATH</p>
              <p className="text-sm font-medium">
                DOM {performance.breakdown.dom.toFixed(1)}ms • ML {performance.breakdown.ml.toFixed(1)}ms • Policy{" "}
                {performance.breakdown.policy.toFixed(1)}ms
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-[1.1fr_.9fr] gap-6">
            <div className="rounded-xl border border-border/60 bg-background/40 p-4">
              <div className="flex items-center gap-2 mb-4">
                <TimerReset className="w-4 h-4 text-primary" />
                <h3 className="font-medium">Latency Trend</h3>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trend}>
                    <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.15} />
                    <XAxis dataKey="name" />
                    <YAxis unit="ms" />
                    <Tooltip formatter={(value: number) => `${value.toFixed(1)} ms`} />
                    <Area
                      type="monotone"
                      dataKey="total"
                      stroke="hsl(var(--primary))"
                      fill="hsl(var(--primary))"
                      fillOpacity={0.18}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="rounded-xl border border-border/60 bg-background/40 p-4">
              <h3 className="font-medium mb-4">Average Stage Breakdown</h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={breakdown}>
                    <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.15} />
                    <XAxis dataKey="name" />
                    <YAxis unit="ms" />
                    <Tooltip formatter={(value: number) => `${value.toFixed(1)} ms`} />
                    <Line
                      type="monotone"
                      dataKey="value"
                      stroke="hsl(var(--cyber-warning))"
                      strokeWidth={3}
                      dot={{ r: 4 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {performance.per_action_overhead_ms && (
            <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
              {Object.entries(performance.per_action_overhead_ms).map(([action, stats]) => (
                <div key={action} className="rounded-xl border border-border/60 bg-background/40 p-4">
                  <p className="text-xs text-muted-foreground font-mono mb-2 uppercase">{action}</p>
                  <p className="text-sm">avg {stats.avg.toFixed(1)}ms</p>
                  <p className="text-sm text-muted-foreground">max {stats.max.toFixed(1)}ms</p>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
};

export default PerformancePanel;
