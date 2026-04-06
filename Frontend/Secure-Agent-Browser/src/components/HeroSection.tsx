import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import { Activity, Gauge, ShieldCheck, TimerReset } from "lucide-react";

import heroBg from "@/assets/hero-bg.jpg";
import { useSystemSnapshot } from "@/hooks/useSystemSnapshot";

const HeroSection = () => {
  const { health, performance, scans, actions, isAuthenticated } = useSystemSnapshot();

  const blockedCount = scans.filter((scan) => {
    const decision = String(scan.decision || scan.status || "").toUpperCase();
    return decision === "BLOCK" || decision === "BLOCKED";
  }).length;

  const avgLatency = Math.round(performance?.avg_latency_ms || 0);
  const totalRecords = scans.length + actions.length;

  const liveStats = [
    {
      label: "Backend",
      value: String(health?.status || "checking").toUpperCase(),
      detail: health?.metrics_ready ? "metrics ready" : "metrics pending",
      icon: ShieldCheck,
    },
    {
      label: "Avg Latency",
      value: performance ? `${avgLatency}ms` : "--",
      detail: performance ? "scan pipeline" : "login to view",
      icon: TimerReset,
    },
    {
      label: "Blocked",
      value: isAuthenticated ? String(blockedCount) : "--",
      detail: isAuthenticated ? "recent detections" : "user telemetry locked",
      icon: Activity,
    },
    {
      label: "Records",
      value: isAuthenticated ? String(totalRecords) : "--",
      detail: isAuthenticated ? "scans + actions" : "sign in for live feed",
      icon: Gauge,
    },
  ];

  return (
    <section className="relative flex min-h-screen items-center overflow-hidden">
      <div className="absolute inset-0">
        <img src={heroBg} alt="" className="h-full w-full object-cover opacity-20" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,hsl(var(--primary)/0.16),transparent_32%),linear-gradient(180deg,hsl(var(--background)/0.6),hsl(var(--background)/0.94)_48%,hsl(var(--background)))]" />
        <div className="absolute inset-0 cyber-grid opacity-20" />
      </div>

      <div className="absolute inset-0 scan-line pointer-events-none" />

      <div className="relative z-10 container mx-auto px-6 pb-16 pt-28">
        <div className="grid gap-12 lg:grid-cols-[1.15fr_0.85fr] lg:items-end">
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7 }}
          >
            <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-primary/25 bg-primary/10 px-4 py-2">
              <span className="h-2 w-2 rounded-full bg-cyber-safe animate-pulse-glow" />
              <span className="font-mono text-xs uppercase tracking-[0.18em] text-muted-foreground">
                LIVE PROTECTION PIPELINE
              </span>
            </div>

            <h1 className="max-w-4xl text-4xl font-bold leading-tight md:text-6xl lg:text-7xl">
              Real-time agent defense for deceptive web flows.
            </h1>

            <p className="mt-6 max-w-2xl text-lg text-muted-foreground md:text-xl">
              SecureAgent combines DOM inspection, ML scoring, threat intelligence, UI-deception
              analysis, and action mediation before a risky page or action reaches the user.
            </p>

            <div className="mt-8 flex flex-wrap gap-3">
              {[
                "FastAPI orchestration",
                "Selenium scanning runtime",
                "Firebase auth + logs",
                "Policy-based mediation",
              ].map((item) => (
                <span
                  key={item}
                  className="rounded-full border border-border/80 bg-background/40 px-3 py-1.5 font-mono text-[11px] text-muted-foreground"
                >
                  {item}
                </span>
              ))}
            </div>

            <div className="mt-10 flex flex-col gap-4 sm:flex-row sm:items-center">
              <Link
                to="/dashboard"
                className="rounded-xl bg-primary px-8 py-3 font-semibold text-primary-foreground transition-opacity hover:opacity-90 glow-primary"
              >
                View Dashboard
              </Link>
              <Link
                to="/scan"
                className="rounded-xl border border-border bg-background/40 px-8 py-3 font-semibold text-foreground transition-colors hover:border-primary/40"
              >
                Scan a URL
              </Link>
              <a
                href="#gallery"
                className="rounded-xl px-4 py-3 font-semibold text-muted-foreground transition-colors hover:text-primary"
              >
                Explore System ↓
              </a>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.15 }}
            className="glass rounded-[30px] border border-border/80 p-6"
          >
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.24em] text-primary">
                  System Pulse
                </p>
                <h2 className="mt-2 text-2xl font-semibold">Current Runtime Snapshot</h2>
              </div>
              <div className="rounded-full border border-cyber-safe/30 bg-cyber-safe/10 px-3 py-1 font-mono text-[11px] text-cyber-safe">
                {health?.status || "checking"}
              </div>
            </div>

            <div className="mt-6 grid gap-3 sm:grid-cols-2">
              {liveStats.map((stat) => (
                <div
                  key={stat.label}
                  className="rounded-2xl border border-border/70 bg-background/35 p-4"
                >
                  <div className="flex items-center justify-between gap-3">
                    <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
                      {stat.label}
                    </p>
                    <stat.icon className="h-4 w-4 text-primary" />
                  </div>
                  <p className="mt-3 text-2xl font-semibold">{stat.value}</p>
                  <p className="mt-1 text-xs text-muted-foreground">{stat.detail}</p>
                </div>
              ))}
            </div>

            <div className="mt-6 rounded-2xl border border-border/70 bg-background/35 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground">
                What this page is showing
              </p>
              <p className="mt-3 text-sm leading-6 text-foreground/85">
                Backend health is public and live. Performance, scans, and action telemetry are
                loaded from your authenticated session when available.
              </p>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
