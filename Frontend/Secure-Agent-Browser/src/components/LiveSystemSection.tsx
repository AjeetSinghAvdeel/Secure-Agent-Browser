import { motion } from "framer-motion";
import { Server, Database, Shield, ActivitySquare } from "lucide-react";

import { useSystemSnapshot } from "@/hooks/useSystemSnapshot";
import { toDateValue, type DateLike } from "@/lib/date";

const formatDateTime = (value: DateLike) => {
  const date = toDateValue(value);
  if (!date) return "--";
  return date.toLocaleString([], {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
};

const LiveSystemSection = () => {
  const { health, performance, scans, actions, isAuthenticated } = useSystemSnapshot();

  const services = [
    {
      label: "FastAPI",
      status: health?.status || "checking",
      detail: "public health endpoint",
      icon: Server,
    },
    {
      label: "Metrics",
      status: health?.metrics_ready ? "ready" : "pending",
      detail: "tracker initialization",
      icon: ActivitySquare,
    },
    {
      label: "Firebase",
      status: health?.firebase_ready ? "ready" : "offline",
      detail: "auth and persistence",
      icon: Database,
    },
    {
      label: "Policy Runtime",
      status: performance ? "active" : "awaiting session",
      detail: performance ? `${Math.round(performance.avg_latency_ms || 0)}ms avg` : "sign in to inspect",
      icon: Shield,
    },
  ];

  return (
    <section id="live-ops" className="py-24">
      <div className="container mx-auto px-6">
        <div className="mb-12 text-center">
          <span className="mb-4 block font-mono text-sm uppercase tracking-[0.22em] text-primary/80">Live Operations</span>
          <h2 className="text-3xl font-bold md:text-4xl">Telemetry From The Running System</h2>
          <p className="mx-auto mt-4 max-w-3xl text-muted-foreground">
            Live health checks are available immediately. Session-backed performance, scans, and
            mediated actions appear here when you are signed in.
          </p>
        </div>

        <div className="grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="glass rounded-[28px] p-6"
          >
            <h3 className="text-xl font-semibold">Service Status</h3>
            <div className="mt-6 grid gap-3">
              {services.map((service) => (
                <div
                  key={service.label}
                  className="flex items-center justify-between rounded-2xl border border-border/70 bg-background/35 px-4 py-3"
                >
                  <div className="flex items-center gap-3">
                    <div className="rounded-xl border border-border/70 bg-background/50 p-2">
                      <service.icon className="h-4 w-4 text-primary" />
                    </div>
                    <div>
                      <p className="text-sm font-medium">{service.label}</p>
                      <p className="text-xs text-muted-foreground">{service.detail}</p>
                    </div>
                  </div>
                  <span className="rounded-full border border-border/80 px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.16em] text-foreground/80">
                    {service.status}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="grid gap-6"
          >
            <div className="glass rounded-[28px] p-6">
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-xl font-semibold">Recent Scan Records</h3>
                <span className="font-mono text-xs text-muted-foreground">
                  {isAuthenticated ? `${scans.length} loaded` : "login required"}
                </span>
              </div>
              <div className="mt-5 space-y-3">
                {(isAuthenticated ? scans.slice(0, 4) : []).map((scan, index) => (
                  <div
                    key={`${scan.url}-${index}`}
                    className="rounded-2xl border border-border/70 bg-background/35 px-4 py-3"
                  >
                    <p className="font-mono text-xs leading-5 break-all text-foreground/90">
                      {scan.url}
                    </p>
                    <div className="mt-2 flex flex-wrap items-center gap-2 font-mono text-[11px] text-muted-foreground">
                      <span>{formatDateTime(scan.timestamp || scan.time)}</span>
                      <span className="text-border">•</span>
                      <span>Risk {scan.risk ?? 0}</span>
                      <span className="text-border">•</span>
                      <span>{scan.attack_type || scan.decision || scan.status || "Unknown"}</span>
                    </div>
                  </div>
                ))}
                {!isAuthenticated && (
                  <div className="rounded-2xl border border-dashed border-border/80 bg-background/30 px-4 py-5 text-sm text-muted-foreground">
                    Sign in to surface your live scan history here.
                  </div>
                )}
              </div>
            </div>

            <div className="glass rounded-[28px] p-6">
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-xl font-semibold">Recent Mediated Actions</h3>
                <span className="font-mono text-xs text-muted-foreground">
                  {isAuthenticated ? `${actions.length} loaded` : "login required"}
                </span>
              </div>
              <div className="mt-5 space-y-3">
                {(isAuthenticated ? actions.slice(0, 4) : []).map((action, index) => (
                  <div
                    key={`${action.action}-${index}`}
                    className="rounded-2xl border border-border/70 bg-background/35 px-4 py-3"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <p className="font-mono text-sm">{action.action || "Unknown action"}</p>
                      <span className="rounded-full border border-border/80 px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.16em] text-foreground/80">
                        {action.decision || "unknown"}
                      </span>
                    </div>
                    <p className="mt-2 text-xs text-muted-foreground">
                      {action.action_context?.target_text || action.url || "No target available"}
                    </p>
                    <p className="mt-2 font-mono text-[11px] text-muted-foreground">
                      {formatDateTime(action.timestamp)}
                    </p>
                  </div>
                ))}
                {!isAuthenticated && (
                  <div className="rounded-2xl border border-dashed border-border/80 bg-background/30 px-4 py-5 text-sm text-muted-foreground">
                    Sign in to surface your mediated action trail here.
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default LiveSystemSection;
