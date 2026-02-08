import { useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import {
  ArrowLeft,
  AlertTriangle,
  Ban,
  CheckCircle,
  Search,
  Brain,
  Eye,
  MousePointerClick,
  FileWarning,
  Filter,
} from "lucide-react";

import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { useScans } from "@/hooks/useScans";

/* ---------------------------------- */
/* UI CONFIG */
/* ---------------------------------- */

const statusIcons = {
  safe: CheckCircle,
  warning: AlertTriangle,
  blocked: Ban,
};

const statusConfig = {
  safe: {
    label: "SAFE",
    color: "text-cyber-safe",
    bg: "bg-cyber-safe/10 border-cyber-safe/30",
  },
  warning: {
    label: "WARNING",
    color: "text-cyber-warning",
    bg: "bg-cyber-warning/10 border-cyber-warning/30",
  },
  blocked: {
    label: "BLOCKED",
    color: "text-cyber-danger",
    bg: "bg-cyber-danger/10 border-cyber-danger/30",
  },
};

const severityColor = {
  high: "text-cyber-danger",
  medium: "text-cyber-warning",
  info: "text-primary",
};

type StatusFilter = "all" | "safe" | "warning" | "blocked";

/* ---------------------------------- */
/* DASHBOARD */
/* ---------------------------------- */

const Dashboard = () => {
  const { scans, loading } = useScans();

  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");

  /* ---------- Derived stats ---------- */

  const filtered = scans.filter((scan) => {
    const matchesSearch = scan.url
      .toLowerCase()
      .includes(searchQuery.toLowerCase());

    const matchesStatus =
      statusFilter === "all" || scan.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  const total = scans.length;
  const safeCount = scans.filter((s) => s.status === "safe").length;
  const warnCount = scans.filter((s) => s.status === "warning").length;
  const blockCount = scans.filter((s) => s.status === "blocked").length;

  const avgScore = total
    ? Math.round(scans.reduce((sum, s) => sum + s.risk, 0) / total)
    : 0;

  /* ---------- Detection breakdown ---------- */

  const detections = [
    {
      title: "Prompt Injection",
      icon: FileWarning,
      detected: scans.filter((s) => s.details?.injection?.length > 0).length,
      severity: "high" as const,
      desc: "Pattern-matched injection attempts in page content.",
    },
    {
      title: "Phishing Detection",
      icon: MousePointerClick,
      detected: scans.filter((s) => s.details?.phishing?.length > 0).length,
      severity: "high" as const,
      desc: "Fake login forms mimicking trusted services.",
    },
    {
      title: "Clickjacking / Hidden",
      icon: Eye,
      detected: scans.filter((s) => s.details?.hidden?.length > 0).length,
      severity: "medium" as const,
      desc: "Hidden overlays or iframe-based deception.",
    },
    {
      title: "ML Model Verdict",
      icon: Brain,
      detected: scans.filter((s) => s.details?.ml_result === 1).length,
      severity: "info" as const,
      desc: "ML classifier malicious verdict.",
    },
    {
      title: "LLM Reasoning",
      icon: Brain,
      detected: scans.filter((s) => s.details?.llm_result === 1).length,
      severity: "info" as const,
      desc: "Reasoning-based intent analysis.",
    },
  ];

  const formatTime = (ts: any) =>
    ts?.toDate ? ts.toDate().toLocaleString() : "--";

  /* ---------------------------------- */

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <div className="pt-24 pb-16">
        <div className="container mx-auto px-6">

          {/* Header */}
          <div className="flex items-center gap-4 mb-8">
            <Link to="/" className="text-muted-foreground hover:text-primary">
              <ArrowLeft className="w-5 h-5" />
            </Link>

            <div>
              <h1 className="text-2xl md:text-3xl font-bold">
                Security Dashboard
              </h1>
              <p className="text-sm text-muted-foreground font-mono">
                Real-time threat monitoring & analysis
              </p>
            </div>

            <div className="ml-auto flex items-center gap-3">
              <Link
                to="/scan"
                className="text-sm font-medium bg-primary/10 text-primary border border-primary/30 px-4 py-2 rounded-lg hover:bg-primary/20 hidden sm:block"
              >
                + New Scan
              </Link>

              <div className="flex items-center gap-2 glass rounded-full px-4 py-2">
                <span
                  className={`w-2 h-2 rounded-full ${
                    loading
                      ? "bg-muted"
                      : "bg-cyber-safe animate-pulse-glow"
                  }`}
                />
                <span className="font-mono text-xs text-muted-foreground">
                  {loading ? "SYNCING" : "LIVE"}
                </span>
              </div>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            {[
              { label: "Total Scans", value: total, filter: "all" },
              { label: "Safe", value: safeCount, filter: "safe" },
              { label: "Warnings", value: warnCount, filter: "warning" },
              { label: "Blocked", value: blockCount, filter: "blocked" },
            ].map((stat) => (
              <motion.button
                key={stat.label}
                onClick={() =>
                  setStatusFilter(
                    statusFilter === stat.filter
                      ? "all"
                      : (stat.filter as StatusFilter)
                  )
                }
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={`glass rounded-xl p-5 text-left ${
                  statusFilter === stat.filter
                    ? "border-primary/50"
                    : "hover:border-primary/20"
                }`}
              >
                <p className="text-xs text-muted-foreground font-mono mb-1">
                  {stat.label}
                </p>
                <p className="text-3xl font-bold font-mono">{stat.value}</p>
              </motion.button>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Scan Table */}
            <div className="lg:col-span-2 glass rounded-xl overflow-hidden">
              <div className="px-6 py-4 border-b border-border flex items-center gap-3">
                <Search className="w-4 h-4 text-muted-foreground" />
                <input
                  placeholder="Search URLs..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-transparent text-sm outline-none flex-1 font-mono"
                />
                {statusFilter !== "all" && (
                  <button
                    onClick={() => setStatusFilter("all")}
                    className="text-xs font-mono text-primary bg-primary/10 px-2 py-1 rounded-full"
                  >
                    <Filter className="w-3 h-3 inline" /> {statusFilter} ×
                  </button>
                )}
              </div>

              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-xs font-mono text-muted-foreground">
                    <th className="px-6 py-3 text-left">URL</th>
                    <th className="px-4 py-3">Time</th>
                    <th className="px-4 py-3 text-center">Risk</th>
                    <th className="px-4 py-3 text-center">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((scan) => {
                    const Icon = statusIcons[scan.status];
                    const cfg = statusConfig[scan.status];

                    return (
                      <tr
                        key={scan.id}
                        className="border-b hover:bg-secondary/30"
                      >
                        <td className="px-6 py-3 font-mono text-xs truncate max-w-[280px]">
                          {scan.url}
                        </td>
                        <td className="px-4 py-3 text-xs font-mono">
                          {formatTime(scan.timestamp)}
                        </td>
                        <td className="px-4 py-3 text-center">
                          <RiskBar score={scan.risk} />
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span
                            className={`inline-flex items-center gap-1 text-xs font-mono px-2 py-1 rounded-full border ${cfg.bg} ${cfg.color}`}
                          >
                            <Icon className="w-3 h-3" />
                            {cfg.label}
                          </span>
                        </td>
                      </tr>
                    );
                  })}

                  {filtered.length === 0 && (
                    <tr>
                      <td
                        colSpan={4}
                        className="px-6 py-8 text-center text-muted-foreground"
                      >
                        No scans available
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Right Panel */}
            <div className="space-y-4">
              <RiskGauge avgScore={avgScore} />
              <DetectionPanel detections={detections} />
            </div>
          </div>
        </div>
      </div>

      <Footer />
    </div>
  );
};

/* ---------------------------------- */
/* COMPONENTS */
/* ---------------------------------- */

const RiskBar = ({ score }: { score: number }) => {
  const color =
    score < 30
      ? "bg-cyber-safe"
      : score < 70
      ? "bg-cyber-warning"
      : "bg-cyber-danger";

  return (
    <div className="flex items-center gap-2 justify-center">
      <div className="w-16 h-1.5 bg-secondary rounded-full overflow-hidden">
        <div className={`${color} h-full`} style={{ width: `${score}%` }} />
      </div>
      <span className="font-mono text-xs w-6">{score}</span>
    </div>
  );
};

const RiskGauge = ({ avgScore }: { avgScore: number }) => (
  <div className="glass rounded-xl p-6 text-center">
    <p className="text-xs font-mono text-muted-foreground mb-3">
      AVG RISK SCORE
    </p>
    <div className="text-4xl font-mono font-bold">{avgScore}</div>
  </div>
);

const DetectionPanel = ({ detections }: any) => (
  <div className="glass rounded-xl overflow-hidden">
    <div className="px-5 py-3 border-b border-border">
      <h3 className="text-sm font-semibold">Detection Breakdown</h3>
    </div>
    {detections.map((d: any) => (
      <div key={d.title} className="px-5 py-3 flex items-center gap-3">
        <d.icon className={`w-4 h-4 ${severityColor[d.severity]}`} />
        <div className="flex-1">
          <p className="text-sm font-medium">{d.title}</p>
          <p className="text-xs text-muted-foreground">{d.desc}</p>
        </div>
        <span className="font-mono text-xs font-bold">{d.detected}</span>
      </div>
    ))}
  </div>
);

export default Dashboard;
