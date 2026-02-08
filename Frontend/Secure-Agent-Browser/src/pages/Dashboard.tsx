import { useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import {
  ArrowLeft,
  AlertTriangle,
  Ban,
  CheckCircle,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
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

type StatusFilter = "all" | "safe" | "warning" | "blocked";

/* ---------------------------------- */
/* DASHBOARD */
/* ---------------------------------- */

const Dashboard = () => {
  const { scans, loading } = useScans();

  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);

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

  const formatTime = (ts: any) =>
    ts?.toDate ? ts.toDate().toLocaleString() : "--";

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
                className="glass rounded-xl p-5 text-left"
              >
                <p className="text-xs text-muted-foreground font-mono mb-1">
                  {stat.label}
                </p>
                <p className="text-3xl font-bold font-mono">{stat.value}</p>
              </motion.button>
            ))}
          </div>

          {/* Scan Table */}
          <div className="glass rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-xs font-mono text-muted-foreground">
                  <th className="px-6 py-3 text-left">URL</th>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3 text-center">Risk</th>
                  <th className="px-4 py-3 text-center">Status</th>
                  <th className="px-4 py-3 text-center">Details</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((scan) => {
                  const Icon = statusIcons[scan.status];
                  const cfg = statusConfig[scan.status];
                  const expanded = expandedScanId === scan.id;

                  return (
                    <>
                      <tr key={scan.id} className="border-b">
                        <td className="px-6 py-3 font-mono text-xs truncate">
                          {scan.url}
                        </td>
                        <td className="px-4 py-3 text-xs font-mono">
                          {formatTime(scan.timestamp)}
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className="font-mono">{scan.risk}</span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span
                            className={`inline-flex items-center gap-1 text-xs font-mono px-2 py-1 rounded-full border ${cfg.bg} ${cfg.color}`}
                          >
                            <Icon className="w-3 h-3" />
                            {cfg.label}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <button
                            onClick={() =>
                              setExpandedScanId(expanded ? null : scan.id)
                            }
                            className="text-xs font-mono text-primary flex items-center gap-1 mx-auto"
                          >
                            {expanded ? <ChevronUp /> : <ChevronDown />}
                            {expanded ? "Hide" : "View"}
                          </button>
                        </td>
                      </tr>

                      {expanded && (
                        <tr className="bg-secondary/20">
                          <td colSpan={5} className="px-6 py-4 text-xs space-y-3">

                            {/* Confidence */}
                            <p className="font-mono">
                              <strong>Confidence:</strong>{" "}
                              {scan.details?.confidence || "unknown"}
                            </p>

                            {/* 🔐 POLICY DECISION */}
                            {scan.policy && (
                              <p className="font-mono">
                                <strong>Policy Decision:</strong>{" "}
                                <span className="font-bold">
                                  {scan.policy.decision}
                                </span>{" "}
                                — {scan.policy.reason}
                              </p>
                            )}

                            {/* 🤖 AGENT ACTION */}
                            {scan.agent_action && (
                              <p className="font-mono">
                                <strong>Agent Action:</strong>{" "}
                                {scan.agent_action.type}
                                {scan.agent_action.fields?.length
                                  ? ` (${scan.agent_action.fields.join(", ")})`
                                  : ""}
                              </p>
                            )}

                            {/* Reasons */}
                            <div>
                              <p className="font-mono mb-1">
                                <strong>Analysis Reasons:</strong>
                              </p>
                              <ul className="list-disc pl-4 space-y-1">
                                {scan.details?.reasons?.map(
                                  (r: string, i: number) => (
                                    <li key={i}>{r}</li>
                                  )
                                )}
                              </ul>
                            </div>

                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>

        </div>
      </div>

      <Footer />
    </div>
  );
};

export default Dashboard;
