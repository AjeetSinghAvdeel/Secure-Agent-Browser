import { Fragment, useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import { collection, onSnapshot, orderBy, query, where } from "firebase/firestore";
import {
  ArrowLeft,
  AlertTriangle,
  Ban,
  CheckCircle,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import RiskIntelligencePanel from "@/components/RiskIntelligencePanel";
import ThreatTimeline from "@/components/ThreatTimeline";
import ThreatAlert from "@/components/ThreatAlert";
import { db } from "@/lib/firebase";
import { useAuth } from "@/context/AuthContext";
import { apiFetch } from "@/lib/api";

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
type Decision = "ALLOW" | "WARN" | "BLOCK";

type Scan = {
  id: string;
  url: string;
  timestamp?: any;
  time?: string;
  risk: number;
  trust?: number;
  trust_score?: number | string;
  domainTrust?: number | string;
  analysisSummary?: string;
  status?: "safe" | "warning" | "blocked";
  decision?: Decision;
  details?: any;
  policy?: {
    decision: "ALLOW" | "WARN" | "BLOCK";
    reason: string;
  };
  actionType?: string;
  action_log?: {
    actionType: string;
    decision: Decision;
    reason: string;
  };
  attack_type?: string;
  analysis?: {
    title?: string;
    summary?: string;
    key_findings?: string[];
    policy_decision?: Decision;
  };
  agent_action?: {
    type: string;
    fields?: string[];
    confidence?: string;
    reason?: string;
  };
};

type ActionAudit = {
  url: string;
  action: string;
  count?: number;
  decision: Decision;
  reason: string;
  risk: number;
  attack_type?: string;
  page_decision?: Decision;
  timestamp?: any;
  action_context?: {
    source?: string;
    target_text?: string;
    input_type?: string;
  };
};

const calculateDomainTrustFallback = (url: string): number => {
  try {
    const parsed = new URL(url);
    const domain = (parsed.hostname || "").toLowerCase();
    let trust = 100;

    const suspiciousTlds = [
      ".xyz",
      ".top",
      ".gq",
      ".tk",
      ".ml",
      ".cf",
      ".click",
      ".work",
    ];

    if (suspiciousTlds.some((tld) => domain.endsWith(tld))) {
      trust -= 30;
    }

    if (parsed.protocol === "http:") {
      trust -= 15;
    }

    if (domain.length > 30) {
      trust -= 10;
    }

    if ((domain.match(/-/g) || []).length > 3) {
      trust -= 10;
    }

    const digits = (domain.match(/[0-9]/g) || []).length;
    if (digits > 5) {
      trust -= 10;
    }

    return Math.max(0, Math.min(100, trust));
  } catch {
    return 50;
  }
};

/* ---------------------------------- */
/* DASHBOARD */
/* ---------------------------------- */

const Dashboard = () => {
  const { user, token, logout } = useAuth();
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [latestThreat, setLatestThreat] = useState<Scan | null>(null);
  const [actionAudits, setActionAudits] = useState<ActionAudit[]>([]);

  const formatTime = (ts: any) => {
    if (ts?.toDate) return ts.toDate().toLocaleString();
    if (ts instanceof Date) return ts.toLocaleString();
    if (typeof ts === "string" || typeof ts === "number") {
      const parsed = new Date(ts);
      if (!Number.isNaN(parsed.getTime())) return parsed.toLocaleString();
    }
    return "--";
  };

  const scanDecision = (scan: Scan): Decision => {
    if (scan.decision === "ALLOW" || scan.decision === "WARN" || scan.decision === "BLOCK") {
      return scan.decision;
    }
    if (
      scan.policy?.decision === "ALLOW" ||
      scan.policy?.decision === "WARN" ||
      scan.policy?.decision === "BLOCK"
    ) {
      return scan.policy.decision;
    }
    if (scan.status === "safe") return "ALLOW";
    if (scan.status === "blocked") return "BLOCK";
    return "WARN";
  };

  const scanStatus = (scan: Scan): "safe" | "warning" | "blocked" => {
    if (scan.status === "safe" || scan.status === "warning" || scan.status === "blocked") {
      return scan.status;
    }
    const decision = scanDecision(scan);
    if (decision === "ALLOW") return "safe";
    if (decision === "BLOCK") return "blocked";
    return "warning";
  };

  const resolveTrustScore = (scan: Scan): number => {
    const rawTrust = scan.trust ?? scan.trust_score ?? scan.domainTrust;
    if (typeof rawTrust === "number" && Number.isFinite(rawTrust)) {
      return Math.max(0, Math.min(100, rawTrust));
    }
    if (typeof rawTrust === "string" && rawTrust.trim() !== "") {
      const parsed = Number(rawTrust);
      if (Number.isFinite(parsed)) {
        return Math.max(0, Math.min(100, parsed));
      }
    }
    return calculateDomainTrustFallback(scan.url || "");
  };

  const scanTimeMs = (scan: Scan): number => {
    const raw = scan.time ?? scan.timestamp;
    if (!raw) return 0;
    if (raw?.toDate) {
      const t = raw.toDate().getTime();
      return Number.isFinite(t) ? t : 0;
    }
    const t = new Date(String(raw)).getTime();
    return Number.isFinite(t) ? t : 0;
  };

  const filtered = scanHistory
    .filter((scan) => {
      const matchesSearch = scan.url
        .toLowerCase()
        .includes(searchQuery.toLowerCase());
      const matchesStatus =
        statusFilter === "all" || scanStatus(scan) === statusFilter;
      return matchesSearch && matchesStatus;
    })
    .sort((a, b) => scanTimeMs(b) - scanTimeMs(a));

  const total = scanHistory.length;
  const safeCount = scanHistory.filter((s) => scanStatus(s) === "safe").length;
  const warnCount = scanHistory.filter((s) => scanStatus(s) === "warning").length;
  const blockCount = scanHistory.filter((s) => scanStatus(s) === "blocked").length;

  const applyScans = (scans: Scan[]) => {
    const sorted = [...scans].sort((a, b) => scanTimeMs(b) - scanTimeMs(a));
    setScanHistory(sorted);

    const blocked = sorted.find((s) => s.decision === "BLOCK");
    if (blocked) {
      setLatestThreat(blocked);
    } else {
      setLatestThreat(null);
    }
  };

  const loadBackendScans = async () => {
    if (!token) return;

    const response = await apiFetch(
      "/scans/my?limit=100",
      {
        method: "GET",
      },
      token
    );

    if (response.status === 401) {
      logout();
      return;
    }

    if (!response.ok) {
      throw new Error(`Scan history fetch failed: ${response.status}`);
    }

    const payload = (await response.json()) as { scans?: Scan[] };
    applyScans(Array.isArray(payload.scans) ? payload.scans : []);
  };

  const loadBackendActions = async () => {
    if (!token) return;

    const response = await apiFetch(
      "/action_history?limit=100",
      {
        method: "GET",
      },
      token
    );

    if (response.status === 401) {
      logout();
      return;
    }

    if (!response.ok) {
      throw new Error(`Action history fetch failed: ${response.status}`);
    }

    const payload = (await response.json()) as { actions?: ActionAudit[] };
    setActionAudits(Array.isArray(payload.actions) ? payload.actions : []);
  };

  useEffect(() => {
    if (!user?.id || !token) {
      setScanHistory([]);
      setLatestThreat(null);
      return;
    }

    void loadBackendScans();
    const pollId = window.setInterval(() => {
      void loadBackendScans();
    }, 3000);

    const unsubscribe = onSnapshot(
      query(
        collection(db, "scans"),
        where("user_id", "==", user.id),
        orderBy("timestamp", "desc")
      ),
      (snapshot) => {
        const scans = snapshot.docs.map((doc) => ({
          id: doc.id,
          ...(doc.data() as Omit<Scan, "id">),
        }));
        applyScans(scans);
      },
      (error) => {
        console.error("Firestore listener error:", error);
      }
    );

    return () => {
      window.clearInterval(pollId);
      unsubscribe();
    };
  }, [user?.id, token]);

  useEffect(() => {
    if (!user?.id || !token) {
      setActionAudits([]);
      return;
    }

    void loadBackendActions();
    const pollId = window.setInterval(() => {
      void loadBackendActions();
    }, 3000);

    const unsubscribe = onSnapshot(
      query(
        collection(db, "agent_actions"),
        where("user_id", "==", user.id),
        orderBy("timestamp", "desc")
      ),
      (snapshot) => {
        const actions = snapshot.docs.map((doc) => doc.data() as ActionAudit);
        setActionAudits(actions);
      },
      (error) => {
        console.error("Agent action listener error:", error);
      }
    );

    return () => {
      window.clearInterval(pollId);
      unsubscribe();
    };
  }, [user?.id, token]);

  const actionDecisionCount = (decision: Decision) =>
    actionAudits
      .filter((entry) => entry.decision === decision)
      .reduce((total, entry) => total + (entry.count || 1), 0);

  const totalActionEvents = actionAudits.reduce(
    (total, entry) => total + (entry.count || 1),
    0
  );

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

          <div className="mb-8">
            <ThreatTimeline scans={scanHistory} />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <div className="glass rounded-xl p-5">
              <p className="text-xs text-muted-foreground font-mono mb-1">
                Agent Actions Audited
              </p>
              <p className="text-3xl font-bold font-mono">{totalActionEvents}</p>
            </div>
            <div className="glass rounded-xl p-5">
              <p className="text-xs text-muted-foreground font-mono mb-1">
                Allowed Actions
              </p>
              <p className="text-3xl font-bold font-mono text-cyber-safe">
                {actionDecisionCount("ALLOW")}
              </p>
            </div>
            <div className="glass rounded-xl p-5">
              <p className="text-xs text-muted-foreground font-mono mb-1">
                Stopped / Warned
              </p>
              <p className="text-3xl font-bold font-mono text-cyber-danger">
                {actionDecisionCount("BLOCK") + actionDecisionCount("WARN")}
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

          <div className="mb-8">
            {latestThreat && (
              <ThreatAlert
                key={`${latestThreat.id}-${latestThreat.time || latestThreat.timestamp || latestThreat.risk}`}
                threat={latestThreat}
              />
            )}
          </div>

          <div className="glass rounded-xl overflow-hidden overflow-x-auto mb-8">
            <div className="px-6 py-4 border-b">
              <h2 className="text-lg font-semibold">Agent Action Audit Trail</h2>
              <p className="text-xs text-muted-foreground font-mono mt-1">
                Every mediated action is logged here, including approvals.
              </p>
            </div>
            <table className="w-full text-sm table-fixed">
              <thead>
                <tr className="border-b text-xs font-mono text-muted-foreground">
                  <th className="px-6 py-3 text-left">Time</th>
                  <th className="px-4 py-3 text-left">Action</th>
                  <th className="px-4 py-3 text-left">Target</th>
                  <th className="px-4 py-3 text-left">Decision</th>
                  <th className="px-4 py-3 text-left">Attack</th>
                  <th className="px-4 py-3 text-left">Reason</th>
                </tr>
              </thead>
              <tbody>
                {actionAudits.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-6 py-6 text-sm text-muted-foreground">
                      No action audits yet.
                    </td>
                  </tr>
                ) : (
                  actionAudits.map((entry, index) => {
                    const decision = entry.decision;
                    const status =
                      decision === "ALLOW"
                        ? statusConfig.safe
                        : decision === "BLOCK"
                        ? statusConfig.blocked
                        : statusConfig.warning;

                    return (
                      <tr key={`${entry.timestamp || index}-${entry.action}-${entry.url}`} className="border-b">
                        <td className="px-6 py-3 text-xs font-mono">
                          {formatTime(entry.timestamp)}
                        </td>
                        <td className="px-4 py-3 text-xs font-mono">
                          {entry.action}
                          {(entry.count || 1) > 1 ? ` x${entry.count}` : ""}
                        </td>
                        <td
                          title={entry.url}
                          className="px-4 py-3 text-xs font-mono break-all"
                        >
                          {entry.action_context?.target_text || entry.url}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center gap-1 text-xs font-mono px-2 py-1 rounded-full border ${status.bg} ${status.color}`}
                          >
                            {decision}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs font-mono">
                          {entry.attack_type || entry.page_decision || "Unknown"}
                        </td>
                        <td className="px-4 py-3 text-xs">{entry.reason}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Scan Table */}
          <div className="glass rounded-xl overflow-hidden overflow-x-auto">
            <table className="w-full text-sm table-fixed">
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
                  const status = scanStatus(scan);
                  const Icon = statusIcons[status];
                  const cfg = statusConfig[status];
                  const expanded = expandedScan === scan.id;
                  const decision = scanDecision(scan);
                  const indicators = Array.isArray(scan?.details?.reasons) ? scan.details.reasons : [];
                  const signalDetails = Array.isArray(scan?.details?.signal_details) ? scan.details.signal_details : [];
                  const analysis = scan.analysis || scan?.details?.analysis || {};
                  const summary = String(scan.analysisSummary || scan?.details?.summary || "No explanation available.");
                  const actionLog = scan.action_log;
                  const attackType = String(scan.attack_type || scan?.details?.attack_type || "Unknown");

                  return (
                    <Fragment key={scan.id}>
                      <tr className="border-b">
                        <td
                          title={scan.url}
                          className="px-6 py-3 font-mono text-xs max-w-[400px] break-all"
                        >
                          {scan.url}
                        </td>
                        <td className="px-4 py-3 text-xs font-mono">
                          {scan.timestamp
                            ? formatTime(scan.timestamp)
                            : scan.time
                            ? formatTime(scan.time)
                            : "Unknown"}
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className="font-mono">{scan.risk ?? 0}</span>
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
                            onClick={() => setExpandedScan(expanded ? null : scan.id)}
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
                            <div className="space-y-6">
                              <RiskIntelligencePanel
                                riskScore={Number(scan.risk ?? 0)}
                                trustScore={resolveTrustScore(scan)}
                                decision={decision}
                                indicators={(signalDetails.length > 0 ? signalDetails : indicators.map((name: string) => ({
                                  type: name,
                                  severity: "low",
                                  confidence: "low",
                                }))).map((signal: any) => ({
                                  name: String(signal.type || signal.name || "unknown"),
                                  detected: true,
                                  severity: signal.severity || "low",
                                  confidence: signal.confidence || "low",
                                }))}
                                explanation={{
                                  summary: String(analysis.summary || summary),
                                  reasons: Array.isArray(analysis.key_findings) && analysis.key_findings.length > 0
                                    ? analysis.key_findings
                                    : indicators,
                                  policyDecision: String(analysis.policy_decision || decision),
                                }}
                              />
                              {actionLog && (
                                <div className="rounded-xl border border-cyber-danger/30 bg-cyber-danger/10 p-4">
                                  <p className="font-mono mb-2">
                                    <strong>Action Mediation Log:</strong>
                                  </p>
                                  <div className="space-y-1 font-mono">
                                    <p>Action: {actionLog.actionType}</p>
                                    <p>Decision: {actionLog.decision}</p>
                                    <p>Reason: {actionLog.reason}</p>
                                    <p>Attack Type: {attackType}</p>
                                  </div>
                                </div>
                              )}
                              <div>
                                <p className="font-mono mb-1">
                                  <strong>Analysis Reasons:</strong>
                                </p>
                                <ul className="list-disc pl-4 space-y-1">
                                  {indicators.map(
                                    (r: string, i: number) => (
                                      <li key={i}>{r}</li>
                                    )
                                  )}
                                </ul>
                              </div>
                            </div>

                          </td>
                        </tr>
                      )}
                    </Fragment>
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
