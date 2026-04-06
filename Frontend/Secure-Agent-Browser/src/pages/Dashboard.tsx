import { useCallback, useEffect, useRef, useState } from "react";
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
import PerformancePanel from "@/components/PerformancePanel";
import BenchmarkPanel from "@/components/BenchmarkPanel";
import { db } from "@/lib/firebase";
import { useAuth } from "@/context/AuthContext";
import { apiFetch } from "@/lib/api";
import { toDateValue, type DateLike } from "@/lib/date";

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
  confirmation: {
    label: "CONFIRM",
    color: "text-orange-300",
    bg: "bg-orange-500/10 border-orange-400/30",
  },
  blocked: {
    label: "BLOCKED",
    color: "text-cyber-danger",
    bg: "bg-cyber-danger/10 border-cyber-danger/30",
  },
};

type StatusFilter = "all" | "safe" | "warning" | "blocked";
type Decision = "ALLOW" | "WARN" | "BLOCK" | "REQUIRE_CONFIRMATION";

type Scan = {
  id: string;
  url: string;
  timestamp?: DateLike;
  time?: string;
  risk: number;
  trust?: number;
  trust_score?: number | string;
  domainTrust?: number | string;
  analysisSummary?: string;
  status?: "safe" | "warning" | "blocked";
  decision?: Decision;
  details?: Record<string, unknown>;
  policy?: {
    decision: Decision;
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
    confidence_score?: number;
    reasoning_steps?: string[];
  };
  score_breakdown?: {
    ml?: number;
    domain?: number;
    ui?: number;
    obfuscation?: number;
  };
  reasoning_steps?: string[];
  confidence_score?: number;
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
  timestamp?: DateLike;
  action_context?: {
    source?: string;
    target_text?: string;
    input_type?: string;
  };
};

type PerformanceSummary = {
  avg_latency_ms: number;
  max_latency_ms: number;
  breakdown: {
    dom: number;
    ml: number;
    policy: number;
  };
  per_action_overhead_ms?: Record<string, { avg: number; max: number }>;
  recent_samples?: Array<{
    action: string;
    pipeline_ms: number;
    dom_ms: number;
    ml_ms: number;
    policy_ms: number;
  }>;
};

type ScanDetails = {
  reasons?: string[];
  signal_details?: Array<{
    type?: string;
    name?: string;
    severity?: string;
    confidence?: string;
  }>;
  analysis?: Scan["analysis"];
  summary?: string;
  attack_type?: string;
};

const resolveScoreBreakdown = (scan: Scan, details: ScanDetails) => {
  const candidates = [
    scan.score_breakdown,
    scan.analysis?.score_breakdown as Scan["score_breakdown"] | undefined,
    (details.analysis as (Scan["analysis"] & { score_breakdown?: Scan["score_breakdown"] }) | undefined)
      ?.score_breakdown,
    (scan.details as { score_breakdown?: Scan["score_breakdown"] } | undefined)?.score_breakdown,
  ];

  for (const candidate of candidates) {
    if (!candidate) continue;
    const hasValue = Object.values(candidate).some((value) => Number(value ?? 0) > 0);
    if (hasValue) {
      return candidate;
    }
  }

  return candidates.find(Boolean) || {};
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

const compactLabelClass =
  "text-[10px] uppercase tracking-[0.18em] text-muted-foreground font-mono";

type AnimatedListProps = {
  itemCount: number;
  maxHeight?: string;
  className?: string;
  getKey: (index: number) => string;
  renderItem: (index: number) => JSX.Element;
};

const AnimatedList = ({
  itemCount,
  maxHeight = "max-h-[30rem]",
  className = "",
  getKey,
  renderItem,
}: AnimatedListProps) => {
  const listRef = useRef<HTMLDivElement | null>(null);
  const [topFade, setTopFade] = useState(0);
  const [bottomFade, setBottomFade] = useState(1);

  useEffect(() => {
    const node = listRef.current;
    if (!node) return;

    const updateFades = () => {
      const { scrollTop, scrollHeight, clientHeight } = node;
      setTopFade(Math.min(scrollTop / 36, 1));
      const remaining = scrollHeight - (scrollTop + clientHeight);
      setBottomFade(scrollHeight <= clientHeight ? 0 : Math.min(remaining / 36, 1));
    };

    updateFades();
    node.addEventListener("scroll", updateFades);
    window.addEventListener("resize", updateFades);

    return () => {
      node.removeEventListener("scroll", updateFades);
      window.removeEventListener("resize", updateFades);
    };
  }, [itemCount]);

  return (
    <div className={`relative ${className}`}>
      <div
        ref={listRef}
        className={`dashboard-scroll-list space-y-2 overflow-y-auto pr-1 ${maxHeight}`}
      >
        {Array.from({ length: itemCount }, (_, index) => (
          <motion.div
            key={getKey(index)}
            initial={{ opacity: 0, y: 14, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.22, delay: Math.min(index * 0.04, 0.2) }}
          >
            {renderItem(index)}
          </motion.div>
        ))}
      </div>

      <div
        aria-hidden="true"
        className="dashboard-list-fade-top pointer-events-none absolute inset-x-0 top-0 h-10"
        style={{ opacity: topFade }}
      />
      <div
        aria-hidden="true"
        className="dashboard-list-fade-bottom pointer-events-none absolute inset-x-0 bottom-0 h-12"
        style={{ opacity: bottomFade }}
      />
    </div>
  );
};

/* ---------------------------------- */
/* DASHBOARD */
/* ---------------------------------- */

const Dashboard = () => {
  const { user, token, logout } = useAuth();
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [expandedAudit, setExpandedAudit] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [latestThreat, setLatestThreat] = useState<Scan | null>(null);
  const [actionAudits, setActionAudits] = useState<ActionAudit[]>([]);
  const [performance, setPerformance] = useState<PerformanceSummary | null>(null);

  const formatDateTime = (ts: DateLike) => {
    const date = toDateValue(ts);
    if (!date) return "--";
    return date.toLocaleString([], {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  };

  const formatShortDateTime = (ts: DateLike) => {
    const date = toDateValue(ts);
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

  const formatTime = (ts: DateLike) => {
    const date = toDateValue(ts);
    return date ? date.toLocaleString() : "--";
  };

  const scanDecision = (scan: Scan): Decision => {
    if (
      scan.decision === "ALLOW" ||
      scan.decision === "WARN" ||
      scan.decision === "BLOCK" ||
      scan.decision === "REQUIRE_CONFIRMATION"
    ) {
      return scan.decision;
    }
    if (
      scan.policy?.decision === "ALLOW" ||
      scan.policy?.decision === "WARN" ||
      scan.policy?.decision === "BLOCK" ||
      scan.policy?.decision === "REQUIRE_CONFIRMATION"
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

  const applyScans = useCallback((scans: Scan[]) => {
    const sorted = [...scans].sort((a, b) => scanTimeMs(b) - scanTimeMs(a));
    setScanHistory(sorted);

    const blocked = sorted.find((s) => s.decision === "BLOCK");
    if (blocked) {
      setLatestThreat(blocked);
    } else {
      setLatestThreat(null);
    }
  }, []);

  const loadBackendScans = useCallback(async () => {
    if (!token) return;

    const response = await apiFetch(
      "/scans/my?limit=100",
      {
        method: "GET",
      },
      token
    );

    if (response.status === 401) {
      setScanHistory([]);
      setLatestThreat(null);
      return;
    }

    if (!response.ok) {
      throw new Error(`Scan history fetch failed: ${response.status}`);
    }

    const payload = (await response.json()) as { scans?: Scan[] };
    applyScans(Array.isArray(payload.scans) ? payload.scans : []);
  }, [applyScans, token]);

  const loadBackendActions = useCallback(async () => {
    if (!token) return;

    const response = await apiFetch(
      "/action_history?limit=100",
      {
        method: "GET",
      },
      token
    );

    if (response.status === 401) {
      setActionAudits([]);
      return;
    }

    if (!response.ok) {
      throw new Error(`Action history fetch failed: ${response.status}`);
    }

    const payload = (await response.json()) as { actions?: ActionAudit[] };
    setActionAudits(Array.isArray(payload.actions) ? payload.actions : []);
  }, [token]);

  const loadPerformance = useCallback(async () => {
    if (!token) return;

    const response = await apiFetch(
      "/performance",
      {
        method: "GET",
      },
      token
    );

    if (response.status === 401) {
      setPerformance(null);
      return;
    }

    if (!response.ok) {
      throw new Error(`Performance fetch failed: ${response.status}`);
    }

    const payload = (await response.json()) as PerformanceSummary;
    setPerformance(payload);
  }, [token]);

  useEffect(() => {
    if (!user?.id || !token) {
      setScanHistory([]);
      setLatestThreat(null);
      return;
    }

    void loadBackendScans();
    void loadPerformance();
    const pollId = window.setInterval(() => {
      void loadBackendScans();
      void loadPerformance();
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
  }, [applyScans, loadBackendScans, loadPerformance, token, user?.id]);

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
  }, [loadBackendActions, token, user?.id]);

  const visibleActionAudits = actionAudits.filter((entry) => {
    const targetText = String(entry.action_context?.target_text || "").trim().toLowerCase();
    return !["dismiss", "continue anyway", "acknowledge warning"].includes(targetText);
  });

  const visibleActionDecisionCount = (decision: Decision) =>
    visibleActionAudits
      .filter((entry) => entry.decision === decision)
      .reduce((total, entry) => total + (entry.count || 1), 0);

  const totalVisibleActionEvents = visibleActionAudits.reduce(
    (total, entry) => total + (entry.count || 1),
    0
  );

  const getDecisionStatus = (decision: Decision) =>
    decision === "ALLOW"
      ? statusConfig.safe
      : decision === "REQUIRE_CONFIRMATION"
      ? statusConfig.confirmation
      : decision === "BLOCK"
      ? statusConfig.blocked
      : statusConfig.warning;

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

          <PerformancePanel performance={performance} />
          <BenchmarkPanel />

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <div className="glass rounded-xl p-5">
              <p className="text-xs text-muted-foreground font-mono mb-1">
                Agent Actions Audited
              </p>
              <p className="text-3xl font-bold font-mono">{totalVisibleActionEvents}</p>
            </div>
            <div className="glass rounded-xl p-5">
              <p className="text-xs text-muted-foreground font-mono mb-1">
                Allowed Actions
              </p>
              <p className="text-3xl font-bold font-mono text-cyber-safe">
                {visibleActionDecisionCount("ALLOW")}
              </p>
            </div>
            <div className="glass rounded-xl p-5">
              <p className="text-xs text-muted-foreground font-mono mb-1">
                Stopped / Warned
              </p>
              <p className="text-3xl font-bold font-mono text-cyber-danger">
                {visibleActionDecisionCount("BLOCK") + visibleActionDecisionCount("WARN")}
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

          <div className="glass rounded-xl overflow-hidden mb-8">
            <div className="border-b px-5 py-3">
              <h2 className="text-base font-semibold">Agent Action Audit Trail</h2>
              <p className="mt-1 text-[11px] text-muted-foreground font-mono">
                Every mediated action is logged here, including approvals.
              </p>
            </div>
            {visibleActionAudits.length === 0 ? (
              <div className="px-5 py-5 text-sm text-muted-foreground">
                No action audits yet.
              </div>
            ) : (
              <div className="p-4">
                <AnimatedList
                  itemCount={visibleActionAudits.length}
                  maxHeight="max-h-[34rem]"
                  getKey={(index) => {
                    const entry = visibleActionAudits[index];
                    return `${entry.timestamp || index}-${entry.action}-${entry.url}`;
                  }}
                  renderItem={(index) => {
                    const entry = visibleActionAudits[index];
                    const decision = entry.decision;
                    const status = getDecisionStatus(decision);
                    const auditId = `${entry.timestamp || index}-${entry.action}-${entry.url}`;
                    const expanded = expandedAudit === auditId;

                    return (
                      <motion.div
                        whileHover={{ scale: 1.01, borderColor: "hsl(var(--primary) / 0.28)" }}
                        className="rounded-lg border border-border bg-background/25 px-3 py-2.5 transition-colors"
                      >
                        <button
                          type="button"
                          onClick={() => setExpandedAudit(expanded ? null : auditId)}
                          className="w-full text-left"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="flex flex-wrap items-center gap-2">
                                <p className="text-sm font-mono">{entry.action}</p>
                                {(entry.count || 1) > 1 && (
                                  <span className="rounded-full border border-border/80 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                                    x{entry.count}
                                  </span>
                                )}
                              </div>
                              <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] font-mono text-muted-foreground">
                                <span>{formatDateTime(entry.timestamp)}</span>
                                <span className="text-border">•</span>
                                <span>{entry.attack_type || entry.page_decision || "Unknown"}</span>
                                <span className="text-border">•</span>
                                <span className="truncate">{entry.action_context?.target_text || entry.url}</span>
                              </div>
                            </div>
                            <div className="flex shrink-0 items-center gap-2">
                              <span
                                className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-mono ${status.bg} ${status.color}`}
                              >
                                {decision}
                              </span>
                              <span className="inline-flex items-center gap-1 text-xs font-mono text-primary">
                                {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                                {expanded ? "Hide" : "View"}
                              </span>
                            </div>
                          </div>
                        </button>

                        {expanded && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            transition={{ duration: 0.22 }}
                            className="mt-3 overflow-hidden border-t border-border/70 pt-3"
                          >
                            <div className="grid gap-2 text-xs md:grid-cols-[minmax(0,1.5fr)_minmax(180px,0.8fr)]">
                              <div className="min-w-0 rounded-md border border-border/60 bg-secondary/10 px-2.5 py-2">
                                <p className={compactLabelClass}>Target</p>
                                <p className="mt-1 font-mono leading-5 break-words">
                                  {entry.action_context?.target_text || entry.url}
                                </p>
                              </div>
                              <div className="rounded-md border border-border/60 bg-secondary/10 px-2.5 py-2">
                                <p className={compactLabelClass}>Attack</p>
                                <p className="mt-1 font-mono leading-5">
                                  {entry.attack_type || entry.page_decision || "Unknown"}
                                </p>
                              </div>
                            </div>

                            <div className="mt-2 rounded-md border border-border/60 bg-secondary/10 px-2.5 py-2">
                              <p className={compactLabelClass}>Reason</p>
                              <p className="mt-1 text-sm leading-5 text-foreground/90">{entry.reason}</p>
                            </div>
                          </motion.div>
                        )}
                      </motion.div>
                    );
                  }}
                />
              </div>
            )}
          </div>

          {/* Scan History */}
          <div className="glass rounded-xl overflow-hidden">
            <div className="border-b px-5 py-3">
              <h2 className="text-base font-semibold">Scan History</h2>
              <p className="mt-1 text-[11px] text-muted-foreground font-mono">
                Recent records ordered by time, with expandable analysis details.
              </p>
            </div>
            {filtered.length === 0 ? (
              <div className="px-5 py-5 text-sm text-muted-foreground">
                No scan history matches the current filters.
              </div>
            ) : (
              <div className="p-4">
                <AnimatedList
                  itemCount={filtered.length}
                  maxHeight="max-h-[42rem]"
                  getKey={(index) => filtered[index].id}
                  renderItem={(index) => {
                    const scan = filtered[index];
                    const status = scanStatus(scan);
                    const Icon = statusIcons[status];
                    const cfg = statusConfig[status];
                    const expanded = expandedScan === scan.id;
                    const decision = scanDecision(scan);
                    const details = (scan.details || {}) as ScanDetails;
                    const indicators = Array.isArray(details.reasons) ? details.reasons : [];
                    const signalDetails = Array.isArray(details.signal_details) ? details.signal_details : [];
                    const analysis = scan.analysis || details.analysis || {};
                    const summary = String(
                      scan.analysisSummary || details.summary || "No explanation available."
                    );
                    const actionLog = scan.action_log;
                    const attackType = String(scan.attack_type || details.attack_type || "Unknown");

                  return (
                    <motion.div
                      whileHover={{ scale: 1.008, borderColor: "hsl(var(--primary) / 0.28)" }}
                      className="rounded-lg border border-border bg-background/25 px-3 py-2.5 transition-colors"
                    >
                      <button
                        type="button"
                        onClick={() => setExpandedScan(expanded ? null : scan.id)}
                        className="w-full text-left"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p
                              title={scan.url}
                              className="font-mono text-xs leading-5 text-foreground break-all"
                            >
                              {scan.url}
                            </p>
                            <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] font-mono text-muted-foreground">
                              <span>
                                {scan.timestamp
                                  ? formatDateTime(scan.timestamp)
                                  : scan.time
                                  ? formatDateTime(scan.time)
                                  : "Unknown"}
                              </span>
                              <span className="text-border">•</span>
                              <span>Risk {scan.risk ?? 0}</span>
                              <span className="text-border">•</span>
                              <span>{attackType}</span>
                            </div>
                          </div>

                          <div className="flex shrink-0 items-center gap-2">
                            <span
                              className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-mono ${cfg.bg} ${cfg.color}`}
                            >
                              <Icon className="h-3 w-3" />
                              {cfg.label}
                            </span>
                            <span className="inline-flex items-center gap-1 text-xs font-mono text-primary">
                              {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                              {expanded ? "Hide" : "View"}
                            </span>
                          </div>
                        </div>
                      </button>

                      {expanded && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          transition={{ duration: 0.22 }}
                          className="mt-3 overflow-hidden border-t border-border/70 pt-3 text-xs"
                        >
                          <div className="space-y-4">
                              <RiskIntelligencePanel
                                riskScore={Number(scan.risk ?? 0)}
                                trustScore={resolveTrustScore(scan)}
                                decision={decision}
                                indicators={(
                                  signalDetails.length > 0
                                    ? signalDetails
                                    : indicators.map((name) => ({
                                        type: name,
                                        severity: "low",
                                        confidence: "low",
                                      }))
                                ).map((signal) => ({
                                  name: String(signal.type || signal.name || "unknown"),
                                  detected: true,
                                  severity:
                                    signal.severity === "critical" ||
                                    signal.severity === "high" ||
                                    signal.severity === "medium" ||
                                    signal.severity === "low"
                                      ? signal.severity
                                      : "low",
                                  confidence:
                                    signal.confidence === "critical" ||
                                    signal.confidence === "high" ||
                                    signal.confidence === "medium" ||
                                    signal.confidence === "low"
                                      ? signal.confidence
                                      : "low",
                                }))}
                                explanation={{
                                  summary: String(analysis.summary || summary),
                                  reasons: Array.isArray(analysis.key_findings) && analysis.key_findings.length > 0
                                    ? analysis.key_findings
                                    : indicators,
                                  policyDecision: String(analysis.policy_decision || decision),
                                  confidenceScore: Number(scan.confidence_score || analysis.confidence_score || 0),
                                  reasoningSteps: Array.isArray(scan.reasoning_steps)
                                    ? scan.reasoning_steps
                                    : Array.isArray(analysis.reasoning_steps)
                                    ? analysis.reasoning_steps
                                    : [],
                                  scoreBreakdown: resolveScoreBreakdown(scan, details),
                                }}
                              />
                              {actionLog && (
                                <div className="rounded-lg border border-cyber-danger/30 bg-cyber-danger/10 p-3">
                                  <p className="mb-2 font-mono">
                                    <strong>Action Mediation Log:</strong>
                                  </p>
                                  <div className="space-y-1 font-mono leading-5">
                                    <p>Action: {actionLog.actionType}</p>
                                    <p>Decision: {actionLog.decision}</p>
                                    <p>Reason: {actionLog.reason}</p>
                                    <p>Attack Type: {attackType}</p>
                                  </div>
                                </div>
                              )}
                              <div>
                                <p className="mb-1 font-mono">
                                  <strong>Analysis Reasons:</strong>
                                </p>
                                <ul className="list-disc space-y-1 pl-4 leading-5">
                                  {indicators.map(
                                    (r: string, i: number) => (
                                      <li key={i}>{r}</li>
                                    )
                                  )}
                                </ul>
                              </div>
                          </div>
                        </motion.div>
                      )}
                    </motion.div>
                  );
                  }}
                />
              </div>
            )}
          </div>

        </div>
      </div>

      <Footer />
    </div>
  );
};

export default Dashboard;
