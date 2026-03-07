import { Fragment, useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import { addDoc, collection, onSnapshot } from "firebase/firestore";
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
import { useToast } from "@/hooks/use-toast";
import { db } from "@/lib/firebase";

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
  agent_action?: {
    type: string;
    fields?: string[];
    confidence?: string;
    reason?: string;
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
  const { toast } = useToast();

  const [scanInput, setScanInput] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [latestThreat, setLatestThreat] = useState<Scan | null>(null);

  const formatTime = (ts: any) => {
    if (ts?.toDate) return ts.toDate().toLocaleString();
    if (ts instanceof Date) return ts.toLocaleString();
    if (typeof ts === "string" || typeof ts === "number") {
      const parsed = new Date(ts);
      if (!Number.isNaN(parsed.getTime())) return parsed.toLocaleString();
    }
    return "--";
  };

  const severityFromIndicator = (indicator: string) => {
    if (
      indicator.includes("suspicious_tld") ||
      indicator.includes("phishing") ||
      indicator.includes("base64")
    ) {
      return "high" as const;
    }
    if (
      indicator.includes("hex") ||
      indicator.includes("unicode") ||
      indicator.includes("hidden")
    ) {
      return "medium" as const;
    }
    return "low" as const;
  };

  const normalizeDecision = (decision: unknown): Decision => {
    const value = String(decision || "").toUpperCase();
    if (value === "ALLOW" || value === "WARN" || value === "BLOCK") {
      return value;
    }
    return "WARN";
  };

  const decisionToStatus = (decision: Decision): Scan["status"] => {
    if (decision === "ALLOW") return "safe";
    if (decision === "WARN") return "warning";
    return "blocked";
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

  useEffect(() => {
    const unsubscribe = onSnapshot(
      collection(db, "scans"),
      (snapshot) => {
        const scans = snapshot.docs.map((doc) => ({
          id: doc.id,
          ...(doc.data() as Omit<Scan, "id">),
        }));
        const sorted = scans.sort((a, b) => {
          const aTime = new Date(String(a.time || a.timestamp || 0)).getTime();
          const bTime = new Date(String(b.time || b.timestamp || 0)).getTime();
          return (Number.isFinite(bTime) ? bTime : 0) - (Number.isFinite(aTime) ? aTime : 0);
        });

        setScanHistory(sorted);

        const blocked = sorted.find((s) => s.decision === "BLOCK");
        if (blocked) {
          setLatestThreat(blocked);
        } else {
          setLatestThreat(null);
        }
      },
      (error) => {
        console.error("Firestore listener error:", error);
      }
    );

    return () => unsubscribe();
  }, []);

  const scanUrl = async (url: string) => {
    const target = url.trim();
    if (!target) {
      toast({
        title: "Scan failed. Please try again.",
        variant: "destructive",
      });
      return;
    }

    try {
      const res = await fetch("http://localhost:8000/analyze_url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: target }),
      });
      if (!res.ok) {
        throw new Error(`Scan request failed (${res.status})`);
      }
      const data = await res.json();
      const decision = normalizeDecision(data?.decision);
      const indicators = Array.isArray(data?.indicators) ? data.indicators : [];
      await addDoc(collection(db, "scans"), {
        url: String(data?.url || target),
        risk: Number(data?.risk ?? 0),
        trust: Number(data?.trust ?? 0),
        analysisSummary: String(data?.explanation || "No explanation available."),
        decision,
        status: decisionToStatus(decision),
        details: {
          confidence: "live",
          reasons: indicators,
        },
        policy: {
          decision,
          reason: "Decision from backend policy engine",
        },
        time: new Date().toISOString(),
      });
    } catch (err) {
      console.error(err);
      toast({
        title: "Scan failed. Please try again.",
        variant: "destructive",
      });
    }
  };

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

          {/* URL Scanner */}
          <div className="mb-5 flex flex-col md:flex-row gap-3">
            <input
              value={scanInput}
              onChange={(e) => setScanInput(e.target.value)}
              placeholder="Enter URL to scan (e.g. https://example.com)"
              className="flex-1 px-4 py-2 rounded-lg border border-border bg-background text-foreground"
            />
            <button
              onClick={() => scanUrl(scanInput)}
              className="bg-primary hover:bg-primary/90 text-primary-foreground px-4 py-2 rounded-lg"
            >
              Scan URL
            </button>
          </div>

          <div className="mb-8">
            {latestThreat && (
              <ThreatAlert
                key={`${latestThreat.id}-${latestThreat.time || latestThreat.timestamp || latestThreat.risk}`}
                threat={latestThreat}
              />
            )}
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
                  const summary = String(scan.analysisSummary || scan?.details?.summary || "No explanation available.");

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
                                indicators={indicators.map((name: string) => ({
                                  name,
                                  detected: true,
                                  severity: severityFromIndicator(String(name)),
                                }))}
                                explanation={{
                                  summary,
                                  reasons: indicators,
                                }}
                              />
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
