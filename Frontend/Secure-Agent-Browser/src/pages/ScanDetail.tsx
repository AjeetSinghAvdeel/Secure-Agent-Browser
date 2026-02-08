import { useParams, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowLeft, Shield, CheckCircle, AlertTriangle, Ban, FileWarning, MousePointerClick, Eye, Brain, ExternalLink } from "lucide-react";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { scanData, statusConfig } from "@/data/scanData";

const statusIcons = { safe: CheckCircle, warning: AlertTriangle, blocked: Ban };

const ScanDetail = () => {
  const { id } = useParams<{ id: string }>();
  const scan = scanData.find((s) => s.id === id);

  if (!scan) {
    return (
      <div className="min-h-screen bg-background">
        <Navbar />
        <div className="pt-24 pb-16 container mx-auto px-6 text-center">
          <Shield className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
          <h1 className="text-2xl font-bold mb-2">Scan Not Found</h1>
          <p className="text-muted-foreground mb-6">The scan result you're looking for doesn't exist.</p>
          <Link to="/dashboard" className="text-primary hover:underline font-mono text-sm">← Back to Dashboard</Link>
        </div>
      </div>
    );
  }

  const cfg = statusConfig[scan.status];
  const Icon = statusIcons[scan.status];
  const scoreColor = scan.score < 30 ? "text-cyber-safe" : scan.score < 70 ? "text-cyber-warning" : "text-cyber-danger";
  const strokeColor = scan.score < 30 ? "hsl(var(--cyber-safe))" : scan.score < 70 ? "hsl(var(--cyber-warning))" : "hsl(var(--cyber-danger))";

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <div className="pt-24 pb-16">
        <div className="container mx-auto px-6 max-w-4xl">
          {/* Header */}
          <div className="flex items-center gap-4 mb-8">
            <Link to="/dashboard" className="text-muted-foreground hover:text-primary transition-colors">
              <ArrowLeft className="w-5 h-5" />
            </Link>
            <div className="flex-1 min-w-0">
              <h1 className="text-xl md:text-2xl font-bold">Scan Analysis</h1>
              <p className="text-xs text-muted-foreground font-mono truncate">{scan.url}</p>
            </div>
            <span className={`inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded-full border ${cfg.bg} ${cfg.color}`}>
              <Icon className="w-3 h-3" />
              {cfg.label}
            </span>
          </div>

          {/* Overview Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            {/* Risk Score */}
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="glass rounded-xl p-6 text-center">
              <p className="text-xs text-muted-foreground font-mono mb-3">RISK SCORE</p>
              <div className="relative w-28 h-28 mx-auto mb-2">
                <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
                  <circle cx="60" cy="60" r="50" fill="none" stroke="hsl(var(--border))" strokeWidth="8" />
                  <circle cx="60" cy="60" r="50" fill="none" stroke={strokeColor} strokeWidth="8" strokeLinecap="round" strokeDasharray={`${(scan.score / 100) * 314} 314`} />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className={`font-mono text-3xl font-bold ${scoreColor}`}>{scan.score}</span>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">/100</p>
            </motion.div>

            {/* Scan Info */}
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass rounded-xl p-6">
              <p className="text-xs text-muted-foreground font-mono mb-3">SCAN DETAILS</p>
              <div className="space-y-3 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground">Target URL</p>
                  <p className="font-mono text-xs truncate">{scan.url}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Scan Time</p>
                  <p className="font-mono text-xs">{scan.time}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Scan ID</p>
                  <p className="font-mono text-xs">{scan.id}</p>
                </div>
              </div>
            </motion.div>

            {/* ML + LLM Summary */}
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass rounded-xl p-6">
              <p className="text-xs text-muted-foreground font-mono mb-3">AI VERDICT</p>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground">ML Classification</p>
                  <p className={`font-mono text-sm font-semibold ${scan.detections.mlVerdict.label === "Benign" ? "text-cyber-safe" : scan.detections.mlVerdict.label === "Suspicious" ? "text-cyber-warning" : "text-cyber-danger"}`}>
                    {scan.detections.mlVerdict.label} ({scan.detections.mlVerdict.confidence}%)
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Confidence</p>
                  <div className="w-full h-1.5 rounded-full bg-secondary overflow-hidden mt-1">
                    <div className="h-full bg-primary rounded-full" style={{ width: `${scan.detections.mlVerdict.confidence}%` }} />
                  </div>
                </div>
              </div>
            </motion.div>
          </div>

          {/* Detection Breakdown */}
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="glass rounded-xl overflow-hidden mb-8">
            <div className="px-6 py-4 border-b border-border flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />
              <h2 className="font-semibold">Detection Breakdown</h2>
            </div>
            <div className="divide-y divide-border/50">
              {/* Prompt Injection */}
              <DetectionRow
                icon={FileWarning}
                title="Prompt Injection"
                found={scan.detections.promptInjection.found}
                count={scan.detections.promptInjection.count}
              >
                {scan.detections.promptInjection.found ? (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Detected patterns:</p>
                    <div className="flex flex-wrap gap-1">
                      {scan.detections.promptInjection.patterns.map((p) => (
                        <span key={p} className="text-xs font-mono bg-cyber-danger/10 text-cyber-danger border border-cyber-danger/30 rounded px-2 py-0.5">{p}</span>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">No injection patterns found in page content.</p>
                )}
              </DetectionRow>

              {/* Phishing */}
              <DetectionRow
                icon={MousePointerClick}
                title="Phishing Detection"
                found={scan.detections.phishing.found}
                count={scan.detections.phishing.count}
              >
                <p className="text-xs text-muted-foreground">{scan.detections.phishing.details}</p>
              </DetectionRow>

              {/* Clickjacking */}
              <DetectionRow
                icon={Eye}
                title="Clickjacking / Hidden Elements"
                found={scan.detections.clickjacking.found}
                count={scan.detections.clickjacking.count}
              >
                <p className="text-xs text-muted-foreground">{scan.detections.clickjacking.details}</p>
              </DetectionRow>

              {/* ML Verdict */}
              <DetectionRow
                icon={Brain}
                title="ML Model Verdict"
                found={scan.detections.mlVerdict.label !== "Benign"}
                count={null}
              >
                <p className="text-xs text-muted-foreground">
                  Naive Bayes classifier result: <span className="font-mono font-semibold">{scan.detections.mlVerdict.label}</span> with {scan.detections.mlVerdict.confidence}% confidence.
                </p>
              </DetectionRow>
            </div>
          </motion.div>

          {/* LLM Reasoning */}
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="glass rounded-xl p-6 mb-8">
            <div className="flex items-center gap-2 mb-4">
              <Brain className="w-5 h-5 text-primary" />
              <h2 className="font-semibold">LLM Reasoning Analysis</h2>
            </div>
            <p className="text-sm text-muted-foreground leading-relaxed">{scan.detections.llmReasoning}</p>
          </motion.div>

          {/* Keywords */}
          {scan.keywords.length > 0 && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }} className="glass rounded-xl p-6 mb-8">
              <p className="text-xs text-muted-foreground font-mono mb-3">DETECTED SUSPICIOUS KEYWORDS</p>
              <div className="flex flex-wrap gap-2">
                {scan.keywords.map((kw) => (
                  <span key={kw} className="text-xs font-mono bg-cyber-danger/10 text-cyber-danger border border-cyber-danger/30 rounded-full px-3 py-1">{kw}</span>
                ))}
              </div>
            </motion.div>
          )}

          {/* Actions */}
          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <Link to="/dashboard" className="px-6 py-2 rounded-lg glass text-sm font-medium hover:border-primary/40 transition-colors text-center">
              ← Back to Dashboard
            </Link>
            <Link to="/scan" className="px-6 py-2 rounded-lg bg-primary/10 text-primary border border-primary/30 text-sm font-medium hover:bg-primary/20 transition-colors text-center inline-flex items-center justify-center gap-2">
              Scan New URL <ExternalLink className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
};

interface DetectionRowProps {
  icon: React.ElementType;
  title: string;
  found: boolean;
  count: number | null;
  children: React.ReactNode;
}

const DetectionRow = ({ icon: IconComp, title, found, count, children }: DetectionRowProps) => {
  return (
    <div className="px-6 py-4">
      <div className="flex items-center gap-3 mb-2">
        <IconComp className={`w-4 h-4 shrink-0 ${found ? "text-cyber-danger" : "text-cyber-safe"}`} />
        <h3 className="font-medium text-sm flex-1">{title}</h3>
        {count !== null && (
          <span className={`font-mono text-xs font-bold ${found ? "text-cyber-danger" : "text-cyber-safe"}`}>
            {count} found
          </span>
        )}
        <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${found ? "bg-cyber-danger/10 border-cyber-danger/30 text-cyber-danger" : "bg-cyber-safe/10 border-cyber-safe/30 text-cyber-safe"}`}>
          {found ? "DETECTED" : "CLEAR"}
        </span>
      </div>
      <div className="ml-7">{children}</div>
    </div>
  );
};

export default ScanDetail;
