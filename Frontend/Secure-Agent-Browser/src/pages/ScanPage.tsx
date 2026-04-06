import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ExternalLink, Loader2, Search, ShieldAlert, Radar, Eye } from "lucide-react";

import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { useAuth } from "@/context/AuthContext";
import { API_BASE_URL, apiFetch } from "@/lib/api";

const DEMO_ATTACKS = [
  {
    label: "Prompt Injection Demo",
    path: "malicious-simulator-lab/pages/attack1_injection.html",
    severity: "Critical",
    attackType: "Prompt Injection",
    description: "A page that tries to coerce an agent into ignoring prior instructions and following hostile prompts.",
  },
  {
    label: "Hidden UI / Clickjacking Demo",
    path: "malicious-simulator-lab/pages/attack2_hidden.html",
    severity: "High",
    attackType: "Hidden Overlay",
    description: "An invisible overlay intercepts clicks while the visible page pretends to be a normal verification flow.",
  },
  {
    label: "Phishing Website Demo",
    path: "malicious-simulator-lab/pages/attack3_phishing.html",
    severity: "High",
    attackType: "Credential Theft",
    description: "A phishing-style form uses urgent account language to pressure users into submitting secrets.",
  },
  {
    label: "Iframe Clickjacking Demo",
    path: "malicious-simulator-lab/pages/attack4_clickjacking_iframe.html",
    severity: "Critical",
    attackType: "Clickjacking",
    description: "A transparent iframe covers the screen so user clicks can be hijacked by hidden content.",
  },
  {
    label: "Dynamic Injection Demo",
    path: "malicious-simulator-lab/pages/attack5_dynamic_injection.html",
    severity: "High",
    attackType: "Dynamic Script Attack",
    description: "The page injects overlays and event hooks after load to simulate runtime manipulation.",
  },
  {
    label: "Combined Threat Demo",
    path: "malicious-simulator-lab/pages/combined-threat.html",
    severity: "Critical",
    attackType: "Multi-Stage Attack",
    description: "Multiple malicious signals appear together so you can test how the system escalates complex threats.",
  },
  {
    label: "Obfuscated Payload Demo",
    path: "malicious-simulator-lab/pages/obfuscated-payload.html",
    severity: "High",
    attackType: "Obfuscation",
    description: "Encoded or disguised payload markers simulate attempts to hide the true behavior of the page.",
  },
  {
    label: "Phishing Login Demo",
    path: "malicious-simulator-lab/pages/phishing-login.html",
    severity: "High",
    attackType: "Phishing",
    description: "A realistic login lure designed to trigger phishing and sensitive-input protections.",
  },
  {
    label: "Prompt Injection Lab Demo",
    path: "malicious-simulator-lab/pages/prompt-injection.html",
    severity: "Critical",
    attackType: "Prompt Injection",
    description: "A simulator-lab variant focused on instruction hijacking and agent-directed prompt abuse.",
  },
];

const ScanPage = () => {
  const { token, logout } = useAuth();
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const normalizeTargetUrl = (value: string): string => {
    const trimmed = value.trim();
    if (!trimmed) return "";

    // Accept demo/local attack paths with or without leading slash.
    if (trimmed.startsWith("malicious-simulator-lab/pages/")) return `/${trimmed}`;
    if (trimmed.startsWith("/malicious-simulator-lab/pages/")) return trimmed;

    // If protocol exists but is malformed (e.g. p://), fall back to http://.
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
      if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
        return trimmed;
      }
      return `http://${trimmed.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "")}`;
    }

    // Bare host/path defaults to http for local dev targets.
    return `http://${trimmed}`;
  };

  const toBrowserNavigableUrl = (value: string): string => {
    const normalized = normalizeTargetUrl(value);
    if (!normalized) return "";

    if (normalized.startsWith("/")) {
      const labPrefix = "/malicious-simulator-lab/";
      if (normalized.startsWith(labPrefix)) {
        const labPath = normalized.slice("/malicious-simulator-lab".length);
        return `${API_BASE_URL}/lab${labPath}`;
      }
      return `${window.location.origin}${normalized}`;
    }

    return normalized;
  };

  const runScan = async (targetUrl: string) => {
    const normalizedTarget = normalizeTargetUrl(targetUrl);
    if (!normalizedTarget) return;

    setLoading(true);
    setError(null);

    try {
      const res = await apiFetch(
        "/scan",
        {
        method: "POST",
        body: JSON.stringify({ url: normalizedTarget }),
        },
        token
      );

      if (res.status === 401) {
        throw new Error("Your session is no longer valid. Sign in again.");
      }

      if (!res.ok) throw new Error(await res.text());

      await res.json();
      setTimeout(() => navigate("/dashboard"), 400);
    } catch (err) {
      console.error(err);
      setError(err instanceof Error ? err.message : "Scan failed. Backend or Selenium error.");
    } finally {
      setLoading(false);
    }
  };

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    runScan(url);
  };

  const handleDemoClick = (path: string) => {
    const normalizedPath = toBrowserNavigableUrl(path);
    setUrl(normalizedPath);
    runScan(normalizedPath);
  };

  const openDemoPage = (path: string) => {
    const normalizedPath = normalizeTargetUrl(path);
    const navigableUrl = toBrowserNavigableUrl(path);
    setUrl(normalizedPath);
    if (!navigableUrl) return;

    const demoTab = window.open("about:blank", "_blank");
    if (demoTab) {
      demoTab.location.href = navigableUrl;
      demoTab.focus();
      return;
    }

    window.location.href = navigableUrl;
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <div className="pt-24 container mx-auto max-w-5xl px-6">
        <h1 className="text-3xl font-bold mb-3 text-center">
          Scan a Web Page
        </h1>
        <p className="text-sm text-muted-foreground text-center max-w-2xl mx-auto mb-6">
          Use a direct URL, or open one of the malicious simulator pages below to see how SecureAgent reacts in the browser before reviewing the verdict in the dashboard.
        </p>

        {/* Scan Input */}
        <form onSubmit={handleScan} className="glass flex gap-2 p-2 max-w-2xl mx-auto">
          <Search className="mt-3 ml-3 text-muted-foreground shrink-0" />
          <input
            className="flex-1 bg-transparent outline-none font-mono"
            placeholder="https://example.com or local file path"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button
            type="submit"
            disabled={loading}
            className="px-5 py-2 bg-primary rounded-lg"
          >
            {loading ? <Loader2 className="animate-spin" /> : "Scan"}
          </button>
        </form>

        {/* 🔥 DEMO ATTACKS – THEMED */}
        <div className="mt-10 glass rounded-2xl p-5 md:p-6">
          <p className="text-xs font-mono text-muted-foreground mb-2">
            DEMO ATTACK SCENARIOS
          </p>
          <p className="text-sm text-muted-foreground mb-5">
            `Open Demo` launches the page itself so the extension can inspect it live. `Scan Only` runs the backend analysis from this screen.
          </p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {DEMO_ATTACKS.map((demo) => (
              <div
                key={demo.path}
                className="rounded-2xl border border-border bg-background/40 p-4 hover:border-primary/40 hover:bg-background/60 transition"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <ShieldAlert className="w-4 h-4 text-cyber-warning" />
                      <h2 className="font-mono text-sm md:text-base">{demo.label}</h2>
                    </div>
                    <p className="text-xs text-muted-foreground mt-3 leading-6">
                      {demo.description}
                    </p>
                  </div>
                  <div className="rounded-full border border-cyber-danger/30 bg-cyber-danger/10 px-3 py-1 text-[11px] font-mono text-cyber-danger">
                    {demo.severity}
                  </div>
                </div>

                <div className="flex items-center gap-2 mt-4 text-[11px] font-mono text-muted-foreground">
                  <Radar className="w-3.5 h-3.5 text-primary" />
                  <span>{demo.attackType}</span>
                </div>

                <div className="mt-3 rounded-lg border border-border/80 bg-background/60 px-3 py-2 text-[11px] font-mono text-muted-foreground break-all">
                  /{demo.path}
                </div>

                <div className="mt-4 flex flex-wrap gap-3">
                  <button
                    type="button"
                    disabled={loading}
                    onClick={() => openDemoPage(demo.path)}
                    className="inline-flex items-center gap-2 rounded-lg border border-primary/30 bg-primary/10 px-4 py-2 text-sm font-medium text-primary hover:bg-primary/20 transition"
                  >
                    <Eye className="w-4 h-4" />
                    Open Demo
                  </button>
                  <button
                    type="button"
                    disabled={loading}
                    onClick={() => handleDemoClick(demo.path)}
                    className="inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm font-medium text-foreground hover:border-primary/40 hover:text-primary transition"
                  >
                    <ExternalLink className="w-4 h-4" />
                    Scan Only
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {error && (
          <p className="mt-4 text-red-500 text-center">{error}</p>
        )}
      </div>

      <Footer />
    </div>
  );
};

export default ScanPage;
