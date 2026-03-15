import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, Search, ShieldAlert } from "lucide-react";

import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import { useAuth } from "@/context/AuthContext";
import { apiFetch } from "@/lib/api";

const DEMO_ATTACKS = [
  {
    label: "Prompt Injection Demo",
    path: "attacks/attack1_injection.html",
  },
  {
    label: "Hidden UI / Clickjacking Demo",
    path: "attacks/attack2_hidden.html",
  },
  {
    label: "Phishing Website Demo",
    path: "attacks/attack3_phishing.html",
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
    if (trimmed.startsWith("attacks/")) return `/${trimmed}`;
    if (trimmed.startsWith("/attacks/")) return trimmed;

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
        logout();
        navigate("/login", { replace: true });
        throw new Error("Unauthorized");
      }

      if (!res.ok) throw new Error(await res.text());

      await res.json();
      setTimeout(() => navigate("/dashboard"), 400);
    } catch (err) {
      console.error(err);
      setError("Scan failed. Backend or Selenium error.");
    } finally {
      setLoading(false);
    }
  };

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    runScan(url);
  };

  const handleDemoClick = (path: string) => {
    const normalizedPath = normalizeTargetUrl(path);
    setUrl(normalizedPath);
    runScan(normalizedPath);
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <div className="pt-24 container mx-auto max-w-xl px-6">
        <h1 className="text-3xl font-bold mb-6 text-center">
          Scan a Web Page
        </h1>

        {/* Scan Input */}
        <form onSubmit={handleScan} className="glass flex gap-2 p-2">
          <Search className="mt-3 ml-3 text-muted-foreground" />
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
        <div className="mt-8 glass rounded-xl p-4 space-y-2">
          <p className="text-xs font-mono text-muted-foreground mb-2">
            DEMO ATTACK SCENARIOS
          </p>

          {DEMO_ATTACKS.map((demo) => (
            <button
              key={demo.path}
              disabled={loading}
              onClick={() => handleDemoClick(demo.path)}
              className="
                w-full flex items-center gap-3
                px-4 py-3 rounded-lg
                font-mono text-sm text-left
                border border-border
                bg-background/40
                hover:border-primary/40
                hover:bg-background/60
                transition
              "
            >
              <ShieldAlert className="w-4 h-4 text-cyber-warning" />
              <span>{demo.label}</span>
            </button>
          ))}
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
