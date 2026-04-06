import { useEffect, useState } from "react";

import { useAuth } from "@/context/AuthContext";
import { type DateLike } from "@/lib/date";
import { apiFetch } from "@/lib/api";

type HealthPayload = {
  status?: string;
  metrics_ready?: boolean;
  firebase_ready?: boolean;
  timestamp?: string;
};

type PerformancePayload = {
  avg_latency_ms?: number;
  max_latency_ms?: number;
  breakdown?: {
    dom?: number;
    ml?: number;
    policy?: number;
  };
};

type ScanItem = {
  id?: string;
  url?: string;
  risk?: number;
  decision?: string;
  status?: string;
  attack_type?: string;
  timestamp?: DateLike;
  time?: string;
};

type ActionItem = {
  url?: string;
  action?: string;
  decision?: string;
  reason?: string;
  attack_type?: string;
  count?: number;
  timestamp?: DateLike;
  action_context?: {
    target_text?: string;
  };
};

export function useSystemSnapshot() {
  const { token, ready, user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [health, setHealth] = useState<HealthPayload | null>(null);
  const [performance, setPerformance] = useState<PerformancePayload | null>(null);
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [actions, setActions] = useState<ActionItem[]>([]);

  useEffect(() => {
    if (!ready) return;

    let cancelled = false;

    const load = async () => {
      try {
        const healthResponse = await apiFetch("/health", { method: "GET" });
        if (!cancelled && healthResponse.ok) {
          setHealth((await healthResponse.json()) as HealthPayload);
        }

        if (!token) {
          if (!cancelled) {
            setPerformance(null);
            setScans([]);
            setActions([]);
            setLoading(false);
          }
          return;
        }

        const [performanceResult, scanResult, actionResult] = await Promise.allSettled([
          apiFetch("/performance", { method: "GET" }, token),
          apiFetch("/scan_history?limit=12", { method: "GET" }, token),
          apiFetch("/action_history?limit=12", { method: "GET" }, token),
        ]);

        if (cancelled) return;

        if (performanceResult.status === "fulfilled" && performanceResult.value.ok) {
          setPerformance((await performanceResult.value.json()) as PerformancePayload);
        }

        if (scanResult.status === "fulfilled" && scanResult.value.ok) {
          const payload = (await scanResult.value.json()) as { scans?: ScanItem[] };
          setScans(Array.isArray(payload.scans) ? payload.scans : []);
        }

        if (actionResult.status === "fulfilled" && actionResult.value.ok) {
          const payload = (await actionResult.value.json()) as { actions?: ActionItem[] };
          setActions(Array.isArray(payload.actions) ? payload.actions : []);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void load();
    const intervalId = window.setInterval(() => {
      void load();
    }, 20000);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [ready, token, user?.id]);

  return {
    loading,
    health,
    performance,
    scans,
    actions,
    isAuthenticated: Boolean(token),
  };
}
