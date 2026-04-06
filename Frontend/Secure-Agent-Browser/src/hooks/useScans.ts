import { useEffect, useState } from "react";
import { collection, onSnapshot, orderBy, query, where } from "firebase/firestore";
import { db } from "@/lib/firebase";
import { useAuth } from "@/context/AuthContext";
import { type DateLike } from "@/lib/date";

/* ---------------------------------- */
/* Types */
/* ---------------------------------- */

export type AgentAction = {
  type: string;
  fields?: string[];
};

export type PolicyDecision = {
  decision: "ALLOW" | "WARN" | "BLOCK";
  reason: string;
};

export type Scan = {
  id: string;
  url: string;
  timestamp: DateLike;
  risk: number;
  status: "safe" | "warning" | "blocked";
  details: Record<string, unknown>;

  agent_action?: {
    type: string;
    fields?: string[];
    confidence?: string;
    reason?: string;
  };
  actionType?: string;
  action_log?: {
    actionType: string;
    decision: "ALLOW" | "WARN" | "BLOCK";
    reason: string;
  };
  attack_type?: string;

  policy?: {
    decision: "ALLOW" | "WARN" | "BLOCK";
    reason: string;
  };
};

/* ---------------------------------- */
/* Hook */
/* ---------------------------------- */

export function useScans() {
  const { user } = useAuth();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user?.id) {
      setScans([]);
      setLoading(false);
      return;
    }

    // newest scans first (recommended)
    const q = query(
      collection(db, "scans"),
      where("user_id", "==", user.id),
      orderBy("timestamp", "desc")
    );

    const unsub = onSnapshot(q, (snap) => {
      const data = snap.docs.map((doc) => ({
        id: doc.id,
        ...(doc.data() as Omit<Scan, "id">),
      }));

      setScans(data);
      setLoading(false);
    });

    return () => unsub();
  }, [user?.id]);

  return { scans, loading };
}
