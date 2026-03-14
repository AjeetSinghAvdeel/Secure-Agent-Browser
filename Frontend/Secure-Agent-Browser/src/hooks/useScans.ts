import { useEffect, useState } from "react";
import { collection, onSnapshot, orderBy, query } from "firebase/firestore";
import { db } from "@/lib/firebase";

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
  timestamp: any;
  risk: number;
  status: "safe" | "warning" | "blocked";
  details: any;

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
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // newest scans first (recommended)
    const q = query(
      collection(db, "scans"),
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
  }, []);

  return { scans, loading };
}
