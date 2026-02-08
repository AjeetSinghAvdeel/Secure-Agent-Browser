import { useEffect, useState } from "react";
import { collection, onSnapshot } from "firebase/firestore";
import { db } from "@/lib/firebase";

export type Scan = {
  id: string;
  url: string;
  timestamp: any;
  risk: number;
  status: "safe" | "warning" | "blocked";
  details: any;
};

export function useScans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsub = onSnapshot(collection(db, "scans"), (snap) => {
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
