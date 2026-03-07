import React, { useMemo } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { Card } from '@/components/ui/card';

interface ScanRecord {
  id?: string;
  url?: string;
  risk?: number;
  decision?: string;
  status?: string;
  policy?: {
    decision?: string;
  };
  timestamp?: any; // Firestore timestamp or Date or string
  time?: string; // alternative simple string field
}

interface ThreatTimelineProps {
  scans: ScanRecord[];
}

/**
 * ThreatTimeline
 *
 * Visualizes number of blocked/warned scans over time. The component
 * takes a list of scan records and groups the ones where decision is
 * "BLOCK" or "WARN" by minute, then renders a responsive line chart.
 */
const ThreatTimeline: React.FC<ThreatTimelineProps> = ({ scans }) => {
  // convert timestamp to minute resolution string (HH:MM)
  const formatTime = (ts: any): string => {
    // accept Date-like objects or simple strings
    if (!ts) return 'unknown';
    if (typeof ts === 'string') {
      // assume already hh:mm or ISO
      const parsed = new Date(ts);
      if (!isNaN(parsed.getTime())) {
        const h = parsed.getHours().toString().padStart(2, '0');
        const m = parsed.getMinutes().toString().padStart(2, '0');
        return `${h}:${m}`;
      }
      return ts;
    }
    let date: Date;
    if (ts.toDate) {
      date = ts.toDate();
    } else if (ts instanceof Date) {
      date = ts;
    } else {
      date = new Date(ts);
    }
    const h = date.getHours().toString().padStart(2, '0');
    const m = date.getMinutes().toString().padStart(2, '0');
    return `${h}:${m}`;
  };

  const timelineData = useMemo(() => {
    const bucket: Record<string, number> = {};

    const normalizeDecision = (s: ScanRecord): string => {
      const decision = String(s.decision || s.policy?.decision || '').toUpperCase();
      if (decision) return decision;
      if (s.status === 'safe') return 'ALLOW';
      if (s.status === 'blocked') return 'BLOCK';
      if (s.status === 'warning') return 'WARN';
      return '';
    };

    scans.forEach((s) => {
      const d = normalizeDecision(s);
      if (d === 'BLOCK' || d === 'WARN') {
        const rawTime = s.timestamp ?? s.time;
        const t = formatTime(rawTime);
        bucket[t] = (bucket[t] || 0) + 1;
      }
    });

    // convert into array sorted by time
    const arr = Object.keys(bucket)
      .map((time) => ({ time, attacks: bucket[time] }))
      .sort((a, b) => a.time.localeCompare(b.time));
    return arr;
  }, [scans]);

  return (
    <Card className="rounded-lg bg-gray-800 border-0 p-4">
      <h3 className="text-lg font-semibold text-white mb-4">Threat Timeline</h3>
      <div className="w-full h-64">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={timelineData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="time" stroke="#9ca3af" />
            <YAxis stroke="#9ca3af" allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: '#1f2937', border: 'none', color: '#fff' }}
            />
            <Line type="monotone" dataKey="attacks" stroke="#3b82f6" strokeWidth={2} dot={{ r: 2 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
};

export default ThreatTimeline;
