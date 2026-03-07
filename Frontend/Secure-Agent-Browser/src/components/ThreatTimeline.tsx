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
  const timelineData = useMemo(() => {
    const grouped: Record<number, number> = {};

    scans.forEach((scan) => {
      const decision = String(scan.decision || scan.policy?.decision || '').toUpperCase();
      const isBlocked = decision === 'BLOCK' || String(scan.status || '').toLowerCase() === 'blocked';
      if (!isBlocked) return;

      const rawTime = scan.time ?? scan.timestamp;
      const date = rawTime?.toDate ? rawTime.toDate() : new Date(rawTime);
      if (Number.isNaN(date.getTime())) return;

      // Normalize to minute buckets using epoch ms to keep chronological sorting correct.
      const minuteBucket = Math.floor(date.getTime() / 60000) * 60000;

      if (!grouped[minuteBucket]) {
        grouped[minuteBucket] = 0;
      }
      grouped[minuteBucket]++;
    });

    return Object.entries(grouped)
      .sort(([a], [b]) => Number(a) - Number(b))
      .map(([bucketMs, count]) => ({
        time: new Date(Number(bucketMs)).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          hour12: false,
        }),
        attacks: count,
      }));
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
