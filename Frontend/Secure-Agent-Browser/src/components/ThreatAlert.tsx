import { useEffect, useState } from "react";

type ThreatAlertProps = {
  threat: {
    url?: string;
    risk?: number;
  };
};

export default function ThreatAlert({ threat }: ThreatAlertProps) {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setVisible(false);
    }, 8000);

    return () => clearTimeout(timer);
  }, []);

  if (!visible) {
    return null;
  }

  return (
    <div className="bg-red-600 text-white p-4 rounded-lg mb-4 animate-pulse">
      🚨 Threat Blocked
      <div className="text-sm mt-1 break-all">
        URL: {threat?.url || "Unknown URL"}
      </div>
      <div className="text-sm">
        Risk Score: {Number(threat?.risk ?? 0)}
      </div>
    </div>
  );
}
