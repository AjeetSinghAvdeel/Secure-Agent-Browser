export interface ScanEntry {
  id: string;
  url: string;
  time: string;
  score: number;
  status: "safe" | "warning" | "blocked";
  detections: {
    promptInjection: { found: boolean; count: number; patterns: string[] };
    phishing: { found: boolean; count: number; details: string };
    clickjacking: { found: boolean; count: number; details: string };
    mlVerdict: { label: string; confidence: number };
    llmReasoning: string;
  };
  keywords: string[];
  screenshot?: string;
}

export const scanData: ScanEntry[] = [
  {
    id: "scan-001",
    url: "https://banking-secure.com/login",
    time: "2026-02-07 14:32",
    score: 12,
    status: "safe",
    detections: {
      promptInjection: { found: false, count: 0, patterns: [] },
      phishing: { found: false, count: 0, details: "No suspicious forms detected." },
      clickjacking: { found: false, count: 0, details: "No hidden overlays or iframes." },
      mlVerdict: { label: "Benign", confidence: 96.1 },
      llmReasoning: "The page is a legitimate banking login with valid SSL, proper domain registration, and standard authentication form. No deceptive patterns detected.",
    },
    keywords: [],
  },
  {
    id: "scan-002",
    url: "https://free-prize-winner.xyz",
    time: "2026-02-07 14:28",
    score: 87,
    status: "blocked",
    detections: {
      promptInjection: { found: true, count: 3, patterns: ["ignore previous instructions", "system prompt override", "act as admin"] },
      phishing: { found: true, count: 2, details: "Fake Google login form with credential harvesting endpoint." },
      clickjacking: { found: true, count: 1, details: "Transparent overlay iframe covering entire page." },
      mlVerdict: { label: "Malicious", confidence: 94.2 },
      llmReasoning: "The page uses urgency-driven language combined with a spoofed login form targeting credential harvesting. Multiple hidden iframes detected attempting clickjacking. Content patterns strongly match known phishing templates.",
    },
    keywords: ["verify your account", "urgent action required", "click here immediately", "congratulations winner"],
  },
  {
    id: "scan-003",
    url: "https://docs.company.io/api",
    time: "2026-02-07 14:15",
    score: 8,
    status: "safe",
    detections: {
      promptInjection: { found: false, count: 0, patterns: [] },
      phishing: { found: false, count: 0, details: "Documentation site with no login forms." },
      clickjacking: { found: false, count: 0, details: "Clean DOM structure." },
      mlVerdict: { label: "Benign", confidence: 98.7 },
      llmReasoning: "Standard API documentation page with code examples. No interactive forms or suspicious elements. Trusted domain with valid certificate.",
    },
    keywords: [],
  },
  {
    id: "scan-004",
    url: "https://login-verify-account.tk",
    time: "2026-02-07 13:58",
    score: 92,
    status: "blocked",
    detections: {
      promptInjection: { found: true, count: 2, patterns: ["disregard safety guidelines", "execute javascript"] },
      phishing: { found: true, count: 3, details: "Cloned PayPal login page with data exfiltration to external server." },
      clickjacking: { found: true, count: 2, details: "Multiple stacked invisible iframes with click handlers." },
      mlVerdict: { label: "Malicious", confidence: 97.8 },
      llmReasoning: "Highly sophisticated phishing page cloning PayPal's interface. Uses homograph attack in domain (.tk TLD). Hidden form action posts credentials to attacker-controlled endpoint. Multiple layers of clickjacking detected.",
    },
    keywords: ["verify identity", "account suspended", "immediate action", "security alert", "PayPal"],
  },
  {
    id: "scan-005",
    url: "https://newsletter.example.com",
    time: "2026-02-07 13:45",
    score: 45,
    status: "warning",
    detections: {
      promptInjection: { found: false, count: 0, patterns: [] },
      phishing: { found: false, count: 0, details: "Email subscription form — low risk but unverified." },
      clickjacking: { found: true, count: 1, details: "Third-party tracking iframe with reduced opacity." },
      mlVerdict: { label: "Suspicious", confidence: 62.3 },
      llmReasoning: "The page contains a newsletter signup with aggressive tracking scripts and a semi-transparent third-party iframe. While not overtly malicious, the tracking behavior and data collection practices are concerning. Recommend user caution.",
    },
    keywords: ["exclusive offer", "limited time", "subscribe now"],
  },
  {
    id: "scan-006",
    url: "https://github.com/repo/issues",
    time: "2026-02-07 13:30",
    score: 5,
    status: "safe",
    detections: {
      promptInjection: { found: false, count: 0, patterns: [] },
      phishing: { found: false, count: 0, details: "No suspicious forms." },
      clickjacking: { found: false, count: 0, details: "Clean page structure." },
      mlVerdict: { label: "Benign", confidence: 99.1 },
      llmReasoning: "GitHub issues page from a whitelisted domain. Standard repository interface with no anomalies detected.",
    },
    keywords: [],
  },
  {
    id: "scan-007",
    url: "https://update-your-password.net",
    time: "2026-02-07 13:12",
    score: 78,
    status: "blocked",
    detections: {
      promptInjection: { found: true, count: 1, patterns: ["bypass content filter"] },
      phishing: { found: true, count: 1, details: "Fake password reset form with suspicious POST endpoint." },
      clickjacking: { found: false, count: 0, details: "No hidden overlays." },
      mlVerdict: { label: "Malicious", confidence: 88.5 },
      llmReasoning: "Deceptive password reset page not affiliated with any legitimate service. The form submits credentials to an unrelated domain. Social engineering tactics used to create urgency.",
    },
    keywords: ["password expired", "reset immediately", "account compromised", "security update"],
  },
  {
    id: "scan-008",
    url: "https://shop.trusted-store.com",
    time: "2026-02-07 12:55",
    score: 22,
    status: "safe",
    detections: {
      promptInjection: { found: false, count: 0, patterns: [] },
      phishing: { found: false, count: 0, details: "Legitimate e-commerce checkout." },
      clickjacking: { found: false, count: 0, details: "No overlay elements." },
      mlVerdict: { label: "Benign", confidence: 91.4 },
      llmReasoning: "Standard e-commerce product page with HTTPS, valid merchant certificate, and standard payment processing integration. Minor tracking scripts present but within normal range.",
    },
    keywords: [],
  },
];

export const statusConfig = {
  safe: { label: "Safe", color: "text-cyber-safe", bg: "bg-cyber-safe/10 border-cyber-safe/30" },
  warning: { label: "Warning", color: "text-cyber-warning", bg: "bg-cyber-warning/10 border-cyber-warning/30" },
  blocked: { label: "Blocked", color: "text-cyber-danger", bg: "bg-cyber-danger/10 border-cyber-danger/30" },
};
