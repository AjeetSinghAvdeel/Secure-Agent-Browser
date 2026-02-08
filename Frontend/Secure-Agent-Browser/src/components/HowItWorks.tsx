import { motion } from "framer-motion";
import { Shield, Eye, Brain, AlertTriangle, Lock, CheckCircle } from "lucide-react";

const steps = [
  {
    icon: Globe,
    title: "Page Loaded",
    desc: "Automated secure browser loads the target URL in a sandboxed environment via Selenium.",
  },
  {
    icon: Eye,
    title: "DOM Monitoring",
    desc: "Live DOM changes are tracked over time to catch delayed injections and dynamic threats.",
  },
  {
    icon: Brain,
    title: "Multi-Layer Analysis",
    desc: "Content analyzed for prompt injection, phishing forms, clickjacking, and suspicious intent.",
  },
  {
    icon: AlertTriangle,
    title: "Risk Scoring",
    desc: "Hybrid ML + LLM reasoning produces a risk score from 0–100 with full explainability.",
  },
  {
    icon: Shield,
    title: "Decision Enforcement",
    desc: "System enforces Allow, Warn, or Block — replacing malicious pages with a security notice.",
  },
];

import { Globe } from "lucide-react";

const HowItWorks = () => {
  return (
    <section id="how-it-works" className="py-24 relative">
      <div className="container mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <span className="font-mono text-sm text-primary mb-4 block">// SYSTEM FLOW</span>
          <h2 className="text-3xl md:text-4xl font-bold mb-4">How It Works</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            A five-stage pipeline that intercepts, analyzes, and acts on web threats before they reach the user.
          </p>
        </motion.div>

        <div className="relative max-w-3xl mx-auto">
          {/* Vertical line */}
          <div className="absolute left-8 top-0 bottom-0 w-px bg-gradient-to-b from-primary/0 via-primary/40 to-primary/0 hidden md:block" />

          <div className="space-y-8">
            {steps.map((step, i) => (
              <motion.div
                key={step.title}
                initial={{ opacity: 0, x: -30 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="flex gap-6 items-start"
              >
                <div className="relative z-10 shrink-0 w-16 h-16 rounded-xl glass flex items-center justify-center border-primary/30">
                  <step.icon className="w-6 h-6 text-primary" />
                  <span className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-primary text-primary-foreground text-xs font-mono font-bold flex items-center justify-center">
                    {i + 1}
                  </span>
                </div>
                <div className="glass rounded-xl p-6 flex-1">
                  <h3 className="font-semibold text-lg mb-1">{step.title}</h3>
                  <p className="text-sm text-muted-foreground">{step.desc}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Decision outcomes */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-4 max-w-3xl mx-auto"
        >
          <div className="glass rounded-xl p-5 border-cyber-safe/30 text-center">
            <CheckCircle className="w-8 h-8 text-cyber-safe mx-auto mb-2" />
            <h4 className="font-semibold text-cyber-safe">Allow</h4>
            <p className="text-xs text-muted-foreground mt-1">Score &lt; 30 — Safe to access</p>
          </div>
          <div className="glass rounded-xl p-5 border-cyber-warning/30 text-center">
            <AlertTriangle className="w-8 h-8 text-cyber-warning mx-auto mb-2" />
            <h4 className="font-semibold text-cyber-warning">Warn</h4>
            <p className="text-xs text-muted-foreground mt-1">Score 30–70 — User confirmation</p>
          </div>
          <div className="glass rounded-xl p-5 border-cyber-danger/30 text-center">
            <Lock className="w-8 h-8 text-cyber-danger mx-auto mb-2" />
            <h4 className="font-semibold text-cyber-danger">Block</h4>
            <p className="text-xs text-muted-foreground mt-1">Score &gt; 70 — Access denied</p>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default HowItWorks;
