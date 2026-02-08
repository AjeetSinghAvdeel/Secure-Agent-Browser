import { motion } from "framer-motion";
import { Brain, Eye, Gauge, UserCheck, Camera, ShieldCheck } from "lucide-react";

const features = [
  {
    icon: Brain,
    title: "Hybrid AI Detection",
    desc: "Combines rule-based patterns, ML classification (Naive Bayes), and simulated LLM reasoning for maximum coverage.",
  },
  {
    icon: Eye,
    title: "Live DOM Monitoring",
    desc: "Continuously tracks DOM mutations to catch delayed script injections and dynamic content manipulation.",
  },
  {
    icon: Gauge,
    title: "Risk Scoring Engine",
    desc: "Produces a 0–100 risk score with weighted contributions from each detection layer for transparent decisions.",
  },
  {
    icon: UserCheck,
    title: "User Confirmation System",
    desc: "Medium-risk pages trigger a human-in-the-loop confirmation step before granting access.",
  },
  {
    icon: Camera,
    title: "Screenshot Evidence",
    desc: "Captures page screenshots at scan time for forensic logging and post-incident review.",
  },
  {
    icon: ShieldCheck,
    title: "Whitelist Trusted Domains",
    desc: "Maintain a curated list of trusted domains that bypass analysis for faster, seamless access.",
  },
];

const FeaturesSection = () => {
  return (
    <section id="features" className="py-24 relative">
      <div className="container mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <span className="font-mono text-sm text-primary mb-4 block">// CAPABILITIES</span>
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Core Features</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Built for depth and precision — every layer adds to the system's ability to detect and explain threats.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-5xl mx-auto">
          {features.map((f, i) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.08 }}
              className="glass rounded-xl p-6 group hover:border-primary/40 transition-colors"
            >
              <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4 group-hover:glow-primary transition-shadow">
                <f.icon className="w-6 h-6 text-primary" />
              </div>
              <h3 className="font-semibold mb-2">{f.title}</h3>
              <p className="text-sm text-muted-foreground">{f.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
