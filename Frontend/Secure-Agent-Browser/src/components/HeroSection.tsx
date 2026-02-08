import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import heroBg from "@/assets/hero-bg.jpg";

const HeroSection = () => {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0">
        <img src={heroBg} alt="" className="w-full h-full object-cover opacity-30" />
        <div className="absolute inset-0 bg-gradient-to-b from-background/60 via-background/80 to-background" />
        <div className="absolute inset-0 cyber-grid opacity-30" />
      </div>

      {/* Scan line effect */}
      <div className="absolute inset-0 scan-line pointer-events-none" />

      <div className="relative z-10 container mx-auto px-6 text-center">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
        >
          <div className="inline-flex items-center gap-2 glass rounded-full px-4 py-2 mb-8">
            <span className="w-2 h-2 rounded-full bg-cyber-safe animate-pulse-glow" />
            <span className="font-mono text-xs text-muted-foreground">SYSTEM ACTIVE — MONITORING ENABLED</span>
          </div>

          <h1 className="text-4xl md:text-6xl lg:text-7xl font-bold mb-6 leading-tight">
            <span className="text-gradient-cyber">Secure Agent</span>
            <br />
            <span className="text-foreground">Browser</span>
          </h1>

          <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-4">
            AI-Driven Protection Against Malicious Web Content
          </p>
          <p className="text-sm text-muted-foreground/70 font-mono max-w-xl mx-auto mb-10">
            Think Before You Click — Secure Agent Decides
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              to="/dashboard"
              className="px-8 py-3 rounded-xl bg-primary text-primary-foreground font-semibold hover:opacity-90 transition-opacity glow-primary"
            >
              View Dashboard
            </Link>
            <Link
              to="/scan"
              className="px-8 py-3 rounded-xl glass text-foreground font-semibold hover:border-primary/40 transition-colors"
            >
              Scan a URL
            </Link>
            <a
              href="#how-it-works"
              className="px-8 py-3 rounded-xl text-muted-foreground font-semibold hover:text-primary transition-colors"
            >
              How It Works ↓
            </a>
          </div>
        </motion.div>

        {/* Floating risk indicators */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1, duration: 1 }}
          className="mt-20 flex items-center justify-center gap-8 flex-wrap"
        >
          {[
            { label: "Threats Blocked", value: "1,247", color: "text-cyber-danger" },
            { label: "Pages Scanned", value: "15,832", color: "text-primary" },
            { label: "Safe Passages", value: "14,585", color: "text-cyber-safe" },
          ].map((stat) => (
            <div key={stat.label} className="glass rounded-xl px-6 py-4 text-center min-w-[140px]">
              <p className={`font-mono text-2xl font-bold ${stat.color}`}>{stat.value}</p>
              <p className="text-xs text-muted-foreground mt-1">{stat.label}</p>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
};

export default HeroSection;
