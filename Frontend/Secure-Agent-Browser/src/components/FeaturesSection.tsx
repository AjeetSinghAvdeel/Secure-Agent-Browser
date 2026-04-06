import { motion } from "framer-motion";
import { Brain, Eye, ShieldAlert, MousePointerSquareDashed, Gauge, FileClock } from "lucide-react";

const features = [
  {
    icon: Eye,
    title: "DOM + UI Deception Analysis",
    desc: "Catches hidden overlays, misleading forms, clickjacking patterns, overlapping elements, and dynamic UI injections.",
  },
  {
    icon: Brain,
    title: "Hybrid Detection Stack",
    desc: "Uses heuristic signals, ML classification, semantic scoring, and threat-intel lookups instead of relying on one detector.",
  },
  {
    icon: Gauge,
    title: "Transparent Risk Breakdown",
    desc: "Produces a 0-100 score and an explanation payload so the dashboard can show why a page was blocked or warned.",
  },
  {
    icon: ShieldAlert,
    title: "Policy Enforcement",
    desc: "Risk is not just displayed. The policy layer actively allows, warns, blocks, or requires confirmation before continuation.",
  },
  {
    icon: MousePointerSquareDashed,
    title: "Agent Action Mediation",
    desc: "The system re-checks proposed clicks and typed actions against context to stop prompt-injection-driven workflows.",
  },
  {
    icon: FileClock,
    title: "Persistent Audit Trail",
    desc: "Every scan and mediated action can be surfaced later in history views for review, evidence, and debugging.",
  },
];

const FeaturesSection = () => {
  return (
    <section id="features" className="py-24">
      <div className="container mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="mb-16 text-center"
        >
          <span className="mb-4 block font-mono text-sm uppercase tracking-[0.22em] text-primary/80">Capabilities</span>
          <h2 className="text-3xl font-bold md:text-4xl">Operational Features</h2>
          <p className="mx-auto mt-4 max-w-3xl text-muted-foreground">
            These are the concrete protections and runtime behaviors implemented in the current system.
          </p>
        </motion.div>

        <div className="grid gap-6 lg:grid-cols-3">
          {features.map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.06 }}
              className="glass rounded-[24px] border border-border/80 p-6 transition-colors hover:border-primary/35"
            >
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-primary/25 bg-primary/10">
                <feature.icon className="h-5 w-5 text-primary" />
              </div>
              <h3 className="mt-5 text-lg font-semibold">{feature.title}</h3>
              <p className="mt-3 text-sm leading-7 text-muted-foreground">{feature.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
