import { motion } from "framer-motion";
import { Brain, Eye, Globe, Shield, Workflow, MousePointerClick } from "lucide-react";

const steps = [
  {
    icon: Globe,
    title: "1. Page Context Collection",
    desc: "The extension and scanner capture URL, DOM/UI context, visible text, and target page metadata.",
  },
  {
    icon: Eye,
    title: "2. Signal Extraction",
    desc: "Domain intelligence, UI deception checks, obfuscation analysis, and prompt-injection heuristics generate signals.",
  },
  {
    icon: Brain,
    title: "3. Risk Computation",
    desc: "ML scoring, semantic reasoning, trust signals, and threat intelligence combine into a weighted risk score.",
  },
  {
    icon: Workflow,
    title: "4. Policy Decision",
    desc: "The policy engine converts that score into Allow, Warn, Block, or confirmation-gated action flow.",
  },
  {
    icon: MousePointerClick,
    title: "5. Action Mediation",
    desc: "If the agent wants to click, type, or navigate, the action mediator revalidates the step against user intent.",
  },
  {
    icon: Shield,
    title: "6. Audit + Replay",
    desc: "Scans, reasons, actions, and timings are persisted for dashboard review and incident analysis.",
  },
];

const HowItWorks = () => {
  return (
    <section id="how-it-works" className="py-24">
      <div className="container mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="mb-16 text-center"
        >
          <span className="mb-4 block font-mono text-sm uppercase tracking-[0.22em] text-primary/80">Execution Flow</span>
          <h2 className="text-3xl font-bold md:text-4xl">How The Runtime Actually Works</h2>
          <p className="mx-auto mt-4 max-w-3xl text-muted-foreground">
            This is the real processing path used by the system: collect context, score risk,
            enforce policy, mediate actions, and persist evidence.
          </p>
        </motion.div>

        <div className="grid gap-4 lg:grid-cols-2">
          {steps.map((step, index) => (
            <motion.div
              key={step.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.06 }}
              className="glass rounded-[24px] border border-border/80 p-6"
            >
              <div className="flex items-start gap-4">
                <div className="rounded-2xl border border-primary/30 bg-primary/10 p-3">
                  <step.icon className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold">{step.title}</h3>
                  <p className="mt-2 text-sm leading-7 text-muted-foreground">{step.desc}</p>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default HowItWorks;
