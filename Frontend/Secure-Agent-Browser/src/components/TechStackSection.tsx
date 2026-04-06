import { motion } from "framer-motion";

const stack = [
  { name: "FastAPI", desc: "Backend API and orchestration" },
  { name: "Firebase Auth", desc: "Google sign-in and session bridge" },
  { name: "Firestore", desc: "Scans and action audit persistence" },
  { name: "Selenium", desc: "Controlled browser runtime" },
  { name: "Scikit-learn", desc: "ML signal generation" },
  { name: "Policy Engine", desc: "Decision enforcement" },
  { name: "React + Vite", desc: "Dashboard and landing UI" },
  { name: "Framer Motion", desc: "Activity and section animation" },
];

const TechStackSection = () => {
  return (
    <section id="tech-stack" className="py-24">
      <div className="container mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="mb-16 text-center"
        >
          <span className="mb-4 block font-mono text-sm uppercase tracking-[0.22em] text-primary/80">Services + Stack</span>
          <h2 className="text-3xl font-bold md:text-4xl">Runtime Services In Use</h2>
          <p className="mx-auto mt-4 max-w-3xl text-muted-foreground">
            The product surface is built directly from the same services used in scanning,
            persistence, authentication, and dashboard telemetry.
          </p>
        </motion.div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {stack.map((tech, index) => (
            <motion.div
              key={tech.name}
              initial={{ opacity: 0, scale: 0.96 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.04 }}
              className="glass rounded-[22px] border border-border/80 p-5"
            >
              <p className="font-mono text-sm font-semibold">{tech.name}</p>
              <p className="mt-2 text-sm text-muted-foreground">{tech.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default TechStackSection;
