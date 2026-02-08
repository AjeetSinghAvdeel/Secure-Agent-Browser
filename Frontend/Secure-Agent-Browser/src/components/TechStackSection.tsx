import { motion } from "framer-motion";

const stack = [
  { name: "Python", desc: "Core engine" },
  { name: "Selenium", desc: "Browser automation" },
  { name: "BeautifulSoup", desc: "HTML parsing" },
  { name: "Scikit-learn", desc: "ML classification" },
  { name: "Naive Bayes", desc: "Text analysis model" },
  { name: "Chrome WebDriver", desc: "Headless browser" },
  { name: "HTML / CSS / JS", desc: "Frontend stack" },
  { name: "React + Vite", desc: "Dashboard UI" },
];

const TechStackSection = () => {
  return (
    <section id="tech-stack" className="py-24 relative">
      <div className="container mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <span className="font-mono text-sm text-primary mb-4 block">// STACK</span>
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Technology Stack</h2>
        </motion.div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-3xl mx-auto">
          {stack.map((tech, i) => (
            <motion.div
              key={tech.name}
              initial={{ opacity: 0, scale: 0.9 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.05 }}
              className="glass rounded-xl p-5 text-center hover:border-primary/40 transition-colors"
            >
              <p className="font-mono font-semibold text-sm mb-1">{tech.name}</p>
              <p className="text-xs text-muted-foreground">{tech.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default TechStackSection;
