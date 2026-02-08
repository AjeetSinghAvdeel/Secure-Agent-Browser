import { Link } from "react-router-dom";

const Footer = () => {
  return (
    <footer className="border-t border-border py-12">
      <div className="container mx-auto px-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <div className="w-6 h-6 rounded bg-primary/20 border border-primary/40 flex items-center justify-center">
                <svg className="w-4 h-4 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              </div>
              <span className="font-mono text-sm text-foreground">Secure<span className="text-primary">Agent</span></span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              AI-powered browser security system that analyzes web pages in real time.
            </p>
          </div>

          <div>
            <h4 className="font-mono text-xs text-muted-foreground mb-3">NAVIGATION</h4>
            <div className="space-y-2">
              <Link to="/" className="block text-sm text-muted-foreground hover:text-primary transition-colors">Home</Link>
              <Link to="/dashboard" className="block text-sm text-muted-foreground hover:text-primary transition-colors">Dashboard</Link>
              <Link to="/scan" className="block text-sm text-muted-foreground hover:text-primary transition-colors">Scan URL</Link>
            </div>
          </div>

          <div>
            <h4 className="font-mono text-xs text-muted-foreground mb-3">SECTIONS</h4>
            <div className="space-y-2">
              <a href="/#how-it-works" className="block text-sm text-muted-foreground hover:text-primary transition-colors">How It Works</a>
              <a href="/#features" className="block text-sm text-muted-foreground hover:text-primary transition-colors">Features</a>
              <a href="/#tech-stack" className="block text-sm text-muted-foreground hover:text-primary transition-colors">Tech Stack</a>
            </div>
          </div>

          <div>
            <h4 className="font-mono text-xs text-muted-foreground mb-3">PROJECT</h4>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Academic / Research / Security Tool
            </p>
            <p className="text-xs text-muted-foreground mt-2 font-mono">v1.0.0</p>
          </div>
        </div>

        <div className="border-t border-border pt-6">
          <p className="text-xs text-muted-foreground text-center">
            For educational and defensive security research purposes only. This is an academic research project demonstrating AI-powered web security analysis.
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
