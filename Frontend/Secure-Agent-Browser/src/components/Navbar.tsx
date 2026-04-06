import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Menu, X, User, ShieldCheck, LayoutDashboard, ScanSearch, LogOut, ChevronDown, KeyRound } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const getInitials = (email: string) =>
  email
    .split("@")[0]
    .split(/[.\-_]/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || "")
    .join("") || "SA";

const roleLabels = {
  user: "Standard user",
  admin: "Administrator",
  researcher: "Researcher",
} as const;

const Navbar = () => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const isLanding = location.pathname === "/";
  const { user, logout, setPassword } = useAuth();

  const scrollLinks = [
    { label: "System", href: "#gallery" },
    { label: "Live Ops", href: "#live-ops" },
    { label: "How It Works", href: "#how-it-works" },
    { label: "Features", href: "#features" },
    { label: "Tech Stack", href: "#tech-stack" },
  ];

  const handleAnchorClick = (e: React.MouseEvent<HTMLAnchorElement>, href: string) => {
    if (isLanding) {
      e.preventDefault();
      const el = document.querySelector(href);
      if (el) el.scrollIntoView({ behavior: "smooth" });
    }
    setMobileOpen(false);
  };

  const handleEnablePasswordLogin = async () => {
    if (!user) return;

    const password = window.prompt("Set a password for email login. Use 8 to 72 characters.");
    if (!password) return;

    const confirmPassword = window.prompt("Re-enter the password to confirm it.");
    if (confirmPassword === null) return;

    if (password !== confirmPassword) {
      window.alert("Passwords did not match. Try again.");
      return;
    }

    try {
      await setPassword(password);
      window.alert(`Password login is now enabled for ${user.email}.`);
    } catch (error) {
      window.alert(error instanceof Error ? error.message : "Unable to set password.");
    }
  };

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 glass">
      <div className="container mx-auto px-6 h-16 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/40 flex items-center justify-center glow-primary">
            <svg className="w-5 h-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <span className="font-mono font-bold text-foreground">Secure<span className="text-primary">Agent</span></span>
        </Link>

        {/* Desktop nav */}
        <div className="hidden md:flex items-center gap-8">
          {scrollLinks.map((link) => (
            <a
              key={link.href}
              href={isLanding ? link.href : `/${link.href}`}
              onClick={(e) => handleAnchorClick(e, link.href)}
              className="text-sm text-muted-foreground hover:text-primary transition-colors"
            >
              {link.label}
            </a>
          ))}
          <Link to="/scan" className="text-sm text-muted-foreground hover:text-primary transition-colors">
            Scan URL
          </Link>
          <Link
            to="/dashboard"
            className="text-sm text-muted-foreground hover:text-primary transition-colors"
          >
            View Dashboard
          </Link>
          {user ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  className="flex items-center gap-3 rounded-full border border-primary/20 bg-background/60 px-2.5 py-1.5 text-left transition-colors hover:border-primary/40 hover:bg-primary/5"
                >
                  <Avatar className="h-9 w-9 border border-primary/25 bg-primary/10">
                    <AvatarFallback className="bg-primary/15 text-xs font-semibold text-primary">
                      {getInitials(user.email)}
                    </AvatarFallback>
                  </Avatar>
                  <div className="min-w-0">
                    <p className="max-w-[180px] truncate text-sm font-medium text-foreground">
                      {user.email.split("@")[0]}
                    </p>
                    <p className="text-[11px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
                      {user.role}
                    </p>
                  </div>
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-80 border-primary/15 bg-background/95 p-2 backdrop-blur-xl">
                <DropdownMenuLabel className="px-3 py-3">
                  <div className="flex items-start gap-3">
                    <Avatar className="h-11 w-11 border border-primary/25 bg-primary/10">
                      <AvatarFallback className="bg-primary/15 text-sm font-semibold text-primary">
                        {getInitials(user.email)}
                      </AvatarFallback>
                    </Avatar>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-semibold text-foreground">{user.email}</p>
                      <p className="mt-1 text-xs text-muted-foreground">{roleLabels[user.role]}</p>
                      <div className="mt-3 grid grid-cols-2 gap-2 text-[11px]">
                        <div className="rounded-lg border border-border/70 bg-secondary/30 px-2.5 py-2">
                          <p className="font-mono uppercase tracking-wide text-muted-foreground">Role</p>
                          <p className="mt-1 font-medium text-foreground">{user.role}</p>
                        </div>
                        <div className="rounded-lg border border-border/70 bg-secondary/30 px-2.5 py-2">
                          <p className="font-mono uppercase tracking-wide text-muted-foreground">Password</p>
                          <p className="mt-1 font-medium text-foreground">
                            {user.has_password ? "Enabled" : "Google only"}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link to="/dashboard" className="flex items-center gap-2">
                    <LayoutDashboard className="h-4 w-4" />
                    Dashboard
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <Link to="/scan" className="flex items-center gap-2">
                    <ScanSearch className="h-4 w-4" />
                    Scan center
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => {
                    void navigator.clipboard?.writeText(user.email);
                  }}
                  className="flex items-center gap-2"
                >
                  <User className="h-4 w-4" />
                  Copy email
                </DropdownMenuItem>
                <DropdownMenuItem className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4" />
                  Security posture: protected
                </DropdownMenuItem>
                {!user.has_password && (
                  <DropdownMenuItem
                    onClick={handleEnablePasswordLogin}
                    className="flex items-center gap-2"
                  >
                    <KeyRound className="h-4 w-4" />
                    Enable password login
                  </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={logout}
                  className="flex items-center gap-2 text-cyber-danger focus:text-cyber-danger"
                >
                  <LogOut className="h-4 w-4" />
                  Logout
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <Link
              to="/login"
              className="text-sm font-medium bg-primary/10 text-primary border border-primary/30 px-4 py-2 rounded-lg hover:bg-primary/20 transition-colors"
            >
              Login
            </Link>
          )}
        </div>

        {/* Mobile toggle */}
        <button
          className="md:hidden text-foreground p-2"
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle menu"
        >
          {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="md:hidden glass border-t border-border px-6 py-4 space-y-3">
          {scrollLinks.map((link) => (
            <a
              key={link.href}
              href={isLanding ? link.href : `/${link.href}`}
              onClick={(e) => handleAnchorClick(e, link.href)}
              className="block text-sm text-muted-foreground hover:text-primary transition-colors py-2"
            >
              {link.label}
            </a>
          ))}
          <Link
            to="/scan"
            onClick={() => setMobileOpen(false)}
            className="block text-sm text-muted-foreground hover:text-primary transition-colors py-2"
          >
            Scan URL
          </Link>
          <Link
            to="/dashboard"
            onClick={() => setMobileOpen(false)}
            className="block text-sm text-muted-foreground hover:text-primary transition-colors py-2"
          >
            View Dashboard
          </Link>
          {user ? (
            <>
              <div className="rounded-xl border border-border bg-background/40 px-4 py-3">
                <div className="flex items-center gap-3">
                  <Avatar className="h-10 w-10 border border-primary/25 bg-primary/10">
                    <AvatarFallback className="bg-primary/15 text-xs font-semibold text-primary">
                      {getInitials(user.email)}
                    </AvatarFallback>
                  </Avatar>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{user.email}</p>
                    <p className="text-[11px] font-mono uppercase tracking-wide text-muted-foreground">
                      {roleLabels[user.role]}
                    </p>
                  </div>
                </div>
                <div className="mt-3 grid grid-cols-2 gap-2 text-[11px]">
                  <div className="rounded-lg border border-border/70 bg-secondary/30 px-3 py-2">
                    <p className="font-mono uppercase tracking-wide text-muted-foreground">Role</p>
                    <p className="mt-1 font-medium text-foreground">{user.role}</p>
                  </div>
                  <div className="rounded-lg border border-border/70 bg-secondary/30 px-3 py-2">
                    <p className="font-mono uppercase tracking-wide text-muted-foreground">Password</p>
                    <p className="mt-1 font-medium text-foreground">
                      {user.has_password ? "Enabled" : "Google only"}
                    </p>
                  </div>
                </div>
              </div>
              {!user.has_password && (
                <button
                  type="button"
                  onClick={() => {
                    void handleEnablePasswordLogin();
                    setMobileOpen(false);
                  }}
                  className="block w-full rounded-lg border border-primary/30 bg-primary/10 px-4 py-2 text-sm text-primary transition-colors hover:bg-primary/20"
                >
                  Enable password login
                </button>
              )}
              <button
                type="button"
                onClick={() => {
                  void navigator.clipboard?.writeText(user.email);
                  setMobileOpen(false);
                }}
                className="block w-full rounded-lg border border-border bg-background/40 px-4 py-2 text-sm text-foreground transition-colors hover:border-primary/30 hover:text-primary"
              >
                Copy email
              </button>
              <button
                type="button"
                onClick={() => {
                  logout();
                  setMobileOpen(false);
                }}
                className="block w-full text-sm font-medium bg-primary/10 text-primary border border-primary/30 px-4 py-2 rounded-lg hover:bg-primary/20 transition-colors text-center"
              >
                Logout
              </button>
            </>
          ) : (
            <Link
              to="/login"
              onClick={() => setMobileOpen(false)}
              className="block text-sm font-medium bg-primary/10 text-primary border border-primary/30 px-4 py-2 rounded-lg hover:bg-primary/20 transition-colors text-center"
            >
              Login
            </Link>
          )}
        </div>
      )}
    </nav>
  );
};

export default Navbar;
