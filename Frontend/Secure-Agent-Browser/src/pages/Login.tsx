import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { AlertTriangle, Chrome, Loader2, Shield } from "lucide-react";

import Footer from "@/components/Footer";
import Navbar from "@/components/Navbar";
import { useAuth } from "@/context/AuthContext";

const Login = () => {
  const { login, register, loginWithGoogle } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<"user" | "admin" | "researcher">("user");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const emailAutoComplete = mode === "login" ? "username" : "off";
  const passwordAutoComplete = mode === "login" ? "current-password" : "new-password";

  const redirectPath =
    (location.state as { from?: { pathname?: string } } | null)?.from?.pathname || "/dashboard";

  const describeAuthError = (message: string) => {
    const normalized = message.toLowerCase();

    if (normalized.includes("at least 8 characters")) {
      return {
        title: "Password Too Short",
        detail: "Your password must be at least 8 characters long.",
        hint: "Try a longer password and submit again.",
        technical: message,
      };
    }

    if (normalized.includes("user already exists")) {
      return {
        title: "Account Already Exists",
        detail: "An account with this email already exists.",
        hint: "Use Login instead, or choose a different email address.",
        technical: message,
      };
    }

    if (normalized.includes("invalid credentials")) {
      return {
        title: "Credentials Rejected",
        detail: "The email or password you entered was not accepted.",
        hint: "Check your email and password, then try again.",
        technical: message,
      };
    }

    if (normalized.includes("admin and researcher accounts")) {
      return {
        title: "Role Not Available",
        detail: "This sign-up form can only create a standard user account.",
        hint: "Select user, or ask an administrator to provision an elevated role.",
        technical: message,
      };
    }

    if (normalized.includes("secureagent backend")) {
      return {
        title: "Connection Problem",
        detail: "We could not connect to SecureAgent right now.",
        hint: "Please try again in a moment. If the problem continues, check that the backend service is running.",
        technical: message,
      };
    }

    if (normalized.includes("google")) {
      return {
        title: "Google Sign-In Failed",
        detail: "Google sign-in could not be completed.",
        hint: "Enable Google in Firebase Authentication and make sure localhost is listed as an authorized domain.",
        technical: message,
      };
    }

    return {
      title: "Authentication Failed",
      detail: "We could not complete your request.",
      hint: "Review the input and backend logs, then try again.",
      technical: message,
    };
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        await register(email, password, role);
      }
      navigate(redirectPath, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    setLoading(true);
    setError(null);

    try {
      await loginWithGoogle();
      navigate(redirectPath, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Google sign-in failed");
    } finally {
      setLoading(false);
    }
  };

  const errorInfo = error ? describeAuthError(error) : null;

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <div className="pt-24 pb-16 px-6">
        <div className="max-w-md mx-auto glass rounded-2xl p-8">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-11 h-11 rounded-xl bg-primary/15 border border-primary/30 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">
                {mode === "login" ? "SecureAgent Login" : "Create Account"}
              </h1>
              <p className="text-sm text-muted-foreground font-mono">
                JWT session access for dashboard and extension
              </p>
            </div>
          </div>

          <div className="flex gap-2 mb-6">
            <button
              type="button"
              onClick={() => setMode("login")}
              className={`flex-1 rounded-lg border px-4 py-2 text-sm font-medium transition-colors ${
                mode === "login"
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground"
              }`}
            >
              Login
            </button>
            <button
              type="button"
              onClick={() => setMode("register")}
              className={`flex-1 rounded-lg border px-4 py-2 text-sm font-medium transition-colors ${
                mode === "register"
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground"
              }`}
            >
              Register
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4" autoComplete="off">
            <div>
              <label className="block text-xs font-mono text-muted-foreground mb-2">
                Email
              </label>
              <input
                type="email"
                name={mode === "login" ? "login_email" : "register_email"}
                className="w-full rounded-lg border border-border bg-background/70 px-4 py-3 outline-none focus:border-primary/50"
                placeholder="analyst@secureagent.dev"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                autoComplete={emailAutoComplete}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                required
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-muted-foreground mb-2">
                Password
              </label>
              <input
                type="password"
                name={mode === "login" ? "login_password" : "register_password"}
                className="w-full rounded-lg border border-border bg-background/70 px-4 py-3 outline-none focus:border-primary/50"
                placeholder="Minimum 8 characters"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete={passwordAutoComplete}
                spellCheck={false}
                required
              />
            </div>

            {mode === "register" && (
              <div>
                <label className="block text-xs font-mono text-muted-foreground mb-2">
                  Role
                </label>
                <select
                  className="w-full rounded-lg border border-border bg-background/70 px-4 py-3 outline-none focus:border-primary/50"
                  value={role}
                  onChange={(event) =>
                    setRole(event.target.value as "user" | "admin" | "researcher")
                  }
                >
                  <option value="user">user</option>
                  <option value="researcher">researcher (admin provisioned)</option>
                  <option value="admin">admin (admin provisioned)</option>
                </select>
              </div>
            )}

            {errorInfo && (
              <div className="rounded-xl border border-cyber-danger/30 bg-cyber-danger/10 p-4">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-4 h-4 text-cyber-danger mt-0.5 shrink-0" />
                  <div className="space-y-1">
                    <p className="text-sm font-semibold text-cyber-danger">{errorInfo.title}</p>
                    <p className="text-sm text-foreground/90">{errorInfo.detail}</p>
                    <p className="text-xs font-mono text-muted-foreground">{errorInfo.hint}</p>
                    <details className="pt-1">
                      <summary className="cursor-pointer text-xs font-mono text-muted-foreground">
                        Technical details
                      </summary>
                      <p className="mt-2 text-xs font-mono text-muted-foreground break-words">
                        {errorInfo.technical}
                      </p>
                    </details>
                  </div>
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-primary px-4 py-3 text-sm font-medium text-primary-foreground"
            >
              {loading ? (
                <span className="inline-flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Processing
                </span>
              ) : mode === "login" ? (
                "Login"
              ) : (
                "Create account"
              )}
            </button>
          </form>

          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-border" />
            </div>
            <div className="relative flex justify-center">
              <span className="bg-card px-3 text-xs font-mono text-muted-foreground">
                OR
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={handleGoogleLogin}
            disabled={loading}
            className="w-full rounded-lg border border-border bg-background/70 px-4 py-3 text-sm font-medium hover:border-primary/40 transition-colors inline-flex items-center justify-center gap-2"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Chrome className="w-4 h-4" />
            )}
            Continue with Google
          </button>

          <p className="mt-6 text-xs text-muted-foreground font-mono">
            Extension sync occurs automatically after authentication. Public sign-up creates
            standard user accounts; elevated roles must be provisioned separately.
          </p>

          <Link to="/" className="mt-4 inline-block text-sm text-primary hover:underline">
            Back to Home
          </Link>
        </div>
      </div>

      <Footer />
    </div>
  );
};

export default Login;
