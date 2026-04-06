import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { signInWithPopup, signOut } from "firebase/auth";

import { apiFetch, readApiError } from "@/lib/api";
import { auth as firebaseAuth, googleProvider } from "@/lib/firebase";

export type AuthUser = {
  id: string;
  email: string;
  role: "user" | "admin" | "researcher";
  created_at: string;
  auth_provider?: string;
  has_password?: boolean;
};

type AuthContextValue = {
  user: AuthUser | null;
  token: string | null;
  ready: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (
    email: string,
    password: string,
    role?: "user" | "admin" | "researcher"
  ) => Promise<void>;
  loginWithGoogle: () => Promise<void>;
  setPassword: (password: string) => Promise<void>;
  logout: () => void;
};

const TOKEN_STORAGE_KEY = "secureagent_token";
const USER_STORAGE_KEY = "secureagent_user";

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const broadcastAuthToken = (token: string | null) => {
  window.postMessage(
    {
      type: "SECURE_AGENT_AUTH",
      token,
    },
    "*"
  );
};

const persistSession = (token: string, user: AuthUser) => {
  localStorage.setItem(TOKEN_STORAGE_KEY, token);
  localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
  broadcastAuthToken(token);
};

const clearSession = () => {
  localStorage.removeItem(TOKEN_STORAGE_KEY);
  localStorage.removeItem(USER_STORAGE_KEY);
  broadcastAuthToken(null);
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

    const storedToken = localStorage.getItem(TOKEN_STORAGE_KEY);
    const storedUser = localStorage.getItem(USER_STORAGE_KEY);

    if (!storedToken) {
      setReady(true);
      return;
    }

    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser) as AuthUser);
      } catch {
        localStorage.removeItem(USER_STORAGE_KEY);
      }
    }

    setToken(storedToken);

    void (async () => {
      try {
        const response = await apiFetch(
          "/auth/me",
          {
            method: "GET",
          },
          storedToken
        );

        if (!response.ok) {
          throw new Error(`Auth check failed: ${response.status}`);
        }

        const me = (await response.json()) as AuthUser;
        setUser(me);
        localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(me));
        broadcastAuthToken(storedToken);
      } catch {
        clearSession();
        setUser(null);
        setToken(null);
      } finally {
        setReady(true);
      }
    })();
  }, []);

  const applyAuthResponse = (nextToken: string, nextUser: AuthUser) => {
    setToken(nextToken);
    setUser(nextUser);
    persistSession(nextToken, nextUser);
  };

  const normalizeAuthError = (error: unknown, fallback: string) => {
    if (error instanceof Error) {
      if (error.message.includes("auth/configuration-not-found")) {
        return new Error(
          "Google sign-in is not configured for this Firebase project. Enable the Google provider in Firebase Authentication and add localhost as an authorized domain."
        );
      }
      if (error.message.includes("auth/popup-closed-by-user")) {
        return new Error("Google sign-in was cancelled before completion.");
      }
      if (error.message.includes("auth/popup-blocked")) {
        return new Error("Google sign-in popup was blocked by the browser. Allow popups and try again.");
      }
      if (error.message === "Failed to fetch") {
        return new Error(
          "Unable to reach the SecureAgent backend. Check that the API is running and CORS allows this frontend origin."
        );
      }
      return error;
    }
    return new Error(fallback);
  };

  const login = async (email: string, password: string) => {
    try {
      const response = await apiFetch("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Login failed"));
      }
      const payload = (await response.json()) as {
        access_token: string;
        user: AuthUser;
      };
      applyAuthResponse(payload.access_token, payload.user);
    } catch (error) {
      throw normalizeAuthError(error, "Login failed");
    }
  };

  const register = async (
    email: string,
    password: string,
    role: "user" | "admin" | "researcher" = "user"
  ) => {
    try {
      const response = await apiFetch("/auth/register", {
        method: "POST",
        body: JSON.stringify({ email, password, role }),
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Registration failed"));
      }
      const payload = (await response.json()) as {
        access_token: string;
        user: AuthUser;
      };
      applyAuthResponse(payload.access_token, payload.user);
    } catch (error) {
      throw normalizeAuthError(error, "Registration failed");
    }
  };

  const loginWithGoogle = async () => {
    try {
      const credential = await signInWithPopup(firebaseAuth, googleProvider);
      const idToken = await credential.user.getIdToken(true);
      const response = await apiFetch("/auth/google", {
        method: "POST",
        body: JSON.stringify({ id_token: idToken, role: "user" }),
      });
      await signOut(firebaseAuth);
      if (!response.ok) {
        throw new Error(await readApiError(response, "Google sign-in failed"));
      }
      const payload = (await response.json()) as {
        access_token: string;
        user: AuthUser;
      };
      applyAuthResponse(payload.access_token, payload.user);
    } catch (error) {
      try {
        await signOut(firebaseAuth);
      } catch {
        // ignore sign-out cleanup failures
      }
      throw normalizeAuthError(error, "Google sign-in failed");
    }
  };

  const setPassword = async (password: string) => {
    if (!token) {
      throw new Error("You must be logged in to set a password.");
    }

    try {
      const response = await apiFetch(
        "/auth/set-password",
        {
          method: "POST",
          body: JSON.stringify({ password }),
        },
        token
      );

      if (!response.ok) {
        throw new Error(await readApiError(response, "Unable to set password"));
      }

      const payload = (await response.json()) as {
        access_token: string;
        user: AuthUser;
      };
      applyAuthResponse(payload.access_token, payload.user);
    } catch (error) {
      throw normalizeAuthError(error, "Unable to set password");
    }
  };

  const logout = () => {
    void signOut(firebaseAuth);
    clearSession();
    setUser(null);
    setToken(null);
  };

  return (
    <AuthContext.Provider
      value={{ user, token, ready, login, register, loginWithGoogle, setPassword, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
