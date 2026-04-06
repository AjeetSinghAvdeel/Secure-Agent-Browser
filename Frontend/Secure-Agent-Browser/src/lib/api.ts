const API_BASE_STORAGE_KEY = "secureagent_api_base_url";

const resolveDefaultApiBaseUrl = () => {
  if (typeof window === "undefined") {
    return "http://127.0.0.1:8000";
  }

  const protocol = window.location.protocol === "https:" ? "https:" : "http:";
  const rawHostname = window.location.hostname || "127.0.0.1";
  const hostname =
    rawHostname === "localhost" || rawHostname === "[::1]" ? "127.0.0.1" : rawHostname;
  return `${protocol}//${hostname}:8000`;
};

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") || resolveDefaultApiBaseUrl();

if (typeof window !== "undefined") {
  window.localStorage.setItem(API_BASE_STORAGE_KEY, API_BASE_URL);
}

const getTimeoutHandle = (callback: () => void, delayMs: number) => {
  if (typeof window !== "undefined") {
    return window.setTimeout(callback, delayMs);
  }
  return globalThis.setTimeout(callback, delayMs);
};

const clearTimeoutHandle = (handle: ReturnType<typeof setTimeout>) => {
  if (typeof window !== "undefined") {
    window.clearTimeout(handle);
    return;
  }
  globalThis.clearTimeout(handle);
};

export async function apiFetch(
  path: string,
  options: RequestInit = {},
  token?: string | null
) {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const controller = new AbortController();
  const timeoutId = getTimeoutHandle(() => controller.abort(), 12000);

  try {
    return await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers,
      signal: options.signal ?? controller.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("SecureAgent backend request timed out");
    }
    throw error;
  } finally {
    clearTimeoutHandle(timeoutId);
  }
}

export async function readApiError(response: Response, fallback: string) {
  try {
    const payload = (await response.json()) as { detail?: string; message?: string };
    if (payload?.detail) return payload.detail;
    if (payload?.message) return payload.message;
  } catch {
    try {
      const text = await response.text();
      if (text) return text;
    } catch {
      // ignore secondary parse failures
    }
  }
  return fallback;
}
