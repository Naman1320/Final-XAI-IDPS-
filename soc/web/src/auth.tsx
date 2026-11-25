import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, getToken, onTokenChange, setToken } from "./api/client";

export type Role = "analyst" | "admin";
export interface Me {
  id: number;
  username: string;
  role: Role;
  /** Missing from older SOCs. */
  mfa_enabled?: boolean;
  /** MFA can't be turned off for this account (admins, by default). */
  mfa_required?: boolean;
  /** Effective permissions from the IAM module. Missing from older SOCs. Used only to show or
   *  hide UI: the backend enforces every permission itself. */
  permissions?: string[];
}

/** POST /auth/login, /auth/mfa/verify, /auth/oidc/callback: an access token, or the MFA step
 *  ("verify": type a code; "enrol": an admin who must set up an authenticator app first). */
export interface LoginResult {
  access_token: string | null;
  expires_in: number | null;
  mfa?: "verify" | "enrol" | null;
  mfa_token?: string | null;
  email_status?: "sent" | "cooldown" | "unavailable" | null;
}

interface AuthState {
  me: Me | null;
  loading: boolean;
  /** Checks the password. Returns an access token (pass it to `finish`) or the MFA step. */
  login: (username: string, password: string) => Promise<LoginResult>;
  /** Finish a sign-in with a result that has an access token. */
  finish: (result: LoginResult) => Promise<void>;
  /** Reload the signed-in user (after MFA changes). */
  refresh: () => Promise<void>;
  logout: () => void;
  /** True if the signed-in user holds this permission (UI hint only; the backend enforces). */
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState<boolean>(Boolean(getToken()));

  const loadMe = useCallback(async () => {
    if (!getToken()) {
      setMe(null);
      setLoading(false);
      return;
    }
    try {
      setMe(await api<Me>("/auth/me"));
    } catch {
      setToken(null);
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadMe();
    // Any 401 clears the token (see api/client.ts); that sends the user back to login.
    const unsubscribe = onTokenChange(() => {
      if (!getToken()) setMe(null);
    });
    const permissionsChanged = () => { void loadMe(); };
    window.addEventListener("idps-iam-changed", permissionsChanged);
    return () => {
      window.removeEventListener("idps-iam-changed", permissionsChanged);
      unsubscribe();
    };
  }, [loadMe]);

  const finish = useCallback(async (res: LoginResult) => {
    if (!res.access_token) throw new Error("no access token in the sign-in result");
    setToken(res.access_token);
    await loadMe();
  }, [loadMe]);

  const login = useCallback(async (username: string, password: string) => {
    return api<LoginResult>("/auth/login", {
      method: "POST",
      json: { username, password, request_email_code: true },
    });
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setMe(null);
  }, []);

  const can = useCallback((permission: string) => Boolean(me && (me.permissions === undefined || me.permissions.includes(permission))), [me]);

  return <AuthContext.Provider value={{ me, loading, login, finish, refresh: loadMe, logout, can }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
