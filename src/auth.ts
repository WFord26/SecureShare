import { ConfidentialClientApplication, CryptoProvider } from "@azure/msal-node";
import { Request, Response, NextFunction, Router } from "express";
import crypto from "crypto";
import { config } from "./config";
import { page } from "./html";
import { logSafe } from "./util";

declare module "express-session" {
  interface SessionData {
    user?: { name: string; email: string; oid: string; tid: string; roles: string[] };
  }
}

const msal = new ConfidentialClientApplication({
  auth: {
    clientId: config.clientId,
    authority: `${config.authorityHost}/${config.tenantId}`,
    clientSecret: config.clientSecret,
    // Trust the configured host without calling the global instance discovery endpoint.
    // Harmless for the global cloud; required for national clouds (Azure China, US Gov).
    knownAuthorities: [new URL(config.authorityHost).host],
  },
});

const cryptoProvider = new CryptoProvider();
const REDIRECT_URI = `${config.baseUrl}/auth/callback`;
const SCOPES = ["openid", "profile", "email"];

// ---------------------------------------------------------------------------------------------
// In flight sign in state (PKCE verifier, CSRF state, return path) lives in a short lived signed
// cookie rather than the session store. Anonymous requests therefore allocate no server side
// state, which closes the "hammer /auth/login to fill the session store" denial of service.
// The __Host- prefix (HTTPS only) stops sibling subdomains from planting a cookie of this name.
// ---------------------------------------------------------------------------------------------
const AUTH_COOKIE = config.isHttps ? "__Host-ss.auth" : "ss.auth";
const AUTH_COOKIE_TTL_MS = 10 * 60 * 1000;

interface PendingAuth {
  verifier: string;
  state: string;
  returnTo: string;
  issuedAt: number;
}

function sign(payload: string): string {
  return crypto.createHmac("sha256", config.sessionSecret).update(payload).digest("base64url");
}

function setPending(res: Response, pending: PendingAuth): void {
  const body = Buffer.from(JSON.stringify(pending), "utf8").toString("base64url");
  res.cookie(AUTH_COOKIE, `${body}.${sign(body)}`, {
    httpOnly: true,
    secure: config.isHttps,
    sameSite: "lax",
    path: "/",
    maxAge: AUTH_COOKIE_TTL_MS,
  });
}

function clearPending(res: Response): void {
  res.clearCookie(AUTH_COOKIE, { httpOnly: true, secure: config.isHttps, sameSite: "lax", path: "/" });
}

function getCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

function readPending(req: Request): PendingAuth | null {
  const raw = getCookie(req, AUTH_COOKIE);
  if (!raw) return null;
  const dot = raw.lastIndexOf(".");
  if (dot < 0) return null;
  const body = raw.slice(0, dot);
  const mac = raw.slice(dot + 1);
  const expected = sign(body);
  if (mac.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as PendingAuth;
    if (typeof p.verifier !== "string" || typeof p.state !== "string" || typeof p.issuedAt !== "number") return null;
    if (Date.now() - p.issuedAt > AUTH_COOKIE_TTL_MS) return null;
    return p;
  } catch {
    return null;
  }
}

/** Only allow same origin absolute paths as a post login destination. */
function safeReturnTo(url: string | undefined): string {
  if (!url || !url.startsWith("/") || url.startsWith("//") || url.startsWith("/\\")) return "/";
  return url;
}

function regenerateSession(req: Request): Promise<void> {
  return new Promise((resolve, reject) => req.session.regenerate((err) => (err ? reject(err) : resolve())));
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (req.session.user) return next();
  // Nothing is written to the session here: the return path rides along to /auth/login instead.
  res.redirect(`/auth/login?returnTo=${encodeURIComponent(safeReturnTo(req.originalUrl))}`);
}

export function requireAuthApi(req: Request, res: Response, next: NextFunction) {
  if (req.session.user) return next();
  res.status(401).json({ error: "Not authenticated" });
}

/** Holds the activity log app role. Roles come from the ID token, so a new assignment needs a fresh sign in. */
export function isAuditor(user: { roles?: string[] } | undefined): boolean {
  return !!user?.roles?.includes(config.auditRole);
}

export function requireAuditor(req: Request, res: Response, next: NextFunction) {
  if (!req.session.user) return requireAuth(req, res, next);
  if (isAuditor(req.session.user)) return next();
  res
    .status(403)
    .send(page("Not authorized", `The activity log requires the ${config.auditRole} app role. Ask an administrator to assign it, then sign out and back in.`, { link: { href: "/", text: "Back to uploads" } }));
}

export function requireAuditorApi(req: Request, res: Response, next: NextFunction) {
  if (!req.session.user) return res.status(401).json({ error: "Not authenticated" });
  if (isAuditor(req.session.user)) return next();
  res.status(403).json({ error: "Not authorized" });
}

// Fixed, non attacker controlled text for the error codes Entra sends back. The raw
// error_description is logged but never rendered, so this page cannot be used to put
// arbitrary text on our domain.
const ENTRA_ERROR_TEXT: Record<string, string> = {
  access_denied: "The sign in was cancelled or blocked by your organization's policy.",
  consent_required: "Your organization has not granted this application consent yet. Ask an administrator.",
  interaction_required: "Microsoft Entra needs additional sign in steps. Please try again.",
  login_required: "Please sign in again.",
  invalid_client: "The application's Entra registration is misconfigured. Contact the administrator.",
  unauthorized_client: "This application is not authorized for your account.",
  temporarily_unavailable: "Microsoft Entra is temporarily unavailable. Try again in a few minutes.",
  server_error: "Microsoft Entra reported an error. Try again in a few minutes.",
};

export const authRouter = Router();

authRouter.get("/login", async (req, res, next) => {
  try {
    const { verifier, challenge } = await cryptoProvider.generatePkceCodes();
    const state = cryptoProvider.createNewGuid();
    setPending(res, {
      verifier,
      state,
      returnTo: safeReturnTo(typeof req.query.returnTo === "string" ? req.query.returnTo : undefined),
      issuedAt: Date.now(),
    });
    const url = await msal.getAuthCodeUrl({
      scopes: SCOPES,
      redirectUri: REDIRECT_URI,
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
      state,
    });
    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

authRouter.get("/callback", async (req, res, next) => {
  try {
    const q = req.query as Record<string, string | undefined>;
    const pending = readPending(req);
    clearPending(res); // single use, whether or not this attempt succeeds

    // State is checked before anything else: a request that did not originate from our own
    // /auth/login in this browser gets a generic page and nothing is rendered from the query.
    if (!pending || !q.state || q.state !== pending.state) {
      return res
        .status(400)
        .send(page("Sign in expired", "Your sign in attempt expired or was invalid. Please start again.", { link: { href: "/auth/login", text: "Sign in" } }));
    }

    // User cancelled, consent denied, conditional access block, etc.
    if (q.error) {
      console.warn(`Sign in failed: ${logSafe(q.error, 64)}: ${logSafe(q.error_description, 300)}`);
      const text = ENTRA_ERROR_TEXT[q.error] ?? "Microsoft Entra could not complete the sign in.";
      return res.status(401).send(page("Sign in failed", text, { link: { href: "/auth/login", text: "Try again" } }));
    }

    if (!q.code) {
      return res
        .status(400)
        .send(page("Sign in expired", "Your sign in attempt expired or was invalid. Please start again.", { link: { href: "/auth/login", text: "Sign in" } }));
    }

    const result = await msal.acquireTokenByCode({
      code: q.code,
      scopes: SCOPES,
      redirectUri: REDIRECT_URI,
      codeVerifier: pending.verifier,
      state: q.state,
    });
    // The claims are all we keep. Drop MSAL's cached account so process memory does not grow per sign in.
    if (result.account) await msal.getTokenCache().removeAccount(result.account);

    const claims = result.idTokenClaims as Record<string, unknown>;
    const tid = String(claims.tid ?? "").toLowerCase();
    const oid = String(claims.oid ?? "");

    // Defense in depth for single tenant, the actual gate for multi tenant ("organizations")
    if (!tid || !config.allowedTenantIds.includes(tid)) {
      console.warn(`Rejected sign in from tenant ${logSafe(tid) || "(none)"} for ${logSafe(claims.preferred_username)}`);
      return res
        .status(403)
        .send(page("Not authorized", "Your organization is not permitted to use this application."));
    }
    if (!oid) {
      console.warn(`Rejected sign in without an object ID claim for ${logSafe(claims.preferred_username)}`);
      return res.status(403).send(page("Not authorized", "Your account type is not supported by this application."));
    }

    await regenerateSession(req); // new session ID after authentication (prevents fixation)
    req.session.user = {
      name: (claims.name as string) ?? "Unknown",
      email: (claims.preferred_username as string) ?? (claims.email as string) ?? "",
      oid,
      tid,
      roles: Array.isArray(claims.roles) ? (claims.roles as unknown[]).map(String) : [],
    };
    res.redirect(safeReturnTo(pending.returnTo));
  } catch (err) {
    next(err);
  }
});

authRouter.get("/logout", (req, res) => {
  req.session.destroy(() => {
    // post_logout_redirect_uri must be a registered redirect URI on the app registration (see README)
    res.redirect(
      `${config.authorityHost}/${config.tenantId}/oauth2/v2.0/logout?post_logout_redirect_uri=${encodeURIComponent(config.baseUrl + "/")}`
    );
  });
});
