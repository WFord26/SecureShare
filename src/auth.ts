import { ConfidentialClientApplication, CryptoProvider } from "@azure/msal-node";
import { Request, Response, NextFunction, Router } from "express";
import { config } from "./config";

declare module "express-session" {
  interface SessionData {
    user?: { name: string; email: string; oid: string };
    pkce?: { verifier: string; challenge: string };
    oauthState?: string;
    returnTo?: string;
  }
}

const msal = new ConfidentialClientApplication({
  auth: {
    clientId: config.clientId,
    authority: `${config.authorityHost}/${config.tenantId}`,
    clientSecret: config.clientSecret,
    // Required for national clouds (e.g. Azure China): skip global instance discovery
    knownAuthorities: [new URL(config.authorityHost).host],
  },
});

const cryptoProvider = new CryptoProvider();
const REDIRECT_URI = `${config.baseUrl}/auth/callback`;
const SCOPES = ["openid", "profile", "email"];

/** Allow only local absolute paths: exactly one leading slash, no protocol relative "//" or "/\" tricks. */
function safeReturnPath(url: string | undefined): string {
  if (url && /^\/(?![/\\])/.test(url)) return url;
  return "/";
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (req.session.user) return next();
  req.session.returnTo = safeReturnPath(req.originalUrl);
  res.redirect("/auth/login");
}

export function requireAuthApi(req: Request, res: Response, next: NextFunction) {
  if (req.session.user) return next();
  res.status(401).json({ error: "Not authenticated" });
}

export const authRouter = Router();

authRouter.get("/login", async (req, res, next) => {
  try {
    const { verifier, challenge } = await cryptoProvider.generatePkceCodes();
    const state = cryptoProvider.createNewGuid();
    req.session.pkce = { verifier, challenge };
    req.session.oauthState = state;
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
    const code = req.query.code;
    const state = req.query.state;
    if (
      typeof code !== "string" ||
      typeof state !== "string" ||
      !req.session.pkce ||
      !req.session.oauthState ||
      state !== req.session.oauthState
    ) {
      return res.redirect("/auth/login");
    }
    delete req.session.oauthState; // single use
    const result = await msal.acquireTokenByCode({
      code,
      scopes: SCOPES,
      redirectUri: REDIRECT_URI,
      codeVerifier: req.session.pkce.verifier,
    });
    const claims = result.idTokenClaims as Record<string, unknown>;
    const user = {
      name: (claims.name as string) ?? "Unknown",
      email: (claims.preferred_username as string) ?? (claims.email as string) ?? "",
      oid: (claims.oid as string) ?? "",
    };
    // Validate again at use: defense in depth against any other writer of returnTo
    const returnTo = safeReturnPath(req.session.returnTo);
    // Regenerate session ID to prevent session fixation
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.user = user;
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        res.redirect(returnTo);
      });
    });
  } catch (err) {
    next(err);
  }
});

// POST only: prevents CSRF forced logout via <img> or link
authRouter.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect(
      `${config.authorityHost}/${config.tenantId}/oauth2/v2.0/logout?post_logout_redirect_uri=${encodeURIComponent(config.baseUrl)}`
    );
  });
});
