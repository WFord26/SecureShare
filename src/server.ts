import express, { ErrorRequestHandler, Request, Response, NextFunction } from "express";
import session from "express-session";
import busboy from "busboy";
import path from "path";
import { randomUUID } from "crypto";
import { Readable } from "stream";
import rateLimit from "express-rate-limit";
import { config } from "./config";
import { authRouter, requireAuth, requireAuthApi, requireAuditor, isAuditor, purviewSupported } from "./auth";
import { uploadFile, getFileMeta, streamFile, deleteFile, listFilesForUser, isOwner, verifyStorageAccess, blobEndpoint, FileMeta } from "./storage";
import { page, passwordPage } from "./html";
import { logSafe, tokenRef, clientIp, getCookie } from "./util";
import * as audit from "./audit";
import { adminRouter } from "./admin";
import { hashPassword, verifyPassword, validatePassword, AttemptTracker, makeUnlockCookie, checkUnlockCookie, MIN_PASSWORD_LENGTH } from "./password";

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(
  session({
    secret: config.sessionSecret,
    // __Host- prefix (HTTPS only): the cookie must be Secure, Path=/ and host only, so a sibling
    // subdomain cannot plant a cookie of the same name (cookie tossing).
    name: config.isHttps ? "__Host-ss.sid" : "ss.sid",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: config.isHttps,
      maxAge: 8 * 60 * 60 * 1000,
    },
  })
);

// Security headers on every response
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
  );
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  // Nothing this app serves should sit in a browser or proxy cache: pages and API responses carry links
  res.setHeader("Cache-Control", "no-store");
  if (config.isHttps) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});

// Cross site request forgery: SameSite=Lax on the session cookie covers cross site origins, but any
// sibling subdomain of the base domain is "same site" and would still get the cookie. Require that
// state changing requests come from our own origin. Browsers always send Sec-Fetch-Site and, for
// POST/DELETE via fetch or forms, Origin; a request with neither (curl) has no cookie to abuse anyway.
app.use((req, res, next) => {
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
  const site = req.headers["sec-fetch-site"];
  if (site && site !== "same-origin" && site !== "none") return res.status(403).json({ error: "Cross site request rejected" });
  const origin = req.headers.origin;
  if (origin && origin !== config.baseOrigin) return res.status(403).json({ error: "Cross site request rejected" });
  next();
});

// Rate limits (per client IP, in memory; one instance). Generous for humans, tight for scripts.
const limiter = (windowMs: number, limit: number, what: string) =>
  rateLimit({
    windowMs,
    limit,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    keyGenerator: (req: Request) => clientIp(req.ip),
    handler: (req: Request, res: Response) => {
      console.warn(`Rate limit hit (${what}) from ${clientIp(req.ip)}`);
      res.status(429);
      if (req.path.startsWith("/api/")) return res.json({ error: "Too many requests, slow down" });
      res.setHeader("Retry-After", String(Math.ceil(windowMs / 1000)));
      res.send(page("Slow down", "Too many requests from your network. Try again in a few minutes."));
    },
  });
app.use("/auth", limiter(10 * 60 * 1000, 30, "auth"));
app.use("/api/upload", limiter(15 * 60 * 1000, 40, "upload"));
app.use("/d", limiter(60 * 1000, 60, "download"));
app.use(limiter(60 * 1000, 300, "global"));

app.use("/auth", authRouter);

// Upload UI (authenticated)
app.get("/", requireAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "index.html"));
});
app.get("/app.js", requireAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "app.js"));
});

// Theme resolution (light/dark). PUBLIC on purpose: index.html, admin.html and the anonymous
// status pages from html.ts all load it in <head>. It contains no data. Without this route the
// dark mode switch does nothing and the page falls back to the system theme only.
app.get("/theme.js", (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.sendFile(path.join(__dirname, "..", "public", "theme.js"));
});

app.get("/api/me", requireAuthApi, (req, res) => {
  res.json({ ...req.session.user, linkTtlDays: config.linkTtlDays, auditor: isAuditor(req.session.user), minPasswordLength: MIN_PASSWORD_LENGTH });
});

app.get("/api/purview/status", requireAuthApi, (req, res) => {
  res.json({ supported: purviewSupported, enforcementEnabled: false, status: req.session.purviewStatus ?? null });
});

// Activity log (app role holders only)
app.get("/admin", requireAuditor, (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "admin.html"));
});
app.get("/admin.js", requireAuditor, (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "admin.js"));
});
app.use(adminRouter);

// Upload endpoint (authenticated). The file part is streamed straight to blob storage rather than
// buffered in memory, so memory use no longer scales with file size; concurrency is still capped as
// a sane ceiling on simultaneous in-flight uploads.
let uploadsInFlight = 0;

app.post("/api/upload", requireAuthApi, (req, res) => {
  const uploadId = randomUUID();
  const startedAt = Date.now();
  res.setHeader("X-Upload-Id", uploadId);
  const diagnostic = () => `upload=${uploadId} elapsedMs=${Date.now() - startedAt} complete=${req.complete}`;
  console.log(`Upload started: ${diagnostic()}`);
  res.on("finish", () => console.log(`Upload response: ${diagnostic()} status=${res.statusCode}`));
  res.on("close", () => {
    if (!res.writableFinished) console.warn(`Upload response closed: ${diagnostic()}`);
  });
  req.on("error", (err: NodeJS.ErrnoException) => {
    console.warn(`Upload connection error: ${diagnostic()} code=${logSafe(err.code ?? "unknown")}`);
  });
  if (uploadsInFlight >= config.maxConcurrentUploads) {
    res.setHeader("Retry-After", "10");
    return res.status(503).json({ error: "The server is busy with other uploads. Try again in a moment." });
  }
  uploadsInFlight++;
  let released = false;
  const release = () => {
    if (!released) {
      released = true;
      uploadsInFlight--;
    }
  };
  res.on("finish", release);
  res.on("close", release);

  let responded = false;
  let currentFileStream: Readable | null = null;
  let uploadPromise: Promise<FileMeta> | null = null;

  // Cleanly ends the request no matter which stage it fails at. If a file is already streaming to
  // blob storage, tearing down its stream propagates into storage.uploadFile's error handling
  // (src/storage.ts) so the in-progress Azure upload aborts instead of hanging on a dead source.
  const fail = (status: number, error: string, cause?: unknown) => {
    if (responded) return;
    responded = true;
    if (currentFileStream) currentFileStream.destroy(cause instanceof Error ? cause : new Error(error));
    if (uploadPromise) uploadPromise.catch(() => {});
    req.unpipe();
    req.resume(); // drain the rest of the request body so the socket doesn't hang
    res.status(status).json({ error });
  };

  let bb: busboy.Busboy;
  try {
    bb = busboy({ headers: req.headers, limits: { fileSize: config.maxUploadBytes, files: 1, fields: 5, fieldSize: 1024, parts: 10 } });
  } catch {
    return fail(400, "Upload failed");
  }

  // Optional download password. An empty field means no password. Only its scrypt hash is kept.
  // The client (public/app.js) sends the password field before the file field on purpose: busboy
  // parses parts in stream order, so this guarantees `password` is already known by the time the
  // 'file' event fires below.
  let password = "";
  let fileSeen = false;
  let tooBig = false;
  let passwordTooLate = false;

  bb.on("field", (name, value) => {
    if (name !== "password") return;
    // A password field can't retroactively apply to an upload already streaming to storage. Rather
    // than tear that upload down mid-flight, let it finish and reject it once it's safe to do so.
    if (fileSeen) {
      passwordTooLate = true;
      return;
    }
    password = value;
  });

  bb.on("file", (name, fileStream, info) => {
    if (name !== "file" || fileSeen) {
      fileStream.resume(); // discard anything we don't recognize or a second file part
      return;
    }
    fileSeen = true;

    if (password) {
      const problem = validatePassword(password);
      if (problem) {
        fileStream.resume();
        return fail(400, problem);
      }
    }

    fileStream.on("limit", () => {
      tooBig = true;
    });
    currentFileStream = fileStream;

    uploadPromise = (async () => {
      const passwordHash = password ? await hashPassword(password) : undefined;
      return uploadFile(fileStream, info.filename, info.mimeType, req.session.user!.email, req.session.user!.oid, passwordHash);
    })();
    // Observe failures while the multipart request is still arriving.
    void uploadPromise.catch((e) => {
      if (responded) return; // Already logged an abort or parse failure.
      console.error(`Upload storage error: ${diagnostic()}`, e);
      fail(500, "Storage error during upload", e);
    });
  });

  bb.on("error", (err) => {
    console.error(`Upload parse error: ${diagnostic()}`, err);
    fail(400, "Upload failed", err);
  });

  req.on("aborted", () => {
    console.warn(`Upload aborted: ${diagnostic()}`);
    bb.destroy();
    fail(400, "Upload failed", new Error("Request aborted"));
  });

  bb.on("close", async () => {
    if (responded) return;
    if (!fileSeen || !uploadPromise) return fail(400, "No file provided");
    try {
      const meta = await uploadPromise;
      if (tooBig || passwordTooLate) {
        await deleteFile(meta.token).catch(() => {});
        return tooBig
          ? fail(413, `File exceeds the ${config.maxUploadBytes / 1024 / 1024} MB limit`)
          : fail(400, "Upload failed");
      }
      console.log(`Upload by ${logSafe(meta.uploadedBy)}: "${logSafe(meta.originalName)}" ${meta.size} bytes, token ${tokenRef(meta.token)}, expires ${meta.expiresAt.toISOString()}${meta.passwordHash ? ", password protected" : ""}`);
      audit.recordUpload(meta, req.session.user!, clientIp(req.ip));
      responded = true;
      res.json({
        link: `${config.baseUrl}/d/${meta.token}`,
        fileName: meta.originalName,
        size: meta.size,
        expiresAt: meta.expiresAt.toISOString(),
        passwordProtected: !!meta.passwordHash,
        note:
          config.scanPolicy === "required"
            ? "File is being scanned for malware. The link works once the scan finds no threats."
            : "File is being scanned for malware. The link works within a couple of minutes.",
      });
    } catch (e) {
      if (responded) return; // already handled via fail() (e.g. aborted or errored mid-upload)
      console.error("Upload error:", e);
      fail(500, "Storage error during upload");
    }
  });

  req.pipe(bb);
});

/** Can this file be downloaded right now under the configured scan policy? */
function isAvailable(meta: FileMeta): boolean {
  if (meta.scanStatus === "clean") return true;
  if (meta.scanStatus === "malicious") return false;
  if (config.scanPolicy === "required") return false;
  // best-effort: give the scanner a head start, then serve regardless of result
  return Date.now() - meta.uploadedAt.getTime() > config.scanGraceMs;
}

function toApi(meta: FileMeta) {
  return {
    token: meta.token,
    fileName: meta.originalName,
    size: meta.size,
    uploadedAt: meta.uploadedAt.toISOString(),
    expiresAt: meta.expiresAt.toISOString(),
    scanStatus: meta.scanStatus,
    available: isAvailable(meta),
    passwordProtected: !!meta.passwordHash,
    link: `${config.baseUrl}/d/${meta.token}`,
  };
}

// The signed in user's uploads (unexpired), newest first
app.get("/api/files", requireAuthApi, async (req, res, next) => {
  try {
    const u = req.session.user!;
    const files = await listFilesForUser(u.oid, u.email);
    files.forEach(audit.recordScanStatus);
    // Download counts are extra: if the activity log is unreachable the list still loads without them
    const stats = await audit.getUploads(files).catch((e) => {
      console.error(`Activity log: could not read download counts: ${(e as Error).message}`);
      return new Map<string, audit.UploadRecord>();
    });
    res.json({
      files: files.map((f) => {
        const s = stats.get(f.token);
        return {
          ...toApi(f),
          downloads: s ? { count: s.downloads, lastAt: s.lastDownloadAt?.toISOString() ?? null } : null,
        };
      }),
    });
  } catch (e) {
    next(e);
  }
});

// Revoke a link early. Only the uploader can do this; anyone else gets the same 404 as a missing file.
app.delete("/api/files/:token", requireAuthApi, async (req, res, next) => {
  try {
    const u = req.session.user!;
    const meta = await getFileMeta(req.params.token);
    if (!meta || !isOwner(meta, u.oid, u.email)) return res.status(404).json({ error: "Not found" });
    await deleteFile(meta.token);
    console.log(`Link revoked by ${logSafe(u.email)}: "${logSafe(meta.originalName)}" token ${tokenRef(meta.token)}`);
    audit.recordEnded(meta, "revoked", u.email);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

/**
 * HTTP header values must be Latin-1 (Node throws on anything else). The quoted filename is an ASCII
 * fallback for old clients; every modern browser uses the RFC 5987 filename* form with the real name.
 */
function contentDisposition(name: string): string {
  const ascii = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_").trim() || "download";
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

// ------------------------------------------------------------------ Anonymous download page

type Visitor = { ip: string; userAgent: string | undefined };

/**
 * Shared first steps of every request for a link: expired and unknown links get an identical 404 so tokens
 * cannot be probed, and malware is deleted on sight whatever else the request was. Returns null once a
 * response has been sent.
 */
async function resolveLink(req: Request, res: Response): Promise<{ meta: FileMeta; who: Visitor } | null> {
  const meta = await getFileMeta(req.params.token);
  const who: Visitor = { ip: clientIp(req.ip), userAgent: req.headers["user-agent"] };

  // Expired or never existed: identical response, no information leak
  if (!meta || Date.now() > meta.expiresAt.getTime()) {
    if (meta) {
      audit.recordDownload(meta, who, "expired");
      await deleteFile(meta.token); // eager cleanup ahead of lifecycle policy
    }
    res.status(404).send(page("Link not found", `This link is invalid or has expired. Links are valid for ${config.linkTtlDays} days.`));
    return null;
  }

  if (meta.scanStatus === "malicious") {
    await deleteFile(meta.token);
    console.warn(`Malicious file deleted: token ${tokenRef(meta.token)} uploaded by ${logSafe(meta.uploadedBy)} at ${meta.uploadedAt.toISOString()}, requested from ${who.ip}`);
    audit.recordDownload(meta, who, "blocked");
    audit.recordEnded(meta, "blocked", "malware scan");
    res.status(403).send(page("File blocked", "This file was flagged by malware scanning and has been removed."));
    return null;
  }

  return { meta, who };
}

// Password protected links. The unlock cookie is scoped to the link's own path, so it is only ever sent
// back for that link. Its value is signed and carries no token (see password.ts).
const UNLOCK_COOKIE = config.isHttps ? "__Secure-ss.dl" : "ss.dl";
const unlockCookieOptions = (token: string) => ({ httpOnly: true, secure: config.isHttps, sameSite: "lax" as const, path: `/d/${token}` });
const passwordAttempts = new AttemptTracker();

function isUnlocked(req: Request, meta: FileMeta): boolean {
  if (!meta.passwordHash) return true;
  return checkUnlockCookie(config.sessionSecret, meta.token, meta.passwordHash, getCookie(req.headers.cookie, UNLOCK_COOKIE));
}

function minutesText(ms: number): string {
  const m = Math.max(1, Math.ceil(ms / 60000));
  return `${m} minute${m === 1 ? "" : "s"}`;
}

/**
 * The password form is a plain HTML form post. Under the site wide Referrer-Policy: no-referrer, browsers send
 * "Origin: null" on such a post (the Fetch spec ties the Origin header of a navigation to the referrer policy),
 * which the cross site check above would reject. "same-origin" makes the browser send the real origin while the
 * link URL still never reaches another site as a referer.
 */
function sendPasswordPage(res: Response, status: number, action: string, opts: { error?: string } = {}): void {
  res.setHeader("Referrer-Policy", "same-origin");
  res.status(status).send(passwordPage(action, opts));
}

// Password form submission. Wrong guesses are throttled per client and per link (in memory), on top of the
// per IP rate limits below. Every guess, right or wrong, is written to the activity log.
app.post(
  "/d/:token",
  limiter(15 * 60 * 1000, 30, "password"),
  express.urlencoded({ extended: false, limit: "4kb", parameterLimit: 5 }),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const link = await resolveLink(req, res);
      if (!link) return;
      const { meta, who } = link;
      const action = `/d/${meta.token}`;
      if (!meta.passwordHash) return res.redirect(303, action);

      const wait = passwordAttempts.retryAfterMs(meta.token, who.ip);
      if (wait > 0) {
        audit.recordDownload(meta, who, "password_locked");
        console.warn(`Password guess refused (locked out): token ${tokenRef(meta.token)} from ${who.ip}`);
        res.setHeader("Retry-After", String(Math.ceil(wait / 1000)));
        return sendPasswordPage(res, 429, action, { error: `Too many wrong passwords. Try again in ${minutesText(wait)}.` });
      }

      const body = (req.body ?? {}) as Record<string, unknown>;
      const password = typeof body.password === "string" ? body.password : "";
      if (!(await verifyPassword(password, meta.passwordHash))) {
        const lock = passwordAttempts.recordFailure(meta.token, who.ip);
        audit.recordDownload(meta, who, "password_wrong");
        console.warn(`Wrong password: token ${tokenRef(meta.token)} "${logSafe(meta.originalName)}" from ${who.ip} ua="${logSafe(who.userAgent, 120)}"${lock ? `, locked out for ${minutesText(lock)}` : ""}`);
        return sendPasswordPage(res, 401, action, { error: lock ? `Wrong password. Too many attempts, try again in ${minutesText(lock)}.` : "Wrong password. Check it with the sender and try again." });
      }

      passwordAttempts.recordSuccess(meta.token, who.ip);
      audit.recordDownload(meta, who, "password_ok");
      console.log(`Password accepted: token ${tokenRef(meta.token)} "${logSafe(meta.originalName)}" from ${who.ip}`);
      const cookie = makeUnlockCookie(config.sessionSecret, meta.token, meta.passwordHash);
      res.cookie(UNLOCK_COOKIE, cookie.value, { ...unlockCookieOptions(meta.token), expires: new Date(cookie.expiresAt) });
      // Back to the link with GET: the same code path as an unprotected file serves it (or shows the scan wait page).
      // A meta refresh rather than a 303 keeps this page on screen while the browser fetches the attachment.
      res.send(page("Password accepted", "Your download is starting. If it does not, use the link below.", { redirect: action, link: { href: action, text: "Download the file" } }));
    } catch (e) {
      next(e);
    }
  }
);

// Anonymous download page: shows status, then streams the file
app.get("/d/:token", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const link = await resolveLink(req, res);
    if (!link) return;
    const { meta, who } = link;

    // Password gate comes before the scan status so a visitor without the password learns nothing about the file
    if (!isUnlocked(req, meta)) {
      audit.recordDownload(meta, who, "password_prompt");
      return sendPasswordPage(res, 200, `/d/${meta.token}`);
    }

    if (!isAvailable(meta)) {
      if (meta.scanStatus === "unscanned") {
        // Only reachable with SCAN_POLICY=required
        audit.recordDownload(meta, who, "unscannable");
        return res
          .status(403)
          .send(page("File unavailable", "This file could not be scanned for malware (for example an encrypted or unsupported archive), so it cannot be downloaded. Ask the sender to share it in a different format."));
      }
      audit.recordDownload(meta, who, "waiting");
      res.setHeader("Retry-After", "30");
      return res
        .status(503)
        .send(page("Scan in progress", "This file is still being scanned for viruses. This page will refresh automatically.", { refresh: 30 }));
    }

    if (meta.scanStatus !== "clean") {
      console.warn(`Serving file without a clean scan verdict (status=${meta.scanStatus}, policy=${config.scanPolicy}): token ${tokenRef(meta.token)} uploaded by ${logSafe(meta.uploadedBy)} at ${meta.uploadedAt.toISOString()}`);
    }

    // Express routes HEAD to GET handlers. Answer with headers only instead of pulling the whole blob from storage.
    if (req.method === "HEAD") {
      audit.recordDownload(meta, who, "head");
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Length", meta.size);
      res.setHeader("Content-Disposition", contentDisposition(meta.originalName));
      return res.end();
    }

    const stream = await streamFile(meta.token);
    if (!stream) return res.status(404).send(page("Link not found", "This link is invalid or has expired."));

    // Audit trail: who fetched what. The token itself is never logged.
    console.log(`Download: token ${tokenRef(meta.token)} "${logSafe(meta.originalName)}" ${meta.size} bytes, uploaded by ${logSafe(meta.uploadedBy)}, from ${who.ip} ua="${logSafe(req.headers["user-agent"], 120)}"`);

    // Activity log entry once the response ends: finish = fully sent, close without finish = cut off
    // Bytes handed to the client socket (includes ~300 bytes of headers). Counting what was read from storage
    // would overstate a cancelled download by the stream read-ahead.
    const started = Date.now();
    const socket = req.socket;
    const socketStart = socket.bytesWritten;
    let failed = false;
    let recorded = false;
    const record = (outcome: audit.DownloadOutcome) => {
      if (recorded) return;
      recorded = true;
      const sent = outcome === "served" && !failed ? meta.size : Math.min(Math.max(socket.bytesWritten - socketStart, 0), meta.size);
      audit.recordDownload(meta, who, failed ? "error" : outcome, sent, Date.now() - started);
    };
    res.on("finish", () => record("served"));
    res.on("close", () => record("incomplete"));

    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Length", meta.size);
    res.setHeader("Content-Disposition", contentDisposition(meta.originalName));
    // Without an error listener a mid transfer storage error would crash the process
    stream.on("error", (err) => {
      console.error("Download stream error:", err);
      failed = true;
      if (!res.headersSent) res.status(500).send(page("Error", "Download failed. Try again later."));
      else res.destroy();
    });
    stream.pipe(res);
  } catch (e) {
    next(e);
  }
});

app.get("/healthz", (_req, res) => res.json({ ok: true }));

app.use((_req, res) => res.status(404).send(page("Not found", "There is nothing here.")));

// Never leak stack traces (Express default handler does when NODE_ENV != production)
const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  console.error(`Unhandled error on ${req.method} ${logSafe(req.path)}:`, err);
  if (res.headersSent) return res.destroy();
  if (req.path.startsWith("/api/")) return res.status(500).json({ error: "Internal error" });
  res.status(500).send(page("Error", "Something went wrong. Try again later."));
};
app.use(errorHandler);

async function main() {
  try {
    await verifyStorageAccess();
    console.log(`Storage OK: ${blobEndpoint}/${config.storageContainer}`);
  } catch (e) {
    // Do not exit: on App Service the managed identity role assignment may still be propagating.
    console.error("Storage check failed (uploads will fail until fixed):", (e as Error).message);
  }
  try {
    await audit.verifyAuditAccess();
    console.log(`Activity log OK: tables ${audit.UPLOAD_TABLE}, ${audit.DOWNLOAD_TABLE} (retention ${config.auditRetentionDays} days)`);
  } catch (e) {
    // Uploads and downloads keep working; only the log is missing. Usually the Storage Table Data Contributor role.
    console.error("Activity log check failed (nothing will be recorded until fixed; check Storage Table Data Contributor role):", (e as Error).message);
  }
  audit.startRetentionPurge();
  const server = app.listen(config.port, () => {
    console.log(`secureshare listening on ${config.baseUrl} (port ${config.port})`);
    console.log(`Auth: ${config.authorityHost}/${config.tenantId}` + (config.multiTenant ? ` allowed tenants: ${config.allowedTenantIds.join(", ")}` : ""));
    console.log(`Scan policy: ${config.scanPolicy}` + (config.scanPolicy === "best-effort" ? ` (serve after ${config.scanGraceMs / 60000} min without a verdict)` : ""));
    console.log(`Request timeout: ${server.requestTimeout / 1000}s; upload limit: ${config.maxUploadBytes / 1024 / 1024} MB`);
  });
  // Large streamed uploads can exceed Node's five-minute default. Keep a finite
  // request deadline and leave the separate header timeout unchanged.
  server.requestTimeout = config.requestTimeoutMs;
}

main();
