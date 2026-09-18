import express, { ErrorRequestHandler, Request, Response, NextFunction } from "express";
import session from "express-session";
import multer from "multer";
import path from "path";
import rateLimit from "express-rate-limit";
import { config } from "./config";
import { authRouter, requireAuth, requireAuthApi, requireAuditor, isAuditor, purviewSupported } from "./auth";
import { uploadFile, getFileMeta, streamFile, deleteFile, listFilesForUser, isOwner, verifyStorageAccess, blobEndpoint, FileMeta } from "./storage";
import { page } from "./html";
import { logSafe, tokenRef, clientIp } from "./util";
import * as audit from "./audit";
import { adminRouter } from "./admin";

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
  res.json({ ...req.session.user, linkTtlDays: config.linkTtlDays, auditor: isAuditor(req.session.user) });
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

// Upload endpoint (authenticated). Files are buffered in memory, so concurrency is capped to bound
// worst case memory at MAX_CONCURRENT_UPLOADS * MAX_UPLOAD_MB.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxUploadBytes, files: 1, fields: 5, fieldSize: 1024, parts: 10 },
});
let uploadsInFlight = 0;

app.post("/api/upload", requireAuthApi, (req, res) => {
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

  upload.single("file")(req, res, async (err) => {
    if (err) {
      const tooBig = err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE";
      return res
        .status(tooBig ? 413 : 400)
        .json({ error: tooBig ? `File exceeds the ${config.maxUploadBytes / 1024 / 1024} MB limit` : "Upload failed" });
    }
    if (!req.file) return res.status(400).json({ error: "No file provided" });
    try {
      const meta = await uploadFile(
        req.file.buffer,
        req.file.originalname,
        req.file.mimetype,
        req.session.user!.email,
        req.session.user!.oid
      );
      console.log(`Upload by ${logSafe(meta.uploadedBy)}: "${logSafe(meta.originalName)}" ${meta.size} bytes, token ${tokenRef(meta.token)}, expires ${meta.expiresAt.toISOString()}`);
      audit.recordUpload(meta, req.session.user!, clientIp(req.ip));
      res.json({
        link: `${config.baseUrl}/d/${meta.token}`,
        fileName: meta.originalName,
        size: meta.size,
        expiresAt: meta.expiresAt.toISOString(),
        note:
          config.scanPolicy === "required"
            ? "File is being scanned for malware. The link works once the scan finds no threats."
            : "File is being scanned for malware. The link works within a couple of minutes.",
      });
    } catch (e) {
      console.error("Upload error:", e);
      res.status(500).json({ error: "Storage error during upload" });
    }
  });
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

// Anonymous download page: shows status, then streams the file
app.get("/d/:token", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const meta = await getFileMeta(req.params.token);
    const who = { ip: clientIp(req.ip), userAgent: req.headers["user-agent"] };

    // Expired or never existed: identical response, no information leak
    if (!meta || Date.now() > meta.expiresAt.getTime()) {
      if (meta) {
        audit.recordDownload(meta, who, "expired");
        await deleteFile(meta.token); // eager cleanup ahead of lifecycle policy
      }
      return res
        .status(404)
        .send(page("Link not found", `This link is invalid or has expired. Links are valid for ${config.linkTtlDays} days.`));
    }

    if (meta.scanStatus === "malicious") {
      await deleteFile(meta.token);
      console.warn(`Malicious file deleted: token ${tokenRef(meta.token)} uploaded by ${logSafe(meta.uploadedBy)} at ${meta.uploadedAt.toISOString()}, requested from ${who.ip}`);
      audit.recordDownload(meta, who, "blocked");
      audit.recordEnded(meta, "blocked", "malware scan");
      return res.status(403).send(page("File blocked", "This file was flagged by malware scanning and has been removed."));
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
  app.listen(config.port, () => {
    console.log(`secureshare listening on ${config.baseUrl} (port ${config.port})`);
    console.log(`Auth: ${config.authorityHost}/${config.tenantId}` + (config.multiTenant ? ` allowed tenants: ${config.allowedTenantIds.join(", ")}` : ""));
    console.log(`Scan policy: ${config.scanPolicy}` + (config.scanPolicy === "best-effort" ? ` (serve after ${config.scanGraceMs / 60000} min without a verdict)` : ""));
  });
}

main();
