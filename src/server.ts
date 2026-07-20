import express from "express";
import session from "express-session";
import createMemoryStore from "memorystore";
import { rateLimit } from "express-rate-limit";
import multer from "multer";
import path from "path";
import { config } from "./config";
import { authRouter, requireAuth, requireAuthApi } from "./auth";
import { uploadFile, getFileMeta, streamFile, deleteFile } from "./storage";

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

// Leak safe in process store (prunes expired sessions). Swap for connect-redis
// if the app ever runs on more than one instance.
const MemoryStore = createMemoryStore(session);

app.use(
  session({
    store: new MemoryStore({ checkPeriod: 60 * 60 * 1000 }),
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: config.baseUrl.startsWith("https"),
      maxAge: 8 * 60 * 60 * 1000,
    },
  })
);

// Basic security headers
app.use((_req, res, next) => {
  if (config.baseUrl.startsWith("https")) {
    res.setHeader("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
  }
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
  );
  next();
});

app.use("/auth", authRouter);

// Upload UI (authenticated)
app.get("/", requireAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "index.html"));
});
app.get("/app.js", requireAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "app.js"));
});

app.get("/api/me", requireAuthApi, (req, res) => {
  res.json(req.session.user);
});

// Upload endpoint (authenticated)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxUploadBytes },
});

// Uploads buffer in memory, so cap the rate per client to bound total RAM use
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many uploads, try again later" },
});

const downloadLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});

app.post("/api/upload", uploadLimiter, requireAuthApi, (req, res) => {
  upload.single("file")(req, res, async (err) => {
    if (err) {
      const tooBig = err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE";
      return res
        .status(tooBig ? 413 : 400)
        .json({ error: tooBig ? "File exceeds size limit" : "Upload failed" });
    }
    if (!req.file) return res.status(400).json({ error: "No file provided" });
    try {
      const meta = await uploadFile(
        req.file.buffer,
        req.file.originalname,
        req.file.mimetype,
        req.session.user!.email
      );
      res.json({
        link: `${config.baseUrl}/d/${meta.token}`,
        fileName: meta.originalName,
        size: meta.size,
        expiresAt: meta.expiresAt.toISOString(),
        note: "File is being scanned for malware. The link works once the scan finds no threats.",
      });
    } catch (e) {
      console.error("Upload error:", e);
      res.status(500).json({ error: "Storage error during upload" });
    }
  });
});

// Anonymous download page: shows status, then streams the file
app.get("/d/:token", downloadLimiter, async (req, res) => {
  try {
    const meta = await getFileMeta(req.params.token);

    // Expired or never existed: identical response, no information leak
    if (!meta || Date.now() > meta.expiresAt.getTime()) {
      if (meta) await deleteFile(meta.token); // eager cleanup ahead of lifecycle policy
      return res.status(404).send(page("Link not found", "This link is invalid or has expired. Links are valid for 7 days."));
    }

    if (meta.scanStatus === "malicious") {
      await deleteFile(meta.token);
      return res.status(403).send(page("File blocked", "This file was flagged by malware scanning and has been removed."));
    }

    if (meta.scanStatus === "pending") {
      res.setHeader("Retry-After", "30");
      return res.status(503).send(page("Scan in progress", "This file is still being scanned for viruses. Try again in a minute.", true));
    }

    const stream = await streamFile(meta.token);
    if (!stream) return res.status(404).send(page("Link not found", "This link is invalid or has expired."));

    const safeName = meta.originalName.replace(/["\r\n\\]/g, "_");
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Length", meta.size);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}"; filename*=UTF-8''${encodeURIComponent(meta.originalName)}`
    );
    stream.pipe(res);
  } catch (e) {
    console.error("Download error:", e);
    res.status(500).send(page("Error", "Something went wrong. Try again later."));
  }
});

app.get("/healthz", (_req, res) => res.json({ ok: true }));

function page(title: string, body: string, refresh = false): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>
${refresh ? '<meta http-equiv="refresh" content="30">' : ""}
<style>body{font-family:system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;background:#f5f5f5}
main{background:#fff;padding:2.5rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:420px;text-align:center}</style>
</head><body><main><h1>${title}</h1><p>${body}</p></main></body></html>`;
}

app.listen(config.port, () => {
  console.log(`secureshare listening on ${config.baseUrl} (port ${config.port})`);
});
