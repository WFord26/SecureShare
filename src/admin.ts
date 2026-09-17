import { Router, Request, Response } from "express";
import { config } from "./config";
import { requireAuditor, requireAuditorApi } from "./auth";
import * as audit from "./audit";

/*
 * Activity log API and CSV exports, for holders of the AUDIT_ROLE app role.
 * Ranges are passed as ISO timestamps (the page converts the viewer's local dates) and are clamped to the retention window.
 */

export const adminRouter = Router();

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_UPLOAD_ROWS = 5000;
const MAX_DOWNLOAD_ROWS = 5000;
const REF_RE = /^[0-9a-f]{12}$/;

function parseRange(req: Request): { from: Date; to: Date } | null {
  const now = Date.now();
  const q = req.query as Record<string, unknown>;
  const to = typeof q.to === "string" && q.to ? new Date(q.to) : new Date(now);
  const from = typeof q.from === "string" && q.from ? new Date(q.from) : new Date(to.getTime() - 30 * DAY_MS);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) || from >= to) return null;
  const earliest = now - config.auditRetentionDays * DAY_MS - DAY_MS;
  return { from: new Date(Math.max(from.getTime(), earliest)), to: new Date(Math.min(to.getTime(), now + DAY_MS)) };
}

/** Counted as a download: the whole file reached a browser. Link scanners and cut off transfers are counted separately. */
function isDownload(d: audit.DownloadRecord): boolean {
  return d.outcome === "served" && !d.automated;
}

adminRouter.get("/api/admin/report", requireAuditorApi, async (req, res, next) => {
  try {
    const range = parseRange(req);
    if (!range) return res.status(400).json({ error: "Invalid date range" });
    const [uploads, events] = await Promise.all([audit.listUploads(range.from, range.to), audit.listDownloads(range.from, range.to)]);

    const uploaders = new Map<string, { name: string; email: string; uploads: number; bytes: number; downloads: number }>();
    for (const u of uploads) {
      const key = u.uploaderOid || u.uploaderEmail.toLowerCase();
      const row = uploaders.get(key) ?? { name: u.uploaderName, email: u.uploaderEmail, uploads: 0, bytes: 0, downloads: 0 };
      row.uploads++;
      row.bytes += u.size;
      row.downloads += u.downloads;
      if (!row.name && u.uploaderName) row.name = u.uploaderName;
      uploaders.set(key, row);
    }

    const downloaders = new Map<string, { ip: string; downloads: number; files: Set<string>; lastAt: Date; userAgent: string }>();
    for (const d of events) {
      if (!isDownload(d)) continue;
      const row = downloaders.get(d.ip) ?? { ip: d.ip, downloads: 0, files: new Set<string>(), lastAt: d.at, userAgent: d.userAgent };
      row.downloads++;
      row.files.add(d.ref);
      if (d.at > row.lastAt) {
        row.lastAt = d.at;
        row.userAgent = d.userAgent;
      }
      downloaders.set(d.ip, row);
    }

    const count = (pred: (d: audit.DownloadRecord) => boolean) => events.filter(pred).length;
    res.json({
      from: range.from.toISOString(),
      to: range.to.toISOString(),
      retentionDays: config.auditRetentionDays,
      summary: {
        uploads: uploads.length,
        uploadBytes: uploads.reduce((n, u) => n + u.size, 0),
        uploaders: uploaders.size,
        downloads: count(isDownload),
        downloadBytes: events.filter(isDownload).reduce((n, d) => n + d.bytes, 0),
        downloaderIps: downloaders.size,
        incomplete: count((d) => d.outcome === "incomplete" && !d.automated),
        automated: count((d) => d.automated && (d.outcome === "served" || d.outcome === "incomplete" || d.outcome === "head")),
        blocked: uploads.filter((u) => u.state === "blocked").length,
        revoked: uploads.filter((u) => u.state === "revoked").length,
      },
      uploaders: [...uploaders.values()].sort((a, b) => b.uploads - a.uploads || b.bytes - a.bytes),
      downloaders: [...downloaders.values()]
        .sort((a, b) => b.downloads - a.downloads)
        .slice(0, 100)
        .map((d) => ({ ip: d.ip, downloads: d.downloads, files: d.files.size, lastAt: d.lastAt, userAgent: d.userAgent })),
      uploads: uploads.slice(0, MAX_UPLOAD_ROWS),
      uploadsTruncated: uploads.length > MAX_UPLOAD_ROWS,
      events: events.slice(0, MAX_DOWNLOAD_ROWS),
      eventsTruncated: events.length > MAX_DOWNLOAD_ROWS,
    });
  } catch (e) {
    next(e);
  }
});

adminRouter.get("/api/admin/files/:ref/downloads", requireAuditorApi, async (req, res, next) => {
  try {
    if (!REF_RE.test(req.params.ref)) return res.status(404).json({ error: "Not found" });
    res.json({ events: await audit.listDownloadsForFile(req.params.ref) });
  } catch (e) {
    next(e);
  }
});

// ------------------------------------------------------------------ CSV export

function csvCell(v: unknown): string {
  let s = v instanceof Date ? v.toISOString() : v === undefined || v === null ? "" : String(v);
  // Spreadsheet formula injection: file names and user agents are user controlled
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function sendCsv(res: Response, name: string, header: string[], rows: unknown[][]): void {
  const body = [header, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
  res.send("﻿" + body + "\r\n"); // BOM so Excel reads UTF-8 file names correctly
}

function stamp(range: { from: Date; to: Date }): string {
  return `${range.from.toISOString().slice(0, 10)}_to_${range.to.toISOString().slice(0, 10)}`;
}

adminRouter.get("/admin/export/uploads.csv", requireAuditor, async (req, res, next) => {
  try {
    const range = parseRange(req);
    if (!range) return res.status(400).send("Invalid date range");
    const uploads = await audit.listUploads(range.from, range.to);
    sendCsv(
      res,
      `secureshare-uploads_${stamp(range)}.csv`,
      ["Uploaded (UTC)", "File", "Size (bytes)", "Uploader", "Uploader email", "Tenant", "Upload IP", "Scan result", "Status", "Ended (UTC)", "Ended by", "Downloads", "Incomplete downloads", "Automated fetches", "Bytes served", "Last download (UTC)", "Expires (UTC)", "File ref"],
      uploads.map((u) => [u.uploadedAt, u.fileName, u.size, u.uploaderName, u.uploaderEmail, u.uploaderTenant, u.uploadIp, u.scanStatus, u.state, u.endedAt, u.endedBy, u.downloads, u.incompleteDownloads, u.automatedFetches, u.bytesServed, u.lastDownloadAt, u.expiresAt, u.ref])
    );
  } catch (e) {
    next(e);
  }
});

adminRouter.get("/admin/export/downloads.csv", requireAuditor, async (req, res, next) => {
  try {
    const range = parseRange(req);
    if (!range) return res.status(400).send("Invalid date range");
    const events = await audit.listDownloads(range.from, range.to);
    sendCsv(
      res,
      `secureshare-downloads_${stamp(range)}.csv`,
      ["Time (UTC)", "File", "Uploaded by", "IP address", "Result", "Automated", "Bytes", "Duration (ms)", "User agent", "File ref"],
      events.map((d) => [d.at, d.fileName, d.uploaderEmail, d.ip, d.outcome, d.automated ? "yes" : "no", d.bytes, d.durationMs, d.userAgent, d.ref])
    );
  } catch (e) {
    next(e);
  }
});
