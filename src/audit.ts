import { TableClient, odata, RestError, TransactionAction } from "@azure/data-tables";
import { DefaultAzureCredential } from "@azure/identity";
import crypto from "crypto";
import { config } from "./config";
import type { FileMeta, ScanStatus } from "./storage";
import { tokenRef } from "./util";

/*
 * Activity log in Azure Table Storage, in the same storage account as the files.
 * The blob lifecycle policy only deletes blobs, so these records outlive the files they describe.
 * Records are deleted AUDIT_RETENTION_DAYS after they were written (daily purge).
 *
 * uploadlog    PartitionKey = upload month "YYYY-MM" (UTC), RowKey = file ref.
 *              One row per upload with running download counters.
 * downloadlog  PartitionKey = file ref, RowKey = inverted time + random (newest first).
 *              One row per request for a download link.
 *
 * The file ref is a one way hash of the link token (util.tokenRef). The token itself is never stored,
 * so neither the tables nor the activity log page can be used to download a file.
 *
 * Logging never blocks or fails a user request: writes run in the background and errors are only logged.
 */

export const UPLOAD_TABLE = "uploadlog";
export const DOWNLOAD_TABLE = "downloadlog";

export type UploadState = "active" | "expired" | "revoked" | "blocked";

/**
 * served       whole file sent
 * incomplete   connection closed before the file finished (cancelled, network drop)
 * head         HEAD request, headers only (link checkers)
 * waiting      scan in progress page shown
 * blocked      malware found, file deleted
 * unscannable  SCAN_POLICY=required and Defender could not scan it
 * expired      link past its expiry
 * error        storage error while sending
 */
export type DownloadOutcome = "served" | "incomplete" | "head" | "waiting" | "blocked" | "unscannable" | "expired" | "error";

export interface UploadRecord {
  ref: string;
  fileName: string;
  contentType: string;
  size: number;
  uploaderName: string;
  uploaderEmail: string;
  uploaderOid: string;
  uploaderTenant: string;
  uploadIp: string;
  uploadedAt: Date;
  expiresAt: Date;
  scanStatus: ScanStatus;
  state: UploadState;
  endedAt?: Date;
  endedBy?: string;
  /** Completed downloads by browsers (automated fetches excluded) */
  downloads: number;
  incompleteDownloads: number;
  automatedFetches: number;
  bytesServed: number;
  lastDownloadAt?: Date;
}

export interface DownloadRecord {
  ref: string;
  at: Date;
  fileName: string;
  uploaderEmail: string;
  ip: string;
  userAgent: string;
  automated: boolean;
  outcome: DownloadOutcome;
  bytes: number;
  durationMs: number;
}

const tableUrl = `https://${config.storageAccount}.table.${config.storageEndpointSuffix}`;

function tableClient(name: string): TableClient {
  return config.storageConnectionString
    ? TableClient.fromConnectionString(config.storageConnectionString, name)
    : new TableClient(tableUrl, name, new DefaultAzureCredential());
}

const uploads = tableClient(UPLOAD_TABLE);
const downloads = tableClient(DOWNLOAD_TABLE);

const MAX_TICKS = 8_640_000_000_000_000; // max JS date in ms; inverted so newer rows sort first

function monthOf(d: Date): string {
  return d.toISOString().slice(0, 7);
}

function statusCode(err: unknown): number | undefined {
  return err instanceof RestError ? err.statusCode : (err as { statusCode?: number })?.statusCode;
}

function clip(s: string | undefined, max: number): string {
  return (s ?? "").slice(0, max);
}

function background(what: string, p: Promise<unknown>): void {
  p.catch((e) => console.error(`Activity log: ${what} failed: ${(e as Error).message}`));
}

// ------------------------------------------------------------------ Request helpers

// Link preview and security scanners that fetch links on their own. Not exhaustive: Defender for Office 365
// Safe Links detonation uses an ordinary browser user agent and cannot be told apart this way.
const AUTOMATED_UA =
  /bot\b|bot\/|crawler|spider|slurp|preview|facebookexternalhit|embedly|whatsapp|skypeuri|microsoft office|ms-office|outlook-|urlscan|proofpoint|mimecast|barracuda|curl\/|wget\/|python-|go-http-client|okhttp|java\/|axios\/|node-fetch|undici|headless/i;

export function isAutomated(userAgent: string | undefined): boolean {
  return !userAgent || AUTOMATED_UA.test(userAgent);
}

// ------------------------------------------------------------------ Upload records

type UploadEntity = Omit<UploadRecord, "ref"> & { partitionKey: string; rowKey: string };

type Stored<T> = T & { etag?: string; timestamp?: string };

/** Drop the service managed properties so a row can be written back. */
function strip<T extends object>(e: Stored<T>): T {
  const { etag: _etag, timestamp: _timestamp, ...rest } = e;
  return rest as T;
}

function toRecord(e: Stored<UploadEntity>): UploadRecord {
  const { partitionKey: _pk, rowKey, ...rest } = strip(e);
  const r: UploadRecord = { ref: rowKey, ...rest };
  if (r.state === "active" && Date.now() > r.expiresAt.getTime()) r.state = "expired";
  return r;
}

function newUploadEntity(meta: FileMeta, extra: Partial<UploadRecord> = {}): UploadEntity {
  return {
    partitionKey: monthOf(meta.uploadedAt),
    rowKey: tokenRef(meta.token),
    fileName: clip(meta.originalName, 1024),
    contentType: clip(meta.contentType, 256),
    size: meta.size,
    uploaderName: "",
    uploaderEmail: clip(meta.uploadedBy, 256),
    uploaderOid: meta.uploaderOid,
    uploaderTenant: "",
    uploadIp: "",
    uploadedAt: meta.uploadedAt,
    expiresAt: meta.expiresAt,
    scanStatus: meta.scanStatus,
    state: "active",
    downloads: 0,
    incompleteDownloads: 0,
    automatedFetches: 0,
    bytesServed: 0,
    ...extra,
  };
}

// Serialize updates per upload so concurrent downloads of one file do not fight over the counters.
const chains = new Map<string, Promise<void>>();

function serialized(token: string, fn: () => Promise<void>): Promise<void> {
  const prev = chains.get(token) ?? Promise.resolve();
  const next = prev.catch(() => undefined).then(fn);
  chains.set(token, next);
  const cleanup = () => {
    if (chains.get(token) === next) chains.delete(token);
  };
  next.then(cleanup, cleanup);
  return next;
}

/**
 * Read, change and write back one upload row with optimistic concurrency.
 * Creates the row from the blob metadata if it is missing (files uploaded before logging existed).
 */
function mutateUpload(meta: FileMeta, change: (e: UploadEntity) => void): Promise<void> {
  return serialized(meta.token, async () => {
    const pk = monthOf(meta.uploadedAt);
    for (let attempt = 0; attempt < 5; attempt++) {
      let entity: UploadEntity;
      let etag: string | undefined;
      try {
        const stored = await uploads.getEntity<UploadEntity>(pk, tokenRef(meta.token));
        etag = stored.etag;
        entity = strip(stored);
      } catch (e) {
        if (statusCode(e) !== 404) throw e;
        entity = newUploadEntity(meta);
      }
      change(entity);
      try {
        if (etag) await uploads.updateEntity(entity, "Replace", { etag });
        else await uploads.createEntity(entity);
        return;
      } catch (e) {
        const code = statusCode(e);
        if (code !== 412 && code !== 409) throw e; // changed or created underneath us: reread
      }
    }
    throw new Error(`gave up updating upload ${meta.token.slice(0, 6)}… after repeated conflicts`);
  });
}

export function recordUpload(meta: FileMeta, user: { name: string; email: string; oid: string; tid: string }, ip: string): void {
  const entity = newUploadEntity(meta, {
    uploaderName: clip(user.name, 256),
    uploaderEmail: clip(user.email, 256),
    uploaderOid: user.oid,
    uploaderTenant: user.tid,
    uploadIp: ip,
  });
  // Queued like every other change to the row, so a download arriving right away cannot be overwritten
  background("upload record", serialized(meta.token, () => uploads.upsertEntity(entity, "Replace").then(() => undefined)));
}

/** Link revoked by its uploader, or file deleted because malware was found. */
export function recordEnded(meta: FileMeta, state: "revoked" | "blocked", by: string): void {
  background(
    `${state} record`,
    mutateUpload(meta, (e) => {
      if (e.state === "active") {
        e.state = state;
        e.endedAt = new Date();
        e.endedBy = clip(by, 256);
      }
      if (state === "blocked") e.scanStatus = "malicious";
    })
  );
}

// Final scan verdicts already written, so polling the uploads list does not rewrite rows
const scanRecorded = new Set<string>();

/** Store a scan verdict the first time the app sees it. */
export function recordScanStatus(meta: FileMeta): void {
  if (meta.scanStatus === "pending") return;
  const key = `${meta.token}:${meta.scanStatus}`;
  if (scanRecorded.has(key)) return;
  scanRecorded.add(key);
  if (scanRecorded.size > 10_000) scanRecorded.clear();
  background(
    "scan status",
    mutateUpload(meta, (e) => {
      e.scanStatus = meta.scanStatus;
    })
  );
}

// ------------------------------------------------------------------ Download records

// The scan in progress page refreshes every 30 seconds; log it once per visitor per 10 minutes
const WAITING_QUIET_MS = 10 * 60 * 1000;
const waitingSeen = new Map<string, number>();

export function recordDownload(
  meta: FileMeta,
  req: { ip: string; userAgent: string | undefined },
  outcome: DownloadOutcome,
  bytes = 0,
  durationMs = 0
): void {
  const now = new Date();
  const automated = isAutomated(req.userAgent);

  if (outcome === "waiting") {
    const key = `${meta.token}|${req.ip}`;
    const last = waitingSeen.get(key);
    if (last && now.getTime() - last < WAITING_QUIET_MS) return;
    waitingSeen.set(key, now.getTime());
    if (waitingSeen.size > 5_000) {
      for (const [k, t] of waitingSeen) if (now.getTime() - t > WAITING_QUIET_MS) waitingSeen.delete(k);
    }
  }

  const entity: { partitionKey: string; rowKey: string } & Omit<DownloadRecord, "ref"> = {
    partitionKey: tokenRef(meta.token),
    rowKey: `${String(MAX_TICKS - now.getTime()).padStart(16, "0")}_${crypto.randomBytes(4).toString("hex")}`,
    at: now,
    fileName: clip(meta.originalName, 1024),
    uploaderEmail: clip(meta.uploadedBy, 256),
    ip: req.ip,
    userAgent: clip(req.userAgent, 512),
    automated,
    outcome,
    bytes,
    durationMs: Math.round(durationMs),
  };
  background("download record", downloads.createEntity(entity));

  background(
    "download counters",
    mutateUpload(meta, (e) => {
      if (meta.scanStatus !== "pending") e.scanStatus = meta.scanStatus;
      if (outcome !== "served" && outcome !== "incomplete") return;
      e.bytesServed = (e.bytesServed ?? 0) + bytes;
      if (automated) e.automatedFetches = (e.automatedFetches ?? 0) + 1;
      else if (outcome === "served") {
        e.downloads = (e.downloads ?? 0) + 1;
        e.lastDownloadAt = now;
      } else e.incompleteDownloads = (e.incompleteDownloads ?? 0) + 1;
    })
  );
}

// ------------------------------------------------------------------ Queries

export async function listUploads(from: Date, to: Date): Promise<UploadRecord[]> {
  const filter = odata`PartitionKey ge ${monthOf(from)} and PartitionKey le ${monthOf(to)} and uploadedAt ge ${from} and uploadedAt lt ${to}`;
  const out: UploadRecord[] = [];
  for await (const e of uploads.listEntities<UploadEntity>({ queryOptions: { filter } })) out.push(toRecord(e));
  return out.sort((a, b) => b.uploadedAt.getTime() - a.uploadedAt.getTime());
}

/** Upload rows for specific files, keyed by token. Missing rows are left out. */
export async function getUploads(metas: FileMeta[]): Promise<Map<string, UploadRecord>> {
  const out = new Map<string, UploadRecord>();
  await Promise.all(
    metas.map(async (m) => {
      try {
        out.set(m.token, toRecord(await uploads.getEntity<UploadEntity>(monthOf(m.uploadedAt), tokenRef(m.token))));
      } catch (e) {
        if (statusCode(e) !== 404) throw e;
      }
    })
  );
  return out;
}

type DownloadEntity = Omit<DownloadRecord, "ref"> & { partitionKey: string; rowKey: string };

function toDownload(e: DownloadEntity): DownloadRecord {
  return {
    ref: e.partitionKey,
    at: e.at,
    fileName: e.fileName,
    uploaderEmail: e.uploaderEmail,
    ip: e.ip,
    userAgent: e.userAgent,
    automated: e.automated,
    outcome: e.outcome,
    bytes: e.bytes ?? 0,
    durationMs: e.durationMs ?? 0,
  };
}

/** Every request for one file, newest first. */
export async function listDownloadsForFile(ref: string): Promise<DownloadRecord[]> {
  const out: DownloadRecord[] = [];
  const filter = odata`PartitionKey eq ${ref}`;
  for await (const e of downloads.listEntities<DownloadEntity>({ queryOptions: { filter } })) out.push(toDownload(e));
  return out;
}

/** Every request for any link in a time range, newest first. */
export async function listDownloads(from: Date, to: Date): Promise<DownloadRecord[]> {
  const out: DownloadRecord[] = [];
  const filter = odata`at ge ${from} and at lt ${to}`;
  for await (const e of downloads.listEntities<DownloadEntity>({ queryOptions: { filter } })) out.push(toDownload(e));
  return out.sort((a, b) => b.at.getTime() - a.at.getTime());
}

// ------------------------------------------------------------------ Setup and retention

/** Startup: creates the tables if missing (no-op when they exist). Throws with the service message. */
export async function verifyAuditAccess(): Promise<void> {
  await uploads.createTable();
  await downloads.createTable();
}

async function deleteMatching(client: TableClient, filter: string): Promise<number> {
  const byPartition = new Map<string, TransactionAction[]>();
  for await (const e of client.listEntities({ queryOptions: { filter, select: ["PartitionKey", "RowKey"] } })) {
    const list = byPartition.get(e.partitionKey!) ?? [];
    list.push(["delete", { partitionKey: e.partitionKey!, rowKey: e.rowKey! }]);
    byPartition.set(e.partitionKey!, list);
  }
  let count = 0;
  for (const actions of byPartition.values()) {
    // Batches must stay within one partition and 100 operations
    for (let i = 0; i < actions.length; i += 100) {
      const batch = actions.slice(i, i + 100);
      await client.submitTransaction(batch);
      count += batch.length;
    }
  }
  return count;
}

export async function purgeExpiredRecords(): Promise<void> {
  const cutoff = new Date(Date.now() - config.auditRetentionDays * 24 * 60 * 60 * 1000);
  const d = await deleteMatching(downloads, odata`at lt ${cutoff}`);
  const u = await deleteMatching(uploads, odata`uploadedAt lt ${cutoff}`);
  if (d || u) console.log(`Activity log retention: deleted ${u} upload and ${d} download records older than ${cutoff.toISOString()}`);
}

export function startRetentionPurge(): void {
  const run = () => background("retention purge", purgeExpiredRecords());
  setTimeout(run, 60 * 1000).unref(); // shortly after startup, then daily
  setInterval(run, 24 * 60 * 60 * 1000).unref();
}
