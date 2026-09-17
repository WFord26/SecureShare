import { BlobServiceClient, ContainerClient } from "@azure/storage-blob";
import { DefaultAzureCredential } from "@azure/identity";
import crypto from "crypto";
import { config } from "./config";

// Blob index tag written by Microsoft Defender for Storage on upload malware scanning.
// Documented values: "No threats found", "Malicious", "Not scanned", "Error" (error values may carry
// a SAM code and detail text). Only an exact "No threats found" counts as clean; anything else that
// is not clearly malicious is treated as unscanned so an unexpected value can never be served by mistake.
const SCAN_TAG = "Malware Scanning scan result";
const SCAN_CLEAN = "No threats found";

/**
 * pending:    no result yet (scan usually completes within a minute)
 * clean:      safe to serve
 * malicious:  delete and block
 * unscanned:  Defender could not scan it (encrypted archive, unsupported type, scan error, monthly cap
 *             reached) or wrote a value this code does not recognize. Fail closed.
 */
export type ScanStatus = "clean" | "malicious" | "pending" | "unscanned";

export interface FileMeta {
  token: string;
  originalName: string;
  contentType: string;
  size: number;
  uploadedBy: string;
  /** Entra object ID of the uploader (empty for files uploaded before this field existed) */
  uploaderOid: string;
  uploadedAt: Date;
  expiresAt: Date;
  scanStatus: ScanStatus;
}

export const blobEndpoint = `https://${config.storageAccount}.blob.${config.storageEndpointSuffix}`;

function getContainerClient(): ContainerClient {
  const service = config.storageConnectionString
    ? BlobServiceClient.fromConnectionString(config.storageConnectionString)
    : new BlobServiceClient(blobEndpoint, new DefaultAzureCredential());
  return service.getContainerClient(config.storageContainer);
}

const container = getContainerClient();

/** Cryptographically random, URL safe, unguessable token. Also the blob name. */
export function newToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}

const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export function isValidToken(token: string): boolean {
  return TOKEN_RE.test(token);
}

function b64(s: string): string {
  return Buffer.from(s, "utf8").toString("base64");
}
function unb64(s: string | undefined): string {
  return s ? Buffer.from(s, "base64").toString("utf8") : "";
}

export function parseScanTag(value: string | undefined): ScanStatus {
  if (value === undefined) return "pending";
  if (value === SCAN_CLEAN) return "clean";
  if (value.toLowerCase().includes("malicious")) return "malicious";
  return "unscanned";
}

export async function uploadFile(
  buffer: Buffer,
  originalName: string,
  contentType: string,
  uploadedBy: string,
  uploaderOid: string
): Promise<FileMeta> {
  const token = newToken();
  const now = new Date();
  const blob = container.getBlockBlobClient(token);
  await blob.uploadData(buffer, {
    blobHTTPHeaders: { blobContentType: contentType || "application/octet-stream" },
    metadata: {
      // Base64 encode to keep arbitrary filenames valid as metadata values
      originalname: b64(originalName),
      uploadedby: b64(uploadedBy),
      uploaderoid: uploaderOid,
      uploadedat: now.toISOString(),
    },
  });
  return {
    token,
    originalName,
    contentType,
    size: buffer.length,
    uploadedBy,
    uploaderOid,
    uploadedAt: now,
    expiresAt: new Date(now.getTime() + config.linkTtlMs),
    scanStatus: "pending",
  };
}

export async function getFileMeta(token: string): Promise<FileMeta | null> {
  // Reject anything that is not a well formed token before touching storage
  if (!isValidToken(token)) return null;
  const blob = container.getBlockBlobClient(token);
  try {
    const props = await blob.getProperties();
    const uploadedAt = props.metadata?.uploadedat
      ? new Date(props.metadata.uploadedat)
      : props.createdOn ?? new Date(0);

    let scanStatus: ScanStatus = "pending";
    try {
      const tags = await blob.getTags();
      scanStatus = parseScanTag(tags.tags[SCAN_TAG]);
    } catch (err) {
      // Most likely the app identity lacks tag read permission (needs Storage Blob Data Owner).
      // Fail closed: the file stays "pending" and is never served. Log so it is diagnosable.
      console.error(`Could not read scan tags for blob (check Storage Blob Data Owner role): ${(err as Error).message}`);
    }

    return {
      token,
      originalName: unb64(props.metadata?.originalname) || "download",
      contentType: props.contentType ?? "application/octet-stream",
      size: props.contentLength ?? 0,
      uploadedBy: unb64(props.metadata?.uploadedby),
      uploaderOid: props.metadata?.uploaderoid ?? "",
      uploadedAt,
      expiresAt: new Date(uploadedAt.getTime() + config.linkTtlMs),
      scanStatus,
    };
  } catch (err: unknown) {
    const code = (err as { statusCode?: number }).statusCode;
    if (code === 404) return null;
    throw err;
  }
}

/** True if this file belongs to the given user. Matches on object ID, falling back to email for older uploads. */
export function isOwner(meta: { uploaderOid: string; uploadedBy: string }, oid: string, email: string): boolean {
  if (meta.uploaderOid) return meta.uploaderOid === oid;
  return !!meta.uploadedBy && !!email && meta.uploadedBy.toLowerCase() === email.toLowerCase();
}

/**
 * All files uploaded by one user, newest first. One list call with metadata and tags included,
 * so it costs a single request regardless of how many files there are. Expired files are skipped
 * and deleted in the background.
 */
export async function listFilesForUser(oid: string, email: string): Promise<FileMeta[]> {
  const out: FileMeta[] = [];
  const expired: string[] = [];
  for await (const blob of container.listBlobsFlat({ includeMetadata: true, includeTags: true })) {
    if (!isValidToken(blob.name)) continue;
    const md = blob.metadata ?? {};
    const meta = { uploaderOid: md.uploaderoid ?? "", uploadedBy: unb64(md.uploadedby) };
    if (!isOwner(meta, oid, email)) continue;
    const uploadedAt = md.uploadedat ? new Date(md.uploadedat) : blob.properties.createdOn ?? new Date(0);
    const expiresAt = new Date(uploadedAt.getTime() + config.linkTtlMs);
    if (Date.now() > expiresAt.getTime()) {
      expired.push(blob.name);
      continue;
    }
    out.push({
      token: blob.name,
      originalName: unb64(md.originalname) || "download",
      contentType: blob.properties.contentType ?? "application/octet-stream",
      size: blob.properties.contentLength ?? 0,
      uploadedBy: meta.uploadedBy,
      uploaderOid: meta.uploaderOid,
      uploadedAt,
      expiresAt,
      scanStatus: parseScanTag(blob.tags?.[SCAN_TAG]),
    });
  }
  if (expired.length) {
    Promise.all(expired.map(deleteFile)).catch((e) => console.error("Eager expiry cleanup failed:", e));
  }
  return out.sort((a, b) => b.uploadedAt.getTime() - a.uploadedAt.getTime());
}

export async function streamFile(token: string): Promise<NodeJS.ReadableStream | null> {
  if (!isValidToken(token)) return null;
  const blob = container.getBlockBlobClient(token);
  const resp = await blob.download();
  return resp.readableStreamBody ?? null;
}

export async function deleteFile(token: string): Promise<void> {
  if (!isValidToken(token)) return;
  await container.getBlockBlobClient(token).deleteIfExists();
}

/** Startup check: confirms credentials and container reachability. Throws with a readable message. */
export async function verifyStorageAccess(): Promise<void> {
  const exists = await container.exists();
  if (!exists) {
    throw new Error(`Container "${config.storageContainer}" not found at ${blobEndpoint} (or no permission to see it)`);
  }
}
