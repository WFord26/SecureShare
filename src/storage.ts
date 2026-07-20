import {
  BlobServiceClient,
  ContainerClient,
} from "@azure/storage-blob";
import { DefaultAzureCredential } from "@azure/identity";
import crypto from "crypto";
import { config } from "./config";

// Blob index tag written by Microsoft Defender for Storage on upload scan
const SCAN_TAG = "Malware Scanning scan result";
const SCAN_CLEAN = "No threats found";
const SCAN_MALICIOUS = "Malicious";

export type ScanStatus = "clean" | "malicious" | "pending";

export interface FileMeta {
  token: string;
  originalName: string;
  contentType: string;
  size: number;
  uploadedBy: string;
  uploadedAt: Date;
  expiresAt: Date;
  scanStatus: ScanStatus;
}

function getContainerClient(): ContainerClient {
  // Identity based auth only; shared key access is disabled on the account
  const service = new BlobServiceClient(
    `https://${config.storageAccount}.blob.core.windows.net`,
    new DefaultAzureCredential()
  );
  return service.getContainerClient(config.storageContainer);
}

const container = getContainerClient();

/** Cryptographically random, URL safe, unguessable token. Also the blob name. */
export function newToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}

export async function uploadFile(
  buffer: Buffer,
  originalName: string,
  contentType: string,
  uploadedBy: string
): Promise<FileMeta> {
  const token = newToken();
  const now = new Date();
  const blob = container.getBlockBlobClient(token);
  await blob.uploadData(buffer, {
    blobHTTPHeaders: { blobContentType: contentType || "application/octet-stream" },
    metadata: {
      // Base64 encode to keep arbitrary filenames valid as metadata values
      originalname: Buffer.from(originalName, "utf8").toString("base64"),
      uploadedby: Buffer.from(uploadedBy, "utf8").toString("base64"),
      uploadedat: now.toISOString(),
    },
  });
  return {
    token,
    originalName,
    contentType,
    size: buffer.length,
    uploadedBy,
    uploadedAt: now,
    expiresAt: new Date(now.getTime() + config.linkTtlMs),
    scanStatus: "pending",
  };
}

export async function getFileMeta(token: string): Promise<FileMeta | null> {
  // Reject anything that is not a well formed token before touching storage
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const blob = container.getBlockBlobClient(token);
  try {
    const props = await blob.getProperties();
    const uploadedAt = props.metadata?.uploadedat
      ? new Date(props.metadata.uploadedat)
      : props.createdOn ?? new Date(0);

    let scanStatus: ScanStatus = "pending";
    try {
      const tags = await blob.getTags();
      const result = tags.tags[SCAN_TAG];
      if (result === SCAN_CLEAN) scanStatus = "clean";
      else if (result === SCAN_MALICIOUS || result?.toLowerCase().includes("malicious"))
        scanStatus = "malicious";
    } catch {
      // No tag permission or no tags yet: treat as pending
    }

    return {
      token,
      originalName: props.metadata?.originalname
        ? Buffer.from(props.metadata.originalname, "base64").toString("utf8")
        : "download",
      contentType: props.contentType ?? "application/octet-stream",
      size: props.contentLength ?? 0,
      uploadedBy: props.metadata?.uploadedby
        ? Buffer.from(props.metadata.uploadedby, "base64").toString("utf8")
        : "",
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

export async function streamFile(token: string): Promise<NodeJS.ReadableStream | null> {
  const blob = container.getBlockBlobClient(token);
  const resp = await blob.download();
  return resp.readableStreamBody ?? null;
}

export async function deleteFile(token: string): Promise<void> {
  await container.getBlockBlobClient(token).deleteIfExists();
}
