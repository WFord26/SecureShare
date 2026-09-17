import dotenv from "dotenv";
dotenv.config();

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required environment variable: ${name}`);
  return v;
}

function num(name: string, fallback: number, min = 1): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < min) throw new Error(`Environment variable ${name} must be a number >= ${min}, got "${raw}"`);
  return n;
}

function list(name: string): string[] {
  return (process.env[name] ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

// Entra tenant the app signs users in against.
//   Single tenant (default): the tenant ID GUID of your organization.
//   Multi tenant: "organizations" plus ALLOWED_TENANT_IDS (comma separated GUIDs).
const tenantId = required("TENANT_ID");
const multiTenant = ["common", "organizations"].includes(tenantId.toLowerCase());
const allowedTenantIds = multiTenant ? list("ALLOWED_TENANT_IDS") : [tenantId.toLowerCase()];
if (multiTenant && allowedTenantIds.length === 0) {
  throw new Error(`ALLOWED_TENANT_IDS is required when TENANT_ID is "${tenantId}"`);
}

const linkTtlDays = num("LINK_TTL_DAYS", 7);

// What to do when Defender has not produced a clean verdict for a file.
//   required (default): never serve a file without a clean verdict (fail closed). Files Defender could not
//                       scan (encrypted archives, scan errors, monthly scan cap reached) are never served.
//   best-effort:        wait SCAN_GRACE_MINUTES after upload for a verdict, then serve the file anyway.
//                       Malware is still blocked, but anything unscanned is served. Only for environments
//                       where a stranded link is worse than an unscanned download.
const scanPolicy = (process.env.SCAN_POLICY ?? "required").toLowerCase();
if (scanPolicy !== "best-effort" && scanPolicy !== "required") {
  throw new Error(`SCAN_POLICY must be "best-effort" or "required", got "${scanPolicy}"`);
}

const baseUrl = (process.env.BASE_URL ?? "http://localhost:3000").replace(/\/$/, "");

export const config = {
  tenantId,
  multiTenant,
  allowedTenantIds,
  clientId: required("CLIENT_ID"),
  clientSecret: required("CLIENT_SECRET"),
  // Entra authority host.
  //   Global / US commercial (default): https://login.microsoftonline.com
  //   Azure China (21Vianet):           https://login.partner.microsoftonline.cn
  //   Azure US Government:              https://login.microsoftonline.us
  authorityHost: (process.env.AUTHORITY_HOST ?? "https://login.microsoftonline.com").replace(/\/$/, ""),
  baseUrl,
  baseOrigin: new URL(baseUrl).origin,
  isHttps: baseUrl.startsWith("https://"),
  storageAccount: required("STORAGE_ACCOUNT"),
  storageContainer: process.env.STORAGE_CONTAINER ?? "uploads",
  // Blob endpoint DNS suffix. Global: core.windows.net, China: core.chinacloudapi.cn, US Gov: core.usgovcloudapi.net
  storageEndpointSuffix: process.env.STORAGE_ENDPOINT_SUFFIX ?? "core.windows.net",
  storageConnectionString: process.env.STORAGE_CONNECTION_STRING || undefined,
  sessionSecret: required("SESSION_SECRET"),
  port: num("PORT", 3000),
  maxUploadBytes: num("MAX_UPLOAD_MB", 100) * 1024 * 1024,
  // Uploads are buffered in memory, so this bounds worst case memory at MAX_CONCURRENT_UPLOADS * MAX_UPLOAD_MB
  maxConcurrentUploads: num("MAX_CONCURRENT_UPLOADS", 4),
  linkTtlDays,
  linkTtlMs: linkTtlDays * 24 * 60 * 60 * 1000,
  scanPolicy: scanPolicy as "best-effort" | "required",
  scanGraceMs: num("SCAN_GRACE_MINUTES", 2, 0) * 60 * 1000,
  // Activity log (upload and download records in Azure Table Storage)
  auditRetentionDays: num("AUDIT_RETENTION_DAYS", 730),
  // App role value on the app registration that grants access to the activity log page
  auditRole: process.env.AUDIT_ROLE || "Audit.Read",
};

if (config.sessionSecret.length < 32) {
  console.warn("WARNING: SESSION_SECRET is short; use at least 32 random characters.");
}
if (config.scanPolicy === "best-effort") {
  console.warn("WARNING: SCAN_POLICY=best-effort serves files that Defender did not scan. Use \"required\" in production.");
}
