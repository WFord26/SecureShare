import dotenv from "dotenv";
dotenv.config();

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required environment variable: ${name}`);
  return v;
}

export const config = {
  tenantId: required("TENANT_ID"),
  clientId: required("CLIENT_ID"),
  clientSecret: required("CLIENT_SECRET"),
  // Entra authority host. Global: https://login.microsoftonline.com
  // Azure China (21Vianet): https://login.partner.microsoftonline.cn
  authorityHost: (process.env.AUTHORITY_HOST ?? "https://login.microsoftonline.com").replace(/\/$/, ""),
  baseUrl: (process.env.BASE_URL ?? "http://localhost:3000").replace(/\/$/, ""),
  storageAccount: required("STORAGE_ACCOUNT"),
  storageContainer: process.env.STORAGE_CONTAINER ?? "uploads",
  sessionSecret: required("SESSION_SECRET"),
  port: parseInt(process.env.PORT ?? "3000", 10),
  maxUploadBytes: parseInt(process.env.MAX_UPLOAD_MB ?? "100", 10) * 1024 * 1024,
  linkTtlMs: parseInt(process.env.LINK_TTL_DAYS ?? "7", 10) * 24 * 60 * 60 * 1000,
};
