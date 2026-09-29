import crypto from "crypto";

/** Strip control characters and cap length so user supplied strings cannot forge log lines. */
export function logSafe(s: unknown, max = 200): string {
  return String(s ?? "")
    .replace(/[^\x20-\x7e]/g, "?")
    .slice(0, max);
}

/** Short non-reversible reference to a download token, safe to write to logs. */
export function tokenRef(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex").slice(0, 12);
}

/**
 * Client IP without a port. App Service puts "ip:port" in X-Forwarded-For (IPv6 as "[addr]:port") and Express's
 * req.ip passes that through, so anything keyed on req.ip would otherwise treat every connection as a new client.
 */
/** Reads one cookie's value out of a raw Cookie header, without pulling in the cookie-parser middleware. */
export function getCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export function clientIp(raw: string | undefined): string {
  let ip = (raw ?? "").trim();
  const v6 = ip.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (v6) ip = v6[1];
  else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(ip)) ip = ip.slice(0, ip.lastIndexOf(":"));
  if (ip.startsWith("::ffff:") && ip.includes(".")) ip = ip.slice(7);
  return ip.slice(0, 64);
}
