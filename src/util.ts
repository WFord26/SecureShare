import crypto from "crypto";
import { isIPv4, isIPv6 } from "net";

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
    const cookieName = part.slice(0, eq).trim();
    if (cookieName !== name) continue;
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
  
  // Handle IPv6 format with port: [addr]:port
  const v6 = ip.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (v6) {
    ip = v6[1];
    if (!isIPv6(ip)) return ""; // Invalid IPv6
    return ip.slice(0, 64);
  }
  
  // Handle IPv4 format with port: addr:port
  const colonIdx = ip.lastIndexOf(":");
  if (colonIdx > 0) {
    const potentialIp = ip.slice(0, colonIdx);
    const potentialPort = ip.slice(colonIdx + 1);
    // Validate it's IPv4 format with a valid port number
    if (isIPv4(potentialIp) && /^\d+$/.test(potentialPort)) {
      ip = potentialIp;
    }
  } else if (!isIPv4(ip) && !isIPv6(ip)) {
    // If no port separator and it's not a valid IP, it may be malformed
    return ip.slice(0, 64);
  }
  
  // Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:192.0.2.1)
  if (ip.startsWith("::ffff:") && ip.includes(".")) {
    const mappedIp = ip.slice(7);
    if (isIPv4(mappedIp)) {
      ip = mappedIp;
    }
  }
  
  return ip.slice(0, 64);
}
