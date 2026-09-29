import crypto from "crypto";

/*
 * Optional download password for a link.
 *
 * The file itself is stored unchanged (so Defender can still scan it) and the app gates the download:
 * a recipient must post the right password on the link page before the file is streamed. Only a
 * scrypt hash of the password is kept, as blob metadata next to the file. The password is never
 * logged and never stored in the activity log.
 *
 * This module has no dependency on config so it can be unit tested on its own.
 */

export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 128;

// scrypt parameters. N is stored with the hash so it can be raised later without breaking existing files.
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const HASH_PREFIX = "scrypt";

/** Validate an uploader supplied password. Returns an error message, or null when it is acceptable. */
export function validatePassword(value: unknown): string | null {
  if (typeof value !== "string") return "Password must be text";
  if (value.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  if (value.length > MAX_PASSWORD_LENGTH) return `Password must be at most ${MAX_PASSWORD_LENGTH} characters`;
  if (!value.trim()) return "Password cannot be only spaces";
  return null;
}

function scrypt(password: string, salt: Buffer, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password.normalize("NFKC"), salt, KEY_LENGTH, { N: n, r: SCRYPT_R, p: SCRYPT_P, maxmem: 64 * 1024 * 1024 }, (err, key) =>
      err ? reject(err) : resolve(key)
    );
  });
}

/** One way hash for storage: "scrypt$N$salt$hash" (base64url parts, ASCII only so it fits blob metadata). */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = await scrypt(password, salt, SCRYPT_N);
  return [HASH_PREFIX, SCRYPT_N, salt.toString("base64url"), key.toString("base64url")].join("$");
}

/** Constant time check of a password against a stored hash. Malformed hashes never verify. */
export async function verifyPassword(password: string, stored: string | undefined): Promise<boolean> {
  if (!stored || typeof password !== "string" || password.length > MAX_PASSWORD_LENGTH) return false;
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== HASH_PREFIX) return false;
  const n = Number(parts[1]);
  if (!Number.isInteger(n) || n < 1024 || n > 1 << 20) return false;
  const salt = Buffer.from(parts[2], "base64url");
  const expected = Buffer.from(parts[3], "base64url");
  if (salt.length !== SALT_LENGTH || expected.length !== KEY_LENGTH) return false;
  const key = await scrypt(password, salt, n);
  return crypto.timingSafeEqual(key, expected);
}

// ------------------------------------------------------------------ Wrong password throttling

export interface AttemptLimits {
  /** Wrong guesses one client (IP) may make on one link before it is locked out */
  perClient: number;
  perClientWindowMs: number;
  /** Wrong guesses on one link across every client before the link is locked for everyone */
  perFile: number;
  perFileWindowMs: number;
}

export const DEFAULT_ATTEMPT_LIMITS: AttemptLimits = {
  perClient: 5,
  perClientWindowMs: 15 * 60 * 1000,
  perFile: 100,
  perFileWindowMs: 60 * 60 * 1000,
};

interface Window {
  count: number;
  startedAt: number;
}

/**
 * In memory counter of wrong password guesses (one instance, same as the rate limits).
 * A fixed window per client and per link: once the limit is reached, further guesses are refused
 * until the window ends. Right guesses clear the client's counter but not the link's.
 */
export class AttemptTracker {
  private readonly clients = new Map<string, Window>();
  private readonly files = new Map<string, Window>();
  private lastPrune = 0;

  constructor(private readonly limits: AttemptLimits = DEFAULT_ATTEMPT_LIMITS, private readonly now: () => number = Date.now) {}

  private static retry(w: Window | undefined, limit: number, windowMs: number, now: number): number {
    if (!w || now - w.startedAt >= windowMs) return 0;
    return w.count >= limit ? w.startedAt + windowMs - now : 0;
  }

  /** Milliseconds until this client may guess again on this link; 0 when a guess is allowed now. */
  retryAfterMs(token: string, ip: string): number {
    const now = this.now();
    return Math.max(
      AttemptTracker.retry(this.clients.get(`${token}|${ip}`), this.limits.perClient, this.limits.perClientWindowMs, now),
      AttemptTracker.retry(this.files.get(token), this.limits.perFile, this.limits.perFileWindowMs, now)
    );
  }

  private static bump(map: Map<string, Window>, key: string, windowMs: number, now: number): void {
    const w = map.get(key);
    if (!w || now - w.startedAt >= windowMs) map.set(key, { count: 1, startedAt: now });
    else w.count++;
  }

  /** Record a wrong guess. Returns the lockout that now applies (0 if more guesses are still allowed). */
  recordFailure(token: string, ip: string): number {
    const now = this.now();
    AttemptTracker.bump(this.clients, `${token}|${ip}`, this.limits.perClientWindowMs, now);
    AttemptTracker.bump(this.files, token, this.limits.perFileWindowMs, now);
    this.prune(now);
    return this.retryAfterMs(token, ip);
  }

  /** Record a right guess: the client starts fresh. */
  recordSuccess(token: string, ip: string): void {
    this.clients.delete(`${token}|${ip}`);
  }

  private prune(now: number): void {
    if (now - this.lastPrune < 60 * 1000) return;
    this.lastPrune = now;
    for (const [k, w] of this.clients) if (now - w.startedAt >= this.limits.perClientWindowMs) this.clients.delete(k);
    for (const [k, w] of this.files) if (now - w.startedAt >= this.limits.perFileWindowMs) this.files.delete(k);
  }

  /** For tests and diagnostics */
  get size(): number {
    return this.clients.size + this.files.size;
  }
}

// ------------------------------------------------------------------ Unlock cookie

/*
 * After a right guess the browser gets a cookie scoped to the link path (/d/<token>) and is sent back to
 * the link with GET, so the scan wait page can keep refreshing and the download is served by the same code
 * as an unprotected file. The value is an expiry plus an HMAC over the token, the stored hash and the
 * expiry: it does not contain the token, cannot be moved to another link, and stops working if the
 * password is ever changed (the hash changes). Signed with the app's session secret.
 */

export const UNLOCK_TTL_MS = 30 * 60 * 1000;

function unlockSignature(secret: string, token: string, storedHash: string, expiresAt: number): string {
  return crypto.createHmac("sha256", secret).update(`unlock\0${token}\0${storedHash}\0${expiresAt}`).digest("base64url");
}

export function makeUnlockCookie(secret: string, token: string, storedHash: string, now = Date.now()): { value: string; expiresAt: number } {
  const expiresAt = now + UNLOCK_TTL_MS;
  return { value: `${expiresAt}.${unlockSignature(secret, token, storedHash, expiresAt)}`, expiresAt };
}

export function checkUnlockCookie(secret: string, token: string, storedHash: string, value: string | undefined, now = Date.now()): boolean {
  if (!value) return false;
  const dot = value.indexOf(".");
  if (dot < 0) return false;
  const expiresAt = Number(value.slice(0, dot));
  if (!Number.isInteger(expiresAt) || expiresAt <= now) return false;
  const given = Buffer.from(value.slice(dot + 1));
  const expected = Buffer.from(unlockSignature(secret, token, storedHash, expiresAt));
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}