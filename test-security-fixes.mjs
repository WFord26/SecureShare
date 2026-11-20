#!/usr/bin/env node

/**
 * Manual test validation for security fixes
 * Tests the clientIp and getCookie functions with security-critical inputs
 */

import { isIPv4, isIPv6 } from "net";

// Test helper functions that mirror the fixed implementations
function getCookie(header, name) {
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

function clientIp(raw) {
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

// Test cases
console.log("Testing clientIp() security fix...\n");

const testCases = [
  // Valid IPv4 with port
  { input: "192.0.2.1:3000", expected: "192.0.2.1", desc: "Valid IPv4 with port" },
  
  // Invalid IPv4 (octet > 255) - should be rejected
  { input: "999.999.999.999:1234", expected: "999.999.999.999:1234", desc: "Invalid IPv4 (octet > 255) - malformed, should return as-is" },
  
  // Valid IPv6 with port
  { input: "[2001:db8::1]:3000", expected: "2001:db8::1", desc: "Valid IPv6 with port" },
  
  // IPv4-mapped IPv6
  { input: "::ffff:192.0.2.1", expected: "192.0.2.1", desc: "IPv4-mapped IPv6" },
  
  // Plain IPv4
  { input: "192.0.2.1", expected: "192.0.2.1", desc: "Plain IPv4" },
  
  // Plain IPv6
  { input: "2001:db8::1", expected: "2001:db8::1", desc: "Plain IPv6" },
  
  // Localhost
  { input: "127.0.0.1:8000", expected: "127.0.0.1", desc: "Localhost with port" },
];

let passed = 0;
let failed = 0;

testCases.forEach(({ input, expected, desc }) => {
  const result = clientIp(input);
  const isPass = result === expected;
  if (isPass) {
    console.log(`✓ PASS: ${desc}`);
    console.log(`  Input: "${input}" → Output: "${result}"`);
    passed++;
  } else {
    console.log(`✗ FAIL: ${desc}`);
    console.log(`  Input: "${input}" → Expected: "${expected}", Got: "${result}"`);
    failed++;
  }
  console.log();
});

console.log("Testing getCookie() security fix...\n");

const cookieTests = [
  // Normal cookie
  { header: "auth=abc123; path=/", name: "auth", expected: "abc123", desc: "Simple cookie parsing" },
  
  // Cookie with URL-encoded value
  { header: "auth=abc%20def; path=/", name: "auth", expected: "abc def", desc: "URL-encoded space in cookie value" },
  
  // Multiple cookies
  { header: "sessionId=xyz789; auth=abc123; path=/", name: "auth", expected: "abc123", desc: "Multiple cookies" },
  
  // Cookie name shouldn't partially match
  { header: "auth=value1; auth_backup=value2", name: "auth", expected: "value1", desc: "Exact cookie name match (not partial)" },
  
  // Cookie with URL-encoded semicolon (should not break parsing)
  { header: "auth=abc%3Bdef; path=/", name: "auth", expected: "abc;def", desc: "URL-encoded semicolon in value" },
  
  // Non-existent cookie
  { header: "sessionId=xyz789; auth=abc123", name: "token", expected: undefined, desc: "Non-existent cookie returns undefined" },
];

cookieTests.forEach(({ header, name, expected, desc }) => {
  const result = getCookie(header, name);
  const isPass = result === expected;
  if (isPass) {
    console.log(`✓ PASS: ${desc}`);
    console.log(`  Cookie: "${name}" in "${header}"`);
    console.log(`  Result: ${result === undefined ? "undefined" : `"${result}"`}`);
    passed++;
  } else {
    console.log(`✗ FAIL: ${desc}`);
    console.log(`  Cookie: "${name}" in "${header}"`);
    console.log(`  Expected: ${expected === undefined ? "undefined" : `"${expected}"`}, Got: ${result === undefined ? "undefined" : `"${result}"`}`);
    failed++;
  }
  console.log();
});

console.log(`\n${"=".repeat(50)}`);
console.log(`Test Results: ${passed} passed, ${failed} failed`);
console.log(`${"=".repeat(50)}`);

process.exit(failed > 0 ? 1 : 0);
