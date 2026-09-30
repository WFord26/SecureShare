#!/usr/bin/env node

/**
 * SecureShare version bump. Mirrors the versioning conventions used in
 * BetTrack's scripts/bump-version.mjs, scaled down to this repo's single
 * package.json (no monorepo, no per-package selection):
 *
 *   npm run bump                    Infer the level from CHANGELOG.md [Unreleased], bump
 *   npm run bump -- minor           Explicit level (patch|minor|major)
 *   npm run bump:dry                Preview only, write nothing
 *   npm run bump:tag                Tag the current version (run after committing the bump)
 *
 * The bump level is read from CHANGELOG.md's `[Unreleased]` section:
 *   "### Removed", or a BREAKING marker   -> major
 *   "### Added"                           -> minor
 *   anything else (Changed/Fixed/...)     -> patch
 *   empty, or no [Unreleased] section     -> patch
 *
 * Tagging is a separate step because the tag must point at the commit that
 * carries the new version, which doesn't exist until the bump is committed:
 *
 *   npm run bump -- minor && git commit -am "chore: release" && npm run bump:tag
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const LEVELS = ["patch", "minor", "major"];
const BREAKING_PATTERN = /breaking[ -]change|\*\*breaking|\bbreaking\b\s*:/i;

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(SCRIPT_DIR, "..");
const PACKAGE_JSON_PATH = path.join(ROOT_DIR, "package.json");
const CHANGELOG_PATH = path.join(ROOT_DIR, "CHANGELOG.md");

export class BumpError extends Error {}

function fail(message) {
  throw new BumpError(message);
}

function printUsage() {
  console.log(
    `
Usage:
  npm run bump                                  Bump at the level inferred from CHANGELOG.md
  npm run bump -- <patch|minor|major>           Bump at an explicit level
  npm run bump:tag                              Tag the current version (run after committing)

Levels:
  Inferred from CHANGELOG.md's [Unreleased] section:
    "### Removed" or a BREAKING marker  -> major
    "### Added"                         -> minor
    anything else (Changed/Fixed/...)   -> patch
  An explicit level on the command line always wins.

Options:
  --dry-run           Report what would change, write nothing
  --tag               Tag mode: create a v<version> tag at HEAD, no version writes
  --allow-dirty       Tag mode: tag even with a dirty working tree
  --help, -h          Show this message

Examples:
  npm run bump
  npm run bump -- minor
  npm run bump:dry
  npm run bump:tag
`.trim()
  );
}

// ---------------------------------------------------------------------------
// Git
// ---------------------------------------------------------------------------

function runGit(args, { allowFailure = false } = {}) {
  try {
    return execFileSync("git", args, {
      cwd: ROOT_DIR,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    if (allowFailure) {
      return "";
    }

    const details = error.stderr?.toString().trim();
    fail(`git ${args.join(" ")} failed${details ? `: ${details}` : "."}`);
  }
}

// ---------------------------------------------------------------------------
// Semver
// ---------------------------------------------------------------------------

export function bumpSemver(version, level) {
  const match = String(version).match(/^(\d+)\.(\d+)\.(\d+)(?:[-+].+)?$/);

  if (!match) {
    fail(`Cannot ${level} bump non-semver version "${version}".`);
  }

  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);

  if (level === "patch") return `${major}.${minor}.${patch + 1}`;
  if (level === "minor") return `${major}.${minor + 1}.0`;
  if (level === "major") return `${major + 1}.0.0`;

  fail(`Unsupported bump level "${level}".`);
}

// ---------------------------------------------------------------------------
// Changelog: level inference and release rewriting
// ---------------------------------------------------------------------------

/**
 * The body of the `## [Unreleased]` section, up to the next `##` heading or a
 * `---` separator. Returns null when the file has no such section.
 */
export function extractUnreleasedSection(content) {
  const lines = String(content).split(/\r?\n/);
  const startIndex = lines.findIndex((line) => /^## \[Unreleased\]/i.test(line));

  if (startIndex === -1) {
    return null;
  }

  const body = [];

  for (let i = startIndex + 1; i < lines.length; i += 1) {
    const line = lines[i];

    if (/^## /.test(line) || /^---\s*$/.test(line)) {
      break;
    }

    body.push(line);
  }

  return body.join("\n");
}

/**
 * Map an `[Unreleased]` section onto a bump level. Keep a Changelog section
 * names drive the decision: Removed (or any BREAKING marker) is a break,
 * Added is a feature, and everything else (Changed, Fixed, Security,
 * Deprecated) is a fix. Missing or empty sections default to patch.
 */
export function inferLevelFromChangelog(content) {
  const section = extractUnreleasedSection(content);

  if (section === null) {
    return { level: "patch", reason: "no [Unreleased] section" };
  }

  const lines = section.split("\n");
  const sectionEntryCounts = new Map();
  const looseEntries = [];
  let currentSection = null;

  for (const line of lines) {
    const headingMatch = line.match(/^#{3,}\s+(.+?)\s*$/);

    if (headingMatch) {
      currentSection = headingMatch[1].toLowerCase();
      if (!sectionEntryCounts.has(currentSection)) {
        sectionEntryCounts.set(currentSection, 0);
      }
      continue;
    }

    if (!line.trim()) {
      continue;
    }

    if (currentSection) {
      sectionEntryCounts.set(currentSection, sectionEntryCounts.get(currentSection) + 1);
    } else {
      looseEntries.push(line);
    }
  }

  const populated = new Set([...sectionEntryCounts.entries()].filter(([, count]) => count > 0).map(([name]) => name));
  const hasContent = populated.size > 0 || looseEntries.length > 0;

  if (!hasContent) {
    return { level: "patch", reason: "[Unreleased] is empty" };
  }

  if (BREAKING_PATTERN.test(section)) {
    return { level: "major", reason: "BREAKING marker in [Unreleased]" };
  }

  if (populated.has("removed")) {
    return { level: "major", reason: "[Unreleased] has a Removed section" };
  }

  if (populated.has("added")) {
    return { level: "minor", reason: "[Unreleased] has an Added section" };
  }

  if (populated.size > 0) {
    const names = [...populated].sort().join(", ");
    return { level: "patch", reason: `[Unreleased] has only ${names}` };
  }

  return { level: "patch", reason: "[Unreleased] has entries but no section headings" };
}

/**
 * Move everything under `[Unreleased]` into a new released section, leaving
 * `[Unreleased]` in place and empty. Pure: returns the new content and
 * whether anything changed.
 */
export function renderChangelogRelease(content, newVersion, today) {
  const unreleasedPattern = /^## \[Unreleased\]\n/m;

  if (!unreleasedPattern.test(content)) {
    return { content, changed: false };
  }

  const versionHeader = `## [${newVersion}] - ${today}`;
  return {
    content: content.replace(unreleasedPattern, `## [Unreleased]\n\n---\n\n${versionHeader}\n`),
    changed: true,
  };
}

export function getTodayDate(now = new Date()) {
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = { level: null, dryRun: false, tag: false, allowDirty: false, help: false };

  for (const arg of argv) {
    if (arg === "--help" || arg === "-h") args.help = true;
    else if (arg === "--dry-run") args.dryRun = true;
    else if (arg === "--tag") args.tag = true;
    else if (arg === "--allow-dirty") args.allowDirty = true;
    else if (LEVELS.includes(arg)) args.level = arg;
    else fail(`Unrecognized argument "${arg}". Run with --help for usage.`);
  }

  return args;
}

function readPackageJson() {
  if (!existsSync(PACKAGE_JSON_PATH)) {
    fail("package.json not found.");
  }
  return JSON.parse(readFileSync(PACKAGE_JSON_PATH, "utf8"));
}

function writePackageJson(pkg) {
  writeFileSync(PACKAGE_JSON_PATH, `${JSON.stringify(pkg, null, 2)}\n`, "utf8");
}

function readChangelog() {
  if (!existsSync(CHANGELOG_PATH)) {
    fail("CHANGELOG.md not found. Create it with an [Unreleased] section before bumping.");
  }
  return readFileSync(CHANGELOG_PATH, "utf8");
}

function tagNameFor(version) {
  return `v${version}`;
}

function runTagMode(args) {
  const pkg = readPackageJson();
  const head = runGit(["rev-parse", "--verify", "--quiet", "HEAD"], { allowFailure: true });

  if (!head) {
    fail("Cannot tag: this repository has no commits yet.");
  }

  const dirty = runGit(["status", "--porcelain"], { allowFailure: true });

  // A dry run writes nothing, so report the dirt and carry on rather than
  // withholding the preview the caller asked for.
  if (dirty && !args.allowDirty) {
    const log = args.dryRun ? console.log : console.error;
    const lead = args.dryRun ? "⚠️  Working tree is dirty" : "❌ Working tree is dirty";

    log(`${lead}. The tag would point at the previous commit.`);
    log("   Commit the version bump first, or pass --allow-dirty if you know better.");
    log("\nUncommitted:");
    dirty
      .split(/\r?\n/)
      .slice(0, 10)
      .forEach((line) => log(`   ${line}`));
    log("");

    if (!args.dryRun) {
      process.exitCode = 1;
      return;
    }
  }

  const tag = tagNameFor(pkg.version);
  const exists = Boolean(runGit(["rev-parse", "--verify", "--quiet", `refs/tags/${tag}`], { allowFailure: true }));
  const shortHead = runGit(["rev-parse", "--short", "HEAD"]);

  console.log(`Tagging at HEAD (${shortHead})\n`);

  if (exists) {
    console.log(`   skipped: ${tag} already exists`);
    return;
  }

  if (args.dryRun) {
    console.log(`   would create ${tag}`);
    console.log("\nDry-run mode - no tag created.");
    return;
  }

  runGit(["tag", "-a", tag, "-m", `v${pkg.version}`]);
  console.log(`   created ${tag}`);
  console.log(`\nPush when ready: git push origin ${tag}`);
}

function runBumpMode(args) {
  const pkg = readPackageJson();
  const changelog = readChangelog();

  const inferred = inferLevelFromChangelog(changelog);
  const level = args.level ?? inferred.level;
  const levelSource = args.level ? "explicit argument" : inferred.reason;

  const currentVersion = pkg.version;
  const nextVersion = bumpSemver(currentVersion, level);
  const today = getTodayDate();

  console.log(`${pkg.name}  ${currentVersion} -> ${nextVersion}  (${level} - ${levelSource})`);

  if (args.dryRun) {
    console.log("\nDry-run mode - no files written.");
    return;
  }

  pkg.version = nextVersion;
  writePackageJson(pkg);

  const { content, changed } = renderChangelogRelease(changelog, nextVersion, today);

  if (changed) {
    writeFileSync(CHANGELOG_PATH, content, "utf8");
    console.log(`   CHANGELOG.md: [Unreleased] -> [${nextVersion}] - ${today}`);
  } else {
    console.log("   CHANGELOG.md: no [Unreleased] section found, left untouched");
  }

  console.log("\nNext:");
  console.log(`   git add -A && git commit -m "chore: release v${nextVersion}"`);
  console.log("   npm run bump:tag && git push origin main --follow-tags");
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    printUsage();
    return;
  }

  if (args.tag) {
    runTagMode(args);
    return;
  }

  runBumpMode(args);
}

function isInvokedDirectly() {
  return import.meta.url === pathToFileURL(process.argv[1] ?? "").href;
}

if (isInvokedDirectly()) {
  try {
    main();
  } catch (error) {
    if (error instanceof BumpError) {
      console.error(`Error: ${error.message}`);
      process.exitCode = 1;
    } else {
      throw error;
    }
  }
}
