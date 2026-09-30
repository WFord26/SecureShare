import { test } from "node:test";
import assert from "node:assert/strict";
import { bumpSemver, inferLevelFromChangelog, renderChangelogRelease, extractUnreleasedSection, getTodayDate } from "./bump-version.mjs";

test("bumpSemver", async (t) => {
  await t.test("patch increments the third number", () => {
    assert.equal(bumpSemver("1.2.3", "patch"), "1.2.4");
  });

  await t.test("minor increments the second number and resets patch", () => {
    assert.equal(bumpSemver("1.2.3", "minor"), "1.3.0");
  });

  await t.test("major increments the first number and resets minor/patch", () => {
    assert.equal(bumpSemver("1.2.3", "major"), "2.0.0");
  });

  await t.test("rejects a non-semver version", () => {
    assert.throws(() => bumpSemver("not-a-version", "patch"));
  });
});

test("extractUnreleasedSection", async (t) => {
  await t.test("returns null when there is no [Unreleased] heading", () => {
    assert.equal(extractUnreleasedSection("# Changelog\n\n## [1.0.0] - 2026-01-01\n"), null);
  });

  await t.test("stops at the next ## heading", () => {
    const content = "## [Unreleased]\n\n### Added\n\n- one\n\n## [1.0.0] - 2026-01-01\n\n### Added\n\n- two\n";
    assert.equal(extractUnreleasedSection(content).includes("two"), false);
  });

  await t.test("stops at a --- separator", () => {
    const content = "## [Unreleased]\n\n### Added\n\n- one\n\n---\n\nstray text\n";
    assert.equal(extractUnreleasedSection(content).includes("stray text"), false);
  });
});

test("inferLevelFromChangelog", async (t) => {
  await t.test("defaults to patch when there is no [Unreleased] section", () => {
    assert.equal(inferLevelFromChangelog("# Changelog\n").level, "patch");
  });

  await t.test("defaults to patch when [Unreleased] is empty", () => {
    assert.equal(inferLevelFromChangelog("## [Unreleased]\n\n---\n").level, "patch");
  });

  await t.test("Added section means minor", () => {
    const content = "## [Unreleased]\n\n### Added\n\n- a new thing\n\n---\n";
    assert.equal(inferLevelFromChangelog(content).level, "minor");
  });

  await t.test("Removed section means major", () => {
    const content = "## [Unreleased]\n\n### Removed\n\n- the old thing\n\n---\n";
    assert.equal(inferLevelFromChangelog(content).level, "major");
  });

  await t.test("a BREAKING marker means major even without a Removed section", () => {
    const content = "## [Unreleased]\n\n### Changed\n\n- **BREAKING CHANGE**: renamed the field\n\n---\n";
    assert.equal(inferLevelFromChangelog(content).level, "major");
  });

  await t.test("Changed/Fixed only means patch", () => {
    const content = "## [Unreleased]\n\n### Fixed\n\n- a bug\n\n---\n";
    assert.equal(inferLevelFromChangelog(content).level, "patch");
  });

  await t.test("an empty Added heading does not count as populated", () => {
    const content = "## [Unreleased]\n\n### Added\n\n### Fixed\n\n- a bug\n\n---\n";
    assert.equal(inferLevelFromChangelog(content).level, "patch");
  });

  await t.test("Removed wins over Added when both are populated", () => {
    const content = "## [Unreleased]\n\n### Added\n\n- a new thing\n\n### Removed\n\n- the old thing\n\n---\n";
    assert.equal(inferLevelFromChangelog(content).level, "major");
  });
});

test("renderChangelogRelease", async (t) => {
  await t.test("moves [Unreleased] content under a new version heading and leaves an empty [Unreleased] behind", () => {
    const content = "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- a new thing\n\n---\n\n## [1.0.0] - 2026-01-01\n";
    const { content: next, changed } = renderChangelogRelease(content, "1.1.0", "2026-02-01");

    assert.equal(changed, true);
    assert.match(next, /^## \[Unreleased\]\n\n---\n\n## \[1\.1\.0\] - 2026-02-01\n/m);
    assert.match(next, /### Added\n\n- a new thing/);
    assert.match(next, /## \[1\.0\.0\] - 2026-01-01/);
  });

  await t.test("is a no-op when there is no [Unreleased] section", () => {
    const content = "# Changelog\n\n## [1.0.0] - 2026-01-01\n";
    const { content: next, changed } = renderChangelogRelease(content, "1.1.0", "2026-02-01");

    assert.equal(changed, false);
    assert.equal(next, content);
  });
});

test("getTodayDate formats as YYYY-MM-DD", () => {
  assert.equal(getTodayDate(new Date(2026, 8, 30)), "2026-09-30");
});
