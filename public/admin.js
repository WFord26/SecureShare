// Activity log page. All text goes in through textContent: file names and user agents are user controlled.

const PAGE_ROWS = 300;

const $ = (id) => document.getElementById(id);
const fromInput = $("from");
const toInput = $("to");
const filterInput = $("filter");

let report = null;
let retentionDays = 730;
let activeTab = "uploads";
const shown = { uploads: PAGE_ROWS, downloads: PAGE_ROWS };

// ------------------------------------------------------------------ Formatting

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c !== null && c !== undefined) node.append(c);
  return node;
}

/** replaceChildren, skipping the null placeholders for optional sections */
function fill(node, ...children) {
  node.replaceChildren(...children.filter((c) => c !== null && c !== undefined));
}

function fmtSize(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  const v = n / 1024 ** i;
  return `${v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

const nf = new Intl.NumberFormat();
const fmtNum = (n) => nf.format(n || 0);

function fmtWhen(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function isoDate(d) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** "Chrome on Windows" from a user agent string. Rough on purpose; the full string is in the tooltip and CSV. */
function describeClient(ua) {
  if (!ua) return "No user agent";
  const browser =
    /Edg\//.test(ua) ? "Edge" :
    /OPR\//.test(ua) ? "Opera" :
    /Firefox\//.test(ua) ? "Firefox" :
    /Chrome\//.test(ua) ? "Chrome" :
    /Safari\//.test(ua) && /Version\//.test(ua) ? "Safari" :
    /curl\//i.test(ua) ? "curl" :
    /python/i.test(ua) ? "Python" :
    /preview|bot|crawler|spider/i.test(ua) ? "Link preview or bot" :
    ua.split(/[\s/;(]/)[0] || "Unknown";
  const os =
    /Windows/.test(ua) ? "Windows" :
    /iPhone|iPad/.test(ua) ? "iOS" :
    /Android/.test(ua) ? "Android" :
    /Mac OS X|Macintosh/.test(ua) ? "macOS" :
    /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

const UPLOAD_STATE = {
  active: ["Active", "ok"],
  expired: ["Expired", "neutral"],
  revoked: ["Revoked", "warn"],
  blocked: ["Malware blocked", "bad"],
};
const SCAN = { clean: "Scanned clean", malicious: "Malicious", pending: "Scan pending", unscanned: "Not scanned" };
const OUTCOME = {
  served: ["Downloaded", "ok"],
  incomplete: ["Incomplete", "warn"],
  head: ["Link checked", "neutral"],
  waiting: ["Waited for scan", "neutral"],
  blocked: ["Blocked (malware)", "bad"],
  unscannable: ["Refused (not scanned)", "bad"],
  expired: ["Expired link", "neutral"],
  error: ["Error", "bad"],
};

function badge([label, cls]) {
  return el("span", { class: `badge ${cls}`, text: label });
}

// ------------------------------------------------------------------ Range

function rangeParams() {
  const from = new Date(`${fromInput.value}T00:00:00`);
  const to = new Date(`${toInput.value}T00:00:00`);
  to.setDate(to.getDate() + 1); // "to" date is inclusive
  return new URLSearchParams({ from: from.toISOString(), to: to.toISOString() });
}

function setPreset(days) {
  const today = new Date();
  const start = new Date(today);
  start.setDate(start.getDate() - (days === "all" ? retentionDays : Number(days) - 1));
  fromInput.value = isoDate(start);
  toInput.value = isoDate(today);
  markPreset(days);
  try { localStorage.setItem("secureshare-activity-range", String(days)); } catch { /* not remembered */ }
  load();
}

function markPreset(days) {
  document.querySelectorAll(".presets button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.days === String(days))));
}

document.querySelectorAll(".presets button").forEach((b) => b.addEventListener("click", () => setPreset(b.dataset.days)));
[fromInput, toInput].forEach((i) =>
  i.addEventListener("change", () => {
    if (!fromInput.value || !toInput.value) return;
    if (fromInput.value > toInput.value) [fromInput.value, toInput.value] = [toInput.value, fromInput.value];
    markPreset(null);
    load();
  })
);

// ------------------------------------------------------------------ Loading

let loadSeq = 0;

async function load() {
  const seq = ++loadSeq;
  const params = rangeParams();
  $("export-uploads").href = `/admin/export/uploads.csv?${params}`;
  $("export-downloads").href = `/admin/export/downloads.csv?${params}`;
  setNotice("Loading…");
  let data;
  try {
    const r = await fetch(`/api/admin/report?${params}`);
    if (r.status === 401) return location.assign(`/auth/login?returnTo=${encodeURIComponent("/admin")}`);
    if (r.status === 403) return setNotice("Your account no longer has access to the activity log. Sign out and back in.", true);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    data = await r.json();
  } catch {
    if (seq === loadSeq) setNotice("Could not load the activity log. Try again in a moment.", true);
    return;
  }
  if (seq !== loadSeq) return; // a newer range was picked while this one loaded
  report = data;
  retentionDays = data.retentionDays;
  $("sub").textContent = `Uploads and downloads across all users. Records are kept for ${retentionDays >= 365 && retentionDays % 365 === 0 ? `${retentionDays / 365} years` : `${retentionDays} days`}.`;
  shown.uploads = shown.downloads = PAGE_ROWS;
  render();
}

function setNotice(text, isError = false) {
  $("tiles").replaceChildren();
  for (const id of ["panel-uploads", "panel-downloads", "panel-people"]) {
    $(id).replaceChildren(el("div", { class: `notice${isError ? " err" : ""}`, text }));
  }
}

// ------------------------------------------------------------------ Rendering

function render() {
  if (!report) return;
  renderTiles();
  const q = filterInput.value.trim().toLowerCase();
  renderUploads(q);
  renderDownloads(q);
  renderPeople(q);
}

function tile(label, value, detail) {
  return el("div", { class: "tile" }, el("div", { class: "label", text: label }), el("div", { class: "value", text: value }), detail ? el("div", { class: "detail", text: detail }) : null);
}

function renderTiles() {
  const s = report.summary;
  $("tiles").replaceChildren(
    tile("Uploads", fmtNum(s.uploads), `${fmtSize(s.uploadBytes)} from ${fmtNum(s.uploaders)} ${s.uploaders === 1 ? "person" : "people"}`),
    tile("Downloads", fmtNum(s.downloads), `${fmtSize(s.downloadBytes)} to ${fmtNum(s.downloaderIps)} IP ${s.downloaderIps === 1 ? "address" : "addresses"}`),
    tile("Incomplete", fmtNum(s.incomplete), "Cancelled or cut off"),
    tile("Automated fetches", fmtNum(s.automated), "Link scanners and previews"),
    tile("Malware blocked", fmtNum(s.blocked), "Files deleted"),
    tile("Revoked", fmtNum(s.revoked), "Links ended early")
  );
  $("count-uploads").textContent = fmtNum(report.uploads.length) + (report.uploadsTruncated ? "+" : "");
  $("count-downloads").textContent = fmtNum(report.events.length) + (report.eventsTruncated ? "+" : "");
}

function matches(q, ...fields) {
  return !q || fields.some((f) => f && String(f).toLowerCase().includes(q));
}

function moreButton(kind, total) {
  if (total <= shown[kind]) return null;
  return el("div", { class: "more" }, el("button", {
    type: "button",
    class: "secondary",
    text: `Show ${fmtNum(Math.min(PAGE_ROWS, total - shown[kind]))} more of ${fmtNum(total - shown[kind])}`,
    onclick: () => { shown[kind] += PAGE_ROWS; render(); },
  }));
}

function truncatedNote(flag, what) {
  return flag ? el("p", { class: "notice", text: `Showing the most recent ${what}. Narrow the date range or export the CSV for everything.` }) : null;
}

function renderUploads(q) {
  const panel = $("panel-uploads");
  const rows = report.uploads.filter((u) => matches(q, u.fileName, u.uploaderName, u.uploaderEmail, u.uploadIp));
  if (!rows.length) return fill(panel, el("div", { class: "notice", text: q ? "No uploads match the filter." : "No uploads in this date range." }));

  const tbody = el("tbody");
  for (const u of rows.slice(0, shown.uploads)) {
    const tr = el("tr", { class: "expandable", tabindex: "0", "aria-expanded": "false", title: "Show every request for this file" },
      el("td", { class: "when" }, el("span", { class: "chev", "aria-hidden": "true", text: "›" }), fmtWhen(u.uploadedAt)),
      el("td", { class: "file" }, u.fileName, el("div", { class: "small muted", text: fmtSize(u.size) })),
      el("td", {}, u.uploaderName || u.uploaderEmail, u.uploaderName ? el("div", { class: "small muted", text: u.uploaderEmail }) : null),
      el("td", {}, badge(UPLOAD_STATE[u.state] || [u.state, "neutral"]), el("div", { class: "small muted", text: SCAN[u.scanStatus] || u.scanStatus })),
      el("td", { class: "num" }, fmtNum(u.downloads), u.incompleteDownloads || u.automatedFetches
        ? el("div", { class: "small muted", text: [u.incompleteDownloads ? `${u.incompleteDownloads} incomplete` : "", u.automatedFetches ? `${u.automatedFetches} automated` : ""].filter(Boolean).join(", ") })
        : null),
      el("td", { class: "when" }, u.lastDownloadAt ? fmtWhen(u.lastDownloadAt) : el("span", { class: "muted", text: "Never" }))
    );
    const toggle = () => toggleDetail(tr, u);
    tr.addEventListener("click", toggle);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    tbody.append(tr);
  }

  fill(panel,
    el("div", { class: "tablewrap" }, el("table", {},
      el("thead", {}, el("tr", {},
        el("th", { text: "Uploaded" }), el("th", { text: "File" }), el("th", { text: "Uploaded by" }),
        el("th", { text: "Status" }), el("th", { class: "num", text: "Downloads" }), el("th", { text: "Last download" }))),
      tbody)),
    moreButton("uploads", rows.length),
    truncatedNote(report.uploadsTruncated, `${fmtNum(report.uploads.length)} uploads`)
  );
}

async function toggleDetail(tr, u) {
  const open = tr.getAttribute("aria-expanded") === "true";
  if (open) {
    tr.setAttribute("aria-expanded", "false");
    if (tr.nextElementSibling?.classList.contains("detail")) tr.nextElementSibling.remove();
    return;
  }
  tr.setAttribute("aria-expanded", "true");
  const cell = el("td", { colspan: "6" }, el("span", { class: "muted small", text: "Loading requests…" }));
  const detail = el("tr", { class: "detail" }, cell);
  tr.after(detail);

  let events;
  try {
    const r = await fetch(`/api/admin/files/${encodeURIComponent(u.ref)}/downloads`);
    if (!r.ok) throw new Error();
    events = (await r.json()).events;
  } catch {
    return fill(cell, el("span", { class: "small", text: "Could not load requests for this file." }));
  }
  const facts = [
    `Uploaded from ${u.uploadIp || "unknown IP"}`,
    `link expires ${fmtWhen(u.expiresAt)}`,
    u.endedAt ? `${u.state} ${fmtWhen(u.endedAt)}${u.endedBy ? ` by ${u.endedBy}` : ""}` : "",
  ].filter(Boolean).join(" · ");
  if (!events.length) return fill(cell, el("div", { class: "small muted", text: `${facts}. Nobody has requested this link.` }));
  fill(cell, el("div", { class: "small muted", text: facts }), eventsTable(events, false));
}

function eventsTable(events, withFile) {
  const tbody = el("tbody");
  for (const d of events) {
    tbody.append(el("tr", {},
      el("td", { class: "when", text: fmtWhen(d.at) }),
      withFile ? el("td", { class: "file" }, d.fileName, el("div", { class: "small muted", text: `from ${d.uploaderEmail}` })) : null,
      el("td", { class: "mono", text: d.ip }),
      el("td", {}, badge(OUTCOME[d.outcome] || [d.outcome, "neutral"])),
      el("td", { title: d.userAgent }, describeClient(d.userAgent), d.automated ? el("div", { class: "small muted", text: "Automated" }) : null),
      el("td", { class: "num", text: d.bytes ? fmtSize(d.bytes) : "" })
    ));
  }
  return el("div", { class: "tablewrap" }, el("table", {},
    el("thead", {}, el("tr", {},
      el("th", { text: "Time" }), withFile ? el("th", { text: "File" }) : null, el("th", { text: "IP address" }),
      el("th", { text: "Result" }), el("th", { text: "Client" }), el("th", { class: "num", text: "Sent" }))),
    tbody));
}

function renderDownloads(q) {
  const panel = $("panel-downloads");
  const rows = report.events.filter((d) => matches(q, d.fileName, d.uploaderEmail, d.ip, d.userAgent));
  if (!rows.length) return fill(panel, el("div", { class: "notice", text: q ? "No requests match the filter." : "No download requests in this date range." }));
  fill(panel,
    eventsTable(rows.slice(0, shown.downloads), true),
    moreButton("downloads", rows.length),
    truncatedNote(report.eventsTruncated, `${fmtNum(report.events.length)} requests`)
  );
}

function renderPeople(q) {
  const uploaders = report.uploaders.filter((u) => matches(q, u.name, u.email));
  const downloaders = report.downloaders.filter((d) => matches(q, d.ip, d.userAgent));

  const upTable = uploaders.length
    ? el("div", { class: "tablewrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", { text: "Person" }), el("th", { class: "num", text: "Uploads" }), el("th", { class: "num", text: "Data" }), el("th", { class: "num", text: "Downloads of their files" }))),
        el("tbody", {}, ...uploaders.map((u) => el("tr", {},
          el("td", {}, u.name || u.email, u.name ? el("div", { class: "small muted", text: u.email }) : null),
          el("td", { class: "num", text: fmtNum(u.uploads) }),
          el("td", { class: "num", text: fmtSize(u.bytes) }),
          el("td", { class: "num", text: fmtNum(u.downloads) })
        )))))
    : el("div", { class: "notice", text: "No uploaders in this range." });

  const downTable = downloaders.length
    ? el("div", { class: "tablewrap" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", { text: "IP address" }), el("th", { class: "num", text: "Downloads" }), el("th", { class: "num", text: "Files" }), el("th", { text: "Last download" }), el("th", { text: "Client" }))),
        el("tbody", {}, ...downloaders.map((d) => el("tr", {},
          el("td", { class: "mono", text: d.ip }),
          el("td", { class: "num", text: fmtNum(d.downloads) }),
          el("td", { class: "num", text: fmtNum(d.files) }),
          el("td", { class: "when", text: fmtWhen(d.lastAt) }),
          el("td", { title: d.userAgent, text: describeClient(d.userAgent) })
        )))))
    : el("div", { class: "notice", text: "No completed downloads in this range." });

  $("panel-people").replaceChildren(
    el("h2", { text: "Uploaders" }), upTable,
    el("h2", { text: "Downloaders" }),
    el("p", { class: "small muted", text: "Download links are anonymous, so recipients are identified by IP address only. Several people behind one office network share an address." }),
    downTable
  );
}

// ------------------------------------------------------------------ Tabs and filter

function selectTab(name) {
  activeTab = name;
  for (const t of ["uploads", "downloads", "people"]) {
    $(`tab-${t}`).setAttribute("aria-selected", String(t === name));
    $(`panel-${t}`).hidden = t !== name;
  }
}
for (const t of ["uploads", "downloads", "people"]) $(`tab-${t}`).addEventListener("click", () => selectTab(t));

let filterTimer;
filterInput.addEventListener("input", () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => { shown.uploads = shown.downloads = PAGE_ROWS; render(); }, 150);
});

// ------------------------------------------------------------------ Start

let initial = "30";
try { initial = localStorage.getItem("secureshare-activity-range") || "30"; } catch { /* default */ }
if (!["7", "30", "90", "365", "all"].includes(initial)) initial = "30";
setPreset(initial);
