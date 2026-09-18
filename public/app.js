const drop = document.getElementById("drop");
const fileInput = document.getElementById("file");
const prog = document.getElementById("prog");
const errBox = document.getElementById("err");
const result = document.getElementById("result");

async function loadPurviewStatus() {
  const status = document.getElementById("purview-status");
  const check = document.getElementById("purview-check");
  try {
    const response = await fetch("/api/purview/status", { signal: AbortSignal.timeout(15000) });
    if (response.status === 401) { status.textContent = "Sign in to check Purview status."; return; }
    if (!response.ok) throw new Error("Status unavailable");
    const data = await response.json();
    if (!data.supported) { status.textContent = "Purview status checks are currently available for commercial Microsoft tenants only."; return; }
    check.hidden = false;
    if (!data.status) { status.textContent = "Not checked for this session. Connect to check the policies for your account."; return; }
    check.textContent = "Check again with Microsoft";
    const labels = { inline: "inline evaluation required", audit: "audit evaluation only", none: "no applicable policy" };
    const s = data.status;
    status.textContent = s.state === "checked"
      ? `Text uploads: ${labels[s.text] || "unknown"}. File uploads: ${labels[s.files] || "unknown"}. Checked ${new Date(s.checkedAt).toLocaleString()}. This does not verify content detection.`
      : s.message;
  } catch { status.textContent = "Purview status is unavailable. Reload the page to retry."; }
}
loadPurviewStatus();

fetch("/api/me").then(r => r.json()).then(u => {
  document.getElementById("user").textContent = `Signed in as ${u.name} (${u.email})`;
  if (u.linkTtlDays) document.getElementById("ttl").textContent = `Links expire after ${u.linkTtlDays} days`;
  if (u.auditor) document.getElementById("activity-link").hidden = false;
});

// ---- Your uploads ----
const filesTable = document.getElementById("files");
const filesBody = filesTable.querySelector("tbody");
const filesEmpty = document.getElementById("files-empty");
const STATUS = {
  pending: "Scanning",
  clean: "Ready",
  malicious: "Blocked",
  unscanned: "Unscannable",
};

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

async function loadFiles() {
  let data;
  try {
    const r = await fetch("/api/files");
    if (r.status === 401) return location.assign("/auth/login");
    data = await r.json();
  } catch {
    return;
  }
  const files = data.files || [];
  filesBody.replaceChildren();
  filesTable.hidden = files.length === 0;
  filesEmpty.hidden = files.length > 0;
  for (const f of files) {
    const tr = document.createElement("tr");

    const name = document.createElement("td");
    name.className = "name";
    name.title = `${f.fileName} (${fmtSize(f.size)}), uploaded ${new Date(f.uploadedAt).toLocaleString()}`;
    const fname = document.createElement("div");
    fname.className = "fname";
    fname.textContent = f.fileName;
    name.appendChild(fname);
    // null when the activity log is unavailable: show nothing rather than a wrong zero
    if (f.downloads) {
      const dl = document.createElement("div");
      dl.className = "dl";
      const n = f.downloads.count;
      dl.textContent = n === 0
        ? "Not downloaded yet"
        : `${n} download${n === 1 ? "" : "s"}, last ${new Date(f.downloads.lastAt).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}`;
      name.appendChild(dl);
    }

    const status = document.createElement("td");
    status.className = "status";
    const badge = document.createElement("span");
    let label = STATUS[f.scanStatus] || f.scanStatus;
    let cls = f.scanStatus;
    if (f.available && f.scanStatus !== "clean") { label = "Ready (not scanned)"; cls = "clean"; }
    badge.className = `badge ${cls}`;
    badge.textContent = label;
    status.appendChild(badge);

    const exp = document.createElement("td");
    exp.className = "expires";
    exp.textContent = new Date(f.expiresAt).toLocaleDateString();
    exp.title = new Date(f.expiresAt).toLocaleString();

    const actions = document.createElement("td");
    actions.className = "actions";
    const copy = document.createElement("button");
    copy.textContent = "Copy";
    copy.addEventListener("click", () => {
      navigator.clipboard.writeText(f.link);
      copy.textContent = "Copied";
      setTimeout(() => (copy.textContent = "Copy"), 1500);
    });
    const revoke = document.createElement("button");
    revoke.className = "revoke";
    revoke.textContent = "Revoke";
    revoke.addEventListener("click", async () => {
      if (!confirm(`Revoke the link for "${f.fileName}"? The file will be deleted immediately.`)) return;
      revoke.disabled = true;
      const r = await fetch(`/api/files/${encodeURIComponent(f.token)}`, { method: "DELETE" });
      if (!r.ok) { revoke.disabled = false; return showError("Could not revoke the link"); }
      loadFiles();
    });
    actions.append(copy, revoke);

    tr.append(name, status, exp, actions);
    filesBody.appendChild(tr);
  }
  // Keep the list fresh while scans are pending
  if (files.some(f => !f.available && f.scanStatus === "pending")) setTimeout(loadFiles, 20000);
}
loadFiles();

drop.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => fileInput.files[0] && upload(fileInput.files[0]));

["dragover", "dragenter"].forEach(ev =>
  drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); })
);
["dragleave", "drop"].forEach(ev =>
  drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); })
);
drop.addEventListener("drop", e => {
  const f = e.dataTransfer.files[0];
  if (f) upload(f);
});

function upload(file) {
  errBox.style.display = "none";
  result.style.display = "none";
  prog.style.display = "block";
  prog.value = 0;

  const form = new FormData();
  form.append("file", file);

  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/upload");
  xhr.upload.onprogress = e => {
    if (e.lengthComputable) prog.value = Math.round((e.loaded / e.total) * 100);
  };
  xhr.onload = () => {
    prog.style.display = "none";
    let data = {};
    try { data = JSON.parse(xhr.responseText); } catch {}
    if (xhr.status === 401) return location.assign("/auth/login");
    if (xhr.status !== 200) return showError(data.error || `Upload failed (${xhr.status})`);
    document.getElementById("fname").textContent = data.fileName;
    document.getElementById("link").value = data.link;
    document.getElementById("note").textContent =
      `${data.note} Expires ${new Date(data.expiresAt).toLocaleString()}.`;
    result.style.display = "block";
    fileInput.value = "";
    loadFiles();
  };
  xhr.onerror = () => { prog.style.display = "none"; showError("Network error"); };
  xhr.send(form);
}

function showError(msg) {
  errBox.textContent = msg;
  errBox.style.display = "block";
}

document.getElementById("copy").addEventListener("click", () => {
  navigator.clipboard.writeText(document.getElementById("link").value);
  document.getElementById("copy").textContent = "Copied";
  setTimeout(() => (document.getElementById("copy").textContent = "Copy"), 1500);
});
