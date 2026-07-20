const drop = document.getElementById("drop");
const fileInput = document.getElementById("file");
const prog = document.getElementById("prog");
const errBox = document.getElementById("err");
const result = document.getElementById("result");

fetch("/api/me").then(r => r.json()).then(u => {
  document.getElementById("user").textContent = `Signed in as ${u.name} (${u.email})`;
});

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
    if (xhr.status !== 200) return showError(data.error || `Upload failed (${xhr.status})`);
    document.getElementById("fname").textContent = data.fileName;
    document.getElementById("link").value = data.link;
    document.getElementById("note").textContent =
      `${data.note} Expires ${new Date(data.expiresAt).toLocaleString()}.`;
    result.style.display = "block";
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
