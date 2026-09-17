function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

// Follows the viewer's system theme, and any explicit choice the uploader made on the app page
// (same origin, so /theme.js sees it). Recipients who never visited the app page get the system theme.
const THEME_CSS = `:root{color-scheme:light;--bg:#f0f2f5;--surface:#fff;--text:#1c1e21;--muted:#65676b;--accent:#0f6cbd;--shadow:0 2px 12px rgba(0,0,0,.08)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#121417;--surface:#1c1f24;--text:#e6e8eb;--muted:#9ba1a8;--accent:#4c9fe8;--shadow:0 2px 16px rgba(0,0,0,.45)}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#121417;--surface:#1c1f24;--text:#e6e8eb;--muted:#9ba1a8;--accent:#4c9fe8;--shadow:0 2px 16px rgba(0,0,0,.45)}
body{font-family:system-ui,sans-serif;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center;padding:1.5rem 16px;background:var(--bg);color:var(--text)}
main{background:var(--surface);padding:2.5rem;border-radius:12px;box-shadow:var(--shadow);max-width:420px;text-align:center}
h1{margin-top:0;font-size:1.3rem}
p{color:var(--muted);line-height:1.5}
a{color:var(--accent)}`;

/** Minimal self contained status page. Title and body are escaped; pass plain text. */
export function page(title: string, body: string, opts: { refresh?: number; link?: { href: string; text: string } } = {}): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
${opts.refresh ? `<meta http-equiv="refresh" content="${opts.refresh}">` : ""}
<script src="/theme.js"></script>
<style>${THEME_CSS}</style>
</head><body><main><h1>${esc(title)}</h1><p>${esc(body)}</p>${
    opts.link ? `<p><a href="${esc(opts.link.href)}">${esc(opts.link.text)}</a></p>` : ""
  }</main></body></html>`;
}
