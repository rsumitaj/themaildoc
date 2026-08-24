/**
 * HTML for the three surfaces the engine shows a human: the approval email,
 * the private draft preview, and the result page after a click. Inline styles
 * only (email clients strip <style>), in the MailDoc clinical palette.
 */
import type { DraftRecord } from './d1';

const esc = (s: string): string =>
  (s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** Tiny, safe Markdown -> HTML for the preview page. Not a full parser. */
export function renderMarkdown(md: string): string {
  const lines = md.split('\n');
  const html: string[] = [];
  let inList = false;
  const inline = (t: string): string =>
    esc(t)
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  const closeList = () => { if (inList) { html.push('</ul>'); inList = false; } };
  for (const raw of lines) {
    const line = raw.replace(/\s+$/, '');
    if (/^###\s+/.test(line)) { closeList(); html.push(`<h3>${inline(line.replace(/^###\s+/, ''))}</h3>`); }
    else if (/^##\s+/.test(line)) { closeList(); html.push(`<h2>${inline(line.replace(/^##\s+/, ''))}</h2>`); }
    else if (/^#\s+/.test(line)) { closeList(); html.push(`<h1>${inline(line.replace(/^#\s+/, ''))}</h1>`); }
    else if (/^[-*]\s+/.test(line)) { if (!inList) { html.push('<ul>'); inList = true; } html.push(`<li>${inline(line.replace(/^[-*]\s+/, ''))}</li>`); }
    else if (line.trim() === '') { closeList(); }
    else { closeList(); html.push(`<p>${inline(line)}</p>`); }
  }
  closeList();
  return html.join('\n');
}

const shell = (title: string, inner: string): string => `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${esc(title)}</title>
<style>
:root{color-scheme:light dark}
body{margin:0;background:#f4f6f8;color:#0f151d;font:16px/1.6 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:32px 22px}
h1{font-size:26px;letter-spacing:-.02em}h2{font-size:20px;margin-top:1.6em}h3{font-size:16px;margin-top:1.4em}
code{background:#eceff2;padding:1px 6px;border-radius:5px;font-size:.9em}
a{color:#e11d28}.meta{color:#68727f;font-size:13px}
.badge{display:inline-block;background:#fdecec;color:#c1121f;border-radius:100px;padding:2px 10px;font-size:12px;font-weight:600}
.card{background:#fff;border:1px solid #e3e7ec;border-radius:14px;padding:22px 26px;box-shadow:0 8px 24px -14px rgba(0,0,0,.15)}
@media(prefers-color-scheme:dark){body{background:#0a0e13;color:#e8edf3}.card{background:#161d26;border-color:#242e3a}code{background:#242e3a}}
</style></head><body><div class="wrap">${inner}</div></body></html>`;

export function previewPage(draft: DraftRecord, bodyHtml: string): string {
  const fm = JSON.parse(draft.frontmatter_json);
  return shell(`Preview — ${draft.title}`, `
    <p><span class="badge">DRAFT PREVIEW · not indexed</span></p>
    <h1>${esc(fm.heading ?? draft.title)}</h1>
    <p class="meta">SERP title: ${esc(draft.title)} · target keyword: <code>${esc(draft.keyword)}</code> · ${draft.word_count} words</p>
    <p style="font-size:18px;color:#3d4856">${esc(fm.standfirst ?? '')}</p>
    <div class="card">${bodyHtml}</div>
  `);
}

export function resultPage(ok: boolean, title: string, message: string): string {
  return shell(title, `<div class="card"><h1>${ok ? '✓ ' : ''}${esc(title)}</h1><p>${esc(message)}</p></div>`);
}

export function approvalEmail(args: {
  draft: DraftRecord; scores: Record<string, number>; checksPassed: number; checksTotal: number;
  previewUrl: string; publishUrl: string; discardUrl: string; estRank: string;
}): string {
  const { draft, scores, checksPassed, checksTotal, previewUrl, publishUrl, discardUrl, estRank } = args;
  const scoreLine = Object.entries(scores).map(([k, v]) => `${k} ${v}`).join(' · ');
  return `<div style="max-width:560px;margin:0 auto;font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;color:#0f151d">
  <div style="font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#e11d28;font-weight:700;letter-spacing:.06em">MAILDOC CONTENT ENGINE</div>
  <h2 style="margin:6px 0 2px;font-size:19px">Ready to publish: ${esc(draft.title)}</h2>
  <div style="color:#68727f;font-size:13px">target <code style="background:#eceff2;padding:1px 5px;border-radius:4px">${esc(draft.keyword)}</code> · est. rank ${esc(estRank)} · ${draft.word_count} words · ${draft.kind}</div>
  <div style="background:#f4f6f8;border-radius:10px;padding:12px 14px;margin:14px 0;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;color:#3d4856">
    why this topic ▸ ${esc(scoreLine)}<br>checks ▸ ${checksPassed}/${checksTotal} passed
  </div>
  <p style="margin:14px 0"><a href="${previewUrl}" style="color:#2f6bab;font-weight:600">▸ Read the full draft →</a></p>
  <table role="presentation" cellpadding="0" cellspacing="0"><tr>
    <td><a href="${publishUrl}" style="display:inline-block;background:#0b8a5b;color:#fff;text-decoration:none;font-weight:600;padding:11px 22px;border-radius:9px">Publish now</a></td>
    <td style="width:12px"></td>
    <td><a href="${discardUrl}" style="display:inline-block;background:transparent;color:#3d4856;border:1px solid #cfd6dd;text-decoration:none;font-weight:600;padding:10px 20px;border-radius:9px">Keep as draft</a></td>
  </tr></table>
  <p style="color:#94a0ac;font-size:12px;margin-top:18px">Nothing is public until you tap Publish. This link expires and can be used once. If you do nothing, it stays a draft.</p>
</div>`;
}
