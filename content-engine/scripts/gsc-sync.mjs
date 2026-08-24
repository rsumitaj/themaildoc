#!/usr/bin/env node
/**
 * Pull Search Console data into local JSON + a D1 seed file. No dependencies.
 *
 *   1. Create a Google Cloud service account, enable the Search Console API,
 *      download its JSON key, and add its email as a user on the GSC property.
 *   2. Save the key as content-engine/service-account.json (gitignored) OR set
 *      GOOGLE_APPLICATION_CREDENTIALS to its path.
 *   3. node scripts/gsc-sync.mjs
 *      -> data/gsc-latest.json  (queries + pages, last 90 days)
 *      -> data/gsc-seed.sql     (apply with: wrangler d1 execute maildoc-leads --remote --file=data/gsc-seed.sql)
 *
 * This is the same data the Worker pulls at runtime; running it by hand proves
 * the credentials and gives the pipeline a warm database on day one.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createSign } from 'node:crypto';

const SITE = process.env.GSC_SITE_URL || 'sc-domain:themaildoc.co';
const keyPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || new URL('../service-account.json', import.meta.url).pathname;

let sa;
try { sa = JSON.parse(readFileSync(keyPath, 'utf8')); }
catch { console.error(`Cannot read service account key at ${keyPath}`); process.exit(1); }

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);

function jwt() {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64url(JSON.stringify({
    iss: sa.client_email, scope: 'https://www.googleapis.com/auth/webmasters.readonly',
    aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600,
  }));
  const sig = createSign('RSA-SHA256').update(`${header}.${claim}`).sign(sa.private_key, 'base64url');
  return `${header}.${claim}.${sig}`;
}

async function token() {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: jwt() }),
  });
  if (!res.ok) { console.error('token error', res.status, await res.text()); process.exit(1); }
  return (await res.json()).access_token;
}

async function query(tok, dimensions) {
  const res = await fetch(
    `https://searchconsole.googleapis.com/webmasters/v3/sites/${encodeURIComponent(SITE)}/searchAnalytics/query`,
    { method: 'POST', headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' },
      body: JSON.stringify({ startDate: daysAgo(90), endDate: daysAgo(1), dimensions, rowLimit: 1000, dataState: 'all' }) },
  );
  if (!res.ok) { console.error('query error', res.status, await res.text()); process.exit(1); }
  return (await res.json()).rows || [];
}

const tok = await token();
const [queries, pages] = await Promise.all([query(tok, ['query']), query(tok, ['page'])]);
const date = new Date().toISOString().slice(0, 10);

writeFileSync(new URL('../data/gsc-latest.json', import.meta.url),
  JSON.stringify({ site: SITE, date, queries, pages }, null, 2));

const esc = (s) => String(s).replace(/'/g, "''");
const sql = [
  ...queries.map((r) => `INSERT OR REPLACE INTO ce_gsc_query (snapshot_date,query,clicks,impressions,position,ctr) VALUES ('${date}','${esc(r.keys[0])}',${r.clicks},${r.impressions},${r.position},${r.ctr});`),
  ...pages.map((r) => `INSERT OR REPLACE INTO ce_gsc_page (snapshot_date,page,clicks,impressions,position) VALUES ('${date}','${esc(r.keys[0])}',${r.clicks},${r.impressions},${r.position});`),
].join('\n');
writeFileSync(new URL('../data/gsc-seed.sql', import.meta.url), sql + '\n');

// Striking distance = real demand you rank low for. The engine's best fuel.
const striking = queries.filter((r) => r.position >= 8 && r.position <= 60 && r.impressions >= 3)
  .sort((a, b) => b.impressions - a.impressions).slice(0, 20);
console.log(`\nGSC ${date} — ${queries.length} queries, ${pages.length} pages -> data/gsc-latest.json + data/gsc-seed.sql`);
console.log('\nTop striking-distance queries (write about these):');
for (const r of striking) console.log(`  ${String(Math.round(r.position)).padStart(3)}  ${String(r.impressions).padStart(4)} impr  ${r.keys[0]}`);
