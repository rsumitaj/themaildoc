/**
 * Google Search Console, read-only, from a Worker.
 *
 * A service account (added to the GSC property as a restricted user) lets the
 * pipeline pull real query + page performance with no browser and no user
 * interaction. We mint a short-lived OAuth token from a self-signed JWT using
 * WebCrypto, then call the Search Analytics API. This is what makes topic
 * selection data-driven: which queries you already get impressions for, and at
 * what position ("striking distance").
 */
import { fetchRetry } from './util';

const SCOPE = 'https://www.googleapis.com/auth/webmasters.readonly';
const enc = new TextEncoder();

const b64url = (buf: ArrayBuffer | Uint8Array): string => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

function pemToPkcs8(pem: string): ArrayBuffer {
  const body = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\\n/g, '').replace(/\s+/g, '');
  const bin = atob(body);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function accessToken(saEmail: string, privateKeyPem: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claim = b64url(enc.encode(JSON.stringify({
    iss: saEmail, scope: SCOPE, aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600,
  })));
  const key = await crypto.subtle.importKey(
    'pkcs8', pemToPkcs8(privateKeyPem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(`${header}.${claim}`));
  const jwt = `${header}.${claim}.${b64url(sig)}`;

  const res = await fetchRetry('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}&assertion=${jwt}`,
  });
  if (!res.ok) throw new Error(`GSC token ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return ((await res.json()) as any).access_token as string;
}

export interface GscRow { keys: string[]; clicks: number; impressions: number; ctr: number; position: number; }

export class Gsc {
  private token?: string;
  constructor(private saEmail: string, private privateKey: string, private siteUrl: string) {}

  private async auth(): Promise<string> {
    if (!this.token) this.token = await accessToken(this.saEmail, this.privateKey);
    return this.token;
  }

  async query(opts: {
    startDate: string; endDate: string; dimensions: string[]; rowLimit?: number;
  }): Promise<GscRow[]> {
    const token = await this.auth();
    const url = `https://searchconsole.googleapis.com/webmasters/v3/sites/${encodeURIComponent(this.siteUrl)}/searchAnalytics/query`;
    const res = await fetchRetry(url, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        startDate: opts.startDate, endDate: opts.endDate,
        dimensions: opts.dimensions, rowLimit: opts.rowLimit ?? 1000, dataState: 'all',
      }),
    });
    if (!res.ok) throw new Error(`GSC query ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return (((await res.json()) as any).rows ?? []) as GscRow[];
  }
}

export const daysAgo = (n: number): string => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);
