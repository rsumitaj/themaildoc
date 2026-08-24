/**
 * One-tap approval tokens.
 *
 * The email link carries `id.exp.sig`. `sig` is HMAC-SHA256 over `id.exp` with
 * APPROVAL_SIGNING_SECRET, so a link cannot be forged or its expiry extended.
 * We also store only sha256(token) in D1 and mark it used, so a link is
 * single-use even though it is stateless to verify.
 */
const enc = new TextEncoder();

function b64url(bytes: ArrayBuffer): string {
  const s = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function signToken(id: string, expEpoch: number, secret: string): Promise<string> {
  const payload = `${id}.${expEpoch}`;
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return `${payload}.${b64url(sig)}`;
}

export async function verifyToken(
  token: string,
  secret: string,
): Promise<{ ok: boolean; id?: string; reason?: string }> {
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed' };
  const [id, expStr, sig] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp)) return { ok: false, reason: 'malformed' };
  const key = await hmacKey(secret);
  const expected = await crypto.subtle.sign('HMAC', key, enc.encode(`${id}.${expStr}`));
  if (b64url(expected) !== sig) return { ok: false, reason: 'bad_signature' };
  if (Date.now() / 1000 > exp) return { ok: false, id, reason: 'expired' };
  return { ok: true, id };
}

export async function sha256hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
