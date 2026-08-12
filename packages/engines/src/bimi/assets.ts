/**
 * BIMI is the only record whose correctness lives outside DNS.
 *
 * The TXT record is two URLs. Whether a mailbox provider will actually show
 * the logo depends on what those URLs serve: an SVG in a profile almost nobody
 * produces by accident, and a certificate that expires. Checking the record
 * alone and reporting success is the exact false positive this product exists
 * to avoid, so both are fetched and judged.
 *
 * Everything here is bounded: HTTPS only, one redirect budget, a byte ceiling,
 * and a timeout. The URLs come from a stranger's DNS record.
 */

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** The BIMI draft caps an indicator at 32KB. */
export const LOGO_MAX_BYTES = 32 * 1024;
/** A certificate chain is a few KB. Anything past this is not one. */
export const CERT_MAX_BYTES = 256 * 1024;

const TIMEOUT_MS = 6_000;

export type AssetFailure =
  | 'NOT_HTTPS'
  | 'UNREACHABLE'
  | 'STATUS'
  | 'TOO_LARGE'
  | 'CONTENT_TYPE';

export interface LogoReport {
  ok: boolean;
  failure?: AssetFailure;
  detail?: string;
  bytes?: number;
  contentType?: string;
  /** SVG Tiny 1.2 Portable/Secure, the only profile BIMI accepts. */
  tinyPs?: boolean;
  hasTitle?: boolean;
  square?: boolean;
  viewBox?: string | null;
  /** Constructs the draft forbids: script, external references, animation. */
  forbidden?: string[];
}

export interface CertReport {
  ok: boolean;
  failure?: AssetFailure;
  detail?: string;
  bytes?: number;
  /** How many certificates the PEM bundle contains. */
  certificates?: number;
  notBefore?: string | null;
  notAfter?: string | null;
  /** Days until expiry, negative once expired. */
  daysRemaining?: number | null;
  issuer?: string | null;
}

async function get(
  url: string,
  doFetch: FetchLike,
  maxBytes: number,
): Promise<{ ok: true; body: Uint8Array; type: string } | { ok: false; failure: AssetFailure; detail: string }> {
  if (!/^https:\/\//i.test(url)) {
    return { ok: false, failure: 'NOT_HTTPS', detail: 'the URL is not https' };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await doFetch(url, { signal: controller.signal, redirect: 'follow' });

    if (response.status !== 200) {
      return { ok: false, failure: 'STATUS', detail: `HTTP ${response.status}` };
    }

    const declared = Number.parseInt(response.headers.get('content-length') ?? '', 10);
    if (Number.isFinite(declared) && declared > maxBytes) {
      return { ok: false, failure: 'TOO_LARGE', detail: `${declared} bytes` };
    }

    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > maxBytes) {
      return { ok: false, failure: 'TOO_LARGE', detail: `${buffer.byteLength} bytes` };
    }

    return {
      ok: true,
      body: new Uint8Array(buffer),
      type: (response.headers.get('content-type') ?? '').toLowerCase(),
    };
  } catch {
    return { ok: false, failure: 'UNREACHABLE', detail: 'the request failed or the certificate is invalid' };
  } finally {
    clearTimeout(timer);
  }
}

/** Things the BIMI draft forbids in an indicator, because they can carry behaviour. */
const FORBIDDEN: ReadonlyArray<{ pattern: RegExp; name: string }> = [
  { pattern: /<script\b/i, name: 'script' },
  { pattern: /\bon[a-z]+\s*=/i, name: 'event handler' },
  { pattern: /<image\b|xlink:href\s*=\s*["']https?:/i, name: 'external reference' },
  { pattern: /<animate|<set\b/i, name: 'animation' },
  { pattern: /<foreignObject\b/i, name: 'foreignObject' },
];

export async function fetchLogo(url: string, doFetch: FetchLike): Promise<LogoReport> {
  const result = await get(url, doFetch, LOGO_MAX_BYTES);
  if (!result.ok) return { ok: false, failure: result.failure, detail: result.detail };

  const type = result.type;
  if (type && !type.includes('image/svg')) {
    return { ok: false, failure: 'CONTENT_TYPE', detail: type, bytes: result.body.length };
  }

  const svg = new TextDecoder('utf-8').decode(result.body);
  const viewBox = /viewBox\s*=\s*["']([^"']+)["']/i.exec(svg)?.[1] ?? null;

  let square = false;
  if (viewBox) {
    const parts = viewBox.trim().split(/[\s,]+/).map(Number);
    square = parts.length === 4 && parts[2] === parts[3];
  }

  return {
    ok: true,
    bytes: result.body.length,
    contentType: type,
    // The draft requires SVG Tiny 1.2 Portable/Secure specifically.
    tinyPs: /baseProfile\s*=\s*["']tiny-ps["']/i.test(svg),
    hasTitle: /<title\b[^>]*>[^<]+<\/title>/i.test(svg),
    square,
    viewBox,
    forbidden: FORBIDDEN.filter((rule) => rule.pattern.test(svg)).map((rule) => rule.name),
  };
}

/* Certificates ------------------------------------------------------------- */

const PEM_BLOCK = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----/g;

export async function fetchCertificate(url: string, doFetch: FetchLike): Promise<CertReport> {
  const result = await get(url, doFetch, CERT_MAX_BYTES);
  if (!result.ok) return { ok: false, failure: result.failure, detail: result.detail };

  const text = new TextDecoder('utf-8').decode(result.body);
  const blocks = [...text.matchAll(PEM_BLOCK)];

  if (blocks.length === 0) {
    return {
      ok: false,
      failure: 'CONTENT_TYPE',
      detail: 'no PEM certificate in the response',
      bytes: result.body.length,
    };
  }

  const parsed = readCertificate(blocks[0]?.[1] ?? '');

  return {
    ok: true,
    bytes: result.body.length,
    certificates: blocks.length,
    notBefore: parsed.notBefore,
    notAfter: parsed.notAfter,
    // Truncate rather than floor. Flooring a negative rounds away from zero,
    // so a certificate 107.9 days expired was reported as 108 days expired.
    // Truncating is right in both directions: it under-states the time left on
    // a live certificate and states the time since expiry exactly.
    daysRemaining: parsed.notAfter
      ? Math.trunc((Date.parse(parsed.notAfter) - Date.now()) / 86_400_000)
      : null,
    issuer: parsed.issuer,
  };
}

/**
 * Just enough DER to answer the two questions that matter: when does it expire
 * and who issued it. A full X.509 parser is a library; this walks the
 * Certificate → TBSCertificate → Validity path and reads the two times, then
 * takes the last common name before them as the issuer.
 */
function readCertificate(base64: string): {
  notBefore: string | null;
  notAfter: string | null;
  issuer: string | null;
} {
  let der: Uint8Array;
  try {
    const clean = base64.replace(/\s+/g, '');
    const binary = atob(clean);
    der = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return { notBefore: null, notAfter: null, issuer: null };
  }

  const times: string[] = [];
  const commonNames: string[] = [];
  let firstTimeAt = -1;

  // UTCTime is 0x17, GeneralizedTime 0x18, PrintableString 0x13, UTF8String 0x0c.
  for (let at = 0; at < der.length - 2; at += 1) {
    const tag = der[at] as number;
    if (tag !== 0x17 && tag !== 0x18 && tag !== 0x13 && tag !== 0x0c) continue;

    const length = der[at + 1] as number;
    if (length === 0 || length > 0x7f || at + 2 + length > der.length) continue;

    const value = new TextDecoder('utf-8').decode(der.subarray(at + 2, at + 2 + length));

    if (tag === 0x17 || tag === 0x18) {
      const iso = tag === 0x17 ? fromUtcTime(value) : fromGeneralizedTime(value);
      if (iso) {
        if (firstTimeAt === -1) firstTimeAt = at;
        times.push(iso);
      }
    } else if (firstTimeAt === -1 && /^[\x20-\x7e]+$/.test(value) && value.length > 2) {
      // Everything before Validity belongs to the issuer.
      commonNames.push(value);
    }
  }

  return {
    notBefore: times[0] ?? null,
    notAfter: times[1] ?? null,
    issuer: commonNames.length > 0 ? (commonNames[commonNames.length - 1] as string) : null,
  };
}

/** `YYMMDDHHMMSSZ`, where YY under 50 means 20YY (RFC 5280 §4.1.2.5.1). */
function fromUtcTime(value: string): string | null {
  const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value.trim());
  if (!match) return null;
  const year = Number(match[1]);
  const century = year < 50 ? 2000 : 1900;
  return `${century + year}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`;
}

/** `YYYYMMDDHHMMSSZ`. */
function fromGeneralizedTime(value: string): string | null {
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value.trim());
  if (!match) return null;
  return `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`;
}
