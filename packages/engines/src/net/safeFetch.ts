/**
 * The one door every record-derived fetch goes through.
 *
 * Two checks in this product take a URL out of a stranger's DNS and ask the
 * network for it: the BIMI indicator and certificate named by an `l=` and `a=`
 * tag, and the MTA-STS policy file. That makes those two the whole of the
 * server-side request surface, and it makes them a server-side request forgery
 * primitive if nothing bounds them: whoever controls a DNS record chooses a URL
 * that our Worker will fetch, from our egress, with our reputation on it.
 *
 * The bound is deliberately narrow. HTTPS on 443 only, no credentials in the
 * URL, no address inside a private or loopback range, redirects re-checked at
 * every hop rather than followed blind, a byte ceiling enforced while reading
 * rather than trusted from a header, and a timeout.
 *
 * One honest limitation, stated rather than papered over: the address check
 * resolves the name itself and then hands the URL to `fetch`, which resolves it
 * again. A name that answers publicly on the first lookup and privately on the
 * second slips between them. Closing that needs connect-time pinning, which the
 * Workers runtime does not expose. What this does stop is the whole of the
 * casual surface: literal addresses, localhost aliases, names that simply point
 * at private space, and redirect chains that walk somewhere they should not.
 */
import { isPrivateIpv4, isPrivateIpv6 } from '../spf/ip.js';

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** Resolves a hostname to its addresses. Absent means the name check is skipped. */
export type ResolveHost = (host: string) => Promise<readonly string[]>;

export type FetchRefusal =
  /** Not https, or not on 443, or carries credentials. */
  | 'NOT_HTTPS'
  /** The URL points inside our own network, or somewhere unroutable. */
  | 'BLOCKED_ADDRESS'
  /** A redirect the caller does not allow, or one hop too many. */
  | 'REDIRECT'
  | 'STATUS'
  | 'TOO_LARGE'
  | 'UNREACHABLE';

export interface SafeFetchOptions {
  fetchImpl: FetchLike;
  /** Hard ceiling on the body, enforced while reading. */
  maxBytes: number;
  timeoutMs?: number;
  /**
   * Hops allowed. Zero means a 3xx is itself the answer, which is what
   * RFC 8461 section 3.3 requires of an MTA-STS policy fetch.
   */
  maxRedirects?: number;
  resolveHost?: ResolveHost;
}

export type SafeFetchResult =
  | { ok: true; body: Uint8Array; contentType: string; status: number; finalUrl: string }
  | { ok: false; refusal: FetchRefusal; detail: string };

/** Names that mean "this machine" or "this network" without ever being resolved. */
const LOCAL_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa', '.onion'];

function isLocalName(host: string): boolean {
  if (host === 'localhost') return true;
  return LOCAL_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

/** True for an address nothing on the public internet should be serving from. */
export function isBlockedAddress(address: string): boolean {
  return isPrivateIpv4(address) || isPrivateIpv6(address);
}

/**
 * Everything decidable without touching the network.
 *
 * `new URL` normalises the encodings people reach for first, so
 * `https://2130706433/` arrives here already spelled `127.0.0.1` and is caught
 * by the same branch as the literal.
 */
export function inspectUrl(raw: string): { ok: true; url: URL; host: string } | { ok: false; refusal: FetchRefusal; detail: string } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, refusal: 'NOT_HTTPS', detail: 'that is not a URL' };
  }

  if (url.protocol !== 'https:') {
    return { ok: false, refusal: 'NOT_HTTPS', detail: `the URL is ${url.protocol.replace(':', '')}, not https` };
  }
  if (url.username !== '' || url.password !== '') {
    return { ok: false, refusal: 'NOT_HTTPS', detail: 'the URL carries credentials' };
  }
  if (url.port !== '' && url.port !== '443') {
    return { ok: false, refusal: 'NOT_HTTPS', detail: `port ${url.port} is not 443` };
  }

  // An IPv6 literal keeps its brackets in `hostname`.
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();

  if (host === '') {
    return { ok: false, refusal: 'BLOCKED_ADDRESS', detail: 'the URL has no host' };
  }
  if (isLocalName(host)) {
    return { ok: false, refusal: 'BLOCKED_ADDRESS', detail: `${host} is not a public name` };
  }
  if (isBlockedAddress(host)) {
    return { ok: false, refusal: 'BLOCKED_ADDRESS', detail: `${host} is not a public address` };
  }

  return { ok: true, url, host };
}

/** The name check, when a resolver is available to do it. */
async function hostResolvesPrivate(host: string, resolveHost: ResolveHost): Promise<string | null> {
  let addresses: readonly string[];
  try {
    addresses = await resolveHost(host);
  } catch {
    // A resolver failure is not evidence of anything. `fetch` will fail on its
    // own if the name is genuinely dead, and reporting that is honest.
    return null;
  }
  const blocked = addresses.find((address) => isBlockedAddress(address));
  return blocked ?? null;
}

/** Read the body with the ceiling applied as it arrives, not as it is declared. */
async function readCapped(response: Response, maxBytes: number): Promise<Uint8Array | null> {
  const declared = Number.parseInt(response.headers.get('content-length') ?? '', 10);
  if (Number.isFinite(declared) && declared > maxBytes) return null;

  const reader = response.body?.getReader();
  if (!reader) {
    const buffer = await response.arrayBuffer();
    return buffer.byteLength > maxBytes ? null : new Uint8Array(buffer);
  }

  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.length;
    // Stop reading rather than buffer a body we have already refused.
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }

  const merged = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    merged.set(chunk, at);
    at += chunk.length;
  }
  return merged;
}

export async function safeFetch(raw: string, options: SafeFetchOptions): Promise<SafeFetchResult> {
  const maxRedirects = options.maxRedirects ?? 0;
  const timeoutMs = options.timeoutMs ?? 6_000;

  let target = raw;

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const inspected = inspectUrl(target);
    if (!inspected.ok) return inspected;

    if (options.resolveHost) {
      const blocked = await hostResolvesPrivate(inspected.host, options.resolveHost);
      if (blocked !== null) {
        return {
          ok: false,
          refusal: 'BLOCKED_ADDRESS',
          detail: `${inspected.host} resolves to ${blocked}, which is not public`,
        };
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await options.fetchImpl(inspected.url.href, {
        // Never `follow`. A followed redirect is a fetch this function never
        // got to check, which is the entire hole being closed here.
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      return {
        ok: false,
        refusal: 'UNREACHABLE',
        detail: 'the request failed or the certificate is invalid',
      };
    } finally {
      clearTimeout(timer);
    }

    if (response.status >= 300 && response.status < 400) {
      if (hop >= maxRedirects) {
        return { ok: false, refusal: 'REDIRECT', detail: `HTTP ${response.status}` };
      }
      const location = response.headers.get('location');
      if (!location) {
        return { ok: false, refusal: 'REDIRECT', detail: `HTTP ${response.status} with no location` };
      }
      // Resolved against the hop we are on, so a relative Location works and an
      // absolute one replaces it. Either way the next pass re-checks it.
      try {
        target = new URL(location, inspected.url).href;
      } catch {
        return { ok: false, refusal: 'REDIRECT', detail: 'the redirect target is not a URL' };
      }
      continue;
    }

    if (response.status !== 200) {
      return { ok: false, refusal: 'STATUS', detail: `HTTP ${response.status}` };
    }

    const body = await readCapped(response, options.maxBytes);
    if (body === null) {
      return { ok: false, refusal: 'TOO_LARGE', detail: `larger than ${options.maxBytes} bytes` };
    }

    return {
      ok: true,
      body,
      contentType: (response.headers.get('content-type') ?? '').toLowerCase(),
      status: response.status,
      finalUrl: inspected.url.href,
    };
  }

  return { ok: false, refusal: 'REDIRECT', detail: 'too many redirects' };
}
