import type { DohProvider } from '@maildoc/shared';
import type { FetchLike } from '../doh.js';
import { DNS_TYPE_NUMBERS, type DnsStatus, type DnsType } from '../types.js';

/**
 * Mock DNS for tests. Engines are only as trustworthy as the fixtures they are
 * proven against, so this renders DoH JSON exactly as Google and Cloudflare do
 * — including quoted, multi-string TXT records.
 */

const STATUS_CODES: Record<DnsStatus, number> = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
  TIMEOUT: 2,
  ERROR: 2,
};

/** A single TXT record: one character-string, or several to be concatenated. */
export type MockRdata = string | string[];

export interface MockRecordSet {
  status?: DnsStatus;
  data?: MockRdata[];
  /** DNSSEC authenticated-data flag. */
  ad?: boolean;
  /** Truncated response flag. */
  tc?: boolean;
  ttl?: number;
}

/**
 * A zone file, near enough. A name that is absent entirely answers NXDOMAIN;
 * a name that exists without the queried type answers NOERROR with no records
 * (an RFC 7208 void lookup).
 */
export type MockZone = Record<string, Partial<Record<DnsType, MockRdata[] | MockRecordSet>>>;

export interface MockDohCall {
  provider: DohProvider;
  name: string;
  type: string;
}

/**
 * How TXT rdata is rendered.
 * - `realistic` (default): Google concatenates and drops the quotes, Cloudflare
 *   preserves the quoted character-strings — exactly what the live APIs do.
 * - `quoted` / `concatenated`: force one style for both providers.
 */
export type MockTxtRendering = 'realistic' | 'quoted' | 'concatenated';

export interface MockDohOptions {
  /** Per-provider zone overrides — how you stage a propagation disagreement. */
  overrides?: Partial<Record<DohProvider, MockZone>>;
  txtRendering?: MockTxtRendering;
  /**
   * Make a provider misbehave. Return 'TIMEOUT' (hangs until aborted),
   * 'NETWORK' (rejects) or an HTTP status code.
   */
  fail?: (call: MockDohCall) => 'TIMEOUT' | 'NETWORK' | number | undefined;
}

export interface MockDoh {
  fetch: FetchLike;
  calls: MockDohCall[];
  /** Upstream queries per provider — proves the fallback/verify behaviour. */
  countFor(provider: DohProvider): number;
}

export function createMockDoh(zone: MockZone, options: MockDohOptions = {}): MockDoh {
  const calls: MockDohCall[] = [];

  const fetch: FetchLike = (input, init) => {
    const url = new URL(input);
    const provider: DohProvider = url.hostname.includes('cloudflare') ? 'cloudflare' : 'google';
    const name = (url.searchParams.get('name') ?? '').replace(/\.$/, '').toLowerCase();
    const type = (url.searchParams.get('type') ?? 'A').toUpperCase();
    const call: MockDohCall = { provider, name, type };
    calls.push(call);

    const failure = options.fail?.(call);
    if (failure === 'TIMEOUT') {
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        if (!signal) return; // hangs forever. the caller's timeout is the test
        signal.addEventListener('abort', () => {
          const error = new Error('The operation was aborted');
          error.name = 'AbortError';
          reject(error);
        });
      });
    }
    if (failure === 'NETWORK') return Promise.reject(new TypeError('Network request failed'));
    if (typeof failure === 'number') {
      return Promise.resolve(new Response('upstream error', { status: failure }));
    }

    const activeZone = { ...zone, ...(options.overrides?.[provider] ?? {}) };
    const rendering = options.txtRendering ?? 'realistic';
    const quoted =
      rendering === 'quoted' || (rendering === 'realistic' && provider === 'cloudflare');

    return Promise.resolve(
      new Response(JSON.stringify(buildAnswer(activeZone, name, type as DnsType, quoted)), {
        status: 200,
        headers: { 'content-type': 'application/dns-json' },
      }),
    );
  };

  return {
    fetch,
    calls,
    countFor: (provider) => calls.filter((call) => call.provider === provider).length,
  };
}

function buildAnswer(zone: MockZone, name: string, type: DnsType, quotedTxt: boolean) {
  const entry = zone[name];
  const question = [{ name: `${name}.`, type: DNS_TYPE_NUMBERS[type] ?? 1 }];

  // Unknown name → NXDOMAIN. Known name, unqueried type → empty NOERROR.
  if (!entry) return { Status: STATUS_CODES.NXDOMAIN, TC: false, AD: false, Question: question };

  const raw = entry[type];
  if (raw === undefined) return { Status: STATUS_CODES.NOERROR, TC: false, AD: false, Question: question };

  const set: MockRecordSet = Array.isArray(raw) ? { data: raw } : raw;
  const status = set.status ?? 'NOERROR';
  const records = set.data ?? [];

  return {
    Status: STATUS_CODES[status],
    TC: set.tc ?? false,
    AD: set.ad ?? false,
    Question: question,
    Answer: records.map((rdata) => ({
      name: `${name}.`,
      type: DNS_TYPE_NUMBERS[type] ?? 1,
      TTL: set.ttl ?? 300,
      data: type === 'TXT' ? renderTxt(rdata, quotedTxt) : String(rdata),
    })),
  };
}

/**
 * Cloudflare renders TXT as quoted, space-separated character-strings;
 * Google concatenates them and returns bare text.
 */
function renderTxt(rdata: MockRdata, quoted: boolean): string {
  const parts = Array.isArray(rdata) ? rdata : [rdata];
  return quoted
    ? parts.map((part) => `"${part.replace(/(["\\])/g, '\\$1')}"`).join(' ')
    : parts.join('');
}
