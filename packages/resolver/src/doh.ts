import {
  DEFAULT_QUERY_RETRIES,
  DEFAULT_QUERY_TIMEOUT_MS,
  DOH_ENDPOINTS,
  type DohProvider,
} from '@maildoc/shared';
import type { DnsType, DohJson } from './types.js';

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface DohRequestOptions {
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  /** Retries *after* the first attempt. One is plenty for a public resolver. */
  retries?: number;
  /**
   * Called before every network attempt. Returning false stops us.
   *
   * A retry and a failover are each a real subrequest, and Cloudflare gives a
   * Worker fifty of them. Counting logical queries instead of attempts meant a
   * chain that hit a couple of slow names quietly blew through the platform
   * limit, at which point `fetch` itself starts throwing and the whole walk
   * looks like the customer's DNS is broken. The caller does the counting,
   * because only the caller knows the budget.
   */
  spend?: () => boolean;
}

export type DohAttempt =
  | { ok: true; json: DohJson }
  | { ok: false; reason: 'TIMEOUT' | 'HTTP' | 'NETWORK' | 'PARSE' | 'BUDGET'; message: string };

export function dohUrl(provider: DohProvider, name: string, type: DnsType): string {
  const endpoint = DOH_ENDPOINTS[provider];
  return `${endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
}

/**
 * One DoH query against one provider: timeout, bounded retry, JSON out.
 * Never throws — every failure is a typed reason the resolver can act on.
 */
export async function queryProvider(
  provider: DohProvider,
  name: string,
  type: DnsType,
  options: DohRequestOptions = {},
): Promise<DohAttempt> {
  const doFetch = options.fetchImpl ?? (globalThis.fetch as FetchLike | undefined);
  if (!doFetch) {
    return { ok: false, reason: 'NETWORK', message: 'No fetch implementation available' };
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_QUERY_TIMEOUT_MS;
  const retries = options.retries ?? DEFAULT_QUERY_RETRIES;
  const url = dohUrl(provider, name, type);

  let last: DohAttempt = { ok: false, reason: 'NETWORK', message: 'not attempted' };

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    if (options.spend && !options.spend()) {
      return { ok: false, reason: 'BUDGET', message: 'Out of query budget' };
    }

    last = await attemptOnce(doFetch, url, timeoutMs);
    if (last.ok) return last;

    // A 4xx is the provider telling us the query itself is wrong, so retrying
    // just burns a subrequest. 429 is the exception: that one means "not right
    // now", which is exactly what a retry is for, and it is what a public
    // resolver answers when a burst of lookups arrives from one address.
    if (last.reason === 'HTTP' && last.message.startsWith('4') && last.message !== '429') {
      return last;
    }
  }
  return last;
}

async function attemptOnce(
  doFetch: FetchLike,
  url: string,
  timeoutMs: number,
): Promise<DohAttempt> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await doFetch(url, {
      headers: { accept: 'application/dns-json' },
      signal: controller.signal,
    });
    if (!response.ok) {
      return { ok: false, reason: 'HTTP', message: String(response.status) };
    }
    try {
      const json = (await response.json()) as DohJson;
      if (!json || typeof json.Status !== 'number') {
        return { ok: false, reason: 'PARSE', message: 'Malformed DoH response' };
      }
      return { ok: true, json };
    } catch {
      return { ok: false, reason: 'PARSE', message: 'Unreadable DoH response' };
    }
  } catch (error) {
    const aborted =
      controller.signal.aborted ||
      (error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError'));
    return aborted
      ? { ok: false, reason: 'TIMEOUT', message: `Timed out after ${timeoutMs}ms` }
      : { ok: false, reason: 'NETWORK', message: 'DNS request failed' };
  } finally {
    clearTimeout(timer);
  }
}
