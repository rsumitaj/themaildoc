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
}

export type DohAttempt =
  | { ok: true; json: DohJson }
  | { ok: false; reason: 'TIMEOUT' | 'HTTP' | 'NETWORK' | 'PARSE'; message: string };

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
    last = await attemptOnce(doFetch, url, timeoutMs);
    if (last.ok) return last;
    // A 4xx is the provider telling us the query itself is wrong — retrying
    // just burns a subrequest.
    if (last.reason === 'HTTP' && last.message.startsWith('4')) return last;
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
