import type { APIRoute } from 'astro';
import { analyzeDkim } from '@maildoc/engines';
import { DohResolver } from '@maildoc/resolver';
import { apiError, jsonResponse, rateLimit, readDomain } from '../../../lib/api';
import { cachedResponse, createDnsCache, storeResponse } from '../../../lib/dnsCache';

/**
 * DKIM lives at its own endpoint because it is the only check that has to
 * guess. Probing a dozen speculative selectors would not fit beside SPF's
 * chain walk inside one request's 50-subrequest budget, so it gets its own.
 */
export const prerender = false;

const RESULT_TTL_SECONDS = 60;
const DKIM_BUDGET = 16;

async function handle(request: Request): Promise<Response> {
  const limit = rateLimit(request);
  if (!limit.allowed) {
    return apiError(
      'RATE_LIMITED',
      'That is a lot of checkups at once. Give it a moment and try again.',
      429,
      { 'retry-after': String(limit.retryAfter) },
    );
  }

  const parsed = await readDomain(request);
  if (!parsed.ok) return parsed.response;

  const url = new URL(request.url);
  /**
   * `selector` for one, `selectors` for a list.
   *
   * A domain with more than one sender has more than one selector: marketing
   * signs with one, the helpdesk with another, the transactional provider with
   * a third, and "is my DKIM working" has a separate answer for each. Both
   * parameters feed the same list so an old link with `?selector=` keeps
   * working.
   */
  const requested = [
    ...(url.searchParams.get('selector') ?? '').split(','),
    ...(url.searchParams.get('selectors') ?? '').split(','),
  ];
  const explicitSelectors = validSelectors(requested);

  const cached = await cachedResponse(request);
  if (cached) return cached;

  try {
    const resolver = new DohResolver({ budget: DKIM_BUDGET, cache: createDnsCache() });
    const result = await analyzeDkim(parsed.domain, resolver, {
      ...(explicitSelectors.length > 0 ? { explicitSelectors } : {}),
    });

    const response = jsonResponse(
      {
        ok: true,
        domain: result.domain,
        found: result.found,
        keys: result.keys,
        probed: result.probed,
        status: result.status,
        conditions: result.conditions,
        /**
         * Echoed back so the page can say which selectors were checked because
         * it was told to, as against which were guesses. The difference is the
         * whole meaning of a miss.
         */
        explicit: explicitSelectors,
        meta: { queriesUsed: result.queriesUsed, notes: result.notes },
      },
      200,
      { 'cache-control': `public, max-age=${RESULT_TTL_SECONDS}` },
    );

    await storeResponse(request, response);
    return response;
  } catch {
    return apiError('CHECK_FAILED', 'The DKIM check couldn’t complete. Let’s try again.', 502);
  }
}

/**
 * A selector is one or more dot-separated labels (RFC 6376 §3.1), and it goes
 * in front of `._domainkey.<domain>`, so the labels have to be real ones. The
 * cap on how many is ours: each is a subrequest, and somebody pasting a
 * hundred would spend the endpoint's whole budget on one request.
 */
const SELECTOR_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_SELECTORS = 10;

function validSelectors(raw: readonly string[]): string[] {
  const out: string[] = [];
  for (const entry of raw) {
    const selector = entry.trim().toLowerCase();
    if (selector === '' || selector.length > 253) continue;
    if (!selector.split('.').every((label) => SELECTOR_LABEL.test(label))) continue;
    if (out.includes(selector)) continue;
    out.push(selector);
    if (out.length === MAX_SELECTORS) break;
  }
  return out;
}

export const GET: APIRoute = ({ request }) => handle(request);
export const POST: APIRoute = ({ request }) => handle(request);
