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
  const selector = url.searchParams.get('selector')?.trim().toLowerCase();
  const validSelector = selector && /^[a-z0-9._-]{1,63}$/.test(selector) ? selector : undefined;

  const cached = await cachedResponse(request);
  if (cached) return cached;

  try {
    const resolver = new DohResolver({ budget: DKIM_BUDGET, cache: createDnsCache() });
    const result = await analyzeDkim(parsed.domain, resolver, {
      ...(validSelector ? { explicitSelector: validSelector } : {}),
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

export const GET: APIRoute = ({ request }) => handle(request);
export const POST: APIRoute = ({ request }) => handle(request);
