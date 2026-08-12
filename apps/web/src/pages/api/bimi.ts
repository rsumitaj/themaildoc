import type { APIRoute } from 'astro';
import { analyzeBimi, analyzeDmarc } from '@maildoc/engines';
import { DohResolver } from '@maildoc/resolver';
import { apiError, jsonResponse, rateLimit, readDomain } from '../../lib/api';
import { cachedResponse, createDnsCache, storeResponse } from '../../lib/dnsCache';

/**
 * BIMI, checked properly.
 *
 * The record is two URLs, and whether a mailbox shows the logo depends on what
 * they serve. Fetching both is too expensive to ride along with the checkup,
 * so it gets its own endpoint, its own budget and its own cache window.
 */
export const prerender = false;

const BUDGET = 16;
const RESULT_TTL_SECONDS = 300;

async function handle(request: Request): Promise<Response> {
  const limit = rateLimit(request);
  if (!limit.allowed) {
    return apiError('RATE_LIMITED', 'That is a lot of requests. Give it a moment.', 429, {
      'retry-after': String(limit.retryAfter),
    });
  }

  const parsed = await readDomain(request);
  if (!parsed.ok) return parsed.response;

  const cached = await cachedResponse(request);
  if (cached) return cached;

  try {
    const resolver = new DohResolver({ budget: BUDGET, cache: createDnsCache() });
    // BIMI is only honoured at an enforcing policy, so the policy is part of
    // the answer rather than a separate trip for the reader.
    const dmarc = await analyzeDmarc(parsed.domain, resolver);
    const result = await analyzeBimi(parsed.domain, resolver, {
      ...(dmarc.effectivePolicy ? { dmarcPolicy: dmarc.effectivePolicy } : {}),
      fetchImpl: fetch,
    });

    const response = jsonResponse(
      {
        ok: true,
        domain: result.domain,
        found: result.found,
        record: result.record,
        logo: result.logo,
        authority: result.authority,
        declined: result.declined,
        logoReport: result.logoReport,
        certReport: result.certReport,
        dmarcPolicy: dmarc.effectivePolicy,
        status: result.status,
        conditions: result.conditions,
        meta: { queriesUsed: result.queriesUsed },
      },
      200,
      { 'cache-control': `public, max-age=${RESULT_TTL_SECONDS}` },
    );

    await storeResponse(request, response);
    return response;
  } catch {
    return apiError('CHECK_FAILED', 'The BIMI check couldn\u2019t complete. Let\u2019s try again.', 502);
  }
}

export const GET: APIRoute = ({ request }) => handle(request);
export const POST: APIRoute = ({ request }) => handle(request);
