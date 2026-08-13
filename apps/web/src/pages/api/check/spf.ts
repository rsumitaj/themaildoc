import type { APIRoute } from 'astro';
import { analyzeSpf, SPF_DEEP_WALK_BUDGET } from '@maildoc/engines';
import { DohResolver } from '@maildoc/resolver';
import { apiError, jsonResponse, rateLimit, readDomain } from '../../../lib/api';
import { cachedResponse, createDnsCache, storeResponse } from '../../../lib/dnsCache';

/**
 * The whole SPF chain, however deep it goes, in a request of its own.
 *
 * A Worker gets fifty subrequests. The checkup spends most of them on the nine
 * other records, which left the include chain a share, and a share is not
 * enough for the domains that need this most: an SPF flattening vendor answers
 * with a chain of per-customer names, each only discoverable by resolving the
 * one above it, and the tree came back ending at the first of them.
 *
 * Reserving budget inside the checkup helped and could not be the whole answer,
 * because the ceiling being divided is fifty for the entire request. The only
 * way to give the chain fifty is to give it a request. So this endpoint does
 * one thing, spends nearly the whole allowance on it, and walks to the end.
 *
 * The checkup still runs its own bounded SPF pass, because the score and the
 * spoofability verdict cannot wait on a second round trip. This is the
 * authoritative one: the result screen replaces the bounded chain and its
 * findings with these the moment they land, exactly as it already does for
 * DKIM.
 */
export const prerender = false;

const RESULT_TTL_SECONDS = 60;

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

  const cached = await cachedResponse(request);
  if (cached) return cached;

  try {
    const resolver = new DohResolver({
      budget: SPF_DEEP_WALK_BUDGET,
      cache: createDnsCache(),
    });
    const result = await analyzeSpf(parsed.domain, resolver, { verifyApex: false });

    const response = jsonResponse(
      {
        ok: true,
        domain: result.domain,
        found: result.found,
        record: result.record,
        chain: result.chain,
        lookupCount: result.lookupCount,
        lookupCountExact: result.lookupCountExact,
        voidLookupCount: result.voidLookupCount,
        voidCountExact: result.voidCountExact,
        allQualifier: result.allQualifier,
        redirect: result.redirect,
        status: result.status,
        conditions: result.conditions,
        meta: {
          queriesUsed: result.queriesUsed,
          budget: SPF_DEEP_WALK_BUDGET,
          notes: result.notes,
        },
      },
      200,
      { 'cache-control': `public, max-age=${RESULT_TTL_SECONDS}` },
    );

    await storeResponse(request, response);
    return response;
  } catch {
    return apiError('CHECK_FAILED', 'The SPF chain walk couldn’t complete. Let’s try again.', 502);
  }
}

export const GET: APIRoute = ({ request }) => handle(request);
export const POST: APIRoute = ({ request }) => handle(request);
