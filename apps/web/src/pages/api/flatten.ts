import type { APIRoute } from 'astro';
import { flattenSpf } from '@maildoc/engines';
import { DohResolver } from '@maildoc/resolver';
import { apiError, jsonResponse, rateLimit, readDomain } from '../../lib/api';
import { cachedResponse, createDnsCache, storeResponse } from '../../lib/dnsCache';
import { countryOf, recordCheckup } from '../../lib/checkups';

/**
 * SPF flattening.
 *
 * The most expensive thing the clinic does: it walks the whole include chain
 * and then resolves A, AAAA and MX for every host inside it. That is why it
 * has its own endpoint and its own budget rather than riding along with the
 * checkup, and why the engine reports a partial answer as partial instead of
 * handing back a record built from half of someone's senders.
 */
export const prerender = false;

const FLATTEN_BUDGET = 44;
const RESULT_TTL_SECONDS = 120;

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
    const resolver = new DohResolver({ budget: FLATTEN_BUDGET, cache: createDnsCache() });
    const result = await flattenSpf(parsed.domain, resolver);

    const response = jsonResponse(
      {
        ok: true,
        domain: result.domain,
        original: result.original,
        flattened: result.flattened,
        strings: result.strings,
        lookupsBefore: result.lookupsBefore,
        lookupsAfter: result.lookupsAfter,
        bytesBefore: result.bytesBefore,
        bytesAfter: result.bytesAfter,
        ipv4: result.ipv4,
        ipv6: result.ipv6,
        expanded: result.expanded,
        preserved: result.preserved,
        allTerm: result.allTerm,
        complete: result.complete,
        notes: result.notes,
        meta: { queriesUsed: result.queriesUsed },
      },
      200,
      { 'cache-control': `public, max-age=${RESULT_TTL_SECONDS}` },
    );

    await recordCheckup({
      domain: parsed.domain,
      source: 'flatten',
      country: countryOf(request),
    });

    await storeResponse(request, response);
    return response;
  } catch {
    return apiError('CHECK_FAILED', 'The flattener couldn’t complete. Let’s try again.', 502);
  }
}

export const GET: APIRoute = ({ request }) => handle(request);
export const POST: APIRoute = ({ request }) => handle(request);
