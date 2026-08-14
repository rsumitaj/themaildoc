import type { APIRoute } from 'astro';
import { healthCheck } from '@maildoc/engines';
import { apiError, jsonResponse, rateLimit, readDomain } from '../../lib/api';
import { cachedResponse, createDnsCache, storeResponse } from '../../lib/dnsCache';
import { countryOf, recordCheckup } from '../../lib/checkups';

/** The checkup itself. Runs on the Worker; everything else on the site is static. */
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
    const result = await healthCheck(parsed.domain, { cache: createDnsCache() });

    const response = jsonResponse(
      {
        ok: true,
        domain: result.domain,
        checkedAt: result.checkedAt,
        vitals: result.vitals,
        spoofability: result.spoofability,
        records: result.records,
        conditions: result.conditions,
        detail: {
          spf: result.spf,
          dmarc: result.dmarc,
          mx: result.mx,
          address: result.address,
          dnssec: result.dnssec,
          mtasts: result.mtasts,
          tlsrpt: result.tlsrpt,
          bimi: result.bimi,
          caa: result.caa,
          ptr: result.ptr,
        },
        meta: result.meta,
      },
      200,
      { 'cache-control': `public, max-age=${RESULT_TTL_SECONDS}` },
    );

    /**
     * Recorded after the answer is built, so nothing a stranger is waiting for
     * depends on it. A cache hit returns above this line and is not recorded,
     * which is right: the same domain checked twice inside a minute is one
     * visit, and the row already exists.
     */
    await recordCheckup({
      domain: result.domain,
      source: 'checkup',
      vitalsScore: result.vitals.score,
      vitalsBand: result.vitals.band,
      spoofable: result.spoofability.verdict,
      country: countryOf(request),
    });

    await storeResponse(request, response);
    return response;
  } catch {
    // Never leak an internal error to a patient — and never imply their
    // domain is at fault for our failure.
    return apiError(
      'CHECK_FAILED',
      'The checkup couldn’t complete. Let’s try again.',
      502,
    );
  }
}

export const GET: APIRoute = ({ request }) => handle(request);
export const POST: APIRoute = ({ request }) => handle(request);
