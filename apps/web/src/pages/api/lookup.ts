import type { APIRoute } from 'astro';
import { DohResolver, type DnsType } from '@maildoc/resolver';
import { apiError, jsonResponse, rateLimit, readDomain } from '../../lib/api';
import { createDnsCache } from '../../lib/dnsCache';
import { countryOf, recordCheckup } from '../../lib/checkups';

/**
 * A plain DNS record lookup.
 *
 * The other endpoints answer "is this correct?". This one answers "what is
 * actually published?", which is the question people reach for a lookup tool
 * to settle. It reads through the same verified resolver, so the answer here
 * and the answer in a diagnosis can never disagree.
 */
export const prerender = false;

const ALLOWED: readonly DnsType[] = [
  'A',
  'AAAA',
  'MX',
  'TXT',
  'NS',
  'SOA',
  'CNAME',
  'CAA',
  'DNSKEY',
  'DS',
  'PTR',
  'SRV',
];

/** Records worth showing when no type is asked for. */
const DEFAULT_TYPES: readonly DnsType[] = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CAA'];

const LOOKUP_BUDGET = 14;
const TTL_SECONDS = 60;

async function handle(request: Request): Promise<Response> {
  const limit = rateLimit(request);
  if (!limit.allowed) {
    return apiError('RATE_LIMITED', 'That is a lot of lookups at once. Give it a moment.', 429, {
      'retry-after': String(limit.retryAfter),
    });
  }

  const parsed = await readDomain(request);
  if (!parsed.ok) return parsed.response;

  const requested = new URL(request.url).searchParams.get('type')?.toUpperCase();
  const types =
    requested && ALLOWED.includes(requested as DnsType)
      ? [requested as DnsType]
      : [...DEFAULT_TYPES];

  try {
    const resolver = new DohResolver({ budget: LOOKUP_BUDGET, cache: createDnsCache() });

    const answers = await Promise.all(
      types.map(async (type) => {
        const result = await resolver.query(parsed.domain, type);
        return {
          type,
          status: result.status,
          ttl: result.records[0]?.ttl ?? null,
          // Raw DNS content — the client escapes it on render.
          records:
            type === 'TXT'
              ? result.txt.map((record) => record.value)
              : result.records.map((record) => record.data),
        };
      }),
    );

    await recordCheckup({
      domain: parsed.domain,
      source: 'lookup',
      country: countryOf(request),
    });

    return jsonResponse(
      {
        ok: true,
        domain: parsed.domain,
        answers,
        meta: { queriesUsed: resolver.queriesIssued },
      },
      200,
      { 'cache-control': `public, max-age=${TTL_SECONDS}` },
    );
  } catch {
    return apiError('CHECK_FAILED', 'The lookup couldn’t complete. Let’s try again.', 502);
  }
}

export const GET: APIRoute = ({ request }) => handle(request);
export const POST: APIRoute = ({ request }) => handle(request);
