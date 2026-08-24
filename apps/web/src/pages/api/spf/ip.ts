import type { APIRoute } from 'astro';
import { evaluateSpf } from '@maildoc/engines';
import { SPF_EVALUATE_BUDGET } from '@maildoc/shared';
import { DohResolver } from '@maildoc/resolver';
import { apiError, jsonResponse, rateLimit, readDomain } from '../../../lib/api';
import { cachedResponse, createDnsCache, storeResponse } from '../../../lib/dnsCache';
import { countryOf, recordCheckup } from '../../../lib/checkups';

/**
 * Is this IP allowed to send as this domain?
 *
 * Every other SPF tool here describes a record. This one evaluates it, the way
 * the receiver that bounced somebody's mail evaluated it, and answers with one
 * of the seven results `check_host()` can return.
 *
 * It gets its own endpoint and its own budget for the same reason the deep
 * chain walk does. The ten-lookup limit bounds terms, not queries: one `mx` is
 * one lookup and up to eleven queries, and `ptr` reverses the address and then
 * forward-confirms every name that comes back. None of that fits inside the
 * checkup's share of fifty subrequests.
 */
export const prerender = false;

/**
 * Longer than a checkup's minute, because the answer is about a record that
 * changes when somebody edits DNS rather than about a message in flight, and
 * the person asking is usually asking about several addresses in a row.
 */
const RESULT_TTL_SECONDS = 120;

/** A local part plus a domain, loosely. The engine only reads it for macros. */
const SENDER = /^[^\s@]{1,64}@[^\s@]{1,253}$/;

async function handle(request: Request): Promise<Response> {
  const limit = rateLimit(request);
  if (!limit.allowed) {
    return apiError(
      'RATE_LIMITED',
      'That is a lot of checks at once. Give it a moment and try again.',
      429,
      { 'retry-after': String(limit.retryAfter) },
    );
  }

  const parsed = await readDomain(request);
  if (!parsed.ok) return parsed.response;

  const url = new URL(request.url);
  const ip = (url.searchParams.get('ip') ?? '').trim();
  if (ip === '' || ip.length > 45) {
    return apiError('INVALID_DOMAIN', 'Give us an IP address to check.', 400);
  }

  /**
   * The envelope sender, only because macros read it.
   *
   * `exists:%{l}.%{o}._spf.example.com` expands differently per sender, so a
   * domain using sender macros gets a different answer for a different address.
   * Left off, the engine uses `postmaster@<domain>`, which is what RFC 7208
   * §2.4 tells a receiver to use when MAIL FROM is empty.
   */
  const sender = (url.searchParams.get('sender') ?? '').trim();
  const helo = (url.searchParams.get('helo') ?? '').trim();

  const cached = await cachedResponse(request);
  if (cached) return cached;

  try {
    const resolver = new DohResolver({
      budget: SPF_EVALUATE_BUDGET,
      cache: createDnsCache(),
    });

    const result = await evaluateSpf(parsed.domain, ip, resolver, {
      ...(SENDER.test(sender) ? { sender } : {}),
      ...(helo !== '' && helo.length <= 253 ? { helo } : {}),
    });

    const response = jsonResponse(
      {
        ok: true,
        domain: result.domain,
        ip: result.ip,
        ipVersion: result.ipVersion,
        sender: result.sender,
        helo: result.helo,
        result: result.result,
        matched: result.matched,
        cause: result.cause,
        breaksEverySender: result.breaksEverySender,
        summary: result.summary,
        trace: result.trace,
        lookups: result.lookups,
        voidLookups: result.voidLookups,
        complete: result.complete,
        meta: {
          queriesUsed: result.queriesUsed,
          budget: SPF_EVALUATE_BUDGET,
          notes: result.notes,
        },
      },
      200,
      { 'cache-control': `public, max-age=${RESULT_TTL_SECONDS}` },
    );

    /**
     * Recorded as a domain that was examined, with no score.
     *
     * A `fail` here is a fact about one sender, not about the domain's health:
     * a perfectly configured domain returns `fail` for every address it does
     * not authorise, which is the record working. Writing a score from this
     * would put "0" beside domains that are doing exactly the right thing.
     */
    await recordCheckup({
      domain: result.domain,
      source: 'spf-ip',
      country: countryOf(request),
    });

    await storeResponse(request, response);
    return response;
  } catch {
    return apiError('CHECK_FAILED', 'The SPF evaluation couldn’t complete. Let’s try again.', 502);
  }
}

export const GET: APIRoute = ({ request }) => handle(request);
export const POST: APIRoute = ({ request }) => handle(request);
