import type { APIRoute } from 'astro';
import { normalizeDomain } from '@maildoc/shared';
import { jsonResponse, rateLimit, sameOrigin } from '../../../lib/api';
import { recordFinalScore } from '../../../lib/checkups';

/**
 * The finished score, coming back from the result screen.
 *
 * A checkup arrives in three requests because fifty subrequests is not enough
 * for one. `/api/check` reads nine records and writes the row; the DKIM probe
 * and the full include-chain walk land afterwards and can only *add* findings.
 * So the score `/api/check` knows is, by construction, never worse than the
 * truth, and it was the number in the `checkups` table. A domain sat there at 85
 * and HEALTHY while the page that caused the row read 78 and NEEDS CARE,
 * and the direction of that error is the damaging one: the table exists to find
 * domains that are struggling, and every row in it was flattered.
 *
 * The merged number only exists in the browser, so the browser reports it. That
 * is a trust boundary and it is drawn deliberately narrow:
 *
 *   - It updates and never inserts, so a caller cannot put a domain in the
 *     table that no checkup ever ran on.
 *   - It does not touch `checks`, so a visit stays one visit however many
 *     times its score is refined.
 *   - Score, band and verdict are range- and enum-checked in `normalizeScore`
 *     before any of them reaches SQL.
 *   - It is same-origin and rate-limited like every other write here.
 *
 * What remains is that somebody who wants to can move one integer on a row for
 * a domain they really did check, in a private prospecting list. That is worth
 * less than the number being wrong on every row, which is what it was.
 */
export const prerender = false;

const MAX_BODY_BYTES = 2 * 1024;

interface ScoreBody {
  domain?: unknown;
  score?: unknown;
  band?: unknown;
  spoofable?: unknown;
}

export const POST: APIRoute = async ({ request }) => {
  const limit = rateLimit(request, 'score');
  if (!limit.allowed) {
    return jsonResponse({ ok: false, error: { code: 'RATE_LIMITED' } }, 429, {
      'retry-after': String(limit.retryAfter),
    });
  }

  // A write, so the same guard the consultation form uses.
  if (!sameOrigin(request)) {
    return jsonResponse({ ok: false, error: { code: 'INVALID' } }, 400);
  }

  const declared = Number.parseInt(request.headers.get('content-length') ?? '0', 10);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    return jsonResponse({ ok: false, error: { code: 'TOO_LARGE' } }, 413);
  }

  let body: ScoreBody;
  try {
    body = (await request.json()) as ScoreBody;
  } catch {
    return jsonResponse({ ok: false, error: { code: 'INVALID' } }, 400);
  }

  const domain = normalizeDomain(typeof body.domain === 'string' ? body.domain : '');
  if (!domain.ok) {
    return jsonResponse({ ok: false, error: { code: 'INVALID_DOMAIN' } }, 400);
  }

  const updated = await recordFinalScore({
    domain: domain.domain,
    vitalsScore: typeof body.score === 'number' ? body.score : Number.NaN,
    vitalsBand: typeof body.band === 'string' ? body.band : '',
    spoofable: typeof body.spoofable === 'string' ? body.spoofable : '',
  });

  /**
   * `updated: false` is not a failure and is not reported as one. A checkup
   * served from the response cache never wrote a row, so there is nothing to
   * correct, and the page that sent this has nothing to do about it either way.
   */
  return jsonResponse({ ok: true, updated }, 200);
};
