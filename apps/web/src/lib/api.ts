import { normalizeDomain, domainRejectionMessage } from '@maildoc/shared';

/**
 * Shared plumbing for the clinic's endpoints: one response shape, one set of
 * headers, one place that decides what a bad request looks like.
 */

export type ApiErrorCode =
  | 'INVALID_DOMAIN'
  | 'RATE_LIMITED'
  | 'CHECK_FAILED'
  | 'METHOD_NOT_ALLOWED';

/**
 * Set here rather than in `public/_headers`, because that file only decorates
 * static asset responses. Every `/api/*` route is `prerender = false`, so its
 * response is built by the Worker and never passes through the asset handler.
 * Anything these endpoints need on the way out has to be attached in code.
 */
const SECURITY_HEADERS: Record<string, string> = {
  'content-type': 'application/json; charset=utf-8',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  // The API is same-origin only; nothing here is meant to be embedded.
  'x-frame-options': 'DENY',
  // A JSON diagnosis of somebody's domain is not a search result.
  'x-robots-tag': 'noindex, nofollow',
};

export function jsonResponse(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...SECURITY_HEADERS, ...extra },
  });
}

export function apiError(
  code: ApiErrorCode,
  message: string,
  status: number,
  extra: Record<string, string> = {},
): Response {
  return jsonResponse({ ok: false, error: { code, message } }, status, extra);
}

/**
 * Is this write coming from our own pages, or from somebody else's?
 *
 * The read endpoints do not need this: they change nothing, and no CORS header
 * is sent, so another site can cause a lookup but never see the answer. The
 * consultation form is different, because it writes a row.
 *
 * Two checks, because either alone has a gap:
 *
 *   - `Origin` must match ours when the browser sends it, which it does on
 *     every cross-origin POST.
 *   - The content type must be JSON. An HTML form on another site can post to
 *     us without any preflight, but only as form-encoded or plain text. It
 *     cannot set `application/json`, so requiring it rules the whole trick out
 *     even where `Origin` is stripped by a privacy tool along the way.
 */
export function sameOrigin(request: Request): boolean {
  const type = request.headers.get('content-type') ?? '';
  if (!type.toLowerCase().startsWith('application/json')) return false;

  const origin = request.headers.get('origin');
  if (origin === null) return true;

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

/**
 * Pull the domain out of a request, whichever way it was sent.
 *
 * A GET with `?domain=` keeps results linkable; the island posts JSON. Both
 * end up in the same validator, so there is one definition of a valid domain.
 */
export async function readDomain(
  request: Request,
): Promise<{ ok: true; domain: string } | { ok: false; response: Response }> {
  let raw: string | null = null;

  if (request.method === 'GET') {
    raw = new URL(request.url).searchParams.get('domain');
  } else if (request.method === 'POST') {
    try {
      const body = (await request.json()) as { domain?: unknown };
      raw = typeof body.domain === 'string' ? body.domain : null;
    } catch {
      raw = null;
    }
  } else {
    return {
      ok: false,
      response: apiError('METHOD_NOT_ALLOWED', 'Use GET or POST.', 405, { allow: 'GET, POST' }),
    };
  }

  const result = normalizeDomain(raw ?? '');
  if (!result.ok) {
    return {
      ok: false,
      response: apiError('INVALID_DOMAIN', domainRejectionMessage(result.reason), 400),
    };
  }
  return { ok: true, domain: result.domain };
}

/**
 * Best-effort per-IP throttle, counted separately per endpoint.
 *
 * Worker isolates are per-colo and short-lived, so this is a speed bump rather
 * than a guarantee — the durable control is the Cloudflare rate-limiting rule
 * on /api/*, which runs before the Worker is ever invoked. This exists so a
 * single client cannot spin the DNS resolvers inside one isolate.
 *
 * The buckets are the point. There used to be one counter for the whole API,
 * which meant that running a dozen checkups — the behaviour of exactly the
 * person this site is built to reach — spent the budget that the consultation
 * form then needed, and their request to hire us came back 429. The busiest
 * visitor was the one most likely to be turned away at the only door that
 * matters. Reading DNS and asking to be contacted are different activities
 * with different abuse profiles, so they get different counters.
 */
const WINDOW_MS = 60_000;

/** Per-minute allowance for each bucket. */
const LIMITS = {
  /**
   * A checkup is ~20 DoH queries. Thirty a minute is far more than a person
   * types and still bounded enough that one client cannot lean on the public
   * resolvers through us.
   */
  check: 30,
  /**
   * Writing a row is cheap; the abuse we care about is volume, and the daily
   * per-address and per-day caps in the endpoint handle that. This only needs
   * to stop a script, so it can be generous enough that no real person, however
   * many times they mistype their email, ever meets it.
   */
  lead: 10,
} as const;

export type RateLimitBucket = keyof typeof LIMITS;

const hits = new Map<string, number[]>();

export function rateLimit(
  request: Request,
  bucket: RateLimitBucket = 'check',
): { allowed: boolean; retryAfter: number } {
  const ip =
    request.headers.get('cf-connecting-ip') ??
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    'unknown';

  const key = `${bucket}:${ip}`;
  const now = Date.now();
  const recent = (hits.get(key) ?? []).filter((time) => now - time < WINDOW_MS);

  if (recent.length >= LIMITS[bucket]) {
    const oldest = recent[0] ?? now;
    return { allowed: false, retryAfter: Math.max(1, Math.ceil((WINDOW_MS - (now - oldest)) / 1000)) };
  }

  recent.push(now);
  hits.set(key, recent);

  // Keep the map from growing without bound inside a long-lived isolate.
  if (hits.size > 5_000) {
    for (const [entry, times] of hits) {
      if (times.every((time) => now - time >= WINDOW_MS)) hits.delete(entry);
    }
  }

  return { allowed: true, retryAfter: 0 };
}
