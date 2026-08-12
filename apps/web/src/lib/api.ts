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

const SECURITY_HEADERS: Record<string, string> = {
  'content-type': 'application/json; charset=utf-8',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  // The API is same-origin only; nothing here is meant to be embedded.
  'x-frame-options': 'DENY',
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
 * Best-effort per-IP throttle.
 *
 * Worker isolates are per-colo and short-lived, so this is a speed bump rather
 * than a guarantee — the durable control is the Cloudflare rate-limiting rule
 * on /api/*, which runs before the Worker is ever invoked. This exists so a
 * single client cannot spin the DNS resolvers inside one isolate.
 */
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 30;
const hits = new Map<string, number[]>();

export function rateLimit(request: Request): { allowed: boolean; retryAfter: number } {
  const ip =
    request.headers.get('cf-connecting-ip') ??
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    'unknown';

  const now = Date.now();
  const recent = (hits.get(ip) ?? []).filter((time) => now - time < WINDOW_MS);

  if (recent.length >= MAX_PER_WINDOW) {
    const oldest = recent[0] ?? now;
    return { allowed: false, retryAfter: Math.ceil((WINDOW_MS - (now - oldest)) / 1000) };
  }

  recent.push(now);
  hits.set(ip, recent);

  // Keep the map from growing without bound inside a long-lived isolate.
  if (hits.size > 5_000) {
    for (const [key, times] of hits) {
      if (times.every((time) => now - time >= WINDOW_MS)) hits.delete(key);
    }
  }

  return { allowed: true, retryAfter: 0 };
}
