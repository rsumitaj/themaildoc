import type { APIRoute } from 'astro';
// Astro 6 removed `Astro.locals.runtime.env`; bindings now come from the
// runtime module. This route is `prerender = false`, so it only ever loads
// inside workerd where that module exists.
import { env } from 'cloudflare:workers';
import { jsonResponse, rateLimit, sameOrigin } from '../../lib/api';
import { validateLead, type Lead } from '../../lib/leads';

/**
 * Consultation requests.
 *
 * The only endpoint in the product that writes anything down. Everything else
 * reads public DNS and forgets; this stores a name and an address because
 * somebody asked to be contacted.
 *
 * It writes to D1 with bound parameters — a lead is untrusted input from a
 * public form, and this is the one place in the codebase where string
 * concatenation would be a vulnerability rather than a style choice.
 */
export const prerender = false;

const MAX_BODY_BYTES = 16 * 1024;

/**
 * Abuse controls, layered because none of them is sufficient alone.
 *
 * The per-isolate rate limit is a speed bump: isolates are per-colo and short
 * lived, so a distributed client walks straight past it. The durable control
 * is the Cloudflare rate-limiting rule on this path, documented in
 * `docs/DEPLOY.md`. These two exist so the database cannot be filled between
 * a rule being edited and it taking effect.
 */
const MAX_PER_EMAIL_PER_DAY = 3;
const MAX_INSERTS_PER_DAY = 200;

interface Env {
  LEADS?: D1Database;
}

export const POST: APIRoute = async ({ request }) => {
  // Its own bucket: a visitor who ran twenty checkups has spent nothing here.
  const limit = rateLimit(request, 'lead');
  if (!limit.allowed) {
    return error('RATE_LIMITED', 'That is a lot of requests. Give it a moment.', 429, {
      'retry-after': String(limit.retryAfter),
    });
  }

  // This is the one endpoint that writes, so it is the one that another site
  // could use a visitor's browser to submit on their behalf.
  if (!sameOrigin(request)) {
    return error('INVALID', 'We couldn’t read that submission.', 400);
  }

  const declared = Number.parseInt(request.headers.get('content-length') ?? '0', 10);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    return error('TOO_LARGE', 'That message is longer than we can accept.', 413);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return error('INVALID', 'We couldn’t read that submission.', 400);
  }

  const checked = validateLead(body);
  if (!checked.ok) {
    return jsonResponse(
      { ok: false, error: { code: 'INVALID', message: checked.message, field: checked.field } },
      400,
    );
  }

  const database = (env as Env).LEADS;
  if (!database) {
    // Never a silent success: a request that was not stored has not been
    // received, and the patient is told to write to us directly instead.
    return error(
      'UNAVAILABLE',
      'We couldn’t record that just now. Write to support@themaildoc.co and we’ll pick it up there.',
      503,
    );
  }

  try {
    const room = await withinLimits(database, checked.lead.email);
    if (!room) {
      // Answered as a success on purpose: a flood is not told which control it
      // hit, and a person who submitted twice by accident is not scolded.
      return jsonResponse({ ok: true, message: 'Received. We read these ourselves and reply properly.' });
    }
    await insert(database, checked.lead, request);
  } catch {
    return error(
      'UNAVAILABLE',
      'We couldn’t record that just now. Write to support@themaildoc.co and we’ll pick it up there.',
      503,
    );
  }

  return jsonResponse({ ok: true, message: 'Received. We read these ourselves and reply properly.' });
};

/** Astro only reaches this when no method handler above matched. */
export const ALL: APIRoute = () =>
  error('METHOD_NOT_ALLOWED', 'Use POST.', 405, { allow: 'POST' });

/**
 * One person asking three times in a day is a person. The fourth is a script,
 * and a day's worth of inserts above the cap is somebody testing us.
 */
async function withinLimits(database: D1Database, email: string): Promise<boolean> {
  const since = new Date(Date.now() - 86_400_000).toISOString().slice(0, 19) + 'Z';

  const mine = await database
    .prepare('SELECT COUNT(*) AS n FROM leads WHERE email = ? AND created_at > ?')
    .bind(email, since)
    .first<{ n: number }>();
  if ((mine?.n ?? 0) >= MAX_PER_EMAIL_PER_DAY) return false;

  const all = await database
    .prepare('SELECT COUNT(*) AS n FROM leads WHERE created_at > ?')
    .bind(since)
    .first<{ n: number }>();
  return (all?.n ?? 0) < MAX_INSERTS_PER_DAY;
}

async function insert(database: D1Database, lead: Lead, request: Request): Promise<void> {
  const cf = (request as { cf?: { country?: string } }).cf;

  await database
    .prepare(
      `INSERT INTO leads (
         name, email, company, domain, help_with, message,
         vitals_score, vitals_band, spoofable,
         source_page, referrer, country, user_agent
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      lead.name,
      lead.email,
      lead.company,
      lead.domain,
      lead.helpWith,
      lead.message,
      lead.vitalsScore,
      lead.vitalsBand,
      lead.spoofable,
      lead.sourcePage,
      trim(request.headers.get('referer'), 300),
      cf?.country ?? null,
      trim(request.headers.get('user-agent'), 300),
    )
    .run();
}

function trim(value: string | null, limit: number): string | null {
  if (!value) return null;
  return value.length > limit ? value.slice(0, limit) : value;
}

function error(
  code: string,
  message: string,
  status: number,
  extra: Record<string, string> = {},
): Response {
  return jsonResponse({ ok: false, error: { code, message } }, status, extra);
}
