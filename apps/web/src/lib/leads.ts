import { toDomain } from '@maildoc/shared';

/**
 * What a consultation request has to look like before it is allowed near the
 * database.
 *
 * Kept as one pure function so it can be unit-tested without a Worker, a form
 * or a network: everything the endpoint does to untrusted input happens here,
 * and everything the form shows the patient comes back out of here.
 */

/**
 * Four, in the words people actually use.
 *
 * Nobody arrives thinking "my SPF record exceeds the lookup limit". They
 * arrive because mail is not landing, or because somebody is pretending to be
 * them. The other options were symptoms nobody self-selects, and a long list
 * makes a short form feel like a survey.
 */
export const HELP_OPTIONS = [
  { value: 'deliverability', label: 'My mail is going to spam or bouncing' },
  { value: 'spoofing', label: 'Someone is sending email as my domain' },
  { value: 'dmarc', label: 'I need to get DMARC to enforcement' },
  { value: 'other', label: 'Something else' },
] as const;

export type HelpValue = (typeof HELP_OPTIONS)[number]['value'];

const HELP_VALUES: readonly string[] = HELP_OPTIONS.map((option) => option.value);

export const VITALS_BANDS: readonly string[] = ['HEALTHY', 'NEEDS_CARE', 'AT_RISK', 'CRITICAL'];
export const SPOOF_VERDICTS: readonly string[] = ['SPOOFABLE', 'PARTIAL', 'PROTECTED'];

export interface Lead {
  name: string;
  email: string;
  company: string | null;
  domain: string | null;
  helpWith: HelpValue;
  message: string | null;
  vitalsScore: number | null;
  vitalsBand: string | null;
  spoofable: string | null;
  sourcePage: string | null;
}

export type LeadResult =
  | { ok: true; lead: Lead }
  | { ok: false; field: string; message: string };

const LIMITS = {
  name: 120,
  email: 254, // RFC 5321 section 4.5.3.1.3
  company: 160,
  message: 4_000,
  sourcePage: 300,
} as const;

/**
 * Deliberately permissive: one `@`, something either side, a dot in the
 * domain. Anything stricter rejects real addresses, and the only way to know
 * an address works is to send to it.
 */
const EMAIL = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;

export function validateLead(input: unknown): LeadResult {
  if (typeof input !== 'object' || input === null) {
    return { ok: false, field: 'form', message: 'We couldn’t read that submission.' };
  }

  const body = input as Record<string, unknown>;

  // Honeypot: a field no human sees and every naive bot fills in. Reported as
  // a normal validation failure so a bot learns nothing from the response.
  if (text(body.website)) {
    return { ok: false, field: 'form', message: 'We couldn’t read that submission.' };
  }

  const name = text(body.name);
  if (!name) return { ok: false, field: 'name', message: 'Tell us who you are.' };
  if (name.length > LIMITS.name) {
    return { ok: false, field: 'name', message: 'That name is longer than we can store.' };
  }

  const email = text(body.email).toLowerCase();
  if (!email) return { ok: false, field: 'email', message: 'We need an address to reply to.' };
  if (email.length > LIMITS.email || !EMAIL.test(email)) {
    return { ok: false, field: 'email', message: 'That address doesn’t look right.' };
  }

  const helpWith = text(body.helpWith);
  if (!HELP_VALUES.includes(helpWith)) {
    return { ok: false, field: 'helpWith', message: 'Pick what you need help with.' };
  }

  const message = text(body.message);
  if (message.length > LIMITS.message) {
    return {
      ok: false,
      field: 'message',
      message: 'That message is very long. Send us the short version and we’ll ask.',
    };
  }

  return {
    ok: true,
    lead: {
      name,
      email,
      company: cap(text(body.company), LIMITS.company),
      // Runs through the same normaliser as the checkup, so a lead and a
      // diagnosis always spell the domain the same way.
      domain: toDomain(text(body.domain)),
      helpWith: helpWith as HelpValue,
      message: message || null,
      vitalsScore: score(body.vitalsScore),
      vitalsBand: oneOf(text(body.vitalsBand), VITALS_BANDS),
      spoofable: oneOf(text(body.spoofable), SPOOF_VERDICTS),
      sourcePage: cap(text(body.sourcePage), LIMITS.sourcePage),
    },
  };
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function cap(value: string, limit: number): string | null {
  if (!value) return null;
  return value.length > limit ? value.slice(0, limit) : value;
}

function score(value: unknown): number | null {
  const parsed = typeof value === 'number' ? value : Number.parseInt(text(value), 10);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 100) return null;
  return Math.round(parsed);
}

function oneOf(value: string, allowed: readonly string[]): string | null {
  const upper = value.toUpperCase();
  return allowed.includes(upper) ? upper : null;
}
