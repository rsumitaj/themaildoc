import { DOMAIN_LABEL_MAX_LENGTH, DOMAIN_MAX_LENGTH } from './constants.js';

export type DomainRejection =
  | 'EMPTY'
  | 'IP_ADDRESS'
  | 'NO_TLD'
  | 'INVALID_TLD'
  | 'INVALID_LABEL'
  | 'INVALID_CHARACTERS'
  | 'TOO_LONG';

export type DomainResult =
  | { ok: true; domain: string; input: string }
  | { ok: false; reason: DomainRejection; input: string };

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const ASCII_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
/** TLDs are alphabetic, or punycode (`xn--…`) for internationalised ones. */
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/;

/**
 * Turn whatever the patient typed into a bare, lowercase, ASCII (punycode)
 * hostname — or an explained rejection. Never throws.
 *
 * Accepts: `https://www.Example.com/path?q=1`, `user@example.com`,
 * `example.com.`, `exämple.com`, `EXAMPLE.CO.UK`.
 */
export function normalizeDomain(input: string): DomainResult {
  const raw = String(input ?? '').trim();
  if (!raw) return { ok: false, reason: 'EMPTY', input: raw };

  let host = raw
    // scheme
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    // userinfo / email local part
    .replace(/^[^/@]*@/, '')
    // path, query, fragment
    .replace(/[/?#].*$/, '')
    .trim();

  // port
  host = host.replace(/:\d+$/, '');
  // trailing root dot
  host = host.replace(/\.$/, '');
  host = host.toLowerCase();

  if (!host) return { ok: false, reason: 'EMPTY', input: raw };
  if (IPV4_RE.test(host) || host.includes(':') || host.startsWith('[')) {
    return { ok: false, reason: 'IP_ADDRESS', input: raw };
  }

  // Internationalised domains → punycode. `URL` does IDNA for us in Node,
  // browsers and workerd alike, so we don't ship a punycode dependency.
  if (/[^\u0020-\u007e]/.test(host)) {
    try {
      const url = new URL(`http://${host}`);
      host = url.hostname;
    } catch {
      return { ok: false, reason: 'INVALID_CHARACTERS', input: raw };
    }
  }

  if (host.length > DOMAIN_MAX_LENGTH) return { ok: false, reason: 'TOO_LONG', input: raw };

  const labels = host.split('.');
  if (labels.length < 2) return { ok: false, reason: 'NO_TLD', input: raw };

  for (const label of labels) {
    if (!label || label.length > DOMAIN_LABEL_MAX_LENGTH || !ASCII_LABEL_RE.test(label)) {
      return { ok: false, reason: 'INVALID_LABEL', input: raw };
    }
  }

  const tld = labels[labels.length - 1] as string;
  if (!TLD_RE.test(tld)) return { ok: false, reason: 'INVALID_TLD', input: raw };

  return { ok: true, domain: host, input: raw };
}

/** `www.` is almost never what the patient means when checking email. */
export function stripWww(domain: string): string {
  return domain.replace(/^www\./, '');
}

/** Convenience wrapper: normalized domain or `null`. */
export function toDomain(input: string): string | null {
  const result = normalizeDomain(input);
  return result.ok ? result.domain : null;
}

const REJECTION_MESSAGES: Record<DomainRejection, string> = {
  EMPTY: 'Enter a domain to examine, e.g. company.com',
  IP_ADDRESS: 'That looks like an IP address. Enter a domain, e.g. company.com',
  NO_TLD: 'That domain is missing a top-level domain, e.g. company.com',
  INVALID_TLD: 'That top-level domain doesn’t look right, e.g. company.com',
  INVALID_LABEL: 'That domain contains an invalid part, e.g. company.com',
  INVALID_CHARACTERS: 'That domain contains characters we can’t read, e.g. company.com',
  TOO_LONG: 'That domain is too long to be real.',
};

/** Patient-facing copy for a rejection — never "undefined". */
export function domainRejectionMessage(reason: DomainRejection): string {
  return REJECTION_MESSAGES[reason];
}
