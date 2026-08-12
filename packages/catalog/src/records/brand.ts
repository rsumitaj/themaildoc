import type { Issue } from '../types.js';

/**
 * BIMI and CAA.
 *
 * BIMI is **not an RFC**. It is an Internet-Draft
 * (draft-brand-indicators-for-message-identification), and citing a
 * non-existent RFC for it — as several checkers do — is exactly the sort of
 * detail that decides whether the rest of our citations get trusted.
 */
export const BIMI_ISSUES: readonly Issue[] = [
  {
    code: 'BIMI_MISSING',
    record: 'BIMI',
    severity: 'INFO',
    category: 'policy',
    title: 'No BIMI record',
    why: '{domain} publishes no brand indicator, so your logo does not appear beside your mail in the inboxes that support it. This is a marketing gain, not a security one, and it is only available to domains already enforcing DMARC.',
    fix: 'Once DMARC is at quarantine or reject, publish default._bimi.{domain}: v=BIMI1; l=https://{domain}/logo.svg; a=https://{domain}/vmc.pem',
    rfc: 'BIMI draft-14 §4.3',
    dismissible: true,
    vars: ['domain'],
  },
  {
    code: 'BIMI_DMARC_NOT_ENFORCED',
    record: 'BIMI',
    severity: 'HIGH',
    category: 'policy',
    title: 'BIMI published without DMARC enforcement',
    why: 'A BIMI record exists, but {domain} is at DMARC p={policy}. Receivers only display a brand indicator for domains enforcing quarantine or reject, so the logo, the certificate and the work behind them are doing nothing.',
    fix: 'Move DMARC to p=quarantine and then p=reject. The BIMI record starts working the moment enforcement does.',
    rfc: 'BIMI draft-14 §7.1',
    vars: ['domain', 'policy'],
  },
  {
    code: 'BIMI_SYNTAX',
    record: 'BIMI',
    severity: 'MEDIUM',
    category: 'syntax',
    title: 'BIMI record is malformed',
    why: 'The record does not begin with v=BIMI1, and receivers are told explicitly not to correct capitalisation or syntax on your behalf. It is ignored as published.',
    fix: 'Start the record with exactly v=BIMI1, then l= and optionally a=, separated by semicolons.',
    rfc: 'BIMI draft-14 §4.3',
    vars: [],
  },
  {
    code: 'BIMI_LOGO_INSECURE',
    record: 'BIMI',
    severity: 'MEDIUM',
    category: 'policy',
    title: 'BIMI logo is not served over HTTPS',
    why: 'The l= location is {offending_term}. Receivers only fetch indicators over HTTPS, so this logo is never retrieved.',
    fix: 'Host the SVG on HTTPS with a valid certificate and point l= at that URL.',
    rfc: 'BIMI draft-14 §4.3',
    vars: ['offending_term'],
  },
  {
    code: 'BIMI_VMC_MISSING',
    record: 'BIMI',
    severity: 'LOW',
    category: 'policy',
    title: 'BIMI has no verified mark certificate',
    why: 'There is no a= tag, so there is no certificate proving the logo is yours. Gmail and Apple Mail require one before they will display an indicator, without it, the record works only where evidence is optional.',
    fix: 'Obtain a VMC from a recognised issuer and publish it: a=https://{domain}/vmc.pem',
    rfc: 'BIMI draft-14 §4.3',
    dismissible: true,
    vars: ['domain'],
  },
  {
    code: 'BIMI_DECLINED',
    record: 'BIMI',
    severity: 'INFO',
    category: 'policy',
    title: 'BIMI record declines participation',
    why: 'The record has an empty l= value, which is the defined way of saying "do not display an indicator for this domain". If that is deliberate, it is working.',
    fix: 'No action needed, unless you meant to publish a logo, in which case set l= to its HTTPS location.',
    rfc: 'BIMI draft-14 §4.3',
    dismissible: true,
    vars: [],
  },
];

export const CAA_ISSUES: readonly Issue[] = [
  {
    code: 'CAA_MISSING',
    record: 'CAA',
    severity: 'INFO',
    category: 'crypto',
    title: 'No CAA record',
    why: 'Any certificate authority on earth may issue a certificate for {domain}. CAA is the record that says which ones you actually use, without it, a mis-issued certificate is one social-engineering call away.',
    fix: 'Publish a CAA record naming your CA, e.g. {domain}. CAA 0 issue "letsencrypt.org"',
    rfc: 'RFC 8659 §4',
    dismissible: true,
    vars: ['domain'],
  },
  {
    code: 'CAA_FORBIDS_ALL',
    record: 'CAA',
    severity: 'INFO',
    category: 'crypto',
    title: 'CAA forbids all certificate issuance',
    why: '{domain} publishes issue ";" which tells every certificate authority to refuse. That is a valid and deliberate lock. It also means nobody can renew a certificate here, including you.',
    fix: 'No action needed if that is intended. To allow renewals, add a CAA record naming the CA you use.',
    rfc: 'RFC 8659 §4.2',
    dismissible: true,
    vars: ['domain'],
  },
  {
    code: 'CAA_SYNTAX',
    record: 'CAA',
    severity: 'MEDIUM',
    category: 'syntax',
    title: 'CAA record uses an unknown property',
    why: 'The property {offending_term} is not one a certificate authority acts on. A CAA set that a CA cannot interpret gives you neither the restriction you intended nor a warning that it is absent.',
    fix: 'Use issue, issuewild or iodef. Anything else is ignored.',
    rfc: 'RFC 8659 §4',
    vars: ['offending_term'],
  },
];

/**
 * PTR / forward-confirmed reverse DNS.
 *
 * These findings are inferred: without a message in hand we do not know which
 * IP a domain sends from, so we check the addresses the domain itself
 * publishes — its MX hosts and any `a`/`mx` mechanism in its own SPF record.
 * Vendor ranges pulled in through an `include:` are somebody else's servers
 * and are deliberately not judged here. The severities reflect that inference:
 * a missing PTR on a machine we believe is yours is worth telling you about,
 * and is not the same certainty as a rejected message.
 */
export const PTR_ISSUES: readonly Issue[] = [
  {
    code: 'PTR_MISSING',
    record: 'PTR',
    severity: 'MEDIUM',
    category: 'existence',
    title: 'A mail server IP has no reverse DNS',
    why: '{offending_term} is published by {domain} as one of its own mail servers, and it has no PTR record. Receivers routinely refuse mail from an address with no reverse DNS, Gmail among them, before the message is ever examined.',
    fix: 'Ask whoever controls that IP (your host or cloud provider, not your DNS registrar) to set a PTR record pointing at the hostname the server introduces itself as.',
    rfc: 'RFC 1912 §2.1',
    vars: ['offending_term', 'domain'],
  },
  {
    code: 'FCRDNS_FAIL',
    record: 'PTR',
    severity: 'MEDIUM',
    category: 'existence',
    title: 'Reverse DNS does not confirm forward',
    why: '{offending_term} has a PTR pointing at {target}, but that hostname does not resolve back to the same address. Strict receivers treat a reverse record that does not round-trip as no reverse record at all.',
    fix: 'Make them agree: the PTR names a host, and that host needs an A or AAAA record pointing back to {offending_term}.',
    rfc: 'RFC 1912 §2.1',
    vars: ['offending_term', 'target'],
  },
  {
    code: 'PTR_GENERIC',
    record: 'PTR',
    severity: 'LOW',
    category: 'policy',
    title: 'Mail server has a generic reverse DNS name',
    why: 'The PTR for {offending_term} is {target}. the automatic name a hosting provider assigns. It resolves, and it also tells receivers that nobody has configured this machine deliberately, which filters weigh against you.',
    fix: 'Set the PTR to a hostname you own, e.g. mail.{domain}, and make sure that name resolves back to the same IP.',
    rfc: 'RFC 1912 §2.1',
    dismissible: true,
    vars: ['offending_term', 'target', 'domain'],
  },
];
