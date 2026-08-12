import type { Issue } from '../types.js';

/** A / AAAA conditions. RFC 1035, RFC 1918 / 5735 (address space). */
export const A_ISSUES: readonly Issue[] = [
  {
    code: 'A_MISSING',
    record: 'A',
    severity: 'INFO',
    category: 'existence',
    title: 'Domain has no address record',
    why: '{domain} has no A or AAAA record, so it resolves to nothing on the web. For a mail-only domain that is perfectly normal.',
    fix: 'Nothing to do unless {domain} is meant to host a website, in which case add the A or AAAA record your host gave you.',
    rfc: 'RFC 1035 §3.4.1',
    dismissible: true,
    vars: ['domain'],
  },
  {
    code: 'A_PRIVATE_IP',
    record: 'A',
    severity: 'MEDIUM',
    category: 'syntax',
    title: 'Public DNS points at a private address',
    why: '{domain} resolves to {offending_term}, an address that only exists inside private networks. Nobody on the internet can reach it, and publishing internal addressing in public DNS tells strangers how your network is laid out.',
    fix: 'Publish the public address instead, and keep internal names on internal DNS.',
    rfc: 'RFC 1918 §3',
    vars: ['domain', 'offending_term'],
  },
  {
    code: 'AAAA_MISSING',
    record: 'A',
    severity: 'LOW',
    category: 'existence',
    title: 'No IPv6 address',
    why: '{domain} is IPv4 only. Nothing breaks today, but a growing share of networks are IPv6-first, and some receivers treat dual-stack presence as a small positive signal.',
    fix: 'Add an AAAA record when your host supports it. There is no downside to publishing both.',
    rfc: 'RFC 3596 §2.1',
    dismissible: true,
    vars: ['domain'],
  },
];

/**
 * DNSSEC conditions. RFC 4033/4034/4035.
 *
 * We read the resolver's authenticated-data flag plus the presence of DNSKEY
 * and DS, which is everything a validating resolver acts on.
 */
export const DNSSEC_ISSUES: readonly Issue[] = [
  {
    code: 'DNSSEC_UNSIGNED',
    record: 'DNSSEC',
    severity: 'LOW',
    category: 'crypto',
    title: 'DNSSEC is not enabled',
    why: 'The zone for {domain} is unsigned, so a resolver cannot tell your real DNS answers from forged ones. An attacker who can poison a cache can redirect your mail without touching your account.',
    fix: 'Enable DNSSEC at your DNS host, then publish the DS record it gives you at your registrar. Most providers do both in a single click.',
    rfc: 'RFC 4033 §3',
    vars: ['domain'],
  },
  {
    code: 'DNSSEC_DS_MISSING',
    record: 'DNSSEC',
    severity: 'MEDIUM',
    category: 'crypto',
    title: 'Zone is signed but the parent has no DS record',
    why: '{domain} publishes DNSSEC keys, but the registrar has not published the matching DS record. The chain of trust is broken at the top, so validating resolvers treat the zone as unsigned, you have the cost of DNSSEC and none of the benefit.',
    fix: 'Copy the DS record from your DNS host into your registrar control panel. It is a one-time step that is easy to miss.',
    rfc: 'RFC 4035 §2.4',
    vars: ['domain'],
  },
  {
    code: 'DNSSEC_BOGUS',
    record: 'DNSSEC',
    severity: 'CRITICAL',
    category: 'crypto',
    title: 'DNSSEC validation is failing',
    why: 'Signatures for {domain} do not validate. Validating resolvers, which includes Google, Cloudflare and most large mail providers. Refuse the answers entirely, so the domain stops resolving for a large part of the internet.',
    fix: 'This is an emergency: check whether the DS record at your registrar still matches the key at your DNS host. A key rotation that only happened on one side is the usual cause.',
    rfc: 'RFC 4035 §5',
    vars: ['domain'],
  },
];
