import type { Issue } from '../types.js';

/**
 * MX conditions — RFC 5321 (SMTP), RFC 7505 (null MX), RFC 2181 (priorities).
 *
 * A domain with no MX is not automatically broken: plenty of domains only send.
 * The engine knows the difference, and this catalog says so.
 */
export const MX_ISSUES: readonly Issue[] = [
  {
    code: 'MX_MISSING',
    record: 'MX',
    severity: 'HIGH',
    category: 'existence',
    title: 'No MX records',
    why: '{domain} publishes no mail exchangers, so no one on the internet can deliver mail to it, including replies to mail you send, and the DMARC reports you asked for.',
    fix: 'Add MX records pointing at your mail provider. If {domain} is genuinely send-only, publish a null MX instead: a single MX record with priority 0 and a target of ".", that states the intent explicitly.',
    rfc: 'RFC 5321 section 5.1',
    vars: ['domain'],
  },
  {
    code: 'MX_NULL',
    record: 'MX',
    severity: 'INFO',
    category: 'existence',
    title: 'Domain declares that it accepts no mail',
    why: '{domain} publishes a null MX, which tells the world it never receives mail. Senders fail fast instead of retrying for days. If that is deliberate, it is exactly right.',
    fix: 'No action needed, unless this domain is supposed to receive mail, in which case replace the null MX with real mail exchangers.',
    rfc: 'RFC 7505 section 3',
    dismissible: true,
    scores: false,
    vars: ['domain'],
  },
  {
    code: 'MX_POINTS_TO_IP',
    record: 'MX',
    severity: 'HIGH',
    category: 'syntax',
    title: 'MX record points at an IP address',
    why: 'The MX target {offending_term} is an IP address, and an MX record must name a host. Strict senders reject the record outright; forgiving ones may still fail to deliver.',
    fix: 'Point the MX at a hostname such as mail.{domain}, and give that hostname an A or AAAA record with the IP.',
    rfc: 'RFC 5321 section 5.1',
    vars: ['offending_term', 'domain'],
  },
  {
    code: 'MX_TARGET_NO_ADDRESS',
    record: 'MX',
    severity: 'HIGH',
    category: 'existence',
    title: 'A mail exchanger has no address',
    why: '{target} is listed as a mail server for {domain} but has no A or AAAA record, so nothing can connect to it. Mail either fails or falls back to a lower-priority host you may not be watching.',
    fix: 'Publish an A or AAAA record for {target}, or remove it from the MX list if it is retired.',
    rfc: 'RFC 5321 section 5.1',
    vars: ['target', 'domain'],
  },
  {
    code: 'MX_TARGET_IS_CNAME',
    record: 'MX',
    severity: 'MEDIUM',
    category: 'syntax',
    title: 'A mail exchanger is a CNAME',
    why: '{target} is an alias rather than a host with its own address. The standard forbids this, and while most senders cope, the ones that do not simply fail to deliver.',
    fix: 'Point the MX at a hostname that has A or AAAA records directly, not at an alias.',
    rfc: 'RFC 5321 section 5.1',
    vars: ['target'],
  },
  {
    code: 'MX_SINGLE_POINT_OF_FAILURE',
    record: 'MX',
    // Advisory only. A single MX hostname behind many addresses is how the
    // large providers do it, and scoring that as a fault would be wrong.
    severity: 'INFO',
    category: 'policy',
    title: 'Only one mail exchanger, on one address',
    why: '{domain} has a single MX host and it resolves to a single address. While that one machine is unreachable, senders queue your mail and eventually return it. a maintenance window turns into lost mail.',
    fix: 'Add a second mail exchanger at a higher priority number. Most providers include one at no extra cost.',
    rfc: 'RFC 5321 section 5.1',
    dismissible: true,
    vars: ['domain'],
  },
];
