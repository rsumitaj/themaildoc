import type { Issue } from '../types.js';

/**
 * Cross-record / operational conditions. Any engine may emit these, which is
 * why they are deduped here under `GENERIC` rather than repeated per record.
 */
export const GENERIC_ISSUES: readonly Issue[] = [
  {
    code: 'DOMAIN_NXDOMAIN',
    record: 'GENERIC',
    severity: 'CRITICAL',
    category: 'existence',
    title: 'The domain does not resolve',
    why: '{domain} returns no DNS answer at all. There is nothing to examine, and no mail, sent or received, can work until it resolves.',
    fix: 'Check that the domain is still registered and that its nameservers are correct at the registrar.',
    rfc: 'RFC 1035 section 4.1.1',
    vars: ['domain'],
  },
  {
    code: 'RESOLVER_TIMEOUT',
    record: 'GENERIC',
    severity: 'INFO',
    category: 'operational',
    // This used to tell people to check their DNS host, on names that answered
    // instantly to every other tool. Almost every occurrence is our side, and
    // sending somebody to debug a healthy nameserver is worse than saying
    // nothing at all.
    title: 'We could not finish one lookup',
    why: 'The {record} lookup for {domain} did not complete, so this part of the checkup is incomplete. This is usually our end rather than yours, and it says nothing about your record.',
    fix: 'Run the checkup again. If the same lookup fails repeatedly, and only then, it is worth asking your DNS host whether that name is slow to answer.',
    rfc: 'RFC 1035 section 7.2',
    dismissible: true,
    scores: false,
    vars: ['domain', 'record'],
  },
  {
    code: 'PROPAGATION_IN_PROGRESS',
    record: 'GENERIC',
    severity: 'INFO',
    category: 'operational',
    title: 'DNS is still propagating',
    why: 'Public resolvers disagree about the {record} record for {domain}, which means it changed recently. Different receivers are seeing different answers right now.',
    fix: 'Wait for the record’s TTL to expire and re-run the checkup before acting on this section.',
    rfc: 'RFC 1035 section 3.2.1',
    dismissible: true,
    vars: ['domain', 'record'],
  },
];
