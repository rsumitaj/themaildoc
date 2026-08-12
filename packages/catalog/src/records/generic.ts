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
    rfc: 'RFC 1035 §4.1.1',
    vars: ['domain'],
  },
  {
    code: 'RESOLVER_TIMEOUT',
    record: 'GENERIC',
    severity: 'INFO',
    category: 'operational',
    title: 'A DNS lookup didn’t answer in time',
    why: 'The {record} lookup for {domain} timed out, so this part of the checkup is incomplete. It usually means a slow or overloaded nameserver rather than a misconfiguration.',
    fix: 'Re-run the checkup. If it keeps timing out, check your DNS host’s status. Receivers hitting the same timeout will treat your mail the same way.',
    rfc: 'RFC 1035 §7.2',
    dismissible: true,
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
    rfc: 'RFC 1035 §3.2.1',
    dismissible: true,
    vars: ['domain', 'record'],
  },
];
