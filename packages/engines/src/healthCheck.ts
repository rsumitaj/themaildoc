import {
  dedupeConditions,
  sortConditions,
  vitals,
  type Condition,
  type Vitals,
} from '@maildoc/catalog';
import { DohResolver, type DnsCache, type FetchLike, type ResolverNote } from '@maildoc/resolver';
import type { RecordKind, RecordStatus } from '@maildoc/shared';
import { analyzeSpf } from './spf/analyze.js';
import { analyzeDmarc } from './dmarc/analyze.js';
import { analyzeMx } from './mx/analyze.js';
import { analyzeAddresses, analyzeDnssec } from './address/analyze.js';
import { analyzeMtaSts, type MtaStsAnalysis } from './transport/mtasts.js';
import {
  analyzeBimi,
  analyzeCaa,
  analyzeTlsRpt,
  type BimiAnalysis,
  type CaaAnalysis,
  type TlsRptAnalysis,
} from './transport/records.js';
import { analyzePtr, type PtrAnalysis } from './ptr/analyze.js';
import { assessSpoofability, type Spoofability } from './spoofability.js';
import type { SpfAnalysis } from './spf/types.js';
import type { DmarcAnalysis } from './dmarc/types.js';
import type { MxAnalysis } from './mx/analyze.js';
import type { AddressAnalysis, DnssecAnalysis } from './address/analyze.js';

/**
 * The whole checkup, in one Worker request.
 *
 * Cloudflare allows 50 subrequests per request, so the budget below is the real
 * design constraint. Each engine gets a cap that keeps the worst case under it,
 * and every engine degrades honestly — a record we could not finish examining
 * says so, and never guesses.
 *
 * DKIM is deliberately absent: probing a dozen speculative selectors does not
 * fit beside SPF's chain walk, so it has its own endpoint.
 */

export const DEFAULT_HEALTH_CHECK_BUDGET = 46;

export interface HealthCheckOptions {
  fetchImpl?: FetchLike;
  cache?: DnsCache;
  /** Total DNS queries this checkup may spend. */
  budget?: number;
  timeoutMs?: number;
  /** Cross-check apex records against a second resolver. On by default. */
  verify?: boolean;
}

export interface RecordSummary {
  record: RecordKind;
  /** Patient-facing name, e.g. "SPF authentication". */
  label: string;
  status: RecordStatus;
  found: boolean;
  /** One line of what we found, already safe to render. */
  summary: string;
  conditionCount: number;
}

export interface HealthCheck {
  domain: string;
  checkedAt: string;
  vitals: Vitals;
  spoofability: Spoofability;
  records: RecordSummary[];
  conditions: Condition[];
  spf: SpfAnalysis;
  dmarc: DmarcAnalysis;
  mx: MxAnalysis;
  address: AddressAnalysis;
  dnssec: DnssecAnalysis;
  mtasts: MtaStsAnalysis;
  tlsrpt: TlsRptAnalysis;
  bimi: BimiAnalysis;
  caa: CaaAnalysis;
  ptr: PtrAnalysis;
  meta: {
    queriesUsed: number;
    budget: number;
    /** True when a guard stopped us short, so the chart is incomplete. */
    partial: boolean;
    notes: ResolverNote[];
    durationMs: number;
  };
}

export async function healthCheck(
  domain: string,
  options: HealthCheckOptions = {},
): Promise<HealthCheck> {
  const started = Date.now();
  const name = domain.trim().replace(/\.$/, '').toLowerCase();
  const budget = options.budget ?? DEFAULT_HEALTH_CHECK_BUDGET;
  const verify = options.verify ?? true;

  const resolver = new DohResolver({
    budget,
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.cache ? { cache: options.cache } : {}),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
  });

  // First pass, in parallel: everything that depends on nothing but the domain.
  // The engines share one resolver, so a name queried by two of them costs one
  // subrequest, and the resolver's counter enforces the cap no matter who gets
  // there first.
  const [dmarc, spf, mx, address, dnssec, tlsrpt, caa] = await Promise.all([
    analyzeDmarc(name, resolver, { verifyApex: verify, maxEdvChecks: 3, maxQueries: 8 }),
    analyzeSpf(name, resolver, { verifyApex: verify }),
    analyzeMx(name, resolver, { maxTargets: 5 }),
    analyzeAddresses(name, resolver),
    analyzeDnssec(name, resolver),
    analyzeTlsRpt(name, resolver),
    analyzeCaa(name, resolver),
  ]);

  // Second pass: these need answers from the first. Checking an MTA-STS policy
  // without knowing the real MX hosts, or BIMI without the effective DMARC
  // policy, would produce confident nonsense.
  const [mtasts, bimi, ptr] = await Promise.all([
    analyzeMtaSts(name, resolver, {
      mxHosts: mx.hosts.map((host) => host.host).filter(Boolean),
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    }),
    analyzeBimi(name, resolver, { dmarcPolicy: dmarc.effectivePolicy }),
    analyzePtr(name, resolver, { addresses: ownAddresses(spf, mx, address), maxAddresses: 2 }),
  ]);

  const conditions = sortConditions(
    dedupeConditions([
      ...dmarc.conditions,
      ...spf.conditions,
      ...mx.conditions,
      ...address.conditions,
      ...dnssec.conditions,
      ...mtasts.conditions,
      ...tlsrpt.conditions,
      ...bimi.conditions,
      ...caa.conditions,
      ...ptr.conditions,
    ]),
  );

  const notes = new Set<ResolverNote>([
    ...dmarc.notes,
    ...spf.notes,
    ...mx.notes,
    ...address.notes,
    ...dnssec.notes,
    ...mtasts.notes,
    ...tlsrpt.notes,
    ...bimi.notes,
    ...caa.notes,
    ...ptr.notes,
  ]);

  return {
    domain: name,
    checkedAt: new Date(started).toISOString(),
    vitals: vitals(conditions),
    spoofability: assessSpoofability(name, dmarc, spf),
    records: summarize({ spf, dmarc, mx, address, dnssec, mtasts, tlsrpt, bimi, caa, ptr }),
    conditions,
    spf,
    dmarc,
    mx,
    address,
    dnssec,
    mtasts,
    tlsrpt,
    bimi,
    caa,
    ptr,
    meta: {
      queriesUsed: resolver.queriesIssued,
      budget,
      partial: resolver.budgetExhausted || !spf.lookupCountExact,
      notes: [...notes],
      durationMs: Date.now() - started,
    },
  };
}

/**
 * The IPs this domain publishes as its *own* mail servers.
 *
 * Only hosts inside the domain's own zone count. A domain on Google Workspace
 * publishes `aspmx.l.google.com` as its MX — that is Google's machine, Google
 * sets its PTR, and telling the customer to fix it would be both wrong and
 * impossible to act on. Same reasoning excludes every vendor range reached
 * through an SPF `include:`.
 *
 * Apex addresses count only when the domain's own SPF contains a bare `a`
 * mechanism — that is the domain stating that this host sends its mail.
 */
function ownAddresses(spf: SpfAnalysis, mx: MxAnalysis, address: AddressAnalysis): string[] {
  const domain = spf.domain;
  const isOwnHost = (host: string) => host === domain || host.endsWith(`.${domain}`);

  const addresses = mx.hosts
    .filter((host) => isOwnHost(host.host))
    .flatMap((host) => host.addresses);

  const usesApex = spf.terms.some(
    (term) => term.kind === 'mechanism' && term.name === 'a' && term.value === null,
  );
  if (usesApex) addresses.push(...address.ipv4);

  return [...new Set(addresses)];
}

interface Analyses {
  spf: SpfAnalysis;
  dmarc: DmarcAnalysis;
  mx: MxAnalysis;
  address: AddressAnalysis;
  dnssec: DnssecAnalysis;
  mtasts: MtaStsAnalysis;
  tlsrpt: TlsRptAnalysis;
  bimi: BimiAnalysis;
  caa: CaaAnalysis;
  ptr: PtrAnalysis;
}

function summarize({
  spf,
  dmarc,
  mx,
  address,
  dnssec,
  mtasts,
  tlsrpt,
  bimi,
  caa,
  ptr,
}: Analyses): RecordSummary[] {
  return [
    {
      record: 'SPF',
      label: 'SPF authentication',
      status: spf.status,
      found: spf.found,
      summary: spf.found
        ? `${spf.lookupCount}${spf.lookupCountExact ? '' : '+'} of 10 lookups used, ending in ${spf.allQualifier ?? 'no all'}`
        : 'No SPF record published',
      conditionCount: spf.conditions.length,
    },
    {
      record: 'DMARC',
      label: 'DMARC policy',
      status: dmarc.status,
      found: dmarc.found,
      summary: dmarc.found
        ? `Policy ${dmarc.effectivePolicy}${dmarc.testMode ? ' (test mode overrides the published policy)' : ''}${dmarc.discovery.source === 'parent' ? `, inherited from ${dmarc.discovery.foundAt}` : ''}`
        : 'No DMARC record published',
      conditionCount: dmarc.conditions.length,
    },
    {
      record: 'MX',
      label: 'Mail servers',
      status: mx.status,
      found: mx.found,
      summary: mx.acceptsNoMail
        ? 'Null MX, this domain accepts no mail, by design'
        : mx.found
          ? `${mx.hosts.length} mail exchanger${mx.hosts.length === 1 ? '' : 's'}`
          : 'No MX records published',
      conditionCount: mx.conditions.length,
    },
    {
      record: 'DNSSEC',
      label: 'DNSSEC',
      status: dnssec.status,
      found: dnssec.signed,
      summary: dnssec.authenticated
        ? 'Signed and validating'
        : dnssec.signed
          ? 'Signed, but the chain of trust is incomplete'
          : 'Not enabled',
      conditionCount: dnssec.conditions.length,
    },
    {
      record: 'A',
      label: 'Address records',
      status: address.status,
      found: address.ipv4.length > 0 || address.ipv6.length > 0,
      summary:
        address.ipv4.length + address.ipv6.length === 0
          ? 'No address records'
          : `${address.ipv4.length} IPv4, ${address.ipv6.length} IPv6`,
      conditionCount: address.conditions.length,
    },
    {
      record: 'PTR',
      label: 'Reverse DNS',
      status: ptr.status,
      found: ptr.checked.some((entry) => entry.pointer !== null),
      summary: ptr.noOwnServers
        ? 'No servers of your own to check, your senders are all external'
        : ptr.checked.length === 0
          ? 'Not checked'
          : `${ptr.checked.filter((entry) => entry.forwardConfirmed).length} of ${ptr.checked.length} confirmed both ways`,
      conditionCount: ptr.conditions.length,
    },
    {
      record: 'MTASTS',
      label: 'MTA-STS',
      status: mtasts.status,
      found: mtasts.announced,
      summary: mtasts.announced
        ? mtasts.policy?.mode
          ? `Policy in ${mtasts.policy.mode} mode`
          : 'Announced, but the policy could not be read'
        : 'Not published, inbound TLS can be stripped',
      conditionCount: mtasts.conditions.length,
    },
    {
      record: 'TLSRPT',
      label: 'TLS reporting',
      status: tlsrpt.status,
      found: tlsrpt.found,
      summary: tlsrpt.found
        ? `${tlsrpt.destinations.length} reporting destination${tlsrpt.destinations.length === 1 ? '' : 's'}`
        : 'Not published, no visibility into TLS failures',
      conditionCount: tlsrpt.conditions.length,
    },
    {
      record: 'BIMI',
      label: 'Brand indicator',
      status: bimi.status,
      found: bimi.found,
      summary: bimi.found
        ? bimi.declined
          ? 'Published, declining to display a logo'
          : bimi.authority
            ? 'Logo and certificate published'
            : 'Logo published, no certificate'
        : 'Not published',
      conditionCount: bimi.conditions.length,
    },
    {
      record: 'CAA',
      label: 'Certificate authority',
      status: caa.status,
      found: caa.found,
      summary: caa.found
        ? caa.forbidsAll
          ? 'All issuance forbidden'
          : `${caa.issuers.length} authorised issuer${caa.issuers.length === 1 ? '' : 's'}`
        : 'Not published. Any CA may issue',
      conditionCount: caa.conditions.length,
    },
  ];
}
