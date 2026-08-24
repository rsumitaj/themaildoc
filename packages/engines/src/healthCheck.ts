import {
  dedupeConditions,
  rollupRecord,
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
import { resolverAddressLookup } from './net/resolveHost.js';
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

/**
 * DNS attempts one checkup may spend.
 *
 * Cloudflare allows fifty subrequests per request, and this is not the only
 * thing spending them: the MTA-STS policy file is one HTTPS fetch on top. The
 * budget now counts real network attempts rather than names we wanted to look
 * up, which is what it always claimed to count. Under the old accounting a
 * retry and a failover were free, so a chain with two slow names walked
 * straight past fifty, at which point the platform makes `fetch` throw and
 * every remaining lookup fails at once. That is what made a healthy record
 * look like broken DNS.
 */
export const DEFAULT_HEALTH_CHECK_BUDGET = 44;

/**
 * Of that budget, the share only the SPF chain walk and DMARC discovery may
 * spend.
 *
 * Ten engines share one resolver and the budget was first-come-first-served,
 * which quietly meant last-served-loses. Nine of them are shallow: an MX
 * lookup and its targets, a TXT at a known name, a pair of address records.
 * They finish in a round trip or two and they spend their queries immediately.
 * The tenth walks an include chain it can only discover one hop at a time, so
 * it is still asking for queries long after the others have taken them.
 *
 * The result was that the deepest chains — exactly the records most likely to
 * be broken, since depth is what breaks them — were the ones that could not be
 * read. A domain publishing SPF through a flattening vendor got a tree ending
 * in "we stopped walking here" three names in, and no card explaining why.
 *
 * Twenty-two covers the worst chain that can exist inside the rules: RFC 7208
 * stops a receiver at ten lookups, each hop is one TXT query, and the leaves
 * that consume no lookup of their own still have to be read. A record past the
 * limit is already reported as past it, so nothing beyond that changes the
 * verdict. The other engines keep twenty-two between them, which is more than
 * their worst case, and they degrade into smaller answers rather than none.
 */
export const HEALTH_CHECK_RESERVE = 22;

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
    /**
     * True when the *budget* is what stopped us, as distinct from the SPF chain
     * running past its share of it.
     *
     * `partial` conflates the two, and the browser needs them apart. The deep
     * chain walk exists precisely to finish a count this pass could not, so
     * once it lands an inexact SPF count is no longer a reason to tell a
     * visitor their complete result is partial. An exhausted budget still is.
     */
    budgetExhausted: boolean;
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
    // Scaled, so a caller that passes a smaller budget for a test or a cheaper
    // mode still gets the same proportion held back rather than all of it.
    reserve: Math.min(HEALTH_CHECK_RESERVE, Math.floor(budget / 2)),
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
      // The policy host is built from a domain a stranger typed, so the fetch
      // guard gets a way to check where it actually points.
      resolveHost: resolverAddressLookup(resolver),
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    }),
    analyzeBimi(name, resolver, { dmarcPolicy: dmarc.effectivePolicy }),
    analyzePtr(name, resolver, { addresses: ownAddresses(spf, mx, address), maxAddresses: 2 }),
  ]);

  // Read the posture from the raw analyses, then narrow every one of them, so
  // the per-record cards, the chart and the score are all built from the same
  // set of findings. Filtering only the merged list left a record card saying
  // "critical, 4 conditions" above a chart that listed none of them.
  const posture = readPosture(spf, mx);
  const narrowed = {
    spf: narrow(spf, posture),
    dmarc: narrow(dmarc, posture),
    mx: narrow(mx, posture),
    address: narrow(address, posture),
    dnssec: narrow(dnssec, posture),
    mtasts: narrow(mtasts, posture),
    tlsrpt: narrow(tlsrpt, posture),
    bimi: narrow(bimi, posture),
    caa: narrow(caa, posture),
    ptr: narrow(ptr, posture),
  };

  const conditions = sortConditions(
    dedupeConditions(
      Object.values(narrowed).flatMap((analysis) => analysis.conditions as Condition[]),
    ),
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

  // The verdict is computed from the policy receivers actually apply, so it is
  // the ground truth for the impersonation pillar. Handing it to the scorer is
  // what stops a page reading "0 out of 100" above "your domain can't be
  // easily spoofed".
  const spoofability = assessSpoofability(name, dmarc, spf);

  return {
    domain: name,
    checkedAt: new Date(started).toISOString(),
    vitals: vitals(conditions, { spoofability: spoofability.verdict }),
    spoofability,
    /**
     * Whether the name exists at all changes what every summary is allowed to
     * say. A domain nobody has registered was being told its MTA-STS was "not
     * published, and not needed, this domain receives no mail" — a sentence
     * that reads as approval, about a zone that does not exist.
     */
    records: summarize(narrowed, !conditions.some((c) => c.code === 'DOMAIN_NXDOMAIN')),
    conditions,
    ...narrowed,
    meta: {
      queriesUsed: resolver.queriesIssued,
      budget,
      partial: resolver.budgetExhausted || !spf.lookupCountExact,
      budgetExhausted: resolver.budgetExhausted,
      notes: [...notes],
      durationMs: Date.now() - started,
    },
  };
}

/**
 * What the domain says it does with mail.
 *
 * This exists because example.com scored 4 out of 100 while being configured
 * exactly right. It publishes `v=spf1 -all`, `p=reject; sp=reject` with strict
 * alignment, and a null MX. That is the textbook lockdown for a domain nobody
 * should ever send as or deliver to, and it was being told it was in critical
 * condition.
 *
 * The cause is that most checks silently assume a domain is in the mail
 * business. MTA-STS and TLS-RPT protect mail arriving at your servers, so they
 * are meaningless without servers. BIMI puts a logo beside mail you send. A
 * DMARC reporting address tells you who is sending as you, which matters far
 * less when the answer is meant to be nobody.
 *
 * So we read the two statements the domain actually made and stop asking for
 * things that do not apply. Parked domains are a large share of what gets
 * tested, and they are the case where a wrong answer is most obvious.
 */
interface MailPosture {
  /** The domain authorises at least one sender. */
  sends: boolean;
  /** The domain publishes somewhere for mail to be delivered. */
  receives: boolean;
}

/** Mechanisms that authorise a sender. `all` is the default, not a permission. */
const AUTHORISING = new Set(['ip4', 'ip6', 'a', 'mx', 'include', 'exists', 'ptr']);

function readPosture(spf: SpfAnalysis, mx: MxAnalysis): MailPosture {
  // RFC 7505: a null MX is an explicit "no mail is delivered here". A domain
  // with no MX at all is a different situation, usually an accident, and is
  // already reported as such, so it is not treated as a statement.
  const receives = !mx.acceptsNoMail && mx.hosts.length > 0;

  // Sending is shut off only by `-all` with nothing authorised before it. A
  // `~all` still lets mail through at most receivers, and a redirect hands the
  // decision to another record we have not judged here.
  const authorises = spf.terms.some(
    (term) =>
      term.kind === 'mechanism' &&
      AUTHORISING.has(term.name) &&
      term.qualifier !== '-' &&
      term.qualifier !== '?',
  );
  const sends = !(spf.found && spf.allQualifier === '-' && spf.redirect === null && !authorises);

  return { sends, receives };
}

/** Findings that only mean something for a domain that receives mail. */
const INBOUND_ONLY = new Set(['MTASTS_MISSING', 'TLSRPT_MISSING']);

/** Findings that only mean something for a domain that sends mail. */
const OUTBOUND_ONLY = new Set([
  'BIMI_MISSING',
  // Both of these say "you are enforcing without visibility". A domain that
  // authorises no senders has no legitimate mail to be blind to, and refusing
  // everything with no report address is the recommended parked configuration.
  'DMARC_BLIND_REJECT',
  'DMARC_RUA_MISSING',
]);

function applyPosture(conditions: Condition[], posture: MailPosture): Condition[] {
  if (posture.sends && posture.receives) return conditions;

  return conditions.filter((condition) => {
    if (!posture.receives && INBOUND_ONLY.has(condition.code)) return false;
    if (!posture.sends && OUTBOUND_ONLY.has(condition.code)) return false;
    return true;
  });
}

/**
 * One analysis with the findings that do not apply removed, and its own status
 * recomputed from what is left.
 *
 * Recomputing the status is the point. A record whose only findings were
 * suppressed is not still in critical condition, and leaving the old status in
 * place put a red dot on a DMARC card that had nothing left to report.
 */
function narrow<T extends { conditions: Condition[]; status: RecordStatus }>(
  analysis: T,
  posture: MailPosture,
): T {
  const kept = applyPosture(analysis.conditions, posture);
  if (kept.length === analysis.conditions.length) return analysis;
  return { ...analysis, conditions: kept, status: rollupRecord(kept) };
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

/**
 * `resolves` is false when the apex answered NXDOMAIN, which RFC 8020 makes
 * unambiguous: nothing exists at or below that name. Nothing about a zone that
 * is not there can be summarised as fine, so the summaries that would otherwise
 * read as approval say what is actually true instead.
 */
function summarize(
  { spf, dmarc, mx, address, dnssec, mtasts, tlsrpt, bimi, caa, ptr }: Analyses,
  resolves: boolean,
): RecordSummary[] {
  const absent = 'Not checked, this domain does not resolve';
  return [
    {
      record: 'SPF',
      label: 'SPF authentication',
      status: spf.status,
      found: spf.found,
      // `-` on its own is not a thing anyone can look up. Say `-all`.
      summary: !resolves
        ? absent
        : spf.found
          ? `${spf.lookupCount}${spf.lookupCountExact ? '' : '+'} of 10 lookups used, ending in ${spf.allQualifier === null ? 'no all mechanism' : `${spf.allQualifier}all`}`
          : 'No SPF record published',
      conditionCount: spf.conditions.length,
    },
    {
      record: 'DMARC',
      label: 'DMARC policy',
      status: dmarc.status,
      found: dmarc.found,
      summary: !resolves
        ? absent
        : dmarc.found
          ? `Policy ${dmarc.effectivePolicy}${dmarc.testMode ? ' (test mode overrides the published policy)' : ''}${dmarc.discovery.source === 'parent' ? `, inherited from ${dmarc.discovery.foundAt}` : ''}`
          : 'No DMARC record published',
      conditionCount: dmarc.conditions.length,
    },
    {
      record: 'MX',
      label: 'Mail servers',
      status: mx.status,
      found: mx.found,
      summary: !resolves
        ? absent
        : mx.acceptsNoMail
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
      summary: !resolves
        ? absent
        : dnssec.authenticated
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
      summary: !resolves
        ? absent
        : address.ipv4.length + address.ipv6.length === 0
          ? 'No address records'
          : `${address.ipv4.length} IPv4, ${address.ipv6.length} IPv6`,
      conditionCount: address.conditions.length,
    },
    {
      record: 'PTR',
      label: 'Reverse DNS',
      status: ptr.status,
      found: ptr.checked.some((entry) => entry.pointer !== null),
      summary: !resolves
        ? absent
        : ptr.noOwnServers
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
      summary: !resolves
        ? absent
        : mtasts.announced
        ? mtasts.policy?.mode
          ? `Policy in ${mtasts.policy.mode} mode`
          : 'Announced, but the policy could not be read'
        : mx.hosts.length === 0
          ? 'Not published, and not needed, this domain receives no mail'
          : 'Not published, inbound TLS can be stripped',
      conditionCount: mtasts.conditions.length,
    },
    {
      record: 'TLSRPT',
      label: 'TLS reporting',
      status: tlsrpt.status,
      found: tlsrpt.found,
      summary: !resolves
        ? absent
        : tlsrpt.found
        ? `${tlsrpt.destinations.length} reporting destination${tlsrpt.destinations.length === 1 ? '' : 's'}`
        : mx.hosts.length === 0
          ? 'Not published, and not needed, this domain receives no mail'
          : 'Not published, no visibility into TLS failures',
      conditionCount: tlsrpt.conditions.length,
    },
    {
      record: 'BIMI',
      label: 'Brand indicator',
      status: bimi.status,
      found: bimi.found,
      summary: !resolves
        ? absent
        : bimi.found
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
      summary: !resolves
        ? absent
        : caa.found
        ? caa.forbidsAll
          ? 'All issuance forbidden'
          : `${caa.issuers.length} authorised issuer${caa.issuers.length === 1 ? '' : 's'}`
        : 'Not published. Any CA may issue',
      conditionCount: caa.conditions.length,
    },
  ];
}
