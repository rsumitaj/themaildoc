import { classifyIp, type IpKind } from '../ip.js';
import { inferService } from './senders.js';
import type {
  AggregateReport,
  AlignmentMode,
  AuthResult,
  Disposition,
  PublishedPolicy,
  ReportRow,
} from './types.js';

/**
 * Turning aggregate reports into the two answers a domain owner actually
 * wants: is anyone sending as me, and can I turn enforcement on without losing
 * my own mail.
 *
 * Two numbers matter and they are not the same number:
 *
 *   - what the receiver did — `policy_evaluated`, which is already
 *     alignment-aware (RFC 9990 §3.1.1) and is ground truth for delivery;
 *   - what the evidence supports — alignment recomputed here from
 *     `auth_results` against the published policy (RFC 9989 §4.4).
 *
 * They usually agree. Where they do not, the disagreement is itself a finding,
 * because a reporter that records a pass with no aligned identifier is
 * describing forwarded mail, not authorised mail. Most tools show only the
 * first number and call it a pass rate.
 *
 * No sentences are written in this file. It emits codes and variables; the
 * catalog supplies the prose.
 */

export type SourceVerdict = 'AUTHORIZED' | 'FORWARDED' | 'MISCONFIGURED' | 'UNAUTHENTICATED';

export const VERDICTS: readonly SourceVerdict[] = [
  'AUTHORIZED',
  'FORWARDED',
  'MISCONFIGURED',
  'UNAUTHENTICATED',
];

/** A finding as the analyzer emits it — code plus variables, no prose. */
export interface FindingSeed {
  code: string;
  vars: Record<string, string | number>;
  evidence?: string;
}

export interface IdentifierSummary {
  domain: string;
  selector: string | null;
  result: AuthResult;
  aligned: boolean;
  volume: number;
}

export interface Source {
  ip: string;
  kind: IpKind;
  volume: number;
  /** Percentage of all mail in the loaded reports, one decimal place. */
  share: number;
  verdict: SourceVerdict;
  byVerdict: Record<SourceVerdict, number>;
  /** More than one verdict present — the table says so rather than picking. */
  mixed: boolean;
  /** Volume with an aligned, passing identifier, recomputed here. */
  aligned: number;
  /** Volume the reporter recorded as passing DMARC. */
  reportedPass: number;
  spf: IdentifierSummary[];
  dkim: IdentifierSummary[];
  dispositions: Record<Disposition, number>;
  overrides: { type: string; comment: string | null; volume: number }[];
  headerFroms: string[];
  /** Inferred from the report's own authenticated domains — never asserted. */
  service: string | null;
  signsWithDkim: boolean;
  alignedDkimPass: boolean;
  alignedSpfPass: boolean;
  reporters: string[];
  rows: ReportRow[];
}

export interface Bloodwork {
  domain: string;
  reporters: { org: string; email: string; reportId: string; volume: number }[];
  range: { begin: number; end: number; days: number };
  policy: PublishedPolicy;
  /** More than one distinct published policy across the files (RFC 9990 §3.3). */
  policyVariants: number;
  reportCount: number;
  volume: number;
  aligned: number;
  reportedPass: number;
  /** Our alignment computation, as a percentage with one decimal place. */
  passRate: number;
  reportedPassRate: number;
  band: PassBand;
  totals: Record<SourceVerdict, number>;
  sources: Source[];
  timeline: { begin: number; volume: number; aligned: number }[];
  findings: FindingSeed[];
  /** Rows where the reporter's verdict and the evidence do not agree. */
  disagreements: number;
  errors: string[];
}

export type PassBand = 'HEALTHY' | 'NEEDS_CARE' | 'AT_RISK' | 'CRITICAL';

/**
 * Bands for an alignment rate. Deliberately harsher than the Vitals bands: 90%
 * aligned sounds respectable and means one message in ten from your domain is
 * unauthenticated.
 */
export function passBand(rate: number): PassBand {
  if (rate >= 98) return 'HEALTHY';
  if (rate >= 90) return 'NEEDS_CARE';
  if (rate >= 70) return 'AT_RISK';
  return 'CRITICAL';
}

/** Overrides that describe mail changing hands, not a receiver's opinion. */
const FORWARDING_REASONS = new Set(['forwarded', 'mailing_list', 'trusted_forwarder']);

const NO_VERDICTS: Record<SourceVerdict, number> = {
  AUTHORIZED: 0,
  FORWARDED: 0,
  MISCONFIGURED: 0,
  UNAUTHENTICATED: 0,
};

const NO_DISPOSITIONS: Record<Disposition, number> = {
  none: 0,
  quarantine: 0,
  reject: 0,
  unknown: 0,
};

export function analyzeReports(reports: readonly AggregateReport[]): Bloodwork {
  if (reports.length === 0) {
    throw new Error('There are no reports to analyse.');
  }

  const policy = mergedPolicy(reports);
  const anchor = policy.domain;
  const byIp = new Map<string, MutableSource>();
  const timeline: Bloodwork['timeline'] = [];
  const reporters = new Map<string, { org: string; email: string; reportId: string; volume: number }>();

  let volume = 0;
  let aligned = 0;
  let reportedPass = 0;
  let disagreements = 0;
  let begin = Number.POSITIVE_INFINITY;
  let end = 0;

  for (const report of reports) {
    let reportVolume = 0;
    let reportAligned = 0;

    for (const row of report.rows) {
      if (row.count <= 0) continue;
      const view = viewRow(row, report.policy, anchor);

      volume += row.count;
      reportVolume += row.count;
      if (view.computedPass) {
        aligned += row.count;
        reportAligned += row.count;
      }
      if (view.reportedPass) reportedPass += row.count;
      if (view.reportedPass !== view.computedPass) disagreements += row.count;

      collect(byIp, row, view, report.reporter.org);
    }

    if (report.range.begin > 0) {
      begin = Math.min(begin, report.range.begin);
      end = Math.max(end, report.range.end || report.range.begin);
      timeline.push({ begin: report.range.begin, volume: reportVolume, aligned: reportAligned });
    }

    const key = `${report.reporter.org}|${report.reporter.email}`;
    const existing = reporters.get(key);
    if (existing) existing.volume += reportVolume;
    else {
      reporters.set(key, {
        org: report.reporter.org,
        email: report.reporter.email,
        reportId: report.reporter.reportId,
        volume: reportVolume,
      });
    }
  }

  const sources = [...byIp.values()]
    .map((source) => finish(source, volume))
    .sort((a, b) => b.volume - a.volume);

  const totals = { ...NO_VERDICTS };
  for (const source of sources) {
    for (const verdict of VERDICTS) totals[verdict] += source.byVerdict[verdict];
  }

  const passRate = rate(aligned, volume);

  const bloodwork: Bloodwork = {
    domain: policy.domain,
    reporters: [...reporters.values()].sort((a, b) => b.volume - a.volume),
    range: {
      begin: Number.isFinite(begin) ? begin : 0,
      end,
      days: end > 0 && Number.isFinite(begin) ? Math.max(1, Math.round((end - begin) / 86_400)) : 0,
    },
    policy,
    policyVariants: countPolicies(reports),
    reportCount: reports.length,
    volume,
    aligned,
    reportedPass,
    passRate,
    reportedPassRate: rate(reportedPass, volume),
    band: passBand(passRate),
    totals,
    sources,
    timeline: timeline.sort((a, b) => a.begin - b.begin),
    findings: [],
    disagreements,
    errors: reports.flatMap((report) => report.errors),
  };

  return { ...bloodwork, findings: findingsFor(bloodwork) };
}

/* Row-level reading -------------------------------------------------------- */

interface RowView {
  /** An aligned identifier that passed — DMARC passes, and we can show why. */
  computedPass: boolean;
  reportedPass: boolean;
  alignedDkimPass: boolean;
  alignedSpfPass: boolean;
  /** An aligned DKIM domain appeared at all, whatever its result. */
  ownDkimSeen: boolean;
  ownSpfSeen: boolean;
  unalignedSpfPass: boolean;
  forwarding: boolean;
  verdict: SourceVerdict;
  dkim: IdentifierSummary[];
  spf: IdentifierSummary[];
}

function viewRow(row: ReportRow, policy: PublishedPolicy, anchor: string): RowView {
  const from = row.headerFrom;

  const dkim: IdentifierSummary[] = row.dkim.map((entry) => ({
    domain: entry.domain,
    selector: entry.selector,
    result: entry.result,
    aligned: isAligned(entry.domain, from, policy.adkim, anchor),
    volume: row.count,
  }));

  const spf: IdentifierSummary[] = row.spf.map((entry) => ({
    domain: entry.domain,
    selector: null,
    result: entry.result,
    aligned: isAligned(entry.domain, from, policy.aspf, anchor),
    volume: row.count,
  }));

  const alignedDkimPass = dkim.some((entry) => entry.aligned && entry.result === 'pass');
  const alignedSpfPass = spf.some((entry) => entry.aligned && entry.result === 'pass');
  const computedPass = alignedDkimPass || alignedSpfPass;
  const reportedPass = row.evaluated.dkim === 'pass' || row.evaluated.spf === 'pass';

  const ownDkimSeen = dkim.some((entry) => entry.aligned);
  const ownSpfSeen = spf.some((entry) => entry.aligned);
  const unalignedSpfPass = spf.some((entry) => !entry.aligned && entry.result === 'pass');
  const forwarding = row.overrides.some((override) => FORWARDING_REASONS.has(override.type));

  return {
    computedPass,
    reportedPass,
    alignedDkimPass,
    alignedSpfPass,
    ownDkimSeen,
    ownSpfSeen,
    unalignedSpfPass,
    forwarding,
    dkim,
    spf,
    verdict: verdictFor({
      computedPass,
      reportedPass,
      forwarding,
      ownDkimSeen,
      ownSpfSeen,
      unalignedSpfPass,
    }),
  };
}

/**
 * Classification, in the order the evidence deserves.
 *
 * Proof of alignment outranks everything. Forwarding evidence outranks the
 * reporter's own verdict, because a report that records a pass while
 * quarantining the message for `forwarded` is describing a relay, and calling
 * that authorised mail would hide the one thing the owner needs to see.
 *
 * The forwarded/unauthenticated boundary is a judgement, not a fact: an
 * attacker who copies a DKIM-Signature header produces the same shape as a
 * mailing list that broke one. The UI says so; nothing here pretends
 * otherwise.
 */
function verdictFor(signals: {
  computedPass: boolean;
  reportedPass: boolean;
  forwarding: boolean;
  ownDkimSeen: boolean;
  ownSpfSeen: boolean;
  unalignedSpfPass: boolean;
}): SourceVerdict {
  if (signals.computedPass) return 'AUTHORIZED';
  if (signals.forwarding) return 'FORWARDED';
  if (signals.ownDkimSeen) return signals.unalignedSpfPass ? 'FORWARDED' : 'MISCONFIGURED';
  if (signals.reportedPass) return 'AUTHORIZED';
  if (signals.ownSpfSeen) return 'MISCONFIGURED';
  return 'UNAUTHENTICATED';
}

/**
 * RFC 9989 §4.4. Strict alignment is an exact match; relaxed alignment holds
 * when both identifiers sit under the same organisational domain.
 *
 * DMARCbis replaced the Public Suffix List with a DNS tree walk (§4.10), which
 * needs queries this parser deliberately cannot make — it runs in the
 * patient's browser on a file, not on the network. The report itself supplies
 * the answer instead: the policy was discovered at `policy_published.domain`,
 * so that domain is the organisational domain for everything this report
 * covers. Where a report omits it, we fall back to comparing the last two
 * labels and the result is no worse than any PSL-free tool's.
 */
export function isAligned(
  authDomain: string,
  headerFrom: string,
  mode: AlignmentMode,
  anchor: string,
): boolean {
  const auth = authDomain.trim().toLowerCase().replace(/\.$/, '');
  const from = headerFrom.trim().toLowerCase().replace(/\.$/, '');
  if (!auth || !from) return false;
  if (auth === from) return true;
  if (mode === 's') return false;

  const base = anchor.trim().toLowerCase().replace(/\.$/, '');
  if (base) return under(auth, base) && under(from, base);

  return lastTwo(auth) === lastTwo(from);
}

function under(domain: string, base: string): boolean {
  return domain === base || domain.endsWith(`.${base}`);
}

function lastTwo(domain: string): string {
  return domain.split('.').slice(-2).join('.');
}

/* Per-source aggregation --------------------------------------------------- */

interface MutableSource {
  ip: string;
  volume: number;
  aligned: number;
  reportedPass: number;
  byVerdict: Record<SourceVerdict, number>;
  dispositions: Record<Disposition, number>;
  overrides: Map<string, { type: string; comment: string | null; volume: number }>;
  dkim: Map<string, IdentifierSummary>;
  spf: Map<string, IdentifierSummary>;
  headerFroms: Set<string>;
  reporters: Set<string>;
  signsWithDkim: boolean;
  alignedDkimPass: boolean;
  alignedSpfPass: boolean;
  rows: ReportRow[];
}

function collect(
  byIp: Map<string, MutableSource>,
  row: ReportRow,
  view: RowView,
  reporter: string,
): void {
  const key = row.sourceIp || 'unknown';
  let source = byIp.get(key);

  if (!source) {
    source = {
      ip: key,
      volume: 0,
      aligned: 0,
      reportedPass: 0,
      byVerdict: { ...NO_VERDICTS },
      dispositions: { ...NO_DISPOSITIONS },
      overrides: new Map(),
      dkim: new Map(),
      spf: new Map(),
      headerFroms: new Set(),
      reporters: new Set(),
      signsWithDkim: false,
      alignedDkimPass: false,
      alignedSpfPass: false,
      rows: [],
    };
    byIp.set(key, source);
  }

  source.volume += row.count;
  if (view.computedPass) source.aligned += row.count;
  if (view.reportedPass) source.reportedPass += row.count;
  source.byVerdict[view.verdict] += row.count;
  source.dispositions[row.disposition] += row.count;
  source.reporters.add(reporter);
  source.rows.push(row);
  if (row.headerFrom) source.headerFroms.add(row.headerFrom);
  if (view.dkim.length > 0) source.signsWithDkim = true;
  if (view.alignedDkimPass) source.alignedDkimPass = true;
  if (view.alignedSpfPass) source.alignedSpfPass = true;

  for (const override of row.overrides) {
    const existing = source.overrides.get(override.type);
    if (existing) existing.volume += row.count;
    else {
      source.overrides.set(override.type, {
        type: override.type,
        comment: override.comment,
        volume: row.count,
      });
    }
  }

  mergeIdentifiers(source.dkim, view.dkim);
  mergeIdentifiers(source.spf, view.spf);
}

function mergeIdentifiers(
  into: Map<string, IdentifierSummary>,
  entries: readonly IdentifierSummary[],
): void {
  for (const entry of entries) {
    const key = `${entry.domain}|${entry.selector ?? ''}|${entry.result}`;
    const existing = into.get(key);
    if (existing) existing.volume += entry.volume;
    else into.set(key, { ...entry });
  }
}

function finish(source: MutableSource, total: number): Source {
  const byVerdict = source.byVerdict;
  const verdict = VERDICTS.reduce<SourceVerdict>(
    (worst, candidate) => (byVerdict[candidate] > byVerdict[worst] ? candidate : worst),
    'AUTHORIZED',
  );

  const dkim = [...source.dkim.values()].sort((a, b) => b.volume - a.volume);
  const spf = [...source.spf.values()].sort((a, b) => b.volume - a.volume);

  return {
    ip: source.ip,
    kind: classifyIp(source.ip),
    volume: source.volume,
    share: rate(source.volume, total),
    verdict,
    byVerdict,
    mixed: VERDICTS.filter((candidate) => byVerdict[candidate] > 0).length > 1,
    aligned: source.aligned,
    reportedPass: source.reportedPass,
    spf,
    dkim,
    dispositions: source.dispositions,
    overrides: [...source.overrides.values()].sort((a, b) => b.volume - a.volume),
    headerFroms: [...source.headerFroms],
    service: inferService(
      [...dkim.map((entry) => entry.domain), ...spf.map((entry) => entry.domain)],
      dkim.map((entry) => entry.selector),
    ),
    signsWithDkim: source.signsWithDkim,
    alignedDkimPass: source.alignedDkimPass,
    alignedSpfPass: source.alignedSpfPass,
    reporters: [...source.reporters],
    rows: source.rows,
  };
}

/* Merging several files ---------------------------------------------------- */

function mergedPolicy(reports: readonly AggregateReport[]): PublishedPolicy {
  // The newest report wins: policy can change mid-window (RFC 9990 §3.3), and
  // the most recent statement is the one that describes the domain today.
  const newest = [...reports].sort((a, b) => b.range.begin - a.range.begin)[0];
  const policy = newest?.policy;
  if (!policy) throw new Error('These reports carry no published policy.');

  if (policy.domain) return policy;

  const named = reports.find((report) => report.policy.domain);
  return named ? { ...policy, domain: named.policy.domain } : policy;
}

function countPolicies(reports: readonly AggregateReport[]): number {
  const seen = new Set(
    reports.map((report) => {
      const policy = report.policy;
      return [policy.p, policy.sp, policy.np, policy.pct, policy.adkim, policy.aspf].join('|');
    }),
  );
  return seen.size;
}

function rate(part: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((part / total) * 1000) / 10;
}

/* Findings ----------------------------------------------------------------- */

/** Below this, a report describes an afternoon rather than a pattern. */
const LOW_VOLUME = 50;
/** Enforcement is a decision; it deserves more than one file's worth of data. */
const ENFORCEMENT_MIN_DAYS = 7;

function findingsFor(bloodwork: Bloodwork): FindingSeed[] {
  const findings: FindingSeed[] = [];
  const { policy, totals, volume, sources } = bloodwork;
  const add = (code: string, vars: Record<string, string | number>, evidence?: string): void => {
    findings.push(evidence === undefined ? { code, vars } : { code, vars, evidence });
  };

  const enforcing = policy.p === 'quarantine' || policy.p === 'reject';
  const domain = policy.domain || 'this domain';

  if (volume === 0) return findings;

  /* What is failing, and whether anything stopped it. */
  const hostile = sources.filter((source) => source.byVerdict.UNAUTHENTICATED > 0);
  const hostileVolume = totals.UNAUTHENTICATED;

  if (hostileVolume > 0) {
    const delivered = hostile.reduce((sum, source) => sum + source.dispositions.none, 0);
    const stopped = hostileVolume - delivered;
    const worst = hostile[0];

    if (delivered > 0 && !enforcing) {
      add('RUA_UNAUTHENTICATED_DELIVERED', {
        count: delivered,
        share: rate(delivered, volume),
        sources: hostile.length,
        domain,
      }, worst ? `${worst.ip}, ${worst.volume} messages, none aligned` : undefined);
    } else if (delivered > 0) {
      add('RUA_UNAUTHENTICATED_LEAKING', {
        count: delivered,
        sources: hostile.length,
        policy: policy.p ?? 'none',
      });
    }

    if (stopped > 0) {
      add('RUA_UNAUTHENTICATED_BLOCKED', {
        count: stopped,
        policy: policy.p ?? 'none',
        sources: hostile.length,
      });
    }
  }

  /* Your own mail, failing. This is what makes enforcement dangerous. */
  if (totals.MISCONFIGURED > 0) {
    const broken = sources.filter((source) => source.byVerdict.MISCONFIGURED > 0);
    const worst = broken[0];
    add('RUA_OWN_MAIL_FAILING', {
      count: totals.MISCONFIGURED,
      share: rate(totals.MISCONFIGURED, volume),
      sources: broken.length,
    }, worst ? `${worst.ip}${worst.service ? `, likely ${worst.service}` : ''}` : undefined);
  }

  /* Policy strength, judged against the evidence rather than in the abstract. */
  const ready =
    bloodwork.passRate >= 98 &&
    totals.MISCONFIGURED === 0 &&
    volume >= LOW_VOLUME &&
    bloodwork.range.days >= ENFORCEMENT_MIN_DAYS;

  if (policy.p === null || policy.p === 'none') {
    if (ready) {
      add('RUA_READY_FOR_ENFORCEMENT', { rate: bloodwork.passRate, domain, days: bloodwork.range.days });
    } else {
      add('RUA_POLICY_NONE_UNPROTECTED', {
        domain,
        rate: bloodwork.passRate,
        count: totals.UNAUTHENTICATED,
      });
    }
  } else if (policy.p === 'quarantine' && bloodwork.passRate >= 98 && totals.MISCONFIGURED === 0) {
    add('RUA_READY_FOR_REJECT', { rate: bloodwork.passRate, domain });
  }

  if (bloodwork.aligned === 0) {
    add('RUA_NOTHING_ALIGNED', { domain, count: volume });
  }

  /* Fragility that only reports can show. */
  const spfOnly = sources.filter(
    (source) => source.alignedSpfPass && !source.signsWithDkim && source.volume > 0,
  );
  if (spfOnly.length > 0) {
    const worst = spfOnly.sort((a, b) => b.volume - a.volume)[0];
    add('RUA_SPF_ONLY_SOURCE', {
      sources: spfOnly.length,
      count: spfOnly.reduce((sum, source) => sum + source.volume, 0),
    }, worst ? `${worst.ip}${worst.service ? `, likely ${worst.service}` : ''}` : undefined);
  }

  if (totals.FORWARDED > 0) {
    add('RUA_FORWARDED_MAIL', {
      count: totals.FORWARDED,
      share: rate(totals.FORWARDED, volume),
    });
  }

  const brokenSignatures = sources.filter((source) =>
    source.dkim.some((entry) => entry.aligned && entry.result === 'fail'),
  );
  if (brokenSignatures.length > 0 && totals.FORWARDED > 0) {
    add('RUA_DKIM_BROKEN_IN_TRANSIT', { sources: brokenSignatures.length });
  }

  /* The published policy's own gaps. */
  if (policy.pct !== null && policy.pct < 100) {
    add('RUA_PCT_PARTIAL', { pct: policy.pct, rest: 100 - policy.pct, domain });
  }

  if (policy.testing) {
    add('RUA_TESTING_MODE', { domain });
  }

  const sp = policy.sp;
  if (enforcing && sp !== null && (sp === 'none' || (sp === 'quarantine' && policy.p === 'reject'))) {
    add('RUA_SUBDOMAIN_POLICY_WEAKER', { domain, sp, p: policy.p ?? 'none' });
  }

  const overridden = sources.flatMap((source) => source.overrides);
  if (overridden.length > 0) {
    const byType = new Map<string, number>();
    for (const override of overridden) {
      byType.set(override.type, (byType.get(override.type) ?? 0) + override.volume);
    }
    const [type = 'unspecified', count = 0] = [...byType.entries()].sort((a, b) => b[1] - a[1])[0] ?? [];
    add('RUA_POLICY_OVERRIDDEN', { type, count, types: byType.size });
  }

  /* Honesty about the data itself. */
  if (bloodwork.disagreements > 0) {
    add('RUA_REPORTER_DISAGREES', {
      count: bloodwork.disagreements,
      reported: bloodwork.reportedPassRate,
      computed: bloodwork.passRate,
    });
  }

  const synthetic = sources.filter((source) => source.kind === 'documentation');
  if (synthetic.length > 0) {
    add('RUA_SAMPLE_DATA', { sources: synthetic.length });
  }

  const internal = sources.filter(
    (source) => source.kind === 'private' || source.kind === 'loopback' || source.kind === 'linklocal',
  );
  if (internal.length > 0) {
    const worst = internal[0];
    add('RUA_PRIVATE_SOURCE_IP', { sources: internal.length }, worst ? worst.ip : undefined);
  }

  if (volume < LOW_VOLUME) {
    add('RUA_LOW_VOLUME', { count: volume });
  }

  if (bloodwork.range.days < 2 || bloodwork.reportCount < 2) {
    add('RUA_SHORT_WINDOW', { days: Math.max(1, bloodwork.range.days), reports: bloodwork.reportCount });
  }

  if (bloodwork.policyVariants > 1) {
    add('RUA_POLICY_CHANGED', { variants: bloodwork.policyVariants });
  }

  if (bloodwork.errors.length > 0) {
    add('RUA_REPORTER_ERROR', { count: bloodwork.errors.length }, bloodwork.errors[0]);
  }

  return findings;
}
