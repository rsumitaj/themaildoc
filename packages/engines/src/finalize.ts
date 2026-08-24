import {
  dedupeConditions,
  sortConditions,
  vitals as computeVitals,
  type Condition,
  type Vitals,
} from '@maildoc/catalog/scoring';
import { assessSpoofability, type Spoofability } from './spoofability.js';

/**
 * One checkup, assembled from the three requests it arrives in.
 *
 * A Worker gets fifty subrequests, which is why a checkup is not one request:
 * `/api/check` reads nine records, `/api/check/spf` walks the include chain to
 * the end, and `/api/check/dkim` probes selectors. Each lands separately and
 * each sees only its own part of the domain.
 *
 * Nothing was wrong with the split. What was wrong is that every consumer
 * merged the parts for itself, or forgot to. The result screen merged
 * conditions and re-scored, and got the right number. `/api/check` recorded its
 * own score into the `checkups` table before the other two legs existed, so the
 * table held a domain's score as it looked without DKIM: 85 and HEALTHY in the
 * row, beside the 78 and NEEDS CARE on screen that caused it. The readiness page never
 * asked for the deep walk at all and passed an SPF record at "9 of 10 lookups"
 * that the checkup was calling a permanent error at twelve. The spoofability
 * banner kept the reasons the bounded walk produced. The "partial result" note
 * stayed on screen after the walk that completed it had landed.
 *
 * Those are four bugs with one cause, so they get one fix: the merge happens
 * here, once, and everything that shows a visitor a number reads the result of
 * this function. Adding a fourth leg later means changing this file and nothing
 * else.
 *
 * Deliberately free of framework and network. It takes the three payloads and
 * returns the finished view, which is what makes it testable without a browser
 * or a DNS server, and small enough to ship to a visitor.
 */

/**
 * The parts of `/api/check` this merge reads. A full response satisfies it.
 *
 * Generic in the record card so a caller gets back exactly the type it passed
 * in. The merge only ever rewrites the fields every card has, and narrowing
 * `RecordKind` to `string` on the way through would make the result unusable
 * by the component that rendered the input.
 */
export interface CoreLeg<R extends RecordLike = RecordLike> {
  domain: string;
  conditions: Condition[];
  records: R[];
  detail: {
    spf: SpfLeg;
    dmarc: {
      found: boolean;
      ignored: boolean;
      testMode: boolean;
      appliedPolicy: 'none' | 'quarantine' | 'reject';
      effectivePolicy: 'none' | 'quarantine' | 'reject';
      discovery: { source: string; foundAt: string | null };
    };
  };
  meta: {
    queriesUsed: number;
    /**
     * Whether a guard stopped the checkup short — as opposed to the SPF chain
     * merely running past its share, which the deep walk goes on to finish.
     * Kept apart from `partial` so the note can be cleared when the second walk
     * lands rather than left on a result that is now complete.
     */
    budgetExhausted: boolean;
    partial: boolean;
  };
}

/** What both SPF walks have in common: enough to score, summarise and draw. */
export interface SpfLeg {
  found: boolean;
  record?: string | null;
  allQualifier: string | null;
  lookupCount: number;
  lookupCountExact: boolean;
  status: string;
  conditions?: Condition[];
}

export interface DeepSpfLeg extends SpfLeg {
  conditions: Condition[];
  meta: { queriesUsed: number };
}

export interface DkimLeg {
  found: boolean;
  status: string;
  conditions: Condition[];
}

export interface RecordLike {
  record: string;
  label: string;
  status: string;
  found: boolean;
  summary: string;
  conditionCount: number;
}

export interface FinalCheckup<R extends RecordLike = RecordLike> {
  domain: string;
  /** Every finding from every leg, deduped and in triage order. */
  conditions: Condition[];
  /** The score a visitor is shown, and the only one worth recording. */
  vitals: Vitals;
  /** Recomputed, so its reasons describe the deepest walk that ran. */
  spoofability: Spoofability;
  /** The authoritative SPF facts: the deep walk when it landed. */
  spf: SpfLeg;
  /** Record cards, with SPF corrected by the deep walk when it landed. */
  records: R[];
  /** True only when something is still genuinely missing from the picture. */
  partial: boolean;
  /** Every DNS query the whole checkup spent, across all legs. */
  queriesUsed: number;
  /**
   * Which of the two later legs are in this result.
   *
   * Reported rather than reduced to one flag, because "has not landed yet" and
   * "failed and never will" are the same thing here and are not the same thing
   * to a caller. The result screen waits for the examination to settle before
   * it reports a score, which covers both; something that wanted to retry a
   * missing leg would need to know which one.
   */
  legs: { deepSpf: boolean; dkim: boolean };
}

export interface FinalizeInput<R extends RecordLike = RecordLike> {
  core: CoreLeg<R>;
  /** The deep chain walk, if it landed. Authoritative over the checkup's own. */
  deepSpf?: DeepSpfLeg | null;
  /** The selector probe, if it landed. */
  dkim?: DkimLeg | null;
}

export function finalizeCheckup<R extends RecordLike>({
  core,
  deepSpf,
  dkim,
}: FinalizeInput<R>): FinalCheckup<R> {
  /**
   * The deep walk's SPF findings replace the checkup's rather than joining
   * them.
   *
   * Both walks judge the same record, so most of what they say is identical and
   * dedupes away. The lookup count does not: a bounded walk that stopped at
   * nine reports nine, the full walk reports twelve, and merging the two would
   * put both numbers on the chart as separate findings. The deeper walk saw
   * more, so it wins outright.
   */
  const spf: SpfLeg = deepSpf ?? core.detail.spf;
  const spfConditions = deepSpf
    ? deepSpf.conditions
    : core.conditions.filter((condition) => condition.record === 'SPF');

  const conditions = sortConditions(
    dedupeConditions([
      ...core.conditions.filter((condition) => condition.record !== 'SPF'),
      ...spfConditions,
      ...(dkim?.conditions ?? []),
    ]),
  );

  /**
   * The verdict is reassessed rather than carried over.
   *
   * Its own answer cannot change — that follows from the effective DMARC
   * policy, which no later leg touches — but the reasons printed under it can.
   * A chain that costs twelve lookups returns a permanent error, and the
   * banner is where a visitor reads why they are exposed. Leaving the bounded
   * walk's reasons there means the banner lists nine lookups and no error while
   * the card beside it lists twelve and one.
   */
  const spoofability = assessSpoofability(core.domain, core.detail.dmarc, {
    found: spf.found,
    allQualifier: spf.allQualifier,
    lookupCount: spf.lookupCount,
  });

  /**
   * Scored with the verdict, always.
   *
   * Without it the headline number is scored one way and the explainer below it
   * another, which is how a page ends up showing 53 above an explanation that
   * adds up to 65.
   */
  const vitals = computeVitals(conditions, { spoofability: spoofability.verdict });

  return {
    domain: core.domain,
    conditions,
    vitals,
    spoofability,
    spf,
    records: mergeRecords(core.records, deepSpf),
    /**
     * A result is partial when a guard stopped the checkup, or when the SPF
     * chain was never counted exactly by either walk. The second clause is why
     * this is not simply `core.meta.partial`: the checkup reports its own
     * bounded walk as inexact, and the whole purpose of the deep walk is to
     * finish that count. Leaving the note up afterwards tells a visitor their
     * complete result is incomplete.
     */
    partial: core.meta.budgetExhausted || !spf.lookupCountExact,
    queriesUsed: core.meta.queriesUsed + (deepSpf?.meta.queriesUsed ?? 0),
    legs: { deepSpf: Boolean(deepSpf), dkim: Boolean(dkim) },
  };
}

/**
 * The record cards, corrected by the leg that knows better.
 *
 * A card has to agree with what is drawn beside it. Leaving the checkup's SPF
 * summary in place while the tree showed a deeper walk put "9+ of 10 lookups
 * used" above a chain that plainly counted twelve.
 */
function mergeRecords<R extends RecordLike>(
  records: readonly R[],
  deepSpf: DeepSpfLeg | null | undefined,
): R[] {
  if (!deepSpf) return [...records];

  return records.map((record) =>
    record.record === 'SPF'
      ? {
          ...record,
          status: deepSpf.status,
          found: deepSpf.found,
          conditionCount: deepSpf.conditions.length,
          summary: deepSpf.found
            ? `${deepSpf.lookupCount}${deepSpf.lookupCountExact ? '' : '+'} of 10 lookups used, ending in ${
                deepSpf.allQualifier === null ? 'no all mechanism' : `${deepSpf.allQualifier}all`
              }`
            : 'No SPF record published',
        }
      : record,
  );
}
