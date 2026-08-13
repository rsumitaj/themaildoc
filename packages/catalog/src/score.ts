import type { RecordStatus, Severity, VitalsBand } from '@maildoc/shared';
import type { Condition } from './types.js';
import { SEVERITY_ORDER, severityRank, vitalsBand, VITALS_VERDICT } from './severity.js';
import {
  PILLAR_LABEL,
  PILLAR_ORDER,
  PILLAR_QUESTION,
  PILLAR_WEIGHT,
  pillarFor,
  type Pillar,
} from './pillars.js';

/**
 * Vitals: start at 100, subtract every condition's weight, clamp to 0–100.
 * Deliberately additive — patients can do the arithmetic, and the before/after
 * simulator can move the number by toggling conditions off.
 *
 * Each distinct condition *code* is charged once, however many times it was
 * found. Three DKIM selectors carrying 1024-bit keys is one problem with one
 * fix, and charging it three times says a domain is in critical condition when
 * it has a single thing to tidy up. The chart still lists every instance.
 */
/**
 * How exposed the domain is to being sent as, judged from the policy receivers
 * actually apply. Optional: the standalone Lab tools score one record and have
 * no verdict to hand in.
 */
export type SpoofVerdict = 'PROTECTED' | 'PARTIAL' | 'SPOOFABLE';

export interface ScoreOptions {
  spoofability?: SpoofVerdict;
}

/**
 * The floor the impersonation pillar cannot fall below, given the verdict.
 *
 * This is not a fudge to make numbers look nicer. The verdict is computed from
 * the DMARC policy a receiver will apply to this domain today, which is the
 * ground truth for the question "can somebody send as you". When a domain
 * publishes p=reject, unauthenticated mail is refused whatever else is missing,
 * so an impersonation score of 35 would be measuring hygiene and calling it
 * exposure. The remaining findings still cost points; they just cannot argue
 * the domain is wide open when it demonstrably is not.
 */
const IMPERSONATION_FLOOR: Record<SpoofVerdict, number> = {
  PROTECTED: 55,
  PARTIAL: 35,
  SPOOFABLE: 0,
};

/**
 * The most a domain may score given how exposed it is, whatever else it does
 * well. These are the tops of the Vitals bands, so the number and the words
 * beside it always tell one story.
 *
 * A domain anybody can send as is in critical condition. That is the whole
 * thesis of the product, and letting tidy hardening lift it into "at risk"
 * would contradict the banner directly above it. Quarantine is genuinely
 * better than nothing and genuinely not the finish line, so it tops out just
 * below healthy however clean the rest is.
 */
const VERDICT_CEILING: Record<SpoofVerdict, number> = {
  PROTECTED: 100,
  PARTIAL: 64,
  SPOOFABLE: 39,
};

/**
 * What a protection's total absence costs the pillars it serves.
 *
 * This exists because subtraction alone cannot express "you have nothing".
 * Every finding is a fault in something published, so a domain that publishes
 * nothing collects almost no findings and the pillars stay near a hundred. A
 * domain registered minutes ago, with no SPF, no DMARC, no MX and no address
 * records, scored 100 out of 100 on "would you find out if something went
 * wrong?" — because there was no DMARC record for a missing `rua` to be a fault
 * in. Its weighted total was 64, and the only reason the page did not print 64
 * was the spoofable ceiling clamping it to 39. The number on screen was the
 * clamp, not a measurement.
 *
 * A ceiling says the thing subtraction cannot: without this record, that
 * question cannot be answered well however tidy everything else is. It is the
 * same mechanism as the verdict ceiling above and it is not a fudge — each
 * entry is a statement about what a receiver can do with the domain:
 *
 *   No DMARC record (RFC 9989 §6.3, §7) — a receiver has no instruction to
 *   refuse forged mail, and no aggregate report is ever sent to anybody. Both
 *   the impersonation and the visibility questions answer themselves.
 *
 *   No SPF record (RFC 7208 §2.1) — nothing states which hosts may send, so
 *   there is no authorisation to align against and no path to the one Google
 *   and Yahoo require of bulk senders. Impersonation is nearly all of the cost;
 *   delivery keeps some credit because DKIM alone can still carry a message.
 *
 *   The domain does not resolve at all (RFC 8020) — there is no zone, so there
 *   is nothing to score in any pillar.
 */
const ABSENCE_CEILING: Record<string, Partial<Record<Pillar, number>>> = {
  DOMAIN_NXDOMAIN: { IMPERSONATION: 0, DELIVERY: 0, VISIBILITY: 0, HARDENING: 0 },
  DMARC_RECORD_MISSING: { IMPERSONATION: 0, VISIBILITY: 0 },
  SPF_RECORD_MISSING: { IMPERSONATION: 20, DELIVERY: 40 },
};

/** Why a pillar could not score higher, in the words the explainer prints. */
export interface PillarCeiling {
  /** The finding that imposed it. */
  code: string;
  limit: number;
}

/** The tightest ceiling the findings impose on one pillar, if any. */
function ceilingFor(pillar: Pillar, codes: Iterable<string>): PillarCeiling | null {
  let tightest: PillarCeiling | null = null;
  for (const code of codes) {
    const limit = ABSENCE_CEILING[code]?.[pillar];
    if (limit === undefined) continue;
    if (tightest === null || limit < tightest.limit) tightest = { code, limit };
  }
  return tightest;
}

export function scoreConditions(
  conditions: readonly Condition[],
  options: ScoreOptions = {},
): number {
  return scoreBreakdown(conditions, options).score;
}

/**
 * The score broken into its parts, so a page can show the arithmetic rather
 * than assert it. Same code path as `scoreConditions`; if these ever disagree
 * the score on screen would stop being reproducible.
 */
export interface ChargedFinding {
  code: string;
  deduction: number;
  pillar: Pillar;
}

export interface PillarBreakdown {
  pillar: Pillar;
  label: string;
  question: string;
  weight: number;
  /** Everything this pillar's findings would remove. */
  deducted: number;
  /** The pillar's own score, out of 100, floored at zero. */
  score: number;
  /** Raised to a floor because the spoofability verdict says otherwise. */
  floored: boolean;
  /** Held down because a protection this pillar depends on is absent. */
  ceiling: PillarCeiling | null;
  findings: ChargedFinding[];
}

export interface ScoreBreakdown {
  pillars: PillarBreakdown[];
  /** Weighted total before the spoofable ceiling. */
  weighted: number;
  score: number;
  /** True when the ceiling for a spoofable domain brought the score down. */
  capped: boolean;
  charged: ChargedFinding[];
}

export function scoreBreakdown(
  conditions: readonly Condition[],
  options: ScoreOptions = {},
): ScoreBreakdown {
  const charged = new Map<string, ChargedFinding>();

  for (const condition of conditions) {
    // Bloodwork findings describe last week's mail, not today's DNS. They share
    // the Condition shape so they render on the same card, and they must never
    // move Vitals: a quiet week would otherwise flatter a broken domain.
    if (condition.record === 'RUA') continue;
    if (condition.deduction <= 0) continue;

    // Each distinct code is charged once, however many times it was found.
    // Three selectors carrying 1024-bit keys is one problem with one fix.
    const current = charged.get(condition.code);
    if (current === undefined || condition.deduction > current.deduction) {
      charged.set(condition.code, {
        code: condition.code,
        deduction: condition.deduction,
        pillar: pillarFor(condition),
      });
    }
  }

  const verdict = options.spoofability;

  /**
   * Absence is judged from every finding, not only the ones that scored.
   *
   * "No DMARC record" is charged to impersonation, but what it says about
   * visibility has nothing to do with which pillar it was charged to, and a
   * finding carrying a zero deduction still states a fact about the domain.
   */
  const present = new Set(conditions.map((condition) => condition.code));

  const pillars: PillarBreakdown[] = PILLAR_ORDER.map((pillar) => {
    const findings = [...charged.values()].filter((entry) => entry.pillar === pillar);
    const deducted = findings.reduce((total, entry) => total + entry.deduction, 0);
    const subtracted = Math.max(0, 100 - deducted);

    // A ceiling wins over subtraction: the protection is not merely faulty.
    const ceiling = ceilingFor(pillar, present);
    const raw = ceiling === null ? subtracted : Math.min(subtracted, ceiling.limit);

    /**
     * The floor is applied last, and it outranks the ceiling.
     *
     * These two can only argue in one case, and the answer there is clear. A
     * domain publishing no SPF but sitting at p=reject with a working signature
     * genuinely cannot be sent as: receivers refuse the mail. The ceiling says
     * "you published nothing", which is true and is not the question this
     * pillar asks. The floor is read from the policy a receiver will actually
     * apply, which is direct evidence about impersonation, so it wins.
     *
     * The reverse case never arises: without a DMARC record the verdict is
     * always SPOOFABLE, whose floor is zero, so nothing is lifted over a
     * ceiling that matters.
     */
    const floor =
      pillar === 'IMPERSONATION' && verdict !== undefined ? IMPERSONATION_FLOOR[verdict] : 0;

    return {
      pillar,
      label: PILLAR_LABEL[pillar],
      question: PILLAR_QUESTION[pillar],
      weight: PILLAR_WEIGHT[pillar],
      deducted,
      score: Math.max(raw, floor),
      floored: raw < floor,
      ceiling,
      findings,
    };
  });

  const totalWeight = pillars.reduce((total, entry) => total + entry.weight, 0);
  const weighted =
    pillars.reduce((total, entry) => total + entry.score * entry.weight, 0) / totalWeight;

  // A domain anybody can send as does not get to score well on the strength of
  // its CAA record. The ceiling only ever bites when the rest of the setup is
  // tidy, which is exactly the case worth being blunt about.
  const ceiling = verdict === undefined ? 100 : VERDICT_CEILING[verdict];
  const capped = weighted > ceiling;

  return {
    pillars,
    weighted: clampScore(weighted),
    score: clampScore(capped ? ceiling : weighted),
    capped,
    charged: [...charged.values()],
  };
}

export function clampScore(score: number): number {
  if (!Number.isFinite(score)) return 0;
  return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * Record rollup: any CRITICAL makes the record critical, any real fault makes
 * it need attention, and only a record with nothing but notes against it is
 * healthy.
 *
 * LOW used to roll up to healthy, which put a green dot beside "DNSSEC: not
 * enabled" on a chart that was simultaneously charging eight points for it.
 * Green is the strongest thing this interface says — it means done, nothing to
 * do here — and a record that costs the score points has not earned it.
 *
 * INFO stays healthy on purpose. Those are genuinely optional: a domain with
 * no BIMI record is not faulty, it has simply not published a logo, and
 * colouring that amber would make the one colour that means "look at this"
 * meaningless.
 */
export function rollupRecord(conditions: readonly Condition[]): RecordStatus {
  let status: RecordStatus = 'HEALTHY';
  for (const condition of conditions) {
    if (condition.severity === 'CRITICAL') return 'CRITICAL';
    if (condition.severity !== 'INFO') status = 'ATTENTION';
  }
  return status;
}

/** The most severe severity present, or `null` for a clean record. */
export function worstSeverity(conditions: readonly Condition[]): Severity | null {
  let worst: Severity | null = null;
  for (const condition of conditions) {
    if (worst === null || severityRank(condition.severity) < severityRank(worst)) {
      worst = condition.severity;
    }
  }
  return worst;
}

/** Triage order: most severe first, stable within a severity. */
export function sortConditions(conditions: readonly Condition[]): Condition[] {
  return [...conditions].sort((a, b) => {
    const bySeverity = severityRank(a.severity) - severityRank(b.severity);
    if (bySeverity !== 0) return bySeverity;
    return a.code.localeCompare(b.code);
  });
}

/** Drop repeats of the same finding about the same thing (same code + vars). */
export function dedupeConditions(conditions: readonly Condition[]): Condition[] {
  const seen = new Set<string>();
  const unique: Condition[] = [];
  for (const condition of conditions) {
    const key = `${condition.code}|${stableVarsKey(condition.vars)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(condition);
  }
  return unique;
}

function stableVarsKey(vars: Condition['vars']): string {
  return Object.keys(vars)
    .sort()
    .map((key) => `${key}=${String(vars[key])}`)
    .join('&');
}

export function countBySeverity(
  conditions: readonly Condition[],
): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<
    Severity,
    number
  >;
  for (const condition of conditions) counts[condition.severity] += 1;
  return counts;
}

export interface Vitals {
  score: number;
  band: VitalsBand;
  headline: string;
  note: string;
  counts: Record<Severity, number>;
}

/** One call for the whole Vitals monitor. */
export function vitals(conditions: readonly Condition[], options: ScoreOptions = {}): Vitals {
  const score = scoreConditions(conditions, options);
  const band = vitalsBand(score);
  const verdict = VITALS_VERDICT[band];
  return {
    score,
    band,
    headline: verdict.headline,
    note: verdict.note,
    counts: countBySeverity(conditions),
  };
}
