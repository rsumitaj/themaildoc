import type { RecordStatus, Severity, VitalsBand } from '@maildoc/shared';
import type { Condition } from './types.js';
import { SEVERITY_ORDER, severityRank, vitalsBand, VITALS_VERDICT } from './severity.js';

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
 * Records that make a domain better but that no receiver requires.
 *
 * Missing MTA-STS or BIMI is worth telling somebody about; it is not what
 * decides whether their mail arrives or whether they can be impersonated.
 * Left uncapped, four such gaps removed 33 points and pushed domains with
 * sound authentication down beside domains with nothing at all.
 */
export const HARDENING_RECORDS: ReadonlySet<string> = new Set([
  'MTASTS',
  'TLSRPT',
  'BIMI',
  'CAA',
  'DNSSEC',
  'A',
]);

/** The most that optional hardening may remove between all of it. */
export const HARDENING_DEDUCTION_CAP = 25;

/**
 * The most that minor findings may remove between all of them.
 *
 * LOW is 8 points and INFO is 2, which is right for one of them. Six is 48,
 * and that put a domain enforcing p=reject with valid SPF and DKIM into the
 * critical band on hygiene alone: extra whitespace, a long record, a couple of
 * advisories. Tidiness must not outweigh whether a domain can be impersonated.
 */
export const MINOR_DEDUCTION_CAP = 20;

const MINOR_SEVERITIES: ReadonlySet<Severity> = new Set(['LOW', 'INFO']);

export function scoreConditions(conditions: readonly Condition[]): number {
  return scoreBreakdown(conditions).score;
}

/**
 * The score broken into its parts, so a page can show the arithmetic rather
 * than assert it. Same code path as `scoreConditions`; if these ever disagree
 * the score on screen would stop being reproducible.
 */
export interface ScoreBreakdown {
  /** Serious findings on records that decide whether mail arrives. */
  core: number;
  /** Minor findings before the cap. */
  minor: number;
  minorCharged: number;
  /** Optional hardening before the cap. */
  hardening: number;
  hardeningCharged: number;
  score: number;
  charged: { code: string; deduction: number; hardening: boolean; minor: boolean }[];
}

export function scoreBreakdown(conditions: readonly Condition[]): ScoreBreakdown {
  const charged = new Map<
    string,
    { code: string; deduction: number; hardening: boolean; minor: boolean }
  >();

  for (const condition of conditions) {
    // Bloodwork findings describe last week's mail, not today's DNS. They share
    // the Condition shape so they render on the same card, and they must never
    // move Vitals: a quiet week would otherwise flatter a broken domain.
    if (condition.record === 'RUA') continue;

    const current = charged.get(condition.code);
    if (current === undefined || condition.deduction > current.deduction) {
      charged.set(condition.code, {
        code: condition.code,
        deduction: condition.deduction,
        hardening: HARDENING_RECORDS.has(condition.record),
        minor: MINOR_SEVERITIES.has(condition.severity),
      });
    }
  }

  let core = 0;
  let minor = 0;
  let hardening = 0;

  for (const entry of charged.values()) {
    // Hardening is judged first: a missing optional record is optional whatever
    // its severity, and must not be counted under two caps.
    if (entry.hardening) hardening += entry.deduction;
    else if (entry.minor) minor += entry.deduction;
    else core += entry.deduction;
  }

  const minorCharged = Math.min(minor, MINOR_DEDUCTION_CAP);
  const hardeningCharged = Math.min(hardening, HARDENING_DEDUCTION_CAP);

  return {
    core,
    minor,
    minorCharged,
    hardening,
    hardeningCharged,
    score: clampScore(100 - core - minorCharged - hardeningCharged),
    charged: [...charged.values()],
  };
}

export function clampScore(score: number): number {
  if (!Number.isFinite(score)) return 0;
  return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * Record rollup (context/03): any CRITICAL makes the record critical, any
 * HIGH or MEDIUM means it needs attention, anything else is healthy.
 */
export function rollupRecord(conditions: readonly Condition[]): RecordStatus {
  let status: RecordStatus = 'HEALTHY';
  for (const condition of conditions) {
    if (condition.severity === 'CRITICAL') return 'CRITICAL';
    if (condition.severity === 'HIGH' || condition.severity === 'MEDIUM') status = 'ATTENTION';
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
export function vitals(conditions: readonly Condition[]): Vitals {
  const score = scoreConditions(conditions);
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
