/**
 * Scoring and triage only — no issue prose.
 *
 * The browser needs to re-score a chart when DKIM's conditions arrive from
 * their own endpoint, and it must do that with the same arithmetic the server
 * used. Importing the whole catalog to get it would ship every condition's
 * wording to every visitor; this entry point is a few hundred bytes instead.
 */

export {
  SEVERITY_DEDUCTION,
  SEVERITY_TRIAGE,
  SEVERITY_ORDER,
  TRIAGE_LABEL,
  TRIAGE_CHIP,
  TRIAGE_COLOR,
  VITALS_VERDICT,
  severityRank,
  deductionFor,
  triageFor,
  vitalsBand,
} from './severity.js';

export {
  scoreConditions,
  clampScore,
  rollupRecord,
  worstSeverity,
  sortConditions,
  dedupeConditions,
  countBySeverity,
  vitals,
  scoreBreakdown,
  HARDENING_RECORDS,
  HARDENING_DEDUCTION_CAP,
  MINOR_DEDUCTION_CAP,
} from './score.js';

export type { Vitals, ScoreBreakdown } from './score.js';
export type { Condition, IssueCategory } from './types.js';
