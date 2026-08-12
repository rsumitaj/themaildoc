export type { Issue, IssueVars, IssueCategory, Condition } from './types.js';

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

export { interpolate, tokensIn } from './interpolate.js';

export { conditionFactory } from './factory.js';

export {
  ALL_ISSUES,
  getIssue,
  issuesForRecord,
  createCondition,
} from './registry.js';
export type { ConditionOptions } from './registry.js';

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

export { SPF_ISSUES } from './records/spf.js';
export { GENERIC_ISSUES } from './records/generic.js';
export { DMARC_ISSUES } from './records/dmarc.js';
export { DKIM_ISSUES } from './records/dkim.js';
export { MX_ISSUES } from './records/mx.js';
export { A_ISSUES, DNSSEC_ISSUES } from './records/a.js';
export { MTASTS_ISSUES, TLSRPT_ISSUES } from './records/transport.js';
export { BIMI_ISSUES, CAA_ISSUES, PTR_ISSUES } from './records/brand.js';
export { RUA_ISSUES } from './records/rua.js';
