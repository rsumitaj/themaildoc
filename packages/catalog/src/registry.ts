import type { Condition, Issue, IssueVars } from './types.js';
import { conditionFactory, type ConditionOptions } from './factory.js';
import { GENERIC_ISSUES } from './records/generic.js';
import { SPF_ISSUES } from './records/spf.js';
import { DMARC_ISSUES } from './records/dmarc.js';
import { DKIM_ISSUES } from './records/dkim.js';
import { MX_ISSUES } from './records/mx.js';
import { A_ISSUES, DNSSEC_ISSUES } from './records/a.js';
import { MTASTS_ISSUES, TLSRPT_ISSUES } from './records/transport.js';
import { BIMI_ISSUES, CAA_ISSUES, PTR_ISSUES } from './records/brand.js';
import { RUA_ISSUES } from './records/rua.js';

/** Every issue MailDoc knows how to diagnose. Records land here as engines ship. */
export const ALL_ISSUES: readonly Issue[] = [
  ...GENERIC_ISSUES,
  ...SPF_ISSUES,
  ...DMARC_ISSUES,
  ...DKIM_ISSUES,
  ...MX_ISSUES,
  ...A_ISSUES,
  ...DNSSEC_ISSUES,
  ...MTASTS_ISSUES,
  ...TLSRPT_ISSUES,
  ...BIMI_ISSUES,
  ...CAA_ISSUES,
  ...PTR_ISSUES,
  ...RUA_ISSUES,
];

const BY_CODE = new Map<string, Issue>(ALL_ISSUES.map((issue) => [issue.code, issue]));

export function getIssue(code: string): Issue | undefined {
  return BY_CODE.get(code);
}

export function issuesForRecord(record: Issue['record']): Issue[] {
  return ALL_ISSUES.filter((issue) => issue.record === record);
}

export type { ConditionOptions };

const create = conditionFactory(ALL_ISSUES);

/**
 * Instantiate a catalog entry as a finding on a real domain.
 *
 * Throws on an unknown code: engines and catalog ship together, so an unknown
 * code is a build-time mistake, and the tests catch it before a patient could.
 */
export function createCondition(
  code: string,
  vars: IssueVars = {},
  options: ConditionOptions = {},
): Condition {
  return create(code, vars, options);
}
