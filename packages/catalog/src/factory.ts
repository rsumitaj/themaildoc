import type { Condition, Issue, IssueVars } from './types.js';
import { interpolate } from './interpolate.js';
import { deductionFor, triageFor } from './severity.js';

export interface ConditionOptions {
  /** Raw evidence (the offending record, the chain path, a source address). */
  evidence?: string;
}

/**
 * Build a condition factory over a set of issues.
 *
 * The whole catalog uses one of these; Bloodwork uses a second over its own
 * twenty-odd entries, so a browser that only needs to read a report does not
 * download every sentence the clinic can say.
 */
export function conditionFactory(
  issues: readonly Issue[],
): (code: string, vars?: IssueVars, options?: ConditionOptions) => Condition {
  const byCode = new Map<string, Issue>(issues.map((issue) => [issue.code, issue]));

  return function create(code, vars = {}, options = {}) {
    const issue = byCode.get(code);
    if (!issue) throw new Error(`Unknown issue code: ${code}`);

    return {
      code: issue.code,
      record: issue.record,
      severity: issue.severity,
      triage: triageFor(issue.severity),
      category: issue.category,
      title: interpolate(issue.title, vars),
      why: interpolate(issue.why, vars),
      fix: interpolate(issue.fix, vars),
      rfc: issue.rfc,
      deduction: issue.scores === false ? 0 : deductionFor(issue.severity),
      dismissible: issue.dismissible ?? false,
      vars,
      ...(options.evidence === undefined ? {} : { evidence: options.evidence }),
    };
  };
}
