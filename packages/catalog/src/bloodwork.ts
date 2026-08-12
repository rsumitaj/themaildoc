/**
 * Bloodwork's findings only — no DNS issue prose.
 *
 * The report analyzer runs in the patient's browser, so it needs the words for
 * about twenty findings and nothing else. Importing the whole catalog to get
 * them would ship all 155 conditions' wording to every visitor who opens a
 * report; this entry point is the twenty.
 */

import { conditionFactory } from './factory.js';
import { RUA_ISSUES } from './records/rua.js';

export { RUA_ISSUES };

/**
 * Instantiate a Bloodwork finding.
 *
 * These carry a `deduction` like any condition because they share the shape,
 * but they must never be passed to `scoreConditions` — Vitals scores what a
 * domain publishes today, and a report describes what its mail did last week.
 */
export const createFinding = conditionFactory(RUA_ISSUES);

export type { Condition, IssueCategory } from './types.js';
export type { ConditionOptions } from './factory.js';
