import { describe, expect, it } from 'vitest';
import { createCondition, type Condition } from '@maildoc/catalog';
import { finalizeCheckup, type CoreLeg, type DeepSpfLeg, type DkimLeg } from '../src/finalize.js';

/**
 * The merge that assembles one checkup out of the three requests it arrives in.
 *
 * Everything here is a regression. Each of these was a real disagreement
 * between two things a visitor could see at the same time, or between what was
 * on screen and what we wrote down about it, and all four had the same cause:
 * every consumer merged the legs for itself, or forgot to.
 */

const weakDkimKey = (): Condition =>
  createCondition('DKIM_KEY_WEAK_1024', { selector: 's2', domain: 'a.com' });

const lookupLimit = (): Condition =>
  createCondition('SPF_LOOKUP_LIMIT_EXCEEDED', { count: 12, domain: 'a.com' });

const noDnssec = (): Condition => createCondition('DNSSEC_DS_MISSING', { domain: 'a.com' });

/** A checkup at `p=reject` with a tidy record set, and one weak DKIM key. */
function core(over: Partial<CoreLeg> = {}): CoreLeg {
  return {
    domain: 'a.com',
    conditions: [noDnssec()],
    records: [
      {
        record: 'SPF',
        label: 'SPF authentication',
        status: 'HEALTHY',
        found: true,
        summary: '7 of 10 lookups used, ending in ~all',
        conditionCount: 0,
      },
      {
        record: 'DMARC',
        label: 'DMARC policy',
        status: 'HEALTHY',
        found: true,
        summary: 'Policy reject',
        conditionCount: 0,
      },
    ],
    detail: {
      spf: {
        found: true,
        allQualifier: '~',
        lookupCount: 7,
        lookupCountExact: true,
        status: 'HEALTHY',
      },
      dmarc: {
        found: true,
        ignored: false,
        testMode: false,
        appliedPolicy: 'reject',
        effectivePolicy: 'reject',
        discovery: { source: 'domain', foundAt: 'a.com' },
      },
    },
    meta: { queriesUsed: 21, budgetExhausted: false, partial: false },
    ...over,
  };
}

function deepSpf(over: Partial<DeepSpfLeg> = {}): DeepSpfLeg {
  return {
    found: true,
    allQualifier: '~',
    lookupCount: 12,
    lookupCountExact: true,
    status: 'CRITICAL',
    conditions: [lookupLimit()],
    meta: { queriesUsed: 14 },
    ...over,
  };
}

const dkim = (conditions: Condition[] = [weakDkimKey()]): DkimLeg => ({
  found: true,
  status: 'ATTENTION',
  conditions,
});

describe('the score is the one every leg produced', () => {
  it('counts DKIM findings that land after the checkup', () => {
    // The bug this whole change exists for. `/api/check` returns before the
    // selector probe has run, so the score it knows cannot include a weak key,
    // and the score it recorded was the one without it: domains sat in the
    // table at 85 and HEALTHY beneath a page reading 78 and NEEDS CARE.
    const without = finalizeCheckup({ core: core() });
    const with_ = finalizeCheckup({ core: core(), dkim: dkim() });

    expect(with_.vitals.score).toBeLessThan(without.vitals.score);
    expect(with_.conditions.map((condition) => condition.code)).toContain('DKIM_KEY_WEAK_1024');
  });

  it('is only ever worse once a later leg lands, never better', () => {
    // Both later legs can only add findings, which is why the provisional score
    // is always an over-estimate of health and why the direction of the error
    // mattered: a prospecting list of struggling domains was flattering every
    // row in it.
    const provisional = finalizeCheckup({ core: core() }).vitals.score;
    const finished = finalizeCheckup({ core: core(), deepSpf: deepSpf(), dkim: dkim() });

    expect(finished.vitals.score).toBeLessThanOrEqual(provisional);
  });

  it('is scored with the verdict, so the headline cannot contradict the banner', () => {
    const finished = finalizeCheckup({ core: core(), dkim: dkim() });

    expect(finished.spoofability.verdict).toBe('PROTECTED');
    // The impersonation floor for a protected domain. Without the verdict the
    // headline is scored one way and the explainer under it another.
    expect(finished.vitals.score).toBeGreaterThan(55);
  });
});

describe('the deeper SPF walk wins outright', () => {
  it('replaces the bounded walk rather than joining it', () => {
    // Both walks judge the same record. Merging them would put two different
    // lookup counts on the chart as separate findings.
    const finished = finalizeCheckup({ core: core(), deepSpf: deepSpf() });

    expect(finished.spf.lookupCount).toBe(12);
    expect(finished.conditions.filter((c) => c.record === 'SPF')).toHaveLength(1);
  });

  it('rewrites the SPF card so it agrees with the tree beside it', () => {
    // "9+ of 10 lookups used" above a chain that plainly counted twelve.
    const finished = finalizeCheckup({ core: core(), deepSpf: deepSpf() });
    const card = finished.records.find((record) => record.record === 'SPF');

    expect(card?.summary).toBe('12 of 10 lookups used, ending in ~all');
    expect(card?.status).toBe('CRITICAL');
  });

  it('leaves every other card alone', () => {
    const finished = finalizeCheckup({ core: core(), deepSpf: deepSpf() });

    expect(finished.records.find((record) => record.record === 'DMARC')?.summary).toBe(
      'Policy reject',
    );
  });

  it('tells the spoof banner what the deeper walk found', () => {
    // The verdict follows the effective DMARC policy and cannot change here.
    // The reasons printed under it can, and a chain costing twelve lookups
    // returns a permanent error a visitor is entitled to read about.
    const shallow = finalizeCheckup({ core: core() });
    const deep = finalizeCheckup({ core: core(), deepSpf: deepSpf() });

    expect(shallow.spoofability.reasons.join(' ')).not.toContain('12 lookups');
    expect(deep.spoofability.reasons.join(' ')).toContain('12 lookups');
  });
});

describe('partial means something is still missing', () => {
  it('clears the note once the deep walk finishes the count', () => {
    // The checkup reports its own bounded walk as inexact, and finishing that
    // count is the entire purpose of the second walk. Leaving the note up tells
    // a visitor their complete result is incomplete.
    const bounded = core({
      detail: {
        ...core().detail,
        spf: { found: true, allQualifier: null, lookupCount: 9, lookupCountExact: false, status: 'ATTENTION' },
      },
      meta: { queriesUsed: 21, budgetExhausted: false, partial: true },
    });

    expect(finalizeCheckup({ core: bounded }).partial).toBe(true);
    expect(finalizeCheckup({ core: bounded, deepSpf: deepSpf() }).partial).toBe(false);
  });

  it('keeps the note when the budget is what ran out', () => {
    // A finished SPF chain says nothing about the nine other records a guard
    // stopped us reading.
    const starved = core({ meta: { queriesUsed: 44, budgetExhausted: true, partial: true } });

    expect(finalizeCheckup({ core: starved, deepSpf: deepSpf() }).partial).toBe(true);
  });

  it('stays partial when neither walk could count the chain', () => {
    const inexact = deepSpf({ lookupCountExact: false });

    expect(finalizeCheckup({ core: core(), deepSpf: inexact }).partial).toBe(true);
  });
});

describe('what is safe to record', () => {
  it('says which later legs are in the result', () => {
    expect(finalizeCheckup({ core: core() }).legs).toEqual({ deepSpf: false, dkim: false });
    expect(finalizeCheckup({ core: core(), dkim: dkim() }).legs).toEqual({
      deepSpf: false,
      dkim: true,
    });
    expect(finalizeCheckup({ core: core(), deepSpf: deepSpf(), dkim: dkim() }).legs).toEqual({
      deepSpf: true,
      dkim: true,
    });
  });

  it('counts every query the whole checkup spent', () => {
    expect(finalizeCheckup({ core: core(), deepSpf: deepSpf() }).queriesUsed).toBe(35);
  });

  it('lists each finding once, in triage order', () => {
    const noisy = core({ conditions: [noDnssec(), noDnssec()] });
    const finished = finalizeCheckup({ core: noisy, deepSpf: deepSpf(), dkim: dkim() });

    expect(finished.conditions.filter((c) => c.code === 'DNSSEC_DS_MISSING')).toHaveLength(1);
    expect(finished.conditions[0]?.severity).toBe('CRITICAL');
  });
});
