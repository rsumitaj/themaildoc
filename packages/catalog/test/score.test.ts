import { describe, expect, it } from 'vitest';
import {
  createCondition,
  dedupeConditions,
  recordScore,
  rollupRecord,
  scoreBreakdown,
  scoreConditions,
  sortConditions,
  vitalsBand,
  vitals,
  worstSeverity,
  SEVERITY_DEDUCTION,
  SEVERITY_ORDER,
  TRIAGE_CHIP,
  TRIAGE_COLOR,
  TRIAGE_LABEL,
  triageFor,
} from '../src/index.js';

const critical = () => createCondition('SPF_RECORD_MISSING', { domain: 'a.com' });
const high = () => createCondition('SPF_ALL_MISSING', { domain: 'a.com' });
const medium = () => createCondition('SPF_UDP_TRUNCATION_RISK', { count: 470 });
const info = () => createCondition('SPF_SOFTFAIL_ADVISORY', { domain: 'a.com' });

describe('scoreConditions', () => {
  it('starts at 100 for a clean bill of health', () => {
    expect(scoreConditions([])).toBe(100);
  });

  it('costs more the more severe the finding is', () => {
    // These all land in the impersonation pillar, which carries 45 percent, so
    // a 40 point finding removes 18 from the total rather than 40. The ordering
    // is what matters and it is preserved exactly.
    const worst = scoreConditions([critical()]);
    const bad = scoreConditions([high()]);
    const middling = scoreConditions([medium()]);
    const slight = scoreConditions([info()]);

    expect(worst).toBeLessThan(bad);
    expect(bad).toBeLessThan(middling);
    expect(middling).toBeLessThan(slight);
    expect(slight).toBeLessThan(100);
  });

  it('empties the pillar rather than the score', () => {
    // No SPF, no DMARC, and a revoked signing key. Impersonation and
    // visibility bottom out: there is no policy for a receiver to apply and no
    // address for a report to go to. Hardening is untouched, because none of
    // these findings is about hardening, and the total is a quarter rather
    // than a zero because the score refuses to say one catastrophe is every
    // catastrophe.
    const distinct = [
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DKIM_KEY_REVOKED', { selector: 's1', domain: 'a.com' }),
    ];
    const sum = scoreBreakdown(distinct);

    expect(sum.pillars.find((p) => p.pillar === 'IMPERSONATION')?.score).toBe(0);
    expect(sum.pillars.find((p) => p.pillar === 'VISIBILITY')?.score).toBe(0);
    expect(sum.pillars.find((p) => p.pillar === 'HARDENING')?.score).toBe(100);
    expect(sum.score).toBe(25);
  });

  it('charges the same problem once, however many times it was found', () => {
    // Three selectors with 1024-bit keys is one fix, not three.
    const repeated = [
      createCondition('DKIM_KEY_WEAK_1024', { selector: 'google' }),
      createCondition('DKIM_KEY_WEAK_1024', { selector: 's1' }),
      createCondition('DKIM_KEY_WEAK_1024', { selector: 'mandrill' }),
    ];
    expect(scoreConditions(repeated)).toBe(scoreConditions([repeated[0]!]));
  });

  it('still charges genuinely different problems separately', () => {
    const one = [createCondition('DKIM_KEY_WEAK_1024', { selector: 'google' })];
    const both = [
      createCondition('DKIM_KEY_WEAK_1024', { selector: 'google' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
    ];
    expect(scoreConditions(both)).toBeLessThan(scoreConditions(one));
  });
});

describe('rollupRecord', () => {
  it('is critical when anything is critical', () => {
    expect(rollupRecord([critical(), info()])).toBe('CRITICAL');
  });

  it('needs attention for HIGH or MEDIUM', () => {
    expect(rollupRecord([high()])).toBe('ATTENTION');
    expect(rollupRecord([medium()])).toBe('ATTENTION');
  });

  it('is healthy for advisories only, and for nothing at all', () => {
    expect(rollupRecord([info()])).toBe('HEALTHY');
    expect(rollupRecord([])).toBe('HEALTHY');
  });
});

describe('worstSeverity', () => {
  it('reports the most severe present', () => {
    expect(worstSeverity([info(), high(), medium()])).toBe('HIGH');
    expect(worstSeverity([])).toBeNull();
  });
});

describe('sortConditions', () => {
  it('triages most severe first', () => {
    const sorted = sortConditions([info(), medium(), critical(), high()]);
    expect(sorted.map((c) => c.severity)).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']);
  });

  it('does not mutate the input', () => {
    const input = [info(), critical()];
    sortConditions(input);
    expect(input[0]?.severity).toBe('INFO');
  });
});

describe('dedupeConditions', () => {
  it('collapses the same finding about the same thing', () => {
    const duplicate = [
      createCondition('SPF_PTR_MECHANISM', { offending_term: 'ptr' }),
      createCondition('SPF_PTR_MECHANISM', { offending_term: 'ptr' }),
    ];
    expect(dedupeConditions(duplicate)).toHaveLength(1);
  });

  it('keeps the same code about different things', () => {
    const distinct = [
      createCondition('SPF_PTR_MECHANISM', { offending_term: 'ptr' }),
      createCondition('SPF_PTR_MECHANISM', { offending_term: 'ptr:mail.example.com' }),
    ];
    expect(dedupeConditions(distinct)).toHaveLength(2);
  });
});

describe('the pillars', () => {
  it('keeps optional hardening away from the rest of the score', () => {
    // Every optional record missing at once. It is worth telling somebody
    // about and it is not what decides whether their mail arrives.
    const hardening = [
      createCondition('MTASTS_MISSING', { domain: 'a.com' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
      createCondition('BIMI_MISSING', { domain: 'a.com' }),
      createCondition('CAA_MISSING', { domain: 'a.com' }),
    ];

    // Hardening carries fifteen percent, so losing all of it cannot cost more
    // than fifteen points however many gaps there are.
    expect(scoreConditions(hardening)).toBeGreaterThanOrEqual(85);
  });

  it('charges impersonation far harder than tidiness', () => {
    const impersonation = [createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' })];
    const tidiness = [createCondition('SPF_EXTRA_WHITESPACE', { domain: 'a.com' })];

    expect(scoreConditions(impersonation)).toBeLessThan(scoreConditions(tidiness) - 10);
  });

  it('files each finding under the question it answers', () => {
    const sum = scoreBreakdown([
      createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('SPF_LOOKUP_LIMIT_EXCEEDED', { count: 12 }),
      createCondition('DMARC_RUA_MISSING', { domain: 'a.com' }),
      createCondition('CAA_MISSING', { domain: 'a.com' }),
    ]);

    const where = (code: string) =>
      sum.pillars.find((p) => p.findings.some((f) => f.code === code))?.pillar;

    expect(where('DMARC_RECORD_MISSING')).toBe('IMPERSONATION');
    expect(where('SPF_LOOKUP_LIMIT_EXCEEDED')).toBe('DELIVERY');
    expect(where('DMARC_RUA_MISSING')).toBe('VISIBILITY');
    expect(where('CAA_MISSING')).toBe('HARDENING');
  });

  it('never lets one catastrophe drag the whole score to nothing', () => {
    // This is the regression. online.sbi.bank.in scored 0 out of 100 with the
    // page beside it reading "Protected, your domain can't be easily spoofed",
    // because four findings summed past 100 in a single pool.
    const sbi = [
      createCondition('DMARC_EDV_MISSING', { domain: 'a.com', target: 'x.com' }),
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DMARC_POLICY_INHERITED', { domain: 'a.com', source_domain: 'b.com' }),
      createCondition('MX_MISSING', { domain: 'a.com' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
      createCondition('BIMI_MISSING', { domain: 'a.com' }),
      createCondition('CAA_MISSING', { domain: 'a.com' }),
    ];

    expect(scoreConditions(sbi, { spoofability: 'PROTECTED' })).toBeGreaterThan(40);
  });

  it('a pillar cannot go below zero and take the others with it', () => {
    const everything = [
      createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DKIM_KEY_REVOKED', { selector: 's1', domain: 'a.com' }),
      createCondition('DMARC_V_CASE_INVALID', {}),
    ];
    const sum = scoreBreakdown(everything);

    expect(sum.pillars.find((p) => p.pillar === 'IMPERSONATION')?.score).toBe(0);
    // Delivery, visibility and hardening are untouched, so the total is not 0.
    expect(sum.score).toBeGreaterThan(0);
  });

  it('reproduces its own arithmetic', () => {
    const sum = scoreBreakdown([
      createCondition('MTASTS_MISSING', { domain: 'a.com' }),
      createCondition('DMARC_P_QUARANTINE', { domain: 'a.com' }),
    ]);

    const byHand =
      sum.pillars.reduce((total, p) => total + p.score * p.weight, 0) /
      sum.pillars.reduce((total, p) => total + p.weight, 0);

    expect(Math.round(byHand)).toBe(sum.score);
  });
});

describe('the score can never contradict the verdict', () => {
  it('does not call a protected domain critical', () => {
    // The whole point of the floor. A domain at p=reject refuses unauthenticated
    // mail whatever else is missing, so an impersonation score in the twenties
    // would be measuring hygiene and calling it exposure.
    const messy = [
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DKIM_KEY_REVOKED', { selector: 's1', domain: 'a.com' }),
      createCondition('DMARC_POLICY_INHERITED', { domain: 'a.com', source_domain: 'b.com' }),
    ];

    // The floor also outranks the ceiling that "no SPF record" imposes: a
    // domain at p=reject with a working signature cannot be sent as, whatever
    // it failed to publish.
    expect(scoreConditions(messy, { spoofability: 'PROTECTED' })).toBeGreaterThanOrEqual(50);
  });

  it('does not let a spoofable domain look healthy on hardening alone', () => {
    const spoofable = [createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' })];
    const score = scoreConditions(spoofable, { spoofability: 'SPOOFABLE' });

    expect(score).toBeLessThanOrEqual(39);
  });

  it('caps a spoofable domain that is otherwise spotless', () => {
    const sum = scoreBreakdown([createCondition('DMARC_P_NONE', { domain: 'a.com' })], {
      spoofability: 'SPOOFABLE',
    });

    expect(sum.score).toBeLessThanOrEqual(39);
  });

  it('keeps quarantine below healthy however clean the rest is', () => {
    // p=quarantine is genuinely better than nothing and genuinely not the
    // finish line. A perfect domain sitting at quarantine tops out just under
    // the healthy band, which is the nudge to reject.
    expect(scoreConditions([], { spoofability: 'PARTIAL' })).toBe(64);
  });
});

describe('vitals', () => {
  it.each([
    [100, 'HEALTHY'],
    [85, 'HEALTHY'],
    [84, 'NEEDS_CARE'],
    [65, 'NEEDS_CARE'],
    [64, 'AT_RISK'],
    [40, 'AT_RISK'],
    [39, 'CRITICAL'],
    [0, 'CRITICAL'],
  ])('scores %i as %s', (score, band) => {
    expect(vitalsBand(score)).toBe(band);
  });

  it('assembles the monitor readout', () => {
    const readout = vitals([critical(), high()]);
    // No SPF record at all, so the two pillars that depend on one are held
    // down rather than merely charged: impersonation at 20, delivery at 40.
    // Visibility and hardening are untouched, because neither finding is about
    // them. (20x45 + 40x25 + 100x15 + 100x15) / 100.
    expect(readout.score).toBe(49);
    expect(readout.band).toBe('AT_RISK');
    expect(readout.counts.CRITICAL).toBe(1);
    expect(readout.counts.HIGH).toBe(1);
    expect(readout.counts.LOW).toBe(0);
  });
});

describe('scoreBreakdown', () => {
  it('agrees with scoreConditions on every shape', () => {
    const samples = [
      [],
      [createCondition('SPF_RECORD_MISSING', { domain: 'a.com' })],
      [
        createCondition('DKIM_KEY_WEAK_1024', { selector: 's1' }),
        createCondition('DKIM_KEY_WEAK_1024', { selector: 's2' }),
        createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
      ],
    ];

    for (const sample of samples) {
      expect(scoreBreakdown(sample).score).toBe(scoreConditions(sample));
    }
  });
});

/**
 * The case that exposed the model.
 *
 * A domain registered minutes ago and configured for nothing scored 39 out of
 * 100, and 39 was not a measurement — it was the spoofable ceiling clamping a
 * weighted total of 64. Underneath, "would you find out if something went
 * wrong?" scored 100 out of 100, because there was no DMARC record for a
 * missing `rua` to be a fault in.
 *
 * That is the flaw in pure subtraction: every finding is a fault in something
 * published, so a domain that publishes nothing collects almost no findings and
 * keeps almost all of its marks. These tests pin the shape of the answer, not
 * only the number, so the model cannot quietly go back to rewarding absence.
 */
describe('a domain that has published nothing', () => {
  const nothing = [
    createCondition('DOMAIN_NXDOMAIN', { domain: 'a.com' }),
    createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' }),
    createCondition('MX_MISSING', { domain: 'a.com' }),
    createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
    createCondition('BIMI_MISSING', { domain: 'a.com' }),
    createCondition('CAA_MISSING', { domain: 'a.com' }),
  ];

  it('scores zero when the domain does not even resolve', () => {
    const sum = scoreBreakdown(nothing, { spoofability: 'SPOOFABLE' });

    expect(sum.score).toBe(0);
    // Every pillar, not just the total: there is no zone, so there is nothing
    // for any of the four questions to be answered from.
    for (const pillar of sum.pillars) expect(pillar.score).toBe(0);
  });

  it('scores near zero for a domain that resolves but publishes nothing', () => {
    const bare = nothing.filter((c) => c.code !== 'DOMAIN_NXDOMAIN');
    bare.push(createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }));

    const sum = scoreBreakdown(bare, { spoofability: 'SPOOFABLE' });

    expect(sum.score).toBeLessThan(30);
    expect(sum.pillars.find((p) => p.pillar === 'IMPERSONATION')?.score).toBe(0);
    expect(sum.pillars.find((p) => p.pillar === 'VISIBILITY')?.score).toBe(0);
  });

  it('reaches that score by arithmetic rather than by hitting the ceiling', () => {
    // The complaint was not really the 39. It was that the number came from a
    // clamp, so it would have read 39 whether the domain was nearly fine or
    // entirely absent. The weighted total now has to be low on its own.
    const sum = scoreBreakdown(nothing, { spoofability: 'SPOOFABLE' });

    expect(sum.capped).toBe(false);
    expect(sum.weighted).toBe(sum.score);
  });

  it('says which missing record held each pillar down', () => {
    // The explainer prints this. A ceiling nobody can see is indistinguishable
    // from a fudge, which is the objection this whole model exists to answer.
    const bare = nothing.filter((c) => c.code !== 'DOMAIN_NXDOMAIN');
    const sum = scoreBreakdown(bare, { spoofability: 'SPOOFABLE' });

    expect(sum.pillars.find((p) => p.pillar === 'VISIBILITY')?.ceiling).toEqual({
      code: 'DMARC_RECORD_MISSING',
      limit: 0,
    });
  });

  it('leaves a well configured domain exactly where it was', () => {
    // The ceilings only fire on absence. A domain that publishes its records
    // and gets them right must be unaffected by any of this.
    expect(scoreConditions([], { spoofability: 'PROTECTED' })).toBe(100);
    expect(scoreConditions([createCondition('BIMI_MISSING', { domain: 'a.com' })])).toBe(100);
  });
});

describe('record status matches what the record costs', () => {
  it('does not call a record healthy while charging points for it', () => {
    // A green dot means done, nothing to do here. DNSSEC being unsigned is
    // eight points off the score, so green was the interface disagreeing with
    // its own arithmetic on the same screen.
    const unsigned = [createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' })];

    expect(rollupRecord(unsigned)).toBe('ATTENTION');
    expect(unsigned[0]!.deduction).toBeGreaterThan(0);
  });

  it('still calls an optional extra healthy', () => {
    // No BIMI record is not a fault. Colouring it amber would spend the one
    // colour that means "look at this" on something nobody needs to look at.
    expect(rollupRecord([createCondition('BIMI_MISSING', { domain: 'a.com' })])).toBe('HEALTHY');
    expect(rollupRecord([])).toBe('HEALTHY');
  });
});

/**
 * Severity is the one input every colour, chip and dot on the site is derived
 * from, so the tables that derive them have to be complete and consistent with
 * each other. TypeScript enforces that each is a `Record<Severity, …>`; these
 * assert the values agree.
 */
describe('severity maps to one triage level, one chip and one colour', () => {
  it('gives every severity a deduction, a triage level and a chip', () => {
    for (const severity of SEVERITY_ORDER) {
      const triage = triageFor(severity);
      expect(SEVERITY_DEDUCTION[severity], severity).toBeGreaterThan(0);
      expect(TRIAGE_LABEL[triage], severity).toBeTruthy();
      expect(TRIAGE_CHIP[triage], severity).toBeTruthy();
      expect(TRIAGE_COLOR[triage], severity).toBeTruthy();
    }
  });

  it('orders the deductions the same way it orders the severities', () => {
    // A CRITICAL that cost less than a HIGH would put the cards in one order
    // and the arithmetic in another.
    const costs = SEVERITY_ORDER.map((s) => SEVERITY_DEDUCTION[s]);
    expect([...costs].sort((a, b) => b - a)).toEqual(costs);
  });

  it('names a design token for every triage colour rather than a hex', () => {
    // These were five literals, which made this package a second copy of the
    // palette and froze every dot to the light theme.
    for (const triage of Object.keys(TRIAGE_COLOR) as Array<keyof typeof TRIAGE_COLOR>) {
      expect(TRIAGE_COLOR[triage]).toMatch(/^var\(--md-[a-z-]+\)$/);
    }
  });

  it('reserves the healthy chip for a note, not for a fault', () => {
    // INFO is the only severity that rolls a record up to healthy, and it is
    // the only one whose chip reads NOTE. Those two have to stay in step or a
    // green dot appears beside an amber card.
    expect(triageFor('INFO')).toBe('HEALTHY');
    expect(TRIAGE_CHIP.HEALTHY).toBe('NOTE');
    expect(rollupRecord([createCondition('BIMI_MISSING', { domain: 'a.com' })])).toBe('HEALTHY');
  });
});

/**
 * One record, on its own scale.
 *
 * The Lab tools print a number beside a single record. They used to call
 * `vitals()`, which is the four-pillar model, and that model cannot answer a
 * question about one record: three of its four questions have no findings, so
 * they score 100 and carry 55 percent of the weight between them.
 */
describe('recordScore', () => {
  it('starts at 100 for a record with nothing against it', () => {
    expect(recordScore([])).toBe(100);
  });

  it('subtracts what the finding costs, and nothing else', () => {
    // The copy beside the number has always said "100 minus the weight of each
    // condition found on this record alone". Now it is true.
    expect(recordScore([critical()])).toBe(100 - SEVERITY_DEDUCTION.CRITICAL);
    expect(recordScore([high()])).toBe(100 - SEVERITY_DEDUCTION.HIGH);
    expect(recordScore([medium()])).toBe(100 - SEVERITY_DEDUCTION.MEDIUM);
  });

  it('does not flatter the worst thing a single record can say', () => {
    // The regression this exists for. `+all` tells every receiver that any
    // server on earth may send as this domain, and under the four-pillar model
    // the SPF Lab tool scored it 82 out of 100 — a pass — because visibility
    // and hardening had no findings to charge and kept full marks between
    // them. On its own scale it is what it is: one critical finding.
    const permissive = createCondition('SPF_ALL_TOO_PERMISSIVE', {
      domain: 'a.com',
      offending_term: '+all',
    });

    expect(recordScore([permissive])).toBe(100 - SEVERITY_DEDUCTION.CRITICAL);
    expect(vitals([permissive]).score).toBe(82);
  });

  it('charges a finding once however many times it was found', () => {
    // Same rule as Vitals: three selectors carrying the same weak key is one
    // fix, not three.
    expect(recordScore([critical(), critical(), critical()])).toBe(recordScore([critical()]));
  });

  it('never goes below zero', () => {
    const many = [
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('SPF_ALL_MISSING', { domain: 'a.com' }),
      createCondition('SPF_UDP_TRUNCATION_RISK', { count: 470 }),
      createCondition('SPF_MULTIPLE_RECORDS', { count: 2 }),
    ];
    expect(recordScore(many)).toBeGreaterThanOrEqual(0);
  });
});

describe('the explainer reconciles to the number above it', () => {
  it('reports the weighted total unrounded, so the column adds up', () => {
    // The table exists so somebody can check the score rather than believe it.
    // Rounding each contribution to a whole number does not preserve the sum,
    // so the contributions are shown exactly and this is what they add to.
    const sum = scoreBreakdown([critical(), medium()]);
    const contributions = sum.pillars.reduce(
      (total, pillar) => total + (pillar.score * pillar.weight) / 100,
      0,
    );

    expect(sum.weightedExact).toBeCloseTo(contributions, 10);
    expect(sum.weighted).toBe(Math.round(sum.weightedExact));
  });

  it('still reports the headline as the rounded, capped number', () => {
    const sum = scoreBreakdown([critical()], { spoofability: 'SPOOFABLE' });

    expect(sum.capped).toBe(true);
    expect(sum.score).toBe(39);
    expect(sum.weightedExact).toBeGreaterThan(39);
  });
});
