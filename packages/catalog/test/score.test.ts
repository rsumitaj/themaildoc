import { describe, expect, it } from 'vitest';
import {
  createCondition,
  dedupeConditions,
  rollupRecord,
  scoreBreakdown,
  scoreConditions,
  sortConditions,
  vitalsBand,
  vitals,
  worstSeverity,
} from '../src/index.js';

const critical = () => createCondition('SPF_RECORD_MISSING', { domain: 'a.com' });
const high = () => createCondition('SPF_ALL_MISSING', { domain: 'a.com' });
const medium = () => createCondition('SPF_UDP_TRUNCATION_RISK', { count: 470 });
const info = () => createCondition('SPF_SOFTFAIL_ADVISORY', { domain: 'a.com' });

describe('scoreConditions', () => {
  it('starts at 100 for a clean bill of health', () => {
    expect(scoreConditions([])).toBe(100);
  });

  it('applies the catalog weights additively', () => {
    expect(scoreConditions([critical()])).toBe(60);
    expect(scoreConditions([high()])).toBe(75);
    expect(scoreConditions([medium()])).toBe(85);
    expect(scoreConditions([info()])).toBe(98);
    expect(scoreConditions([critical(), high(), medium(), info()])).toBe(18);
  });

  it('clamps at zero', () => {
    const distinct = [
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DKIM_KEY_REVOKED', { selector: 's1', domain: 'a.com' }),
    ];
    expect(scoreConditions(distinct)).toBe(0);
  });

  it('charges the same problem once, however many times it was found', () => {
    // Three selectors with 1024-bit keys is one fix, not three.
    const repeated = [
      createCondition('DKIM_KEY_WEAK_1024', { selector: 'google' }),
      createCondition('DKIM_KEY_WEAK_1024', { selector: 's1' }),
      createCondition('DKIM_KEY_WEAK_1024', { selector: 'mandrill' }),
    ];
    expect(scoreConditions(repeated)).toBe(85);
  });

  it('still charges genuinely different problems separately', () => {
    const mixed = [
      createCondition('DKIM_KEY_WEAK_1024', { selector: 'google' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
    ];
    expect(scoreConditions(mixed)).toBe(77);
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

describe('optional hardening is capped', () => {
  it('does not let optional records dominate the score', () => {
    // MTA-STS, TLS-RPT, BIMI, CAA, DNSSEC and IPv6 gaps together removed 33
    // points, which put a well-authenticated domain beside one with nothing.
    const hardening = [
      createCondition('MTASTS_MISSING', { domain: 'a.com' }),
      createCondition('TLSRPT_MISSING', { domain: 'a.com' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
      createCondition('AAAA_MISSING', { domain: 'a.com' }),
      createCondition('BIMI_MISSING', { domain: 'a.com' }),
      createCondition('CAA_MISSING', { domain: 'a.com' }),
    ];
    const raw = hardening.reduce((total, condition) => total + condition.deduction, 0);

    expect(raw).toBeGreaterThan(25);
    expect(scoreConditions(hardening)).toBe(75);
  });

  it('still charges authentication problems in full', () => {
    const core = [
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' }),
    ];
    expect(scoreConditions(core)).toBe(20);
  });

  it('keeps a well-authenticated domain clear of one with nothing', () => {
    const wellRun = [
      createCondition('SPF_LOOKUP_APPROACHING_LIMIT', { count: 10 }),
      createCondition('DMARC_P_QUARANTINE', { domain: 'a.com' }),
      createCondition('MTASTS_MISSING', { domain: 'a.com' }),
      createCondition('TLSRPT_MISSING', { domain: 'a.com' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
    ];
    const nothing = [
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('MX_MISSING', { domain: 'a.com' }),
      createCondition('MTASTS_MISSING', { domain: 'a.com' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
    ];

    expect(scoreConditions(wellRun)).toBeGreaterThan(scoreConditions(nothing) + 25);
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
    expect(readout.score).toBe(35);
    expect(readout.band).toBe('CRITICAL');
    expect(readout.headline).toBe('CRITICAL CONDITION');
    expect(readout.counts.CRITICAL).toBe(1);
    expect(readout.counts.HIGH).toBe(1);
    expect(readout.counts.LOW).toBe(0);
  });
});

describe('scoreBreakdown', () => {
  it('reproduces the score it explains', () => {
    const conditions = [
      createCondition('DMARC_OBSOLETE_TAGS', { domain: 'a.com', offending_term: 'pct=100' }),
      createCondition('MX_DUPLICATE_PRIORITY', { domain: 'a.com', count: 2 }),
      createCondition('MTASTS_MISSING', { domain: 'a.com' }),
      createCondition('TLSRPT_MISSING', { domain: 'a.com' }),
    ];

    const sum = scoreBreakdown(conditions);
    // Both DNS findings are LOW, so they fall under the minor cap rather than
    // core. Nothing here threatens delivery or lets anyone impersonate.
    expect(sum.core).toBe(0);
    expect(sum.minor).toBe(16);
    expect(sum.minorCharged).toBe(16);
    expect(sum.hardening).toBe(23);
    expect(sum.hardeningCharged).toBe(23);
    expect(100 - sum.core - sum.minorCharged - sum.hardeningCharged).toBe(sum.score);
    // The arithmetic on screen and the score on screen come from one function.
    expect(sum.score).toBe(scoreConditions(conditions));
  });

  it('shows the cap when hardening exceeds it', () => {
    const conditions = [
      createCondition('MTASTS_MISSING', { domain: 'a.com' }),
      createCondition('TLSRPT_MISSING', { domain: 'a.com' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
      createCondition('BIMI_MISSING', { domain: 'a.com' }),
      createCondition('CAA_MISSING', { domain: 'a.com' }),
    ];

    const sum = scoreBreakdown(conditions);
    expect(sum.hardening).toBeGreaterThan(25);
    expect(sum.hardeningCharged).toBe(25);
    expect(sum.score).toBe(scoreConditions(conditions));
  });

  it('stops tidiness outweighing protection', () => {
    // Six minor findings is 48 points, which put a p=reject domain with valid
    // SPF and DKIM into the critical band on hygiene alone.
    const hygiene = [
      createCondition('DMARC_STRING_TOO_LONG', { domain: 'a.com', count: 300 }),
      createCondition('DMARC_TOO_MANY_URIS', { count: 4 }),
      createCondition('SPF_SOFTFAIL_ADVISORY', { domain: 'a.com' }),
      createCondition('DMARC_ADKIM_STRICT_ADV', { domain: 'a.com' }),
      createCondition('SPF_EXTRA_WHITESPACE', { domain: 'a.com' }),
    ];

    const sum = scoreBreakdown(hygiene);
    expect(sum.minor).toBeGreaterThan(20);
    expect(sum.minorCharged).toBe(20);
    expect(sum.score).toBe(80);
    expect(sum.core).toBe(0);
  });

  it('still charges a real defect in full alongside capped minors', () => {
    const mixed = [
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DMARC_STRING_TOO_LONG', { domain: 'a.com', count: 300 }),
      createCondition('DMARC_TOO_MANY_URIS', { count: 4 }),
      createCondition('SPF_SOFTFAIL_ADVISORY', { domain: 'a.com' }),
      createCondition('DMARC_ADKIM_STRICT_ADV', { domain: 'a.com' }),
    ];

    const sum = scoreBreakdown(mixed);
    expect(sum.core).toBe(40);
    expect(sum.minorCharged).toBe(20);
    expect(sum.score).toBe(40);
  });

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
