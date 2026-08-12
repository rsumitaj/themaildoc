import { describe, expect, it } from 'vitest';
import {
  ALL_ISSUES,
  SPF_ISSUES,
  createCondition,
  getIssue,
  interpolate,
  issuesForRecord,
  scoreConditions,
  tokensIn,
} from '../src/index.js';

describe('catalog integrity', () => {
  it('has unique, screaming-snake issue codes', () => {
    const codes = ALL_ISSUES.map((issue) => issue.code);
    expect(new Set(codes).size).toBe(codes.length);
    for (const code of codes) expect(code).toMatch(/^[A-Z][A-Z0-9_]+$/);
  });

  it('declares every {placeholder} used in its copy', () => {
    for (const issue of ALL_ISSUES) {
      const used = new Set([
        ...tokensIn(issue.title),
        ...tokensIn(issue.why),
        ...tokensIn(issue.fix),
      ]);
      const declared = new Set(issue.vars ?? []);
      for (const token of used) {
        expect(declared, `${issue.code} uses {${token}} without declaring it`).toContain(token);
      }
      for (const declaredVar of declared) {
        expect(used, `${issue.code} declares unused var ${declaredVar}`).toContain(declaredVar);
      }
    }
  });

  it('cites an RFC for every issue', () => {
    for (const issue of ALL_ISSUES) {
      expect(issue.rfc, issue.code).toMatch(
        /^(RFC \d+ (§[\d.]+|Appendix [A-Z](\.\d+)*)|BIMI draft-\d+ §[\d.]+)$/,
      );
    }
  });

  it('cites only current specs — never an obsoleted DMARC RFC', () => {
    // RFC 9989 obsoletes 7489 and 9091. A citation to either is a citation to
    // rules that no longer apply.
    for (const issue of ALL_ISSUES) {
      expect(issue.rfc, `${issue.code} cites an obsoleted RFC`).not.toMatch(
        /RFC (7489|9091)\b/,
      );
    }
  });

  it('writes copy that is complete and human', () => {
    for (const issue of ALL_ISSUES) {
      expect(issue.title.length, issue.code).toBeGreaterThan(6);
      expect(issue.why.length, issue.code).toBeGreaterThan(40);
      expect(issue.fix.length, issue.code).toBeGreaterThan(30);
      // The chart is prose, not a headline: why/fix end in a sentence.
      expect(issue.why.trim().endsWith('.'), issue.code).toBe(true);
    }
  });

  it('ships no emoji (production rule)', () => {
    for (const issue of ALL_ISSUES) {
      const text = `${issue.title} ${issue.why} ${issue.fix}`;
      expect(/\p{Extended_Pictographic}/u.test(text), issue.code).toBe(false);
    }
  });

  it('threatens with exposure, never with death (voice guardrail)', () => {
    const banned = /\b(dead|death|died|flatlin\w*|autopsy|corpse|morgue|terminal|fatal)\b/i;
    for (const issue of ALL_ISSUES) {
      const text = `${issue.title} ${issue.why} ${issue.fix}`;
      expect(banned.test(text), `${issue.code}: ${text}`).toBe(false);
    }
  });

  it('covers every SPF code the issue catalog specifies', () => {
    const expected = [
      'SPF_RECORD_MISSING',
      'SPF_MULTIPLE_RECORDS',
      'SPF_INVALID_VERSION',
      'SPF_LOOKUP_LIMIT_EXCEEDED',
      'SPF_VOID_LOOKUP_EXCEEDED',
      'SPF_ALL_TOO_PERMISSIVE',
      'SPF_CIRCULAR_INCLUDE',
      'SPF_INCLUDE_NXDOMAIN',
      'SPF_ALL_MISSING',
      'SPF_ALL_NOT_LAST',
      'SPF_PTR_MECHANISM',
      'SPF_REDIRECT_ALL_CONFLICT',
      'SPF_INVALID_IPV4',
      'SPF_INVALID_IPV4_CIDR',
      'SPF_INVALID_IPV6',
      'SPF_INVALID_IPV6_CIDR',
      'SPF_DUPLICATE_INCLUDE',
      'SPF_LOOKUP_APPROACHING_LIMIT',
      'SPF_RECORD_STRING_TOO_LONG',
      'SPF_UDP_TRUNCATION_RISK',
      'SPF_INVALID_MACRO',
      'SPF_SOFTFAIL_ADVISORY',
      'SPF_PRIVATE_IP_IN_SPF',
    ];
    const actual = SPF_ISSUES.map((issue) => issue.code);
    for (const code of expected) expect(actual).toContain(code);
    expect(SPF_ISSUES.every((issue) => issue.record === 'SPF')).toBe(true);
  });

  it('matches the catalog severities for the SPF headline cases', () => {
    expect(getIssue('SPF_LOOKUP_LIMIT_EXCEEDED')?.severity).toBe('CRITICAL');
    expect(getIssue('SPF_ALL_TOO_PERMISSIVE')?.severity).toBe('CRITICAL');
    expect(getIssue('SPF_INCLUDE_NXDOMAIN')?.severity).toBe('HIGH');
    expect(getIssue('SPF_UDP_TRUNCATION_RISK')?.severity).toBe('MEDIUM');
    expect(getIssue('SPF_SOFTFAIL_ADVISORY')?.severity).toBe('INFO');
  });

  it('indexes issues by record', () => {
    expect(issuesForRecord('SPF').length).toBe(SPF_ISSUES.length);
    expect(issuesForRecord('GENERIC').map((i) => i.code)).toContain('PROPAGATION_IN_PROGRESS');
  });
});

describe('Bloodwork findings', () => {
  it('reads a report’s findings without loading the whole catalog', async () => {
    const { createFinding, RUA_ISSUES } = await import('../src/bloodwork.js');
    expect(RUA_ISSUES.length).toBeGreaterThan(15);
    expect(RUA_ISSUES.every((issue) => issue.record === 'RUA')).toBe(true);

    const finding = createFinding('RUA_OWN_MAIL_FAILING', { count: 40, share: 2.5, sources: 2 });
    expect(finding.title).toBe('Your own mail is failing authentication');
    expect(finding.why).toContain('40 messages');
    expect(finding.why).toContain('2.5%');
  });

  it('never moves Vitals, because a report is not a configuration', async () => {
    const { createFinding } = await import('../src/bloodwork.js');
    const findings = [
      createFinding('RUA_UNAUTHENTICATED_DELIVERED', {
        count: 900,
        share: 40,
        sources: 3,
        domain: 'a.com',
      }),
      createFinding('RUA_NOTHING_ALIGNED', { count: 900, domain: 'a.com' }),
    ];

    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(scoreConditions(findings)).toBe(100);
    expect(scoreConditions([...findings, createCondition('SPF_ALL_MISSING', { domain: 'a.com' })])).toBe(75);
  });
});

describe('interpolate', () => {
  it('fills supplied tokens', () => {
    expect(interpolate('{count} of 10 lookups on {domain}', { count: 12, domain: 'a.com' })).toBe(
      '12 of 10 lookups on a.com',
    );
  });

  it('leaves unsupplied tokens visible rather than blanking the sentence', () => {
    expect(interpolate('costs {count} lookups', {})).toBe('costs {count} lookups');
  });

  it('lists tokens without duplicates', () => {
    expect(tokensIn('{a} then {b} then {a}')).toEqual(['a', 'b']);
  });
});

describe('createCondition', () => {
  it('interpolates, triages and weights an issue', () => {
    const condition = createCondition('SPF_LOOKUP_LIMIT_EXCEEDED', { count: 13 });
    expect(condition.code).toBe('SPF_LOOKUP_LIMIT_EXCEEDED');
    expect(condition.record).toBe('SPF');
    expect(condition.severity).toBe('CRITICAL');
    expect(condition.triage).toBe('CRITICAL');
    expect(condition.deduction).toBe(40);
    expect(condition.why).toContain('13 DNS lookups');
    expect(condition.dismissible).toBe(false);
  });

  it('carries optional evidence', () => {
    const condition = createCondition(
      'SPF_ALL_TOO_PERMISSIVE',
      { domain: 'a.com', offending_term: '+all' },
      { evidence: 'v=spf1 +all' },
    );
    expect(condition.evidence).toBe('v=spf1 +all');
    expect(condition.title).toBe('SPF authorises the entire internet');
    expect(condition.why).toContain('+all');
  });

  it('throws on an unknown code', () => {
    expect(() => createCondition('SPF_NOT_A_REAL_CODE')).toThrow(/Unknown issue code/);
  });
});
