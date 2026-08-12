import { describe, expect, it } from 'vitest';
import { assessReadiness, type ReadinessInput } from '../src/index.js';

const base: ReadinessInput = {
  domain: 'example.com',
  spf: { found: true, allQualifier: '-', lookupCount: 3 },
  dmarc: {
    found: true,
    effectivePolicy: 'reject',
    alignment: { dkim: 'r', spf: 'r' },
    rua: ['dmarc@example.com'],
  },
  dkim: { found: true, weakestKey: 2048 },
  ptr: { checked: 2, forwardConfirmed: 2, noOwnServers: false },
  mtasts: { announced: true },
};

const find = (input: ReadinessInput, id: string) =>
  assessReadiness(input).requirements.find((requirement) => requirement.id === id);

describe('sender readiness', () => {
  it('passes a domain that meets every checkable requirement', () => {
    const result = assessReadiness(base);

    expect(result.ready).toBe(true);
    expect(result.failed).toBe(0);
    expect(result.passed).toBe(result.checkable);
  });

  it('never claims to have verified what DNS cannot show', () => {
    // Tools that show these as passing are guessing, and being caught guessing
    // costs the credibility of every other line on the page.
    const result = assessReadiness(base);
    const unverifiable = result.requirements
      .filter((requirement) => requirement.status === 'UNVERIFIABLE')
      .map((requirement) => requirement.id);

    expect(unverifiable).toContain('tls');
    expect(unverifiable).toContain('unsubscribe');
    expect(unverifiable).toContain('spam-rate');
    expect(unverifiable).toContain('format');
    // …and they are excluded from the score rather than counted as passes.
    expect(result.checkable).toBeLessThan(result.requirements.length);
  });

  it('fails a domain with no SPF', () => {
    const requirement = find({ ...base, spf: { ...base.spf, found: false } }, 'spf');
    expect(requirement?.status).toBe('FAIL');
  });

  it('fails SPF that is published but over the lookup limit', () => {
    // A PermError means SPF does not pass, which is the same as not having it.
    const requirement = find({ ...base, spf: { ...base.spf, lookupCount: 12 } }, 'spf');
    expect(requirement?.status).toBe('FAIL');
    expect(requirement?.detail).toContain('12 DNS lookups');
  });

  it('warns rather than fails on +all', () => {
    const requirement = find({ ...base, spf: { ...base.spf, allQualifier: '+' } }, 'spf');
    expect(requirement?.status).toBe('WARN');
  });

  it('fails a DKIM key below the accepted minimum', () => {
    const requirement = find({ ...base, dkim: { found: true, weakestKey: 512 } }, 'dkim');
    expect(requirement?.status).toBe('FAIL');
  });

  it('warns, not fails, when no DKIM selector answered', () => {
    // We probed and missed; that is not proof the domain has no DKIM.
    const requirement = find({ ...base, dkim: { found: false, weakestKey: null } }, 'dkim');
    expect(requirement?.status).toBe('WARN');
    expect(requirement?.detail).toContain('no index in DNS');
  });

  it('fails a domain with no DMARC', () => {
    const input = {
      ...base,
      dmarc: { ...base.dmarc, found: false },
    };
    expect(find(input, 'dmarc')?.status).toBe('FAIL');
    expect(find(input, 'alignment')?.status).toBe('FAIL');
  });

  it('warns when DMARC has no reporting address', () => {
    expect(find({ ...base, dmarc: { ...base.dmarc, rua: [] } }, 'dmarc')?.status).toBe('WARN');
  });

  it('warns about strict alignment', () => {
    const input = {
      ...base,
      dmarc: { ...base.dmarc, alignment: { dkim: 's' as const, spf: 'r' as const } },
    };
    expect(find(input, 'alignment')?.status).toBe('WARN');
  });

  it('fails reverse DNS that does not round-trip', () => {
    const requirement = find(
      { ...base, ptr: { checked: 2, forwardConfirmed: 1, noOwnServers: false } },
      'ptr',
    );
    expect(requirement?.status).toBe('FAIL');
    expect(requirement?.detail).toContain('1 of 2');
  });

  it('does not judge reverse DNS when every sender is external', () => {
    const requirement = find(
      { ...base, ptr: { checked: 0, forwardConfirmed: 0, noOwnServers: true } },
      'ptr',
    );
    expect(requirement?.status).toBe('UNVERIFIABLE');
    expect(requirement?.detail).toContain('their responsibility');
  });

  it('marks DKIM unverifiable when that check has not run', () => {
    expect(find({ ...base, dkim: null }, 'dkim')?.status).toBe('UNVERIFIABLE');
  });

  it('gives every failing requirement something to do about it', () => {
    const broken: ReadinessInput = {
      ...base,
      spf: { found: false, allQualifier: null, lookupCount: 0 },
      dmarc: { found: false, effectivePolicy: 'none', alignment: { dkim: 'r', spf: 'r' }, rua: [] },
      dkim: { found: true, weakestKey: 512 },
      ptr: { checked: 2, forwardConfirmed: 0, noOwnServers: false },
    };
    const result = assessReadiness(broken);

    expect(result.ready).toBe(false);
    for (const requirement of result.requirements) {
      if (requirement.status === 'FAIL' || requirement.status === 'WARN') {
        expect(requirement.fix, requirement.id).toBeTruthy();
      }
    }
  });
});
