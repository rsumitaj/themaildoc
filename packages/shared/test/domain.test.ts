import { describe, expect, it } from 'vitest';
import { normalizeDomain, stripWww, tidyDomainInput, toDomain } from '../src/index.js';

describe('normalizeDomain', () => {
  it.each([
    ['example.com', 'example.com'],
    ['  Example.COM  ', 'example.com'],
    ['https://example.com', 'example.com'],
    ['http://example.com/some/path?q=1#x', 'example.com'],
    ['https://www.example.com/', 'www.example.com'],
    ['example.com.', 'example.com'],
    ['example.com:8080', 'example.com'],
    ['user@example.com', 'example.com'],
    ['mail.corp.example.co.uk', 'mail.corp.example.co.uk'],
    ['xn--80ak6aa92e.com', 'xn--80ak6aa92e.com'],
  ])('normalizes %j → %j', (input, expected) => {
    expect(toDomain(input)).toBe(expected);
  });

  it('converts internationalised domains to punycode', () => {
    expect(toDomain('exämple.com')).toBe('xn--exmple-cua.com');
  });

  it.each([
    ['', 'EMPTY'],
    ['   ', 'EMPTY'],
    ['192.168.0.1', 'IP_ADDRESS'],
    ['2001:db8::1', 'IP_ADDRESS'],
    ['localhost', 'NO_TLD'],
    ['example.c0m', 'INVALID_TLD'],
    ['-bad.example.com', 'INVALID_LABEL'],
    ['exa mple.com', 'INVALID_LABEL'],
    ['under_score.com', 'INVALID_LABEL'],
    [`${'a'.repeat(64)}.com`, 'INVALID_LABEL'],
  ])('rejects %j as %s', (input, reason) => {
    const result = normalizeDomain(input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe(reason);
  });

  it('rejects domains over 253 characters', () => {
    const long = `${Array.from({ length: 20 }, () => 'abcdefghijkl').join('.')}.com`;
    const result = normalizeDomain(long);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('TOO_LONG');
  });

  it('keeps the original input on the result for error copy', () => {
    const result = normalizeDomain(' HTTPS://Example.com/x ');
    expect(result.input).toBe('HTTPS://Example.com/x');
  });
});

describe('stripWww', () => {
  it('strips only a leading www label', () => {
    expect(stripWww('www.example.com')).toBe('example.com');
    expect(stripWww('wwwx.example.com')).toBe('wwwx.example.com');
    expect(stripWww('mail.www.example.com')).toBe('mail.www.example.com');
  });
});

describe('tidyDomainInput', () => {
  it('strips a scheme, because the field already shows one', () => {
    expect(tidyDomainInput('https://online.canarabank.bank.in')).toBe('online.canarabank.bank.in');
    expect(tidyDomainInput('http://example.com')).toBe('example.com');
  });

  it('keeps only the host from a full URL', () => {
    expect(tidyDomainInput('https://bank.example.com/login?next=/account#top')).toBe(
      'bank.example.com',
    );
  });

  it('takes the domain out of an email address', () => {
    expect(tidyDomainInput('sumit@example.co.uk')).toBe('example.co.uk');
  });

  it('drops a leading www, but never down to a bare TLD', () => {
    expect(tidyDomainInput('www.example.com')).toBe('example.com');
    expect(tidyDomainInput('www.com')).toBe('www.com');
  });

  it('leaves a plain domain exactly as typed', () => {
    expect(tidyDomainInput('example.com')).toBe('example.com');
    expect(tidyDomainInput('mail.example')).toBe('mail.example');
  });

  it('does not fight someone mid-keystroke', () => {
    // Half-typed input must survive untouched, or the caret jumps.
    expect(tidyDomainInput('exam')).toBe('exam');
    expect(tidyDomainInput('example.')).toBe('example.');
  });

  it('agrees with the validator on everything it produces', () => {
    for (const raw of [
      'https://www.example.com/path',
      'sumit@example.com',
      'HTTP://Example.COM',
      'example.com',
    ]) {
      expect(normalizeDomain(tidyDomainInput(raw)).ok, raw).toBe(true);
    }
  });
});
