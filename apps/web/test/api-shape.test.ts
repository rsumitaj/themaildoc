import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * API responses are built as plain object literals, so nothing type checks the
 * key names against the islands that read them. A capitalised `Records` shipped
 * to production once and broke the DNS lookup tool silently: the endpoint
 * answered 200, the page rendered, and the records simply never appeared.
 *
 * Every key a client reads is lower camel case. This asserts it.
 */

const API = join(import.meta.dirname, '../src/pages/api');

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) return files(path);
    return path.endsWith('.ts') ? [path] : [];
  });
}

/** Strip comments and strings so prose and record data are not mistaken for code. */
function code(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``');
}

describe('API response shape', () => {
  const endpoints = files(API);

  it('covers every endpoint', () => {
    expect(endpoints.length).toBeGreaterThanOrEqual(5);
  });

  it('uses lower camel case for every object key', () => {
    const offenders: string[] = [];

    for (const file of endpoints) {
      const source = code(readFileSync(file, 'utf8'));
      for (const match of source.matchAll(/^\s+([A-Z][A-Za-z0-9]*)\s*:/gm)) {
        offenders.push(`${file.split('/').slice(-2).join('/')}: ${match[1]}`);
      }
    }

    expect(offenders.join('\n')).toBe('');
  });

  it('keeps the lookup endpoint answering with `records`', () => {
    // The one that broke. Named explicitly so the regression has a home.
    const source = readFileSync(join(API, 'lookup.ts'), 'utf8');
    expect(source).toMatch(/^\s+records:/m);
    expect(source).not.toMatch(/^\s+Records:/m);
  });
});

/**
 * The three endpoints the result screen fires together.
 *
 * Two of the checks have requests of their own, and for the same reason: a
 * Worker gets fifty subrequests and neither fits inside the checkup's share of
 * them. DKIM has to probe speculative selectors; the SPF chain has to be walked
 * one hop at a time and can be fifty names long.
 */
describe('the checks that need a request of their own', () => {
  it('walks the SPF chain in a request that spends nothing else', () => {
    const source = readFileSync(join(API, 'check/spf.ts'), 'utf8');

    // The whole point: its own budget, not a share of the checkup's.
    expect(source).toMatch(/budget:\s*SPF_DEEP_WALK_BUDGET/);
    expect(source).toMatch(/analyzeSpf\(/);
    // Nothing else may run here, or the budget stops being the chain's.
    expect(source).not.toMatch(/analyzeDmarc|analyzeMx|healthCheck/);
  });

  it('throttles and validates like every other endpoint', () => {
    const source = readFileSync(join(API, 'check/spf.ts'), 'utf8');

    expect(source).toMatch(/rateLimit\(request\)/);
    expect(source).toMatch(/readDomain\(request\)/);
    expect(source).toMatch(/prerender = false/);
  });
});
