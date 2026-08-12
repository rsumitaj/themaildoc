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
