import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { BRAND_RED, TRIAGE_VAR, triageColorVar } from '../src/index.js';

/**
 * The palette has one definition, and two things need it in a form CSS cannot
 * provide. This is what stops those copies drifting.
 */
const tokens = readFileSync(join(import.meta.dirname, '../src/tokens.css'), 'utf8');

/** Read a custom property out of the `:root` block. */
function token(name: string): string | null {
  const match = new RegExp(`^\\s*${name}:\\s*([^;]+);`, 'm').exec(tokens);
  return match ? match[1]!.trim() : null;
}

describe('the palette has one definition', () => {
  it('keeps BRAND_RED equal to --md-red', () => {
    // The `theme-color` meta tag is an HTML attribute and cannot read a custom
    // property, so this one value exists twice. It may not exist twice with two
    // different values.
    expect(BRAND_RED).toBe(token('--md-red'));
  });

  it('names a token for every triage level rather than a colour', () => {
    // These used to be five hex literals in the catalog, which made that file a
    // second copy of the palette and froze every triage dot to the light theme.
    for (const [level, name] of Object.entries(TRIAGE_VAR)) {
      expect(token(name), `${level} names ${name}, which tokens.css must define`).not.toBeNull();
      expect(triageColorVar(level as keyof typeof TRIAGE_VAR)).toBe(`var(${name})`);
    }
  });
});
