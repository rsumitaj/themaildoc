#!/usr/bin/env node
/**
 * The design system's own unit test.
 *
 * Three tokens were being used that had never been defined — `--md-space-7`,
 * `--md-space-9` and `--md-tracking-wide`. CSS does not warn about that. It
 * drops the whole declaration and moves on, so the mobile nav panel lost its
 * padding entirely and the home page's FAQ section lost its vertical rhythm,
 * and both looked deliberate enough that nobody caught them.
 *
 * This is the check that would have. It fails on:
 *
 *   1. any `var(--md-…)` naming a token `tokens.css` does not define;
 *   2. any raw colour outside `tokens.css`, because the palette is the palette;
 *   3. any font-size that is not a rung on the scale.
 *
 * Spacing is deliberately not policed to the same degree: a handful of optical
 * nudges (`top: 0.55rem` to sit a bullet on a baseline) are legitimate and a
 * rule strict enough to catch drift would mostly generate exemptions.
 *
 * Run directly, or as part of `pnpm test`.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const TOKENS = join(root, 'packages/ui/src/tokens.css');

/**
 * `packages/catalog` is here because the palette got copied into it.
 * `TRIAGE_COLOR` held five hex literals that `tokens.css` also defined, so
 * there were two places to change ambulance red and this check could only see
 * one of them. Anything that names a colour is in scope.
 */
const ROOTS = ['apps/web/src', 'packages/ui/src', 'packages/catalog/src'];
const EXTENSIONS = ['.css', '.astro', '.tsx', '.ts'];

/**
 * Files allowed to name a colour directly.
 *
 * `index.ts` holds exactly one: the brand red, for the `theme-color` meta tag,
 * which is an HTML attribute and cannot read a custom property. That it matches
 * `--md-red` is asserted in `packages/ui/test/tokens.test.ts` rather than left
 * to trust, which is the difference between a permitted duplicate and a
 * forgotten one.
 */
const PALETTE = ['packages/ui/src/tokens.css', 'packages/ui/src/index.ts'];

/**
 * SVG artwork and OG cards are drawings, not interface. A logo's stroke is
 * `currentColor` and its geometry is not a design token.
 */
const NOT_INTERFACE = [/\/Logo\.astro$/, /\/Icon\.astro$/, /\/Icons\.tsx$/];

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else if (EXTENSIONS.some((extension) => entry.endsWith(extension))) out.push(path);
  }
  return out;
}

const tokensSource = readFileSync(TOKENS, 'utf8');
const defined = new Set([...tokensSource.matchAll(/^\s*(--md-[\w-]+)\s*:/gm)].map((m) => m[1]));

/** Every size the scale allows, plus the relative and fluid exceptions. */
const SIZE_TOKENS = new Set(
  [...tokensSource.matchAll(/^\s*(--md-text-[\w-]+)\s*:/gm)].map((m) => m[1]),
);

const problems = [];

for (const base of ROOTS) {
  for (const file of walk(join(root, base))) {
    const rel = relative(root, file);
    const source = readFileSync(file, 'utf8');

    for (const match of source.matchAll(/var\((--md-[\w-]+)/g)) {
      if (!defined.has(match[1])) {
        problems.push(`${rel}: uses ${match[1]}, which tokens.css does not define`);
      }
    }

    if (!PALETTE.includes(rel) && !NOT_INTERFACE.some((pattern) => pattern.test(rel))) {
      for (const match of source.matchAll(/#[0-9a-fA-F]{3,8}\b/g)) {
        // `#` inside a URL, an anchor or a comment is not a colour.
        const before = source.slice(Math.max(0, match.index - 40), match.index);
        if (/(https?:|href=|url\(|#)\S*$/.test(before)) continue;
        problems.push(`${rel}: raw colour ${match[0]} — add it to tokens.css and use the token`);
      }
    }

    for (const match of source.matchAll(/font-size:\s*([^;]+);/g)) {
      const value = match[1].trim();
      if (value.startsWith('var(')) {
        const named = /var\((--md-[\w-]+)/.exec(value);
        if (named && !SIZE_TOKENS.has(named[1])) {
          problems.push(`${rel}: font-size uses ${named[1]}, which is not on the type scale`);
        }
        continue;
      }
      // `em` is relative to a rung that has already been chosen; `inherit` and
      // `1` (a line-height-style reset) are not sizes at all.
      if (/^(inherit|\d*\.?\d+em)$/.test(value)) continue;
      problems.push(`${rel}: font-size: ${value} is not on the type scale`);
    }
  }
}

if (problems.length > 0) {
  console.error('Design token problems:\n');
  for (const problem of problems) console.error(`  ${problem}`);
  console.error(`\n${problems.length} problem(s). The scale is in packages/ui/src/tokens.css.`);
  process.exit(1);
}

console.error(`Design tokens clean: ${defined.size} defined, all references resolve.`);
