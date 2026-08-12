import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The voice guardrail.
 *
 * Wording drifts one commit at a time and nobody notices until the site reads
 * like it was generated. These are the tells we have decided against, checked
 * on every file a visitor can read.
 */

const ROOTS = [
  join(import.meta.dirname, '../src'),
  join(import.meta.dirname, '../../../packages/catalog/src'),
  join(import.meta.dirname, '../../../packages/engines/src'),
  join(import.meta.dirname, '../../../packages/report-parsers/src'),
];

const EXTENSIONS = ['.astro', '.tsx', '.ts'];

function files(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist') continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...files(path));
    else if (EXTENSIONS.some((extension) => entry.endsWith(extension))) out.push(path);
  }
  return out;
}

const ALL = ROOTS.flatMap(files);

/** Strip comments: this checks what visitors read, not what we say to each other. */
function prose(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/^\s*\*.*$/gm, '');
}

interface Offence {
  file: string;
  line: number;
  text: string;
}

function scan(pattern: RegExp): Offence[] {
  const found: Offence[] = [];
  for (const file of ALL) {
    const lines = prose(readFileSync(file, 'utf8')).split('\n');
    lines.forEach((line, index) => {
      if (pattern.test(line)) {
        found.push({ file: file.split('/').slice(-2).join('/'), line: index + 1, text: line.trim() });
      }
      pattern.lastIndex = 0;
    });
  }
  return found;
}

function report(found: Offence[]): string {
  return found
    .slice(0, 12)
    .map((offence) => `${offence.file}:${offence.line} ${offence.text.slice(0, 110)}`)
    .join('\n');
}

/** Titles and descriptions carry their own rules. */
function metaStrings(): { file: string; kind: string; value: string }[] {
  const out: { file: string; kind: string; value: string }[] = [];
  // Pages only: a `title` attribute on a div is a tooltip, not a page title.
  for (const file of ALL.filter((path) => path.includes('/src/pages/'))) {
    const source = readFileSync(file, 'utf8');
    for (const match of source.matchAll(/^\s*(title|description)=["']([^"']{10,})["']/gm)) {
      out.push({ file: file.split('/').slice(-2).join('/'), kind: match[1] as string, value: match[2] as string });
    }
    for (const match of source.matchAll(/^const (title|description) = ['"]([^'"]{10,})['"]/gm)) {
      out.push({ file: file.split('/').slice(-2).join('/'), kind: match[1] as string, value: match[2] as string });
    }
  }
  return out;
}

describe('titles and descriptions', () => {
  const metas = metaStrings();

  it('finds them', () => {
    expect(metas.length).toBeGreaterThan(20);
  });

  it('separates with a colon or a pipe, never a comma doing a dash job', () => {
    // `Is My Domain Spoofed?, free test` is what a dash-to-comma rule produces.
    const bad = metas.filter((meta) => meta.kind === 'title' && /[?!],\s/.test(meta.value));
    expect(bad.map((m) => `${m.file}: ${m.value}`).join('\n')).toBe('');
  });

  it('keeps titles inside what a search result will show', () => {
    const long = metas.filter((meta) => meta.kind === 'title' && meta.value.length > 70);
    expect(long.map((m) => `${m.file}: ${m.value.length} ${m.value}`).join('\n')).toBe('');
  });

  it('gives every title the brand', () => {
    const orphan = metas.filter(
      (meta) => meta.kind === 'title' && !/\| (The MailDoc|Sumit Raj)$/.test(meta.value),
    );
    expect(orphan.map((m) => `${m.file}: ${m.value}`).join('\n')).toBe('');
  });
});

describe('voice', () => {
  it('reads a lot of files', () => {
    expect(ALL.length).toBeGreaterThan(50);
  });

  it('uses no em or en dashes', () => {
    // They set a rhythm that reads as generated, and a full stop is almost
    // always the better break.
    const found = scan(/[—–]/);
    expect(found.length, `\n${report(found)}`).toBe(0);
  });

  it('uses no double hyphen standing in for a dash', () => {
    const found = scan(/\s--\s/);
    expect(found.length, `\n${report(found)}`).toBe(0);
  });

  it('ships no emoji', () => {
    const found = scan(/\p{Extended_Pictographic}/u).filter(
      (offence) => !offence.text.includes('©'),
    );
    expect(found.length, `\n${report(found)}`).toBe(0);
  });

  it('threatens with exposure, never with death', () => {
    // CONVENTIONS.md bans this about a *domain*. "A dead include" is ordinary
    // engineering English and stays.
    const found = scan(
      /\b(death|died|flatlin\w*|autopsy|corpse|morgue)\b|\b(domain|record|mail|score)s?\s+(is|are|was|were)\s+(dead|fatal|terminal)\b/i,
    );
    expect(found.length, `\n${report(found)}`).toBe(0);
  });

  it('avoids the "not X, it is Y" construction', () => {
    // The single most recognisable generated-prose tell.
    const found = scan(/\b(is|are|was|were)\s+not\s+[^.,;]{3,40},\s+(it|they|this|that)\s+(is|are)\b/i);
    expect(found.length, `\n${report(found)}`).toBe(0);
  });

  it('avoids filler openers', () => {
    const found = scan(
      /\b(the (truth|reality|fact) is|at the end of the day|it goes without saying|needless to say|in today's world)\b/i,
    );
    expect(found.length, `\n${report(found)}`).toBe(0);
  });

  it('does not call anything a game changer or similar', () => {
    const found = scan(
      /\b(game.?changer|leverage the power|unlock the|seamless(ly)?|robust solution|cutting.edge|best.in.class)\b/i,
    );
    expect(found.length, `\n${report(found)}`).toBe(0);
  });
});
