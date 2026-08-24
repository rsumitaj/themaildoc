/**
 * Deterministic content checks. Fast, free, and run on every draft before any
 * model-based critique. Two kinds of outcome:
 *   - hard fail  -> the draft cannot ship, full stop (regenerate or hold)
 *   - scored     -> contributes to the content score; low score = weak draft
 *
 * The AI-pattern check is a hard gate by request: no em dashes, no "--", no
 * invisible watermark characters, no emoji, none of the tell-tale LLM phrases.
 * These run on PROSE only (code fences and inline code are stripped first) so a
 * legitimate CLI flag or record sample is never mistaken for a watermark.
 */
import type { Config } from '../config';
import type { LibraryFrontmatter } from '../lib/schema';
import { validateFrontmatter } from '../lib/schema';

export interface CheckResult { name: string; pass: boolean; hard: boolean; score: number; detail: string; }

/** Remove fenced + inline code and inline SVG so text checks only see prose. */
function prose(body: string): string {
  return body
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`[^`]*`/g, ' ')
    .replace(/<svg[\s\S]*?<\/svg>/gi, ' ');
}

// --- AI / machine-text watermark patterns (hard) ---
const EM_DASH = /[—–]|--/;                       // em, en, or double hyphen
const ZERO_WIDTH = /[​‌‍⁠﻿  ]/; // invisible/odd spaces LLMs emit
// Real emoji + pictographs only. Deliberately excludes the arrow blocks so that
// typographic arrows (->, the site uses them) are never flagged.
const EMOJI = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F1E6}-\u{1F1FF}]️?/u;
const AI_DISCLOSURE = /\b(as an ai|as a language model|i cannot|i'm just an ai|i am an ai)\b/i;

const CLICHES: RegExp[] = [
  /in today's (digital |fast-paced )?world/i, /in the (ever-|)evolving/i, /ever-changing landscape/i,
  /it's (important|worth) (to note|noting)/i, /it is worth noting/i, /needless to say/i,
  /at the end of the day/i, /when it comes to/i, /in the realm of/i, /navigating the/i,
  /unlock (the |your )?(power|potential)/i, /\bdelve\b/i, /\btapestry\b/i, /testament to/i,
  /game[- ]changer/i, /in conclusion/i, /in summary/i, /let's (dive|delve) in/i, /buckle up/i,
  /rest assured/i, /look no further/i, /gone are the days/i, /\bseamless(ly)?\b/i,
  /\bleverage\b/i, /\brobust\b/i, /not only\b[\s\S]{0,60}\bbut also\b/i, /whether you're a\b[\s\S]{0,40}\bor a\b/i,
  /\bfirstly\b/i, /\bmoreover\b/i, /\bfurthermore\b/i,
];

const words = (s: string): number => (s.trim().match(/\S+/g) ?? []).length;

export function aiPatternCheck(body: string): CheckResult[] {
  const t = prose(body);
  const out: CheckResult[] = [];
  out.push({ name: 'no-em-dash', hard: true, pass: !EM_DASH.test(t), score: EM_DASH.test(t) ? 0 : 100,
    detail: EM_DASH.test(t) ? 'contains an em/en dash or "--"; use commas, periods or parentheses' : 'clean' });
  out.push({ name: 'no-watermark-chars', hard: true, pass: !ZERO_WIDTH.test(body), score: ZERO_WIDTH.test(body) ? 0 : 100,
    detail: ZERO_WIDTH.test(body) ? 'invisible/zero-width characters present' : 'clean' });
  out.push({ name: 'no-emoji', hard: true, pass: !EMOJI.test(body), score: EMOJI.test(body) ? 0 : 100,
    detail: EMOJI.test(body) ? 'emoji present (brand rule)' : 'clean' });
  out.push({ name: 'no-ai-disclosure', hard: true, pass: !AI_DISCLOSURE.test(t), score: AI_DISCLOSURE.test(t) ? 0 : 100,
    detail: AI_DISCLOSURE.test(t) ? 'contains AI self-reference' : 'clean' });
  const hits = CLICHES.filter((r) => r.test(t)).length;
  out.push({ name: 'no-ai-cliches', hard: hits >= 3, pass: hits <= 1, score: Math.max(0, 100 - hits * 25),
    detail: hits === 0 ? 'clean' : `${hits} cliche phrase(s) found` });
  return out;
}

const FORBIDDEN = /\b(flatlin|autopsy|\bdead\b|deceased|terminal(ly)? ill|corpse|morgue)\b/i;

export function brandSafetyCheck(body: string, title: string): CheckResult {
  const bad = FORBIDDEN.test(`${title}\n${prose(body)}`);
  return { name: 'brand-safe', hard: bad, pass: !bad, score: bad ? 0 : 100,
    detail: bad ? 'death-morbid wording (voice guardrail)' : 'clean' };
}

export function seoCheck(fm: LibraryFrontmatter, body: string, cfg: Config): CheckResult[] {
  const kw = fm.keyword.toLowerCase();
  const first100 = words(body) ? body.split(/\s+/).slice(0, 100).join(' ').toLowerCase() : '';
  const internal = (body.match(/\]\(\/[a-z]/g) ?? []).length;
  const external = (body.match(/\]\(https?:\/\//g) ?? []).length;
  const wc = words(prose(body));
  const out: CheckResult[] = [];
  out.push({ name: 'kw-in-title', hard: false, pass: (fm.title + fm.heading).toLowerCase().includes(kw),
    score: (fm.title + fm.heading).toLowerCase().includes(kw) ? 100 : 40, detail: 'keyword in title/heading' });
  out.push({ name: 'kw-early', hard: false, pass: first100.includes(kw), score: first100.includes(kw) ? 100 : 50, detail: 'keyword in first 100 words' });
  out.push({ name: 'internal-links', hard: false, pass: internal >= 2, score: Math.min(100, internal * 40), detail: `${internal} internal link(s), need >=2` });
  out.push({ name: 'external-ref', hard: false, pass: external >= 1, score: external >= 1 ? 100 : 40, detail: `${external} external reference(s)` });
  out.push({ name: 'word-count', hard: wc < cfg.words.min * 0.6, pass: wc >= cfg.words.min && wc <= cfg.words.max,
    score: wc >= cfg.words.min && wc <= cfg.words.max ? 100 : 55, detail: `${wc} words (target ${cfg.words.min}-${cfg.words.max})` });
  return out;
}

export function structureCheck(body: string, fm: LibraryFrontmatter): CheckResult[] {
  const hasDiagram = /<svg[\s>]/i.test(body) || /```mermaid/i.test(body);
  const hasExample = /\b(for example|for instance|say your|imagine|real[- ]world|in practice|here's what|worked example)\b/i.test(body)
    || /(example\.com|v=spf1|v=DMARC1|p=(none|quarantine|reject)|IN\s+(TXT|MX|CNAME))/i.test(body);
  const hasHeadings = (body.match(/^##\s+/gm) ?? []).length >= 2;
  return [
    { name: 'has-diagram', hard: false, pass: hasDiagram, score: hasDiagram ? 100 : 30, detail: hasDiagram ? 'inline SVG/mermaid present' : 'no diagram found' },
    { name: 'has-real-example', hard: false, pass: hasExample, score: hasExample ? 100 : 40, detail: hasExample ? 'concrete example/record present' : 'no concrete example found' },
    { name: 'has-structure', hard: false, pass: hasHeadings, score: hasHeadings ? 100 : 50, detail: 'section headings present' },
    { name: 'faq-present', hard: false, pass: (fm.faq?.length ?? 0) >= 2, score: (fm.faq?.length ?? 0) >= 2 ? 100 : 40, detail: `${fm.faq?.length ?? 0} FAQ(s)` },
  ];
}

export function schemaCheck(fm: LibraryFrontmatter): CheckResult {
  const { ok, errors } = validateFrontmatter(fm);
  return { name: 'schema-valid', hard: !ok, pass: ok, score: ok ? 100 : 0, detail: ok ? 'valid' : errors.join('; ') };
}

/** Run every deterministic check; caller merges model-based scores on top. */
export function runDeterministicChecks(fm: LibraryFrontmatter, body: string, cfg: Config): {
  checks: CheckResult[]; hardFail: boolean; score: number;
} {
  const checks: CheckResult[] = [
    schemaCheck(fm),
    ...aiPatternCheck(body),
    brandSafetyCheck(body, fm.title),
    ...seoCheck(fm, body, cfg),
    ...structureCheck(body, fm),
  ];
  const hardFail = checks.some((c) => c.hard && !c.pass);
  const score = Math.round(checks.reduce((s, c) => s + c.score, 0) / checks.length);
  return { checks, hardFail, score };
}
