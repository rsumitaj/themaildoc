/**
 * Step 2 — write and verify.
 *
 * Draft with Gemini in your voice, run the deterministic checks, and if any
 * hard gate fails (em dash, schema, brand-safety) or the score is low,
 * regenerate with the exact failures fed back, up to MAX_REGEN_ATTEMPTS. Then a
 * separate Gemini critique scores voice/accuracy/humanised/originality, which
 * is merged into the final content score. A draft that never clears the bar is
 * held, not shipped.
 */
import type { Config } from '../config';
import { Gemini } from '../lib/gemini';
import type { LibraryFrontmatter } from '../lib/schema';
import { runDeterministicChecks, type CheckResult } from './checks';
import { WRITER_SYSTEM, CRITIC_SYSTEM } from '../prompts';
import type { Topic } from './select';

export interface WriteResult {
  ok: boolean; reason?: string;
  fm?: LibraryFrontmatter; body?: string; checks?: CheckResult[]; score?: number;
  critique?: Record<string, number>;
}

const today = (): string => new Date().toISOString().slice(0, 10);
const wc = (s: string): number => (s.trim().match(/\S+/g) ?? []).length;

function toFrontmatter(j: any, topic: Topic): LibraryFrontmatter {
  return {
    title: String(j.title ?? topic.title).trim(),
    description: String(j.description ?? '').trim(),
    keyword: String(j.keyword ?? topic.keyword).trim(),
    heading: String(j.heading ?? topic.title).trim(),
    standfirst: String(j.standfirst ?? '').trim(),
    kind: 'cluster',
    updated: today(),
    published: today(),
    faq: Array.isArray(j.faq) ? j.faq.slice(0, 6).map((f: any) => ({ q: String(f.q ?? ''), a: String(f.a ?? '') })) : [],
    tools: Array.isArray(j.tools) ? j.tools.map(String).slice(0, 3) : [],
    related: Array.isArray(j.related) ? j.related.map(String).slice(0, 3) : [],
    steps: Array.isArray(j.steps) ? j.steps.map((s: any) => ({ name: String(s.name ?? ''), text: String(s.text ?? '') })) : [],
    draft: true,
  };
}

async function draft(gemini: Gemini, topic: Topic, feedback: string): Promise<{ fm: LibraryFrontmatter; body: string }> {
  const prompt = `Write the MailDoc article.
Topic: ${topic.title}
Target keyword: ${topic.keyword}
Angle: ${topic.angle}
${topic.refUrl ? `Grounded in this source (summarise, do not copy): ${topic.refUrl}` : ''}
${feedback ? `\nFIX THESE PROBLEMS from the previous attempt:\n${feedback}` : ''}`;
  const j = await gemini.json<any>(prompt, { system: WRITER_SYSTEM, temperature: 0.7, maxOutputTokens: 6000 });
  return { fm: toFrontmatter(j, topic), body: String(j.body ?? '') };
}

async function critique(gemini: Gemini, fm: LibraryFrontmatter, body: string): Promise<{ scores: Record<string, number>; issues: string[] }> {
  try {
    const j = await gemini.json<any>(`Title: ${fm.title}\nKeyword: ${fm.keyword}\n\n${body}`,
      { system: CRITIC_SYSTEM, temperature: 0.1, maxOutputTokens: 1024 });
    return {
      scores: { voice: +j.voice || 0, humanized: +j.humanized || 0, accuracy: +j.accuracy || 0, originality: +j.originality || 0 },
      issues: Array.isArray(j.issues) ? j.issues.map(String) : [],
    };
  } catch { return { scores: { voice: 0, humanized: 0, accuracy: 0, originality: 0 }, issues: ['critique failed'] }; }
}

export async function writeArticle(gemini: Gemini, topic: Topic, cfg: Config): Promise<WriteResult> {
  let feedback = '';
  let last: { fm: LibraryFrontmatter; body: string } | undefined;
  let det: ReturnType<typeof runDeterministicChecks> | undefined;

  for (let attempt = 0; attempt < cfg.maxRegen; attempt++) {
    try {
      last = await draft(gemini, topic, feedback);
    } catch (err) {
      feedback = `generation error: ${(err as Error).message}`;
      continue;
    }
    det = runDeterministicChecks(last.fm, last.body, cfg);
    if (!det.hardFail && det.score >= cfg.minContentScore) break;
    feedback = det.checks.filter((c) => !c.pass).map((c) => `- ${c.name}: ${c.detail}`).join('\n');
  }

  if (!last || !det) return { ok: false, reason: 'no draft produced' };
  if (det.hardFail) {
    return { ok: false, reason: 'hard check failed after retries: ' + det.checks.filter((c) => c.hard && !c.pass).map((c) => c.name).join(', '),
      fm: last.fm, body: last.body, checks: det.checks, score: det.score };
  }

  // Model critique, merged into the final score.
  const crit = await critique(gemini, last.fm, last.body);
  const cs = crit.scores;
  const critAvg = Math.round(((cs.voice ?? 0) + (cs.humanized ?? 0) + (cs.accuracy ?? 0) + (cs.originality ?? 0)) / 4);
  const critChecks: CheckResult[] = Object.entries(crit.scores).map(([name, score]) => ({
    name: `critic-${name}`, hard: name === 'accuracy' && score < 60, pass: score >= 70, score, detail: crit.issues.join(' | ').slice(0, 200) || 'ok',
  }));
  const checks = [...det.checks, ...critChecks];
  const finalScore = Math.round((det.score + critAvg) / 2);
  const hardFail = checks.some((c) => c.hard && !c.pass);

  if (hardFail || finalScore < cfg.minContentScore) {
    return { ok: false, reason: `below bar (score ${finalScore}, accuracy ${crit.scores.accuracy})`, fm: last.fm, body: last.body, checks, score: finalScore, critique: crit.scores };
  }
  return { ok: true, fm: last.fm, body: last.body, checks, score: finalScore, critique: crit.scores };
}
