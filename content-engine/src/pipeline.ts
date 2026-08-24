/**
 * The orchestrator. Ties the five steps together, enforces the weekly volume
 * caps from config, and treats "nothing worth posting" as a normal outcome.
 * Every stage is wrapped so one failure (GSC down, one bad draft) degrades
 * gracefully instead of killing the run.
 */
import { loadConfig, assertSecrets, isoWeek, type Env } from './config';
import { Db } from './lib/d1';
import { Gemini } from './lib/gemini';
import { uid, randomSecret } from './lib/util';
import { syncGsc } from './stages/measure';
import { selectTopics } from './stages/select';
import { writeArticle } from './stages/write';
import { emailForApproval } from './stages/approve';

function mondayUtcIso(now: Date): string {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const day = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() - (day - 1));
  return d.toISOString();
}

export async function run(env: Env, trigger: 'cron' | 'manual'): Promise<Record<string, unknown>> {
  const cfg = loadConfig(env);
  const db = new Db(env.DB);
  const now = new Date();
  const week = isoWeek(now);

  const missing = assertSecrets(env);
  const runId = await db.startRun(trigger, week);
  if (missing.length) {
    await db.finishRun(runId, 'error', `missing secrets: ${missing.join(', ')}`, { missing });
    return { ok: false, runId, error: `missing secrets: ${missing.join(', ')}` };
  }

  const monday = mondayUtcIso(now);
  const [madeTrendy, madeNews] = await Promise.all([
    db.weeklyCountSince(monday, 'trendy'),
    db.weeklyCountSince(monday, 'news'),
  ]);
  const need = { trendy: Math.max(0, cfg.weekly.trendy - madeTrendy), news: Math.max(0, cfg.weekly.news - madeNews) };

  if (need.trendy + need.news <= 0) {
    await db.finishRun(runId, 'skipped', 'weekly target already met', { need, madeTrendy, madeNews });
    return { ok: true, runId, skipped: 'weekly target met', need };
  }

  // Refresh GSC (best effort).
  let gscInfo: unknown = 'skipped';
  try { gscInfo = await syncGsc(env, cfg, db); } catch (e) { gscInfo = `gsc error: ${(e as Error).message}`; }

  const gemini = new Gemini(env.GEMINI_API_KEY, cfg.geminiModel);

  // Select.
  let selected: Awaited<ReturnType<typeof selectTopics>>['selected'] = [];
  try {
    const r = await selectTopics(db, gemini, cfg, need);
    selected = r.selected;
  } catch (e) {
    await db.finishRun(runId, 'error', `select failed: ${(e as Error).message}`, { gscInfo });
    return { ok: false, runId, error: `select: ${(e as Error).message}` };
  }

  if (selected.length === 0) {
    await db.finishRun(runId, 'skipped', 'no topic cleared the score threshold', { need, gscInfo });
    return { ok: true, runId, skipped: 'no topic cleared threshold', need };
  }

  // Write + email each.
  const results: unknown[] = [];
  for (const topic of selected) {
    const candidateId = await db.insertCandidate({
      runId, kind: topic.kind, source: topic.source, title: topic.title, keyword: topic.keyword,
      refUrl: topic.refUrl, score: topic.score, scores: topic.scores, verdict: 'selected', reason: topic.reason,
    });
    try {
      const w = await writeArticle(gemini, topic, cfg);
      if (!w.ok || !w.fm || !w.body) {
        results.push({ topic: topic.title, ok: false, reason: w.reason });
        continue;
      }
      const draftId = await db.insertDraft({
        candidateId, kind: topic.kind, slug: topic.slug, title: w.fm.title, keyword: w.fm.keyword,
        frontmatter: w.fm, body: w.body, wordCount: (w.body.match(/\S+/g) ?? []).length,
        contentScore: w.score ?? 0, checks: w.checks, previewSecret: uid('pv_') + randomSecret(8), status: 'draft',
      });
      const draft = await db.getDraft(draftId);
      let emailed: unknown = 'dry-run';
      if (draft) emailed = await emailForApproval(env, cfg, db, draft);
      await db.markSeen(`slug:${topic.slug}`, 'drafted');
      results.push({ topic: w.fm.title, ok: true, draftId, score: w.score, emailed });
    } catch (e) {
      results.push({ topic: topic.title, ok: false, reason: (e as Error).message });
    }
  }

  const shipped = results.filter((r: any) => r.ok).length;
  await db.finishRun(runId, 'ok', `emailed ${shipped}/${selected.length} draft(s)`, { need, gscInfo, results });
  return { ok: true, runId, shipped, considered: selected.length, results };
}
