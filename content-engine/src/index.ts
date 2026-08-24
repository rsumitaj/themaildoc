/**
 * MailDoc Content Engine — Worker entry.
 *
 * scheduled(): the cron wakes the pipeline. It decides for itself whether to
 * produce anything (weekly caps + score threshold), so a daily cron is safe.
 * fetch(): the human-facing surfaces — preview, and the one-tap publish/discard
 * links from the approval email — plus a token-guarded manual /run for testing.
 */
import { loadConfig, type Env } from './config';
import { Db } from './lib/d1';
import { run } from './pipeline';
import { handlePublish, handleDiscard } from './stages/publish';
import { previewPage, resultPage, renderMarkdown } from './lib/html';

const html = (body: string, status = 200): Response =>
  new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'x-robots-tag': 'noindex' } });
const json = (obj: unknown, status = 200): Response =>
  new Response(JSON.stringify(obj, null, 2), { status, headers: { 'content-type': 'application/json' } });

export default {
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(run(env, 'cron').then((r) => console.log('run', JSON.stringify(r).slice(0, 500))));
  },

  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const cfg = loadConfig(env);
    const db = new Db(env.DB);

    try {
      if (url.pathname === '/health') {
        return json({ ok: true, weekly: cfg.weekly, model: cfg.geminiModel, dryRun: cfg.dryRun, engineUrl: cfg.engineUrl || '(set ENGINE_PUBLIC_URL)' });
      }

      if (url.pathname.startsWith('/preview/')) {
        const secret = url.pathname.slice('/preview/'.length);
        const draft = await db.getDraftByPreview(secret);
        if (!draft) return html(resultPage(false, 'Not found', 'No draft matches this preview link.'), 404);
        return html(previewPage(draft, renderMarkdown(draft.body_md)));
      }

      if (url.pathname === '/publish') {
        const t = url.searchParams.get('t') ?? '';
        const out = await handlePublish(env, cfg, db, t);
        return html(resultPage(out.ok, out.title, out.message), out.ok ? 200 : 400);
      }

      if (url.pathname === '/discard') {
        const t = url.searchParams.get('t') ?? '';
        const out = await handleDiscard(env, cfg, db, t);
        return html(resultPage(out.ok, out.title, out.message), out.ok ? 200 : 400);
      }

      // Manual trigger for testing. Guarded by RUN_TOKEN.
      if (url.pathname === '/run') {
        const provided = request.headers.get('authorization')?.replace('Bearer ', '') ?? url.searchParams.get('token') ?? '';
        if (!env.RUN_TOKEN || provided !== env.RUN_TOKEN) return json({ ok: false, error: 'unauthorized' }, 401);
        const result = await run(env, 'manual');
        return json(result);
      }

      return html(resultPage(false, 'MailDoc Content Engine', 'Nothing to see here. This service runs on a schedule.'), 404);
    } catch (err) {
      return html(resultPage(false, 'Error', (err as Error).message), 500);
    }
  },
};
