/**
 * Step 5 — measure. Refresh the Search Console mirror in D1 so topic selection
 * is driven by your real, current demand. Runs best-effort at the top of a
 * pipeline run; a GSC hiccup never blocks content.
 */
import type { Config, Env } from '../config';
import type { Db } from '../lib/d1';
import { Gsc, daysAgo } from '../lib/gsc';

export async function syncGsc(env: Env, cfg: Config, db: Db): Promise<{ queries: number; pages: number }> {
  const gsc = new Gsc(env.GSC_SA_EMAIL, env.GSC_SA_PRIVATE_KEY, cfg.gscSiteUrl);
  const date = new Date().toISOString().slice(0, 10);
  const q = await gsc.query({ startDate: daysAgo(90), endDate: daysAgo(1), dimensions: ['query'], rowLimit: 1000 });
  await db.upsertGscQuery(date, q.map((r) => ({ query: r.keys[0] ?? '', clicks: r.clicks, impressions: r.impressions, position: r.position, ctr: r.ctr })));
  return { queries: q.length, pages: 0 };
}
