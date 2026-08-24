/**
 * Step 1 — topic selection.
 *
 * Candidates come from three grounded sources: your own GSC queries (real
 * demand you already rank low for = "striking distance"), fresh email-security
 * news (the weekly attack/CVE angle), and rising trends. Gemini scores each
 * against eight gates and proposes a concrete article. Only candidates that are
 * novel and clear MIN_TOPIC_SCORE survive. If none do, we return nothing and
 * the week stays quiet — by design.
 */
import type { Config } from '../config';
import type { Db } from '../lib/d1';
import { Gemini } from '../lib/gemini';
import { fetchNews } from '../lib/rss';
import { fetchRetry, slugify } from '../lib/util';

export interface Topic {
  kind: 'trendy' | 'news';
  title: string; keyword: string; angle: string; source: string; refUrl?: string;
  score: number; scores: Record<string, number>; reason: string; slug: string;
}

/** Existing live article slugs, so we never propose a duplicate. */
async function existingSlugs(cfg: Config): Promise<Set<string>> {
  try {
    const xml = await (await fetchRetry(`${cfg.siteUrl}/sitemap-0.xml`, {}, { tries: 2 })).text();
    const slugs = [...xml.matchAll(/\/health-library\/([a-z0-9-]+)</g)].map((m) => m[1]!);
    return new Set(slugs);
  } catch { return new Set(); }
}

const SCORING_RUBRIC = `Score each 0-100 and give an overall (weighted) score:
- onBrand: is it squarely about email authentication / deliverability / email security?
- freshness: tied to a recent attack, CVE, vendor rule change, or a rising query? evergreen-but-in-demand is mid.
- demand: real, ongoing search demand?
- rankable: is page one currently blog posts/guides (winnable by a newer site) rather than only big tool pages? high = winnable.
- novelty: NOT already covered by the existing slugs provided.
- linkFit: does it naturally link to MailDoc tools (/lab/*) or checks?
- businessValue: does it map to a real deliverability pain that leads toward "consult an expert"?
- grounding: can it be written accurately from RFCs + the source (enough verifiable facts)?`;

export async function selectTopics(
  db: Db, gemini: Gemini, cfg: Config,
  need: { trendy: number; news: number },
): Promise<{ selected: Topic[]; considered: number }> {
  const existing = await existingSlugs(cfg);
  const gsc = await db.topGscQueries(60);
  const news = (await fetchNews()).slice(0, 20);

  // Grounding payload for the model.
  const gscLines = gsc.map((r) => `query="${r.query}" impressions=${r.impressions} position=${Math.round(r.position)}`).join('\n');
  const newsLines = news.map((n, i) => `[N${i}] ${n.title} :: ${n.summary.slice(0, 180)} :: ${n.link}`).join('\n');
  const existingList = [...existing].slice(0, 200).join(', ');

  const prompt = `You are the topic strategist for MailDoc (themaildoc.co), a free email-authentication health checker whose blog ranks by being genuinely useful and RFC-accurate.

Propose blog article candidates from the signals below. Return JSON: an array of objects:
{ "kind": "trendy"|"news", "title": string (<=60 chars, plain, specific), "keyword": string (the one phrase to rank for), "angle": string (2-3 sentences on what the piece argues/teaches), "source": string, "refUrl": string|null, "scores": { "onBrand":n,"freshness":n,"demand":n,"rankable":n,"novelty":n,"linkFit":n,"businessValue":n,"grounding":n }, "score": n (0-100 overall), "reason": string }

Rules:
- "trendy" candidates should come from the GSC queries (winnable striking-distance) or evergreen high-demand gaps.
- "news" candidates must come from a news item and take the angle "how this attack/change works and how to stop it hitting your domain".
- Do NOT propose anything whose slug matches an existing article. Existing slugs: ${existingList || '(none provided)'}
- Prefer topics where page one is beatable by a newer site.
- Be honest in scores. If nothing is strong, it is fine to return few or none.

${SCORING_RUBRIC}

GSC QUERIES (your real demand):
${gscLines || '(no GSC data yet — rely on news + evergreen judgement)'}

EMAIL-SECURITY NEWS (this week):
${newsLines || '(no news fetched this run)'}

Return ONLY the JSON array, best first.`;

  let proposals: any[] = [];
  try {
    proposals = await gemini.json<any[]>(prompt, { temperature: 0.4, maxOutputTokens: 4096 });
  } catch { proposals = []; }
  if (!Array.isArray(proposals)) proposals = [];

  const selected: Topic[] = [];
  const takeByKind = { trendy: need.trendy, news: news.length ? need.news : 0 };

  for (const p of proposals) {
    const kind = p?.kind === 'news' ? 'news' : 'trendy';
    if (takeByKind[kind] <= 0) continue;
    const title = String(p?.title ?? '').trim();
    const keyword = String(p?.keyword ?? '').trim();
    if (title.length < 12 || keyword.length < 3) continue;
    const slug = slugify(title);
    if (existing.has(slug) || await db.hasSeen(`slug:${slug}`)) continue;
    const score = Number(p?.score) || 0;
    if (score < cfg.minTopicScore) continue;
    selected.push({
      kind, title, keyword, angle: String(p?.angle ?? ''), source: String(p?.source ?? kind),
      refUrl: p?.refUrl ?? undefined, score, scores: p?.scores ?? {}, reason: String(p?.reason ?? ''), slug,
    });
    takeByKind[kind]--;
    if (selected.length >= need.trendy + need.news) break;
  }
  return { selected, considered: proposals.length };
}
