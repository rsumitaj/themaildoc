/**
 * Step 4 — publish (or discard) on your click.
 *
 * Verifies the signed token, checks the stored approval is unused and unexpired,
 * writes the finished markdown (draft:false) into CONTENT_DIR via the GitHub
 * API, and marks the draft published. Your normal build/deploy then ships it;
 * the provided GitHub Action also runs IndexNow. Idempotent: a second click on
 * an already-used link is refused, not double-published.
 */
import type { Config, Env } from '../config';
import type { Db } from '../lib/d1';
import { verifyToken, sha256hex } from '../lib/hmac';
import { commitFile } from '../lib/github';
import { toMarkdown, type LibraryFrontmatter } from '../lib/schema';

export interface ActionOutcome { ok: boolean; title: string; message: string; }

export async function handlePublish(env: Env, cfg: Config, db: Db, token: string): Promise<ActionOutcome> {
  const v = await verifyToken(token, env.APPROVAL_SIGNING_SECRET);
  if (!v.ok || !v.id) return fail(v.reason === 'expired' ? 'Link expired' : 'Invalid link', 'This approval link is not valid. Re-run the pipeline to get a fresh one.');
  const draft = await db.getDraft(v.id);
  if (!draft) return fail('Not found', 'That draft no longer exists.');
  if (draft.status === 'published') return ok('Already published', 'This article is already live. Nothing to do.');

  const appr = await db.findApproval(draft.id, 'publish', await sha256hex(token));
  if (!appr) return fail('Invalid link', 'This publish link was not recognised.');
  if (appr.used_at) return fail('Already used', 'This link was already used once.');
  if (new Date(appr.expires_at).getTime() < Date.now()) return fail('Link expired', 'Re-run the pipeline for a fresh link.');

  const fm = JSON.parse(draft.frontmatter_json) as LibraryFrontmatter;
  fm.draft = false;
  fm.updated = new Date().toISOString().slice(0, 10);
  const md = toMarkdown(fm, draft.body_md);
  const path = `${cfg.contentDir}/${draft.slug}.md`;

  try {
    const res = await commitFile({
      repo: cfg.githubRepo, path, branch: cfg.githubBranch, token: env.GITHUB_TOKEN,
      content: md, message: `content: publish "${draft.title}" via engine`,
    });
    await db.markApprovalUsed(appr.id);
    await db.setDraftStatus(draft.id, 'published', res.commitSha);
    await db.markSeen(`slug:${draft.slug}`, 'published');
    const liveUrl = `${cfg.siteUrl}/health-library/${draft.slug}`;
    return ok('Published', `Committed to ${path}. It goes live at ${liveUrl} once the site redeploys (usually a couple of minutes).`);
  } catch (err) {
    return fail('Publish failed', `Could not commit: ${(err as Error).message}. The draft is safe; try again.`);
  }
}

export async function handleDiscard(env: Env, cfg: Config, db: Db, token: string): Promise<ActionOutcome> {
  const v = await verifyToken(token, env.APPROVAL_SIGNING_SECRET + ':discard');
  if (!v.ok || !v.id) return fail('Invalid link', 'This link is not valid.');
  const draft = await db.getDraft(v.id);
  if (!draft) return fail('Not found', 'That draft no longer exists.');
  const appr = await db.findApproval(draft.id, 'discard', await sha256hex(token));
  if (appr && !appr.used_at) await db.markApprovalUsed(appr.id);
  await db.setDraftStatus(draft.id, 'discarded');
  return ok('Kept as draft', 'This draft will not be published. It stays available in the engine database.');
}

const ok = (title: string, message: string): ActionOutcome => ({ ok: true, title, message });
const fail = (title: string, message: string): ActionOutcome => ({ ok: false, title, message });
