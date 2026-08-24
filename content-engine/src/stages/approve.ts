/**
 * Step 3 — send the approval email.
 *
 * Builds single-use, expiring publish/discard links (HMAC-signed), stores their
 * hashes, and emails you the draft with a private preview link. Sets the draft
 * to 'emailed'. Nothing is public yet.
 */
import type { Config, Env } from '../config';
import type { Db, DraftRecord } from '../lib/d1';
import { sendEmail } from '../lib/email';
import { approvalEmail } from '../lib/html';
import { signToken, sha256hex } from '../lib/hmac';

export async function emailForApproval(env: Env, cfg: Config, db: Db, draft: DraftRecord): Promise<{ ok: boolean; error?: string }> {
  const exp = Math.floor(Date.now() / 1000) + cfg.approvalTtlHours * 3600;
  const expiresIso = new Date(exp * 1000).toISOString();

  const pubToken = await signToken(draft.id, exp, env.APPROVAL_SIGNING_SECRET);
  const disToken = await signToken(draft.id, exp, env.APPROVAL_SIGNING_SECRET + ':discard');
  await db.insertApproval({ draftId: draft.id, action: 'publish', tokenHash: await sha256hex(pubToken), expiresAt: expiresIso });
  await db.insertApproval({ draftId: draft.id, action: 'discard', tokenHash: await sha256hex(disToken), expiresAt: expiresIso });

  const base = cfg.engineUrl || '';
  const previewUrl = `${base}/preview/${draft.preview_secret}`;
  const publishUrl = `${base}/publish?t=${encodeURIComponent(pubToken)}`;
  const discardUrl = `${base}/discard?t=${encodeURIComponent(disToken)}`;

  const checks = draft.checks_json ? JSON.parse(draft.checks_json) as { pass: boolean }[] : [];
  const passed = checks.filter((c) => c.pass).length;
  const scores = summariseScores(draft);

  const html = approvalEmail({
    draft, scores, checksPassed: passed, checksTotal: checks.length || 1,
    previewUrl, publishUrl, discardUrl, estRank: estimateRank(scores),
  });

  if (cfg.dryRun) return { ok: true };
  const sent = await sendEmail({
    apiKey: env.RESEND_API_KEY,
    from: `MailDoc Engine <engine@${new URL(cfg.siteUrl).hostname}>`,
    to: env.APPROVAL_EMAIL,
    subject: `Ready to publish: ${draft.title}`,
    html,
  });
  if (sent.ok) await db.setDraftStatus(draft.id, 'emailed');
  return sent;
}

function summariseScores(draft: DraftRecord): Record<string, number> {
  return { content: draft.content_score ?? 0 };
}
function estimateRank(scores: Record<string, number>): string {
  const s = scores.content ?? 0;
  return s >= 90 ? 'page 1-2' : s >= 82 ? 'page 2-4' : 'page 4+';
}
