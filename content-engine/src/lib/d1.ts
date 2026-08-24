/** Typed D1 helpers. All writes use bound parameters. */
import { nowIso, uid } from './util';

export interface DraftRecord {
  id: string; candidate_id: string | null; kind: string; slug: string; title: string;
  keyword: string; frontmatter_json: string; body_md: string; word_count: number;
  content_score: number | null; checks_json: string | null; status: string;
  preview_secret: string; commit_sha: string | null; created_at: string; updated_at: string;
}

export class Db {
  constructor(private db: D1Database) {}

  async startRun(trigger: string, isoWeek: string): Promise<string> {
    const id = uid('run_');
    await this.db.prepare(
      'INSERT INTO ce_run (id, started_at, trigger, status, iso_week) VALUES (?,?,?,?,?)',
    ).bind(id, nowIso(), trigger, 'running', isoWeek).run();
    return id;
  }

  async finishRun(id: string, status: string, note: string, stats: unknown): Promise<void> {
    await this.db.prepare(
      'UPDATE ce_run SET finished_at=?, status=?, note=?, stats_json=? WHERE id=?',
    ).bind(nowIso(), status, note.slice(0, 500), JSON.stringify(stats), id).run();
  }

  /** Posts already published OR awaiting your approval this ISO week, by kind. */
  async weeklyCount(isoWeek: string, kind: string): Promise<number> {
    const row = await this.db.prepare(
      `SELECT COUNT(*) AS n FROM ce_draft d
       WHERE d.kind=? AND d.status IN ('emailed','published')
       AND EXISTS (SELECT 1 FROM ce_run r WHERE r.iso_week=? AND r.started_at <= d.created_at)`,
    ).bind(kind, isoWeek).first<{ n: number }>();
    // Simpler + robust fallback: count drafts created since the week's Monday.
    return row?.n ?? 0;
  }

  async weeklyCountSince(mondayIso: string, kind: string): Promise<number> {
    const row = await this.db.prepare(
      `SELECT COUNT(*) AS n FROM ce_draft WHERE kind=? AND status IN ('emailed','published') AND created_at >= ?`,
    ).bind(kind, mondayIso).first<{ n: number }>();
    return row?.n ?? 0;
  }

  async insertCandidate(c: {
    runId: string; kind: string; source: string; title: string; keyword?: string;
    refUrl?: string; score?: number; scores?: unknown; verdict: string; reason?: string;
  }): Promise<string> {
    const id = uid('cand_');
    await this.db.prepare(
      `INSERT INTO ce_candidate (id, run_id, kind, source, title, keyword, ref_url, score, scores_json, verdict, reason, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).bind(id, c.runId, c.kind, c.source, c.title, c.keyword ?? null, c.refUrl ?? null,
      c.score ?? null, c.scores ? JSON.stringify(c.scores) : null, c.verdict, c.reason ?? null, nowIso()).run();
    return id;
  }

  async insertDraft(d: {
    candidateId: string | null; kind: string; slug: string; title: string; keyword: string;
    frontmatter: unknown; body: string; wordCount: number; contentScore: number;
    checks: unknown; previewSecret: string; status: string;
  }): Promise<string> {
    const id = uid('draft_');
    const now = nowIso();
    await this.db.prepare(
      `INSERT INTO ce_draft (id, candidate_id, kind, slug, title, keyword, frontmatter_json, body_md, word_count, content_score, checks_json, status, preview_secret, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).bind(id, d.candidateId, d.kind, d.slug, d.title, d.keyword, JSON.stringify(d.frontmatter),
      d.body, d.wordCount, d.contentScore, JSON.stringify(d.checks), d.status, d.previewSecret, now, now).run();
    return id;
  }

  async getDraft(id: string): Promise<DraftRecord | null> {
    return this.db.prepare('SELECT * FROM ce_draft WHERE id=?').bind(id).first<DraftRecord>();
  }

  async getDraftByPreview(secret: string): Promise<DraftRecord | null> {
    return this.db.prepare('SELECT * FROM ce_draft WHERE preview_secret=?').bind(secret).first<DraftRecord>();
  }

  async setDraftStatus(id: string, status: string, commitSha?: string): Promise<void> {
    await this.db.prepare('UPDATE ce_draft SET status=?, commit_sha=COALESCE(?, commit_sha), updated_at=? WHERE id=?')
      .bind(status, commitSha ?? null, nowIso(), id).run();
  }

  async insertApproval(a: { draftId: string; action: string; tokenHash: string; expiresAt: string }): Promise<void> {
    await this.db.prepare(
      'INSERT INTO ce_approval (id, draft_id, action, token_hash, expires_at, created_at) VALUES (?,?,?,?,?,?)',
    ).bind(uid('appr_'), a.draftId, a.action, a.tokenHash, a.expiresAt, nowIso()).run();
  }

  async findApproval(draftId: string, action: string, tokenHash: string): Promise<{ id: string; used_at: string | null; expires_at: string } | null> {
    return this.db.prepare('SELECT id, used_at, expires_at FROM ce_approval WHERE draft_id=? AND action=? AND token_hash=?')
      .bind(draftId, action, tokenHash).first();
  }

  async markApprovalUsed(id: string): Promise<void> {
    await this.db.prepare('UPDATE ce_approval SET used_at=? WHERE id=?').bind(nowIso(), id).run();
  }

  async hasSeen(key: string): Promise<boolean> {
    const r = await this.db.prepare('SELECT 1 AS x FROM ce_seen WHERE key=?').bind(key).first();
    return !!r;
  }

  async markSeen(key: string, kind: string): Promise<void> {
    await this.db.prepare('INSERT OR IGNORE INTO ce_seen (key, kind, first_seen) VALUES (?,?,?)')
      .bind(key, kind, nowIso()).run();
  }

  async topGscQueries(limit = 60): Promise<{ query: string; impressions: number; position: number }[]> {
    const res = await this.db.prepare(
      `SELECT query, impressions, position FROM ce_gsc_query
       WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM ce_gsc_query)
       ORDER BY impressions DESC LIMIT ?`,
    ).bind(limit).all<{ query: string; impressions: number; position: number }>();
    return res.results ?? [];
  }

  async upsertGscQuery(date: string, rows: { query: string; clicks: number; impressions: number; position: number; ctr: number }[]): Promise<void> {
    const stmt = this.db.prepare(
      `INSERT INTO ce_gsc_query (snapshot_date, query, clicks, impressions, position, ctr) VALUES (?,?,?,?,?,?)
       ON CONFLICT(snapshot_date, query) DO UPDATE SET clicks=excluded.clicks, impressions=excluded.impressions, position=excluded.position, ctr=excluded.ctr`,
    );
    const batch = rows.map((r) => stmt.bind(date, r.query, r.clicks, r.impressions, r.position, r.ctr));
    if (batch.length) await this.db.batch(batch);
  }
}
