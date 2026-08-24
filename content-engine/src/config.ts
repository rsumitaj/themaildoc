/**
 * All configuration in one typed place.
 *
 * Non-secret knobs come from wrangler `vars` (edit wrangler.jsonc, or override
 * per-environment) and secrets come from `wrangler secret put`. Everything is
 * read through here so the rest of the code never touches `env` directly and
 * volume/threshold changes never require a code edit.
 */

export interface Env {
  DB: D1Database;

  // vars
  PUBLIC_BASE_URL: string;
  GITHUB_REPO: string;
  GITHUB_BRANCH: string;
  CONTENT_DIR: string;
  AUTHOR_NAME: string;
  GEMINI_MODEL: string;
  GSC_SITE_URL: string;
  WEEKLY_TRENDY_POSTS: string;
  WEEKLY_NEWS_POSTS: string;
  MIN_TOPIC_SCORE: string;
  MIN_CONTENT_SCORE: string;
  MAX_REGEN_ATTEMPTS: string;
  TARGET_WORDS_MIN: string;
  TARGET_WORDS_MAX: string;
  APPROVAL_TTL_HOURS: string;
  DRY_RUN: string;

  // secrets
  GEMINI_API_KEY: string;
  GITHUB_TOKEN: string;
  GSC_SA_EMAIL: string;
  GSC_SA_PRIVATE_KEY: string;
  RESEND_API_KEY: string;
  APPROVAL_EMAIL: string;
  APPROVAL_SIGNING_SECRET: string;
  RUN_TOKEN?: string;
  DEVTO_API_KEY?: string;

  // where the engine is reachable (set after first deploy; used in email links)
  ENGINE_PUBLIC_URL?: string;
}

export interface Config {
  siteUrl: string;
  engineUrl: string;
  githubRepo: string;
  githubBranch: string;
  contentDir: string;
  authorName: string;
  geminiModel: string;
  gscSiteUrl: string;
  weekly: { trendy: number; news: number; total: number };
  minTopicScore: number;
  minContentScore: number;
  maxRegen: number;
  words: { min: number; max: number };
  approvalTtlHours: number;
  dryRun: boolean;
}

const num = (v: string | undefined, fallback: number): number => {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) ? n : fallback;
};

export function loadConfig(env: Env): Config {
  const trendy = num(env.WEEKLY_TRENDY_POSTS, 2);
  const news = num(env.WEEKLY_NEWS_POSTS, 1);
  return {
    siteUrl: env.PUBLIC_BASE_URL ?? 'https://themaildoc.co',
    engineUrl: env.ENGINE_PUBLIC_URL ?? '',
    githubRepo: env.GITHUB_REPO,
    githubBranch: env.GITHUB_BRANCH ?? 'main',
    contentDir: env.CONTENT_DIR ?? 'apps/web/src/content/library',
    authorName: env.AUTHOR_NAME ?? 'Sumit Raj',
    geminiModel: env.GEMINI_MODEL ?? 'gemini-2.5-flash',
    gscSiteUrl: env.GSC_SITE_URL ?? 'sc-domain:themaildoc.co',
    weekly: { trendy, news, total: trendy + news },
    minTopicScore: num(env.MIN_TOPIC_SCORE, 68),
    minContentScore: num(env.MIN_CONTENT_SCORE, 80),
    maxRegen: num(env.MAX_REGEN_ATTEMPTS, 3),
    words: { min: num(env.TARGET_WORDS_MIN, 850), max: num(env.TARGET_WORDS_MAX, 1600) },
    approvalTtlHours: num(env.APPROVAL_TTL_HOURS, 120),
    dryRun: (env.DRY_RUN ?? 'false') === 'true',
  };
}

/** Fail fast, with a clear message, if a required secret is missing. */
export function assertSecrets(env: Env): string[] {
  const required: (keyof Env)[] = [
    'GEMINI_API_KEY', 'GITHUB_TOKEN', 'GSC_SA_EMAIL', 'GSC_SA_PRIVATE_KEY',
    'RESEND_API_KEY', 'APPROVAL_EMAIL', 'APPROVAL_SIGNING_SECRET',
  ];
  return required.filter((k) => !env[k]).map(String);
}

/** ISO week key like 2026-W35, used to cap posts per calendar week. */
export function isoWeek(d: Date): string {
  const date = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = date.getUTCDay() || 7;
  date.setUTCDate(date.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(date.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((date.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  return `${date.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
}
