/**
 * The library content shape, mirrored from apps/web/src/content/config.ts.
 *
 * We validate here BEFORE writing a file so a bad draft never reaches the repo,
 * and the Astro build's own Zod check becomes a second, independent gate rather
 * than the first line of defence.
 */
export interface FaqItem { q: string; a: string; }
export interface Step { name: string; text: string; }

export interface LibraryFrontmatter {
  title: string;        // 15..60
  description: string;  // 70..155
  keyword: string;      // >=3
  heading: string;      // >=10
  standfirst: string;   // 40..300
  kind: 'pillar' | 'cluster';
  pillar?: string;
  updated: string;      // YYYY-MM-DD
  published?: string;   // YYYY-MM-DD
  faq: FaqItem[];
  tools: string[];
  related: string[];
  steps: Step[];
  draft: boolean;
}

export function validateFrontmatter(fm: LibraryFrontmatter): { ok: boolean; errors: string[] } {
  const e: string[] = [];
  const len = (s: string) => (s ?? '').trim().length;
  if (len(fm.title) < 15 || len(fm.title) > 60) e.push(`title length ${len(fm.title)} (need 15-60)`);
  if (len(fm.description) < 70 || len(fm.description) > 155) e.push(`description length ${len(fm.description)} (need 70-155)`);
  if (len(fm.keyword) < 3) e.push('keyword too short');
  if (len(fm.heading) < 10) e.push('heading too short (need >=10)');
  if (len(fm.standfirst) < 40 || len(fm.standfirst) > 300) e.push(`standfirst length ${len(fm.standfirst)} (need 40-300)`);
  if (fm.kind !== 'pillar' && fm.kind !== 'cluster') e.push('kind must be pillar|cluster');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(fm.updated)) e.push('updated must be YYYY-MM-DD');
  for (const f of fm.faq ?? []) {
    if (len(f.q) < 10) e.push('faq question too short');
    if (len(f.a) < 40) e.push('faq answer too short');
  }
  return { ok: e.length === 0, errors: e };
}

const yamlStr = (s: string): string => JSON.stringify(s); // safe double-quoted scalar

function yamlList(items: string[]): string {
  if (!items || items.length === 0) return '[]';
  return `[${items.map(yamlStr).join(', ')}]`;
}

/** Serialise frontmatter + body into a complete Astro content .md file. */
export function toMarkdown(fm: LibraryFrontmatter, body: string): string {
  const lines: string[] = ['---'];
  lines.push(`title: ${yamlStr(fm.title)}`);
  lines.push(`description: ${yamlStr(fm.description)}`);
  lines.push(`keyword: ${yamlStr(fm.keyword)}`);
  lines.push(`heading: ${yamlStr(fm.heading)}`);
  lines.push(`standfirst: ${yamlStr(fm.standfirst)}`);
  lines.push(`kind: ${fm.kind}`);
  if (fm.pillar) lines.push(`pillar: ${yamlStr(fm.pillar)}`);
  lines.push(`updated: ${fm.updated}`);
  if (fm.published) lines.push(`published: ${fm.published}`);
  lines.push(`tools: ${yamlList(fm.tools)}`);
  lines.push(`related: ${yamlList(fm.related)}`);
  if (fm.steps?.length) {
    lines.push('steps:');
    for (const s of fm.steps) {
      lines.push(`  - name: ${yamlStr(s.name)}`);
      lines.push(`    text: ${yamlStr(s.text)}`);
    }
  }
  if (fm.faq?.length) {
    lines.push('faq:');
    for (const f of fm.faq) {
      lines.push(`  - q: ${yamlStr(f.q)}`);
      lines.push(`    a: ${yamlStr(f.a)}`);
    }
  }
  lines.push(`draft: ${fm.draft ? 'true' : 'false'}`);
  lines.push('---', '', body.trim(), '');
  return lines.join('\n');
}
