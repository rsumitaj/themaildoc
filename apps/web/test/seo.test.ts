import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The SEO guardrail, run against the built HTML rather than the source.
 *
 * Every rule here is one that fails silently: a page ships, looks fine, and
 * quietly cannot rank or renders a broken card. None of them are visible
 * without viewing source, so they need a test rather than a review.
 *
 * Skipped when `dist` is absent so `pnpm test` works before a build.
 */
const DIST = join(import.meta.dirname, '../dist/client');
const built = existsSync(DIST);

function pages(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) return pages(path);
    return path.endsWith('.html') ? [path] : [];
  });
}

const all = built ? pages(DIST) : [];
const read = (file: string) => readFileSync(file, 'utf8');
const name = (file: string) => file.replace(DIST, '') || '/';

describe.skipIf(!built)('every built page', () => {
  it('has pages to check at all', () => {
    expect(all.length).toBeGreaterThan(200);
  });

  it('has exactly one h1', () => {
    const offenders = all
      .map((file) => ({ file: name(file), count: (read(file).match(/<h1[\s>]/g) ?? []).length }))
      .filter((page) => page.count !== 1);
    expect(offenders.map((p) => `${p.file}: ${p.count}`).join('\n')).toBe('');
  });

  it('has a self-referencing canonical', () => {
    const offenders = all.filter((file) => !/rel="canonical"/.test(read(file))).map(name);
    expect(offenders.join('\n')).toBe('');
  });

  it('keeps every title inside what a search result shows', () => {
    const offenders = all
      .map((file) => ({ file: name(file), title: /<title>([^<]*)<\/title>/.exec(read(file))?.[1] ?? '' }))
      .filter((page) => page.title.length === 0 || page.title.length > 62);
    expect(offenders.map((p) => `${p.file}: ${p.title.length} chars`).join('\n')).toBe('');
  });

  it('keeps every meta description inside what a search result shows', () => {
    const offenders = all
      .map((file) => ({
        file: name(file),
        description:
          /<meta name="description" content="([^"]*)"/.exec(read(file))?.[1] ?? '',
      }))
      .filter((page) => page.description.length < 50 || page.description.length > 160);
    expect(offenders.map((p) => `${p.file}: ${p.description.length} chars`).join('\n')).toBe('');
  });

  it('gives every page a unique title', () => {
    const titles = new Map<string, string[]>();
    for (const file of all) {
      const title = /<title>([^<]*)<\/title>/.exec(read(file))?.[1] ?? '';
      titles.set(title, [...(titles.get(title) ?? []), name(file)]);
    }
    const duplicates = [...titles.entries()].filter(([, files]) => files.length > 1);
    expect(duplicates.map(([title, files]) => `${title}: ${files.join(', ')}`).join('\n')).toBe('');
  });

  it('carries an Organization block so the brand resolves as an entity', () => {
    const offenders = all.filter((file) => !/"@type":"Organization"/.test(read(file))).map(name);
    expect(offenders.join('\n')).toBe('');
  });

  it('ships a social card', () => {
    const offenders = all
      .filter((file) => !/property="og:image"/.test(read(file)))
      .map(name);
    expect(offenders.join('\n')).toBe('');
  });

  it('emits only valid JSON in every ld+json block', () => {
    const offenders: string[] = [];
    for (const file of all) {
      for (const match of read(file).matchAll(
        /<script type="application\/ld\+json">([\s\S]*?)<\/script>/g,
      )) {
        try {
          JSON.parse((match[1] ?? '').replace(/\\u003c/g, '<'));
        } catch {
          offenders.push(name(file));
        }
      }
    }
    expect(offenders.join('\n')).toBe('');
  });
});

describe.skipIf(!built)('long-form content', () => {
  const articles = all.filter(
    (file) => file.includes('/health-library/') || file.includes('/glossary/'),
  );

  it('finds the articles', () => {
    expect(articles.length).toBeGreaterThan(20);
  });

  it('styles the markdown body rather than shipping it bare', () => {
    // The body used to render with no styling at all: `.prose` set a max-width
    // and nothing else, so headings, code and lists came out as one block.
    const offenders = articles
      .filter((file) => /<h2|<p>/.test(read(file)))
      .filter((file) => !read(file).includes('class="md-prose'))
      .map(name);
    expect(offenders.join('\n')).toBe('');
  });

  it('does not let a highlighter theme paint a black block into a white page', () => {
    // Shiki applies `github-dark` as an inline style, which beat the
    // stylesheet and put a terminal block in the middle of a clinical article.
    const offenders = articles.filter((file) => /astro-code|github-dark/.test(read(file))).map(name);
    expect(offenders.join('\n')).toBe('');
  });

  it('never lists the same page twice in Read next', () => {
    const offenders: string[] = [];
    for (const file of articles) {
      const hrefs = [...read(file).matchAll(/href="(\/health-library\/[a-z0-9-]+)"/g)].map(
        (match) => match[1],
      );
      const counted = new Map<string, number>();
      for (const href of hrefs) counted.set(href, (counted.get(href) ?? 0) + 1);
      // One link in the body plus one card is fine; three is a duplicate card.
      for (const [href, count] of counted) {
        if (count > 2) offenders.push(`${name(file)} -> ${href} x${count}`);
      }
    }
    expect(offenders.join('\n')).toBe('');
  });
});

describe.skipIf(!built)('the crawler files', () => {
  it('publishes a sitemap, a feed and an llms.txt', () => {
    for (const file of ['sitemap-index.xml', 'rss.xml', 'llms.txt', 'robots.txt']) {
      expect(existsSync(join(DIST, file)), file).toBe(true);
    }
  });

  it('points robots.txt at the sitemap', () => {
    expect(read(join(DIST, 'robots.txt'))).toContain('sitemap-index.xml');
  });

  it('renders every social card the Seo component can ask for', () => {
    for (const kind of ['home', 'tool', 'article', 'term', 'page']) {
      expect(existsSync(join(DIST, 'og', `${kind}.png`)), kind).toBe(true);
    }
  });

  it('never lists a noindexed page in the sitemap', () => {
    // Asking a crawler to index a URL that then tells it not to is the one
    // combination guaranteed to waste crawl budget on a new domain.
    const sitemap = read(join(DIST, 'sitemap-0.xml'));
    const listed = new Set(
      [...sitemap.matchAll(/<loc>https:\/\/themaildoc\.co([^<]*)<\/loc>/g)].map(
        (match) => match[1] || '/',
      ),
    );
    const offenders = all
      .filter((file) => /name="robots" content="noindex/.test(read(file)))
      .map(name)
      .map((path) => path.replace(/\.html$/, '').replace(/\/index$/, '') || '/')
      .filter((path) => listed.has(path));
    expect(offenders.join('\n')).toBe('');
  });

  it('keeps the condition pages from being most of what is offered for indexing', () => {
    // 166 pages off one template, on a domain with no authority yet, is how a
    // site gets read as boilerplate. Only the conditions people search for by
    // name are submitted; the rest stay reachable and unindexed.
    const sitemap = read(join(DIST, 'sitemap-0.xml'));
    const total = (sitemap.match(/<loc>/g) ?? []).length;
    const checks = (sitemap.match(/<loc>https:\/\/themaildoc\.co\/library\/checks\//g) ?? []).length;
    expect(checks).toBeGreaterThan(0);
    expect(checks / total).toBeLessThan(0.6);
  });
});

describe.skipIf(!built)('the brand as an entity', () => {
  // Google returns results for a different site when the brand is searched,
  // because it has never seen the word. Three different spellings of it across
  // the structured data made three weak entities out of one.
  it('calls itself the same thing on every page', () => {
    const names = new Set<string>();
    const siteNames = new Set<string>();
    for (const file of all) {
      const html = read(file);
      for (const match of html.matchAll(/"@type":"Organization","@id":"[^"]*","name":"([^"]*)"/g)) {
        names.add(match[1] ?? '');
      }
      const og = /property="og:site_name" content="([^"]*)"/.exec(html)?.[1];
      if (og) siteNames.add(og);
    }
    expect([...names]).toEqual(['MailDoc']);
    expect([...siteNames]).toEqual(['MailDoc']);
  });

  it('declares the spellings people will type', () => {
    const home = read(join(DIST, 'index.html'));
    for (const alias of ['The MailDoc', 'themaildoc', 'themaildoc.co']) {
      expect(home, alias).toContain(alias);
    }
    expect(home).toMatch(/"alternateName":\[/);
  });

  it('claims no profile that does not exist', () => {
    // github.com/rsumitaj/themaildoc was declared as sameAs on all 221 pages
    // and has always 404ed. An entity claim pointing at nothing is worse than
    // no claim, so anything added here has to be checked first.
    const known = ['https://www.linkedin.com/in/sumit-raj-9918ba183/'];
    const claimed = new Set<string>();
    for (const file of all) {
      for (const match of read(file).matchAll(/"sameAs":\[([^\]]*)\]/g)) {
        for (const url of (match[1] ?? '').split(',')) claimed.add(url.replace(/"/g, ''));
      }
    }
    expect([...claimed].filter((url) => url && !known.includes(url))).toEqual([]);
  });
});

describe.skipIf(!built)('the sourced statistics on the home page', () => {
  const home = read(join(DIST, 'index.html'));

  it('shows several, not one', () => {
    expect((home.match(/class="pill"/g) ?? []).length).toBeGreaterThan(3);
  });

  it('links every claim to the document it came from', () => {
    // The figure that stood here originally was unsourced and wrong. Every
    // replacement was read out of the primary document, and the link is the
    // only thing that lets a reader check that.
    const stat = home.slice(home.indexOf('data-stat'), home.indexOf('</h1>'));
    const claims = (stat.match(/class="pill"/g) ?? []).length;
    const links = [...stat.matchAll(/href="(https:\/\/[^"]+)"/g)].map((match) => match[1]);
    expect(links.length).toBe(claims);
    expect(links.every((href) => href?.startsWith('https://'))).toBe(true);
  });

  it('leaves exactly one active before any script runs', () => {
    const stat = home.slice(home.indexOf('data-stat'), home.indexOf('</h1>'));
    const claims = (stat.match(/class="pill"/g) ?? []).length;
    const inactive = (stat.match(/class="pill" inert/g) ?? []).length;
    expect(inactive).toBe(claims - 1);
  });
});
