// @ts-check
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import preact from '@astrojs/preact';
import sitemap from '@astrojs/sitemap';
import { INDEXABLE_CHECK_SLUGS } from './src/data/indexable-checks.mjs';

const pkg = (name, entry = 'src/index.ts') =>
  fileURLToPath(new URL(`../../packages/${name}/${entry}`, import.meta.url));

/**
 * Resolve workspace packages to TypeScript source rather than their built
 * `dist/`.
 *
 * Without this, editing an engine while `astro dev` is running changes nothing
 * on screen — the site keeps serving the last build, and the mismatch shows up
 * as a wrong score rather than as an error. Vite compiles the source directly,
 * so dev and build always reflect what is actually in the repo.
 */
const workspaceAliases = {
  '@maildoc/shared': pkg('shared'),
  '@maildoc/catalog/scoring': pkg('catalog', 'src/scoring.ts'),
  '@maildoc/catalog/bloodwork': pkg('catalog', 'src/bloodwork.ts'),
  '@maildoc/catalog': pkg('catalog'),
  '@maildoc/report-parsers': pkg('report-parsers'),
  '@maildoc/resolver': pkg('resolver'),
  '@maildoc/engines/readiness': pkg('engines', 'src/readiness.ts'),
  '@maildoc/engines': pkg('engines'),
};

/**
 * `@maildoc/ui` has to match exactly, not as a prefix.
 *
 * Every other alias here is a prefix match, which is what you want when a
 * package has one entry point. This one also publishes `@maildoc/ui/*.css` and
 * `@maildoc/ui/EkgBackground.astro`, and a prefix rule rewrites those into
 * `…/src/index.ts/maildoc.css`, which is not a directory and fails the build.
 * Vite's array form takes a regex, so the bare specifier can be pinned on its
 * own while the subpaths keep resolving through the package's own exports.
 */
const aliasList = [
  ...Object.entries(workspaceAliases).map(([find, replacement]) => ({ find, replacement })),
  { find: /^@maildoc\/ui$/, replacement: pkg('ui') },
];

/**
 * Pages are prerendered by default and served as free Cloudflare Worker static
 * assets; only routes that opt out (`export const prerender = false`, i.e.
 * `/api/*`) consume Worker invocations. That is what keeps the clinic at $0.
 */
/**
 * Stamped once per build so every URL carries a real date rather than none.
 * A sitemap without lastmod gives a crawler nothing to prioritise on.
 */
const BUILD_TIME = new Date().toISOString();

/**
 * Make the homepage's sitemap entry byte-identical to its canonical.
 *
 * `Seo.astro` declares `https://themaildoc.co/`, because `new URL('/', site)`
 * keeps the slash and that is the form Google has indexed. The `sitemap`
 * package writes `https://themaildoc.co`, because it normalises an empty path
 * away, and `serialize` cannot prevent it: the URL arrives there already
 * correct and is stripped downstream on the way out.
 *
 * RFC 3986 section 6.2.3 makes those two the same URL and Google treats them as
 * one, so nothing is broken by it. But Search Console matches sitemap
 * membership as a string, and it reported "No referring sitemaps detected"
 * against the homepage while showing the same sitemap read successfully with
 * 107 URLs in it. Spending one line to stop the one page that matters most
 * looking undiscovered is worth it.
 */
function sitemapRootSlash() {
  return {
    name: 'maildoc:sitemap-root-slash',
    hooks: {
      'astro:build:done': async ({ dir, logger }) => {
        const file = new URL('sitemap-0.xml', dir);
        try {
          const xml = await readFile(file, 'utf8');
          const site = 'https://themaildoc.co';
          const fixed = xml.replace(`<loc>${site}</loc>`, `<loc>${site}/</loc>`);
          if (fixed !== xml) {
            await writeFile(file, fixed);
            logger.info('Root URL in sitemap-0.xml now matches the canonical.');
          }
        } catch {
          // No sitemap on this build is not a reason to fail one.
        }
      },
    },
  };
}

export default defineConfig({
  site: 'https://themaildoc.co',
  output: 'static',
  adapter: cloudflare({
    imageService: 'compile',
    platformProxy: { enabled: true },
    // Prerender in Node rather than workerd: the workerd prerenderer in
    // @astrojs/cloudflare 14.2.1 writes "[object Object]" into every static
    // page instead of its HTML. Verified by building a page with no layout,
    // no island and no imports — it came out broken too.
    prerenderEnvironment: 'node',
  }),
  integrations: [
    preact({ compat: false }),
    // Only real pages: API routes are not content, and a sitemap that lists a
    // 404 is worse than no sitemap.
    //
    // `lastmod` and `priority` are what a crawler uses to decide what to fetch
    // first on a site it has just discovered. Without them every one of the two
    // hundred URLs looks equally important, and the 166 generated condition
    // pages get crawled ahead of the twenty pages that are trying to rank.
    sitemap({
      // A sitemap is a list of pages you are asking to have indexed, so the
      // condition pages carrying `noindex` have no business in it. Listing
      // them would send a crawler two opposite instructions about the same URL.
      filter: (page) => {
        if (page.includes('/api/')) return false;
        const match = new URL(page).pathname.match(/^\/library\/checks\/(.+)$/);
        return match ? INDEXABLE_CHECK_SLUGS.has(match[1]) : true;
      },
      serialize(item) {
        const path = new URL(item.url).pathname;

        // Deepest first, so a more specific rule wins.
        const priority = path === '/'
          ? 1.0
          : path.startsWith('/library/checks/')
            ? 0.3
            : path.startsWith('/lab/') || path.startsWith('/health-library/')
              ? 0.8
              : path.startsWith('/glossary/')
                ? 0.6
                : ['/privacy', '/terms'].includes(path)
                  ? 0.2
                  : 0.7;

        return {
          ...item,
          lastmod: item.lastmod ?? BUILD_TIME,
          changefreq: path.startsWith('/library/checks/') ? 'yearly' : 'weekly',
          priority,
        };
      },
    }),
    sitemapRootSlash(),
  ],
  /**
   * No syntax highlighting in markdown.
   *
   * Shiki ships a `github-dark` theme by default and applies it as an inline
   * style on every `<pre>`, which put a black terminal block in the middle of a
   * clinical white article and beat the stylesheet trying to fix it. Nothing in
   * these articles is code: they are DNS records, which Shiki treats as
   * plaintext anyway. Turning it off lets records look the way records look
   * everywhere else on the site.
   */
  markdown: { syntaxHighlight: false },
  prefetch: { prefetchAll: true, defaultStrategy: 'hover' },
  // One canonical URL per page: /lab, not /lab/ reached through a 307.
  trailingSlash: 'never',
  build: { inlineStylesheets: 'auto', format: 'file' },
  devToolbar: { enabled: false },
  vite: {
    resolve: { alias: aliasList },
  },
});
