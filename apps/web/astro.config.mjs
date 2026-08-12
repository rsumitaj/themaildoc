// @ts-check
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import preact from '@astrojs/preact';
import sitemap from '@astrojs/sitemap';

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
 * Pages are prerendered by default and served as free Cloudflare Worker static
 * assets; only routes that opt out (`export const prerender = false`, i.e.
 * `/api/*`) consume Worker invocations. That is what keeps the clinic at $0.
 */
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
    sitemap({ filter: (page) => !page.includes('/api/') }),
  ],
  prefetch: { prefetchAll: true, defaultStrategy: 'hover' },
  // One canonical URL per page: /lab, not /lab/ reached through a 307.
  trailingSlash: 'never',
  build: { inlineStylesheets: 'auto', format: 'file' },
  devToolbar: { enabled: false },
  vite: {
    resolve: { alias: workspaceAliases },
  },
});
