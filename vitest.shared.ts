import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const pkg = (name: string, entry = 'src/index.ts') =>
  fileURLToPath(new URL(`./packages/${name}/${entry}`, import.meta.url));

/**
 * Shared Vitest config for every package.
 *
 * Workspace imports are aliased straight at TypeScript source so unit tests run
 * without a build step — the published `exports` still point at `dist/`.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@maildoc/shared': pkg('shared'),
      '@maildoc/catalog/scoring': pkg('catalog', 'src/scoring.ts'),
      '@maildoc/catalog/bloodwork': pkg('catalog', 'src/bloodwork.ts'),
      '@maildoc/catalog': pkg('catalog'),
      '@maildoc/resolver/testing': pkg('resolver', 'src/testing/index.ts'),
      '@maildoc/resolver': pkg('resolver'),
      '@maildoc/engines/readiness': pkg('engines', 'src/readiness.ts'),
      '@maildoc/engines': pkg('engines'),
      '@maildoc/report-parsers': pkg('report-parsers'),
      '@maildoc/geo': pkg('geo'),
    },
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    clearMocks: true,
  },
});
