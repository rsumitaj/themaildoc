import { defineConfig, mergeConfig } from 'vitest/config';
import shared from './vitest.shared';

/**
 * Root config: `vitest` from the repo root runs every package's tests with the
 * workspace aliases applied.
 *
 * Without it, a bare `vitest` here has no aliases and resolves `@maildoc/*`
 * through node_modules to each package's built `dist/` — stale the moment you
 * edit a source file, and it fails as "unknown issue code" rather than as a
 * misconfigured test run.
 *
 * Every package carries its own config too, so running tests from inside a
 * package never walks up to this file and resolves globs from the wrong
 * directory.
 */
export default mergeConfig(
  shared,
  defineConfig({
    test: {
      name: 'maildoc',
      include: ['packages/*/test/**/*.test.ts'],
    },
  }),
);
