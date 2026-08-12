import { defineConfig, mergeConfig } from 'vitest/config';
import shared from '../../vitest.shared';

// Its own config so running vitest inside this package never walks up to the
// root config and resolves globs from the wrong place.
export default mergeConfig(
  shared,
  defineConfig({ test: { name: 'report-parsers', include: ['test/**/*.test.ts'] } }),
);
