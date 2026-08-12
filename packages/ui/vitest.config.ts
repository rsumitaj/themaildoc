import { defineConfig, mergeConfig } from 'vitest/config';
import shared from '../../vitest.shared';

// No tests here yet; the config exists so running vitest inside this package
// never walks up to the root config and resolves globs from the wrong place.
export default mergeConfig(
  shared,
  defineConfig({ test: { name: 'ui', include: ['test/**/*.test.ts'], passWithNoTests: true } }),
);
