import { defineConfig, mergeConfig } from 'vitest/config';
import shared from '../../vitest.shared';

// The site has no unit tests of its own — it is verified by building it and
// driving the real Worker. This config keeps `vitest` here self-contained.
export default mergeConfig(
  shared,
  defineConfig({ test: { name: 'web', include: ['test/**/*.test.ts'], passWithNoTests: true } }),
);
