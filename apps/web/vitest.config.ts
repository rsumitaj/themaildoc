import { fileURLToPath } from 'node:url';
import { defineConfig, mergeConfig } from 'vitest/config';
import shared from '../../vitest.shared';

export default mergeConfig(
  shared,
  defineConfig({
    resolve: {
      alias: {
        // The runtime module only exists inside workerd. See the stub.
        'cloudflare:workers': fileURLToPath(
          new URL('./test/stubs/cloudflare-workers.ts', import.meta.url),
        ),
      },
    },
    test: { name: 'web', include: ['test/**/*.test.ts'], passWithNoTests: true },
  }),
);
