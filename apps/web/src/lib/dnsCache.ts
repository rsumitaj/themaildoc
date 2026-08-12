import type { DnsCache, DnsQueryResult } from '@maildoc/resolver';

/**
 * The Cloudflare Cache API as the clinic's DNS cache.
 *
 * This is what keeps us inside the free tier: popular domains get checked over
 * and over, and every cached answer is a subrequest we do not spend and an
 * upstream resolver we do not annoy. TTLs stay short because the whole point of
 * the product is telling people what their DNS says *now*.
 */

const NAMESPACE = 'https://dns-cache.themaildoc.co';

function cacheStorage(): Cache | null {
  const store = (globalThis as { caches?: { default?: Cache } }).caches;
  return store?.default ?? null;
}

export function createDnsCache(): DnsCache | undefined {
  const cache = cacheStorage();
  if (!cache) return undefined;

  return {
    async get(key: string): Promise<DnsQueryResult | undefined> {
      try {
        const hit = await cache.match(`${NAMESPACE}/${encodeURIComponent(key)}`);
        if (!hit) return undefined;
        return (await hit.json()) as DnsQueryResult;
      } catch {
        // A cache that misbehaves must never take the checkup down with it.
        return undefined;
      }
    },

    async set(key: string, value: DnsQueryResult, ttlSeconds: number): Promise<void> {
      try {
        await cache.put(
          `${NAMESPACE}/${encodeURIComponent(key)}`,
          new Response(JSON.stringify(value), {
            headers: {
              'content-type': 'application/json',
              'cache-control': `max-age=${Math.max(1, Math.floor(ttlSeconds))}`,
            },
          }),
        );
      } catch {
        /* caching is an optimisation, never a requirement */
      }
    },
  };
}

/** Cache an assembled result for a burst of visitors hitting the same domain. */
export async function cachedResponse(request: Request): Promise<Response | undefined> {
  const cache = cacheStorage();
  if (!cache || request.method !== 'GET') return undefined;
  try {
    return (await cache.match(request)) ?? undefined;
  } catch {
    return undefined;
  }
}

export async function storeResponse(request: Request, response: Response): Promise<void> {
  const cache = cacheStorage();
  if (!cache || request.method !== 'GET') return;
  try {
    await cache.put(request, response.clone());
  } catch {
    /* ignore */
  }
}
