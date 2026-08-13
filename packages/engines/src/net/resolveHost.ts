/**
 * The address lookup the fetch guard uses, built from the resolver we already
 * have rather than a second one.
 *
 * Every check in the product runs against a `DohResolver` with a subrequest
 * budget, so resolving the BIMI asset host costs from the same budget as
 * everything else and is visible in the same accounting. Two queries per host,
 * A and AAAA, and only when an asset is actually going to be fetched.
 */
import type { DohResolver } from '@maildoc/resolver';
import type { ResolveHost } from './safeFetch.js';

export function resolverAddressLookup(resolver: DohResolver): ResolveHost {
  return async (host: string): Promise<readonly string[]> => {
    const [v4, v6] = await Promise.all([
      resolver.query(host, 'A').catch(() => null),
      resolver.query(host, 'AAAA').catch(() => null),
    ]);

    // `records` rather than `answers`: the latter includes the CNAMEs walked on
    // the way, and a hostname is not an address to check ranges against.
    const addresses: string[] = [];
    for (const result of [v4, v6]) {
      for (const record of result?.records ?? []) {
        const data = String(record.data ?? '').trim();
        if (data !== '') addresses.push(data);
      }
    }
    return addresses;
  };
}
