import { describe, expect, it } from 'vitest';
import type { SpfChainNode } from '@maildoc/engines';
import { walkChain } from '../src/islands/SpfTree';

/**
 * The tree draws its own running total. If that arithmetic ever drifts from
 * the engine's `lookupCount`, the page shows two different answers to the same
 * question and neither is trustworthy.
 */

const node = (
  domain: string,
  lookups: number,
  children: SpfChainNode[] = [],
): SpfChainNode => ({
  domain,
  via: children.length > 0 || domain !== 'root.example' ? 'include' : 'root',
  depth: 0,
  record: `v=spf1 ip4:192.0.2.0/24 ~all`,
  lookups,
  status: 'OK',
  children,
});

describe('walkChain', () => {
  it('totals what a receiver would spend', () => {
    // The apex spends 3, one include spends 1, its child spends 1.
    const chain = node('root.example', 3, [
      node('a.example', 0),
      node('b.example', 1, [node('c.example', 1)]),
    ]);

    const { total, entries } = walkChain(chain);
    expect(total).toBe(5);
    expect(entries.get(chain)?.running).toBe(3);
  });

  it('carries the running total in evaluation order, depth first', () => {
    const deep = node('d.example', 1);
    const middle = node('b.example', 1, [deep]);
    const chain = node('root.example', 2, [node('a.example', 0), middle]);

    const { entries } = walkChain(chain);
    expect(entries.get(chain)?.running).toBe(2);
    expect(entries.get(middle)?.running).toBe(3);
    expect(entries.get(deep)?.running).toBe(4);
  });

  it('marks exactly one node as the point the limit is crossed', () => {
    const eleventh = node('over.example', 1);
    const chain = node('root.example', 10, [eleventh]);

    const { entries } = walkChain(chain);
    expect(entries.get(chain)?.crosses).toBe(false);
    expect(entries.get(eleventh)?.crosses).toBe(true);

    const crossings = [...entries.values()].filter((entry) => entry.crosses);
    expect(crossings).toHaveLength(1);
  });

  it('marks nothing when the chain stays inside the limit', () => {
    const chain = node('root.example', 7, [node('a.example', 3)]);
    const { entries, total } = walkChain(chain);

    expect(total).toBe(10);
    expect([...entries.values()].some((entry) => entry.crosses)).toBe(false);
  });

  it('handles a chain that spends nothing', () => {
    const chain = node('root.example', 0);
    expect(walkChain(chain).total).toBe(0);
  });
});
