import { useState } from 'preact/hooks';
import type { SpfChainNode } from '@maildoc/engines';
import { Explain } from './Explain';

/**
 * The SPF chain, as a receiver walks it.
 *
 * The lookup limit is the most common way SPF breaks, and a number on its own
 * does not tell anybody which include to remove. This shows where every lookup
 * is spent, with a running total, so the term that pushes a record over the
 * limit is visible rather than inferred.
 *
 * Records stay collapsed. A chain of seven includes is several hundred IP
 * addresses, and printing all of them buries the one thing worth seeing, which
 * is the shape of the chain.
 *
 * Everything rendered here is DNS content published by other people, so it all
 * goes through text nodes.
 */

/**
 * `UNRESOLVED` used to read "DNS did not answer", which blamed the customer
 * for our own failure. The names it appeared on answered instantly to dig and
 * to the same DoH endpoints we use; we had simply run out of budget mid-walk.
 * Saying whose problem it is, accurately, is the whole point of this product.
 */
const STATUS_LABEL: Record<string, string> = {
  OK: '',
  NO_RECORD: 'no SPF record here',
  MULTIPLE: 'more than one SPF record, a permanent error',
  VOID: 'does not exist',
  CIRCULAR: 'already visited in this chain',
  UNRESOLVED: 'we could not finish this lookup, not a fault in your record',
  TRUNCATED: 'we stopped walking here',
};

const STATUS_TONE: Record<string, string> = {
  OK: '',
  NO_RECORD: 'is-bad',
  MULTIPLE: 'is-bad',
  VOID: 'is-bad',
  CIRCULAR: 'is-bad',
  UNRESOLVED: 'is-warn',
  TRUNCATED: 'is-warn',
};

/** RFC 7208 section 4.6.4. */
const LOOKUP_LIMIT = 10;

interface Walked {
  /** Lookups spent by the time this node has been evaluated. */
  running: number;
  /** The first node that takes the count past the limit. */
  crosses: boolean;
}

/**
 * Depth first, the order a receiver evaluates in, carrying the running total.
 * A receiver stops at the eleventh lookup, so the node that takes the count
 * past ten is the one worth pointing at.
 */
export function walkChain(root: SpfChainNode): {
  entries: Map<SpfChainNode, Walked>;
  total: number;
} {
  const entries = new Map<SpfChainNode, Walked>();
  let running = 0;
  let crossed = false;

  const visit = (node: SpfChainNode): void => {
    const before = running;
    running += node.lookups;
    const crosses = !crossed && before <= LOOKUP_LIMIT && running > LOOKUP_LIMIT;
    if (crosses) crossed = true;

    entries.set(node, { running, crosses });
    for (const child of node.children) visit(child);
  };

  visit(root);
  return { entries, total: running };
}

export function SpfTree({
  chain,
  lookupCount,
  exact = true,
}: {
  chain: SpfChainNode;
  lookupCount: number;
  /** False when a branch went unwalked, so the count is a floor, not a total. */
  exact?: boolean;
}) {
  const { entries, total } = walkChain(chain);
  const over = lookupCount > LOOKUP_LIMIT;

  // An incomplete walk cannot claim the domain is inside the limit. It can
  // only claim it is at least this far along, so the chip says "at least" and
  // stays neutral rather than showing a green pass the evidence does not
  // support.
  const tone = over
    ? 'is-critical'
    : !exact
      ? 'is-attention'
      : lookupCount >= 9
        ? 'is-attention'
        : 'is-healthy';

  return (
    <section class="md-tree" aria-label="SPF chain">
      <div class="md-tree__head">
        <h3>
          The chain a receiver walks
          <Explain label="the SPF chain">
            A receiver evaluates your record by following it. Every <code>include</code>,{' '}
            <code>a</code>, <code>mx</code>, <code>ptr</code> and <code>exists</code> costs one DNS
            lookup, and the ones inside your includes count against the same budget. Past ten the
            receiver gives up and returns a permanent error, which fails SPF for every message from
            the domain.
          </Explain>
        </h3>
        <span class={`md-chip ${tone}`}>
          {exact ? '' : 'at least '}
          {lookupCount} of {LOOKUP_LIMIT} lookups
        </span>
      </div>

      <div class="md-tree__cols">
        <span>Open a row to see the record it publishes</span>
        <span>Cost</span>
        <span>Total</span>
      </div>

      <ol class="md-tree__list">
        <Node node={chain} entries={entries} depth={0} />
      </ol>

      {!exact && (
        <p class="md-tree__note">
          One or more branches could not be walked to the end, so this is the smallest the count can
          be, not the count. Nothing here says your record is wrong. Run the checkup again and it
          usually completes.
        </p>
      )}

      {exact && total !== lookupCount && (
        <p class="md-tree__note">
          The rows above add up to {total}. The count in the chip is {lookupCount}, which includes
          terms from a branch we could not finish walking.
        </p>
      )}
    </section>
  );
}

interface NodeProps {
  node: SpfChainNode;
  entries: Map<SpfChainNode, Walked>;
  depth: number;
}

function Node({ node, entries, depth }: NodeProps) {
  // The apex opens so the shape is visible. Everything below waits to be asked.
  const [open, setOpen] = useState(depth < 1);
  const walked = entries.get(node);
  const tone = STATUS_TONE[node.status] ?? '';
  const note = STATUS_LABEL[node.status] ?? '';
  const spent = node.lookups > 0;

  // Every node opens: its children if it has them, its record either way.
  const openable = node.children.length > 0 || node.record !== null;

  return (
    <li class="md-tree__item">
      <div class={`md-tree__row ${tone} ${walked?.crosses ? 'is-over' : ''}`}>
        {openable ? (
          <button
            type="button"
            class="md-tree__toggle"
            aria-expanded={open}
            onClick={() => setOpen(!open)}
          >
            <span aria-hidden="true">{open ? '−' : '+'}</span>
            <span class="md-visually-hidden">
              {open ? 'Hide' : 'Show'} what {node.domain} publishes
            </span>
          </button>
        ) : (
          <span class="md-tree__toggle is-leaf" aria-hidden="true" />
        )}

        <div class="md-tree__body">
          <div class="md-tree__name">
            <span class="md-mono">{node.domain}</span>
            {node.via !== 'root' && <span class="md-tree__via md-mono">{node.via}</span>}
            {note && <span class="md-tree__status">{note}</span>}
          </div>
        </div>

        {/* Blank rather than zero: a node that spends nothing has nothing to report. */}
        <span class="md-tree__own">{spent ? `+${node.lookups}` : ''}</span>
        <span class="md-tree__running">{spent ? (walked?.running ?? '') : ''}</span>
      </div>

      {walked?.crosses && (
        <p class="md-tree__limit">
          The eleventh lookup happens here. A receiver stops evaluating at this point and returns
          PermError, so nothing below this line is ever read.
        </p>
      )}

      {open && node.record && <pre class="md-tree__record md-mono">{node.record}</pre>}

      {/*
        Past a few levels the indent stops growing.

        Each nested list steps in by about 23px, which reads well for the four
        or five levels a real chain has and walks a twenty-hop one off the right
        edge of a phone. The rule that draws the nesting is the left border, and
        that keeps working at zero indent, so deep chains stay readable rather
        than becoming a horizontal scroll.
      */}
      {open && node.children.length > 0 && (
        <ol class={`md-tree__list ${depth >= 5 ? 'is-deep' : ''}`}>
          {node.children.map((child, index) => (
            <Node key={`${child.domain}-${index}`} node={child} entries={entries} depth={depth + 1} />
          ))}
        </ol>
      )}
    </li>
  );
}
