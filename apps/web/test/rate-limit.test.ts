import { beforeEach, describe, expect, it, vi } from 'vitest';
import { rateLimit } from '../src/lib/api';

/**
 * The throttle, and specifically the thing it got wrong.
 *
 * It used to keep one counter for the whole API. Running checkups — the exact
 * behaviour of someone taking this seriously — spent the allowance that the
 * consultation form then needed, so the most engaged visitor on the site was
 * the one whose request to hire us came back 429. That is the single most
 * expensive failure this codebase can have, and nothing was watching for it.
 */

function from(ip: string): Request {
  return new Request('https://themaildoc.co/api/check', { headers: { 'cf-connecting-ip': ip } });
}

/** Isolate resets are not enough — the counter is module state. */
beforeEach(() => {
  vi.resetModules();
});

describe('rateLimit', () => {
  it('lets a normal burst of checkups through', () => {
    const request = from('198.51.100.1');
    for (let i = 0; i < 30; i += 1) {
      expect(rateLimit(request, 'check').allowed).toBe(true);
    }
  });

  it('stops a client that keeps going', () => {
    const request = from('198.51.100.2');
    for (let i = 0; i < 30; i += 1) rateLimit(request, 'check');

    const blocked = rateLimit(request, 'check');
    expect(blocked.allowed).toBe(false);
    // A `retry-after: 0` tells a client to come straight back, which is not
    // what we mean and not what the header is for.
    expect(blocked.retryAfter).toBeGreaterThan(0);
  });

  it('does not let checkups spend the consultation allowance', () => {
    const request = from('198.51.100.3');

    // Well past the checkup limit, from one address.
    for (let i = 0; i < 60; i += 1) rateLimit(request, 'check');
    expect(rateLimit(request, 'check').allowed).toBe(false);

    // The person then asks to be contacted. This must go through.
    expect(rateLimit(request, 'lead').allowed).toBe(true);
  });

  it('counts each address separately', () => {
    const mine = from('198.51.100.4');
    for (let i = 0; i < 30; i += 1) rateLimit(mine, 'check');
    expect(rateLimit(mine, 'check').allowed).toBe(false);

    expect(rateLimit(from('198.51.100.5'), 'check').allowed).toBe(true);
  });
});
