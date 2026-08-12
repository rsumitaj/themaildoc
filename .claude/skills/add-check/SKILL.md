---
name: add-check
description: Add a new diagnosable condition to MailDoc — one catalog entry, one detector, one golden test, verified against the RFC. Use whenever a new check, issue code or finding is being added to any record engine (SPF, DMARC, DKIM, MX, A, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA).
---

# Add a check

A check is never "some strings inside an engine". It is exactly three things, added
together, or it does not ship.

## 1. Catalog entry — `packages/catalog/src/records/<record>.ts`

```ts
{
  code: 'SPF_LOOKUP_LIMIT_EXCEEDED',   // stable, SCREAMING_SNAKE, record-prefixed
  record: 'SPF',
  severity: 'CRITICAL',                // CRITICAL 40 · HIGH 25 · MEDIUM 15 · LOW 8 · INFO 2
  category: 'lookup',
  title: '…',                          // short condition name, no placeholder-only titles
  why: '…',                            // plain English, ends in a full stop, names the consequence
  fix: '…',                            // copy-paste oriented; a record the patient can paste
  rfc: 'RFC 7208 §4.6.4',              // VERIFIED, never guessed — see /verify-rfc
  vars: ['count'],                     // every {placeholder} used, and no unused ones
}
```

Rules the tests already enforce: unique code, declared vars match used placeholders
exactly, RFC citation present and well-formed, no emoji, no death metaphors
(threaten with exposure/infection/emergency — never "dead", "fatal", "terminal").

## 2. Detector — `packages/engines/src/<record>/analyze.ts`

Emit the code with its vars. Detectors detect; they never carry patient-facing
copy:

```ts
emit(context, 'SPF_LOOKUP_LIMIT_EXCEEDED', { count: context.lookups });
```

If the finding has raw DNS evidence (the offending record, a chain path), pass it
as `evidence` — and remember it is untrusted and must be escaped at render.

## 3. Golden test — `packages/engines/test/<record>-engine.test.ts`

A zone a real domain could have, and the exact codes a receiver's behaviour
justifies:

```ts
it('reports X when Y', async () => {
  const { codes } = await run({ 'example.com': { TXT: ['v=spf1 …'] } });
  expect(codes).toContain('…');
});
```

Assert the *absence* of codes too — a false positive is worse than a miss,
because it destroys trust in every other finding on the page.

## Then

`pnpm test` from the repo root. If the check needs a new DNS query, confirm it
fits the engine's subrequest budget (`DEFAULT_DNS_QUERY_BUDGET`) — Cloudflare
allows 50 per request and the orchestrator shares that across every engine.
