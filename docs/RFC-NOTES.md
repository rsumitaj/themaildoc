# RFC notes

Every `rfc:` field in the catalog is checked before it ships. A wrong section
number, or a rule quoted from a spec that has been obsoleted, is worse than no
citation at all: the whole product rests on being right.

## Verifying a citation

1. Fetch the section: `https://www.rfc-editor.org/rfc/rfc<NNNN>.html#section-<X.Y>`
2. Confirm three things:
   - the RFC is **current**, not obsoleted (the header says so),
   - that section number really contains the rule,
   - the requirement level. MUST, SHOULD and MAY change the severity we assign.
3. Only then write `rfc: 'RFC NNNN §X.Y'`.

`packages/catalog/test/catalog.test.ts` asserts the format of every citation
and fails the build on any reference to an obsoleted DMARC RFC.

## Current specs

| Area | RFC | Sections we rely on |
|---|---|---|
| SPF | 7208 | §4 check_host() · §4.6.4 lookup and void limits · §5 mechanisms · §6 modifiers · §7 macros · §12 ABNF |
| DMARC | **9989** | obsoletes 7489 **and 9091**. §4.4 alignment · §4.7.x tags · §4.8 ABNF · §4.10 DNS tree walk |
| DMARC aggregate reports | **9990** | §3.1.1 report contents · §3.1.6 override reasons · §4 external destinations · §8.1 report content as an attack |
| DMARC failure reports | **9991** | §5 external destinations |
| DKIM | 6376 | §3.6.1 key record |
| DKIM crypto | 8301 | §3.1 rsa-sha1 MUST NOT · §3.2 RSA at least 1024 MUST, 2048 SHOULD |
| DKIM Ed25519 | 8463 | |
| MX and null MX | 5321 / 7505 | |
| DNSSEC | 4034 / 4035 | |
| MTA-STS | 8461 | §3.2 policy file · §3.3 no redirects, HTTPS only |
| TLS-RPT | 8460 | |
| CAA | 8659 | |
| Reverse DNS | 1912 §2.1 | |

**BIMI is not an RFC.** It is
`draft-brand-indicators-for-message-identification`. Citing an RFC number for
it, as several checkers do, is the kind of detail that decides whether the rest
of our citations are believed.

## Traps that have already cost us time

- **RFC 7489 and 9091 are obsolete.** Anything citing them is out of date.
  External destination verification is RFC 9990 §4 and RFC 9991 §5 now.
- **DMARC `p` is optional.** RFC 9989 §4.8: a syntactically valid record with no
  `p` tag is treated as `p=none`. The record is not discarded. Only a missing,
  misplaced or wrong-case `v=DMARC1` makes receivers ignore the whole thing.
- **`psd` takes `y`, `n` or `u`** (§4.7.6), default `u`. Rejecting `u` is a bug.
- **DMARCbis replaced the Public Suffix List** with the §4.10 tree walk. Do not
  add a PSL dependency to work out the organisational domain.
- **A DKIM key with an empty `p=` is revoked** (RFC 6376 §3.6.1), which is a
  deliberate signal, not a broken record. A wildcard under `_domainkey` answers
  for every selector, so identical answers at many selectors are one fact.
- **SPF is first match wins.** Order matters: a mechanism placed after `all`
  is never evaluated, and an include placed before a `-` term can mask it.
- **A void lookup is NXDOMAIN or NOERROR with no records** (RFC 7208 §4.6.4).
  A lookup that never completed is not void.

- **`include:` matches only on pass** (RFC 7208 §5.2). An include that returns
  fail is *not* a fail for the outer record; evaluation moves to the next term.
  Getting this backwards turns every domain with two vendors into a failure on
  its second one. `none` and `permerror` inside an include *are* a permerror
  outside it, which is the opposite direction and just as easy to get wrong.

- **The lookup limit is ten, and ten is allowed** (§4.6.4). The eleventh term is
  the error. Erroring at the tenth condemns records receivers evaluate happily.

- **The two permanent errors are not the same problem.** Over the lookup limit,
  or two records at one name, breaks the record for *every* sender including the
  domain's own servers. Exceeding the void-lookup limit usually breaks it for
  *one* sender: records built on `exists:` with macros perform a lookup per
  connecting address by design, and empty answers are the expected outcome for
  an address the domain never authorised. Reporting both as "your record cannot
  be evaluated" sends somebody to rewrite a working record.

- **A macro hides everything past it** (§7). `include:%{ir}.%{v}.%{d}.…` is a
  different name per sender, so a static read cannot follow it and the lookup
  count stops being a total. Report it as a floor. booking.com publishes exactly
  one macro include: read statically it costs one lookup, evaluated against a
  real address it costs three.

- **`redirect=` is ignored when the record has an `all` mechanism** (§6.1). A
  receiver reaches `all`, which always matches, so the redirect is unreachable
  and costs no lookup.

- **An IPv4-mapped IPv6 address is an IPv4 sender.** A dual-stack receiver
  reports `::ffff:203.0.113.9` for a client that connected over IPv4 and matches
  it against `ip4:` mechanisms.

## Adding a check

One catalog entry plus one detector. The detector emits a code and variables;
the catalog supplies the title, the reason, the prescription, the severity and
the citation. If you are writing a sentence inside an engine, it belongs in the
catalog instead.

Every new condition needs a golden test that asserts the codes a receiver's
behaviour justifies, and asserts the codes that must **not** appear. A false
positive costs the credibility of every other finding on the page.
