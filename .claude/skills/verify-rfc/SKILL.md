---
name: verify-rfc
description: Verify an RFC citation (number, section, and the actual requirement) before it goes into the catalog or a fix. Use whenever writing or reviewing an `rfc:` field, quoting a spec requirement, or deciding a severity that depends on what the RFC actually mandates.
---

# Verify an RFC citation

MailDoc's whole claim is that it is right. A wrong section number, or a rule
quoted from an obsoleted spec, is worse than no citation at all.

## Do this

1. Fetch the section itself: `https://www.rfc-editor.org/rfc/rfc<NNNN>.html#section-<X.Y>`
2. Confirm three things:
   - the RFC is **current**, not obsoleted (the header says so),
   - the section number really contains the rule,
   - the requirement level — MUST / SHOULD / MAY changes the severity we assign.
3. Only then write `rfc: 'RFC NNNN §X.Y'`.

## Current specs for this product

| Area | RFC | Notes |
|---|---|---|
| SPF | 7208 | §4.6.4 lookup + void limits · §5 mechanisms · §6 modifiers · §7 macros |
| DMARC | **9989** | obsoletes 7489 **and 9091**. §4.7.x tags · §4.8 ABNF · §4.10 DNS tree walk |
| DMARC aggregate reports | **9990** | §4 verifying external destinations |
| DMARC failure reports | **9991** | §5 verifying external destinations |
| DKIM | 6376 | §3.6.1 key record |
| DKIM crypto | 8301 | §3.1 rsa-sha1 MUST NOT · §3.2 RSA ≥1024 MUST, ≥2048 SHOULD |
| DKIM Ed25519 | 8463 | |
| MX / null MX | 5321 / 7505 | |
| DNSSEC | 4034 / 4035 | |
| MTA-STS | 8461 | §3.2 policy file · §3.3 no redirects, HTTPS only |
| TLS-RPT | 8460 | |
| CAA | 8659 | |

## Traps that have already bitten us

- **RFC 7489 and 9091 are obsolete.** Anything citing them (including kdmarc) is
  out of date. External destination verification is 9990 §4 / 9991 §5 now.
- **DMARC `p` is optional.** §4.8: a syntactically valid record without `p` is
  treated as `p=none` — the record is *not* discarded. Only a missing/misplaced/
  wrong-case `v=DMARC1` makes receivers ignore the whole record.
- **`psd` takes `y`, `n` or `u`** (§4.7.6), default `u`. Rejecting `u` is a bug.
- **DMARCbis replaced the Public Suffix List** with the §4.10 tree walk. Do not
  add a PSL dependency to determine the organizational domain.
