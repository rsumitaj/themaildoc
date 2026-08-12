# Conventions

## Voice

One doctor speaks on every surface: cool, blunt, caring, never cute. Threaten
with **exposure, infection, emergency, untreated** — never with death. No
"dead", "fatal", "terminal", "flatlined" about a domain. No emoji anywhere in
production. Tests enforce both.

| Thing | Word we use |
|---|---|
| health check | Diagnosis / Checkup |
| score 0–100 | Vitals |
| severity | Triage (Critical · Urgent · Needs attention · Minor · Healthy) |
| a finding | Condition |
| the fix | Rx / Prescription |
| the report | Your chart |
| tools / one tool | The Lab / a Test |
| DMARC reports | Bloodwork |
| multi-domain | Ward rounds |
| blog | Health Library |
| team | The Practice |
| loading · empty · error | "Examining…" · "No symptoms to report yet." · "The checkup couldn't complete — let's try again." |

## Code

- TypeScript everywhere, `strict` + `noUncheckedIndexedAccess`. No `any` in
  engines or catalog.
- Engines emit **codes and vars**. If you are writing a sentence inside an
  engine, it belongs in the catalog instead.
- Every DNS-derived string is untrusted: escape at render, never `innerHTML`,
  never `eval`.
- Imports inside packages use explicit `.js` extensions so the emitted ESM is
  valid for Node and workerd alike.
- Prefer a named function to a clever one-liner. These files are read by people
  deciding whether to trust the numbers.

## Design

- Clinical white + ambulance red. Triage colour carries meaning only, and is
  always paired with an icon and a label (WCAG AA).
- Low radii, hairline rules, generous whitespace, a coloured left border to
  carry a card's triage level.
- Banned: Inter/Roboto as brand type, purple→blue gradients, glassmorphism,
  16px radius everywhere, fade-in-everything, the Red Cross emblem (it is
  legally protected).
- Motion is purposeful: scan reveal, score count-up, chip transitions. Nothing
  else moves. `prefers-reduced-motion` is honoured.

## Tests

Golden tests per catalog entry and engine, fed mock DoH JSON. Assert the exact
codes a receiver's behaviour justifies — and assert the codes that must *not*
appear. A false positive is worse than a miss: it costs the credibility of
every other finding on the page.

## Voice guardrails, enforced

`apps/web/test/voice.test.ts` runs on every page and every catalog entry:

- no em or en dashes, and no `--` standing in for one
- no emoji
- nothing death-morbid about a domain
- no "is not X, it is Y"
- no filler openers, no "game changer", "seamless" or "best in class"

A full stop is almost always the better break. Where a dash was doing real work,
a colon or a rewrite carries it.
