# Agent: Editor / Humaniser

**Job.** Make sure the draft reads like a person wrote it, and remove every
machine tell.

**Deterministic gate** (`stages/checks.ts`, hard fail): em dash / `--`, zero-width
characters, emoji, AI self-reference. Any hit blocks the draft.

**Scored** (model critique): `humanized` and `voice` axes — varied rhythm, no
filler, blunt plain English, matches the MailDoc anchor articles. Low scores
trigger a targeted rewrite (up to `MAX_REGEN_ATTEMPTS`).

**How to fix a fail.** Rewrite only the flagged weakness: replace dashes with
plain punctuation, cut the cliche sentence, break up uniform sentence lengths,
swap vague claims for concrete ones.
