# Content Engine — agent skills

Six agent roles run the pipeline. Each is a focused prompt with only the context
it needs. The operative strings live in `../prompts.ts`; these docs are the
human-readable source of truth — edit here first, mirror into code.

| Agent | Runs in | Job |
|---|---|---|
| Topic Scout | `stages/select.ts` | Gather grounded candidates from GSC + news + trends |
| Topic Scorer | `stages/select.ts` | Score each candidate on the 8 gates, propose the article |
| Writer | `stages/write.ts` | Draft the article in MailDoc voice, to schema, with a diagram |
| Editor / Humaniser | `stages/checks.ts` + critique | Strip AI tells; enforce plain-English human voice |
| Fact-checker | critique in `write.ts` | Verify every claim + citation; flag the unsupported |
| SEO Editor | `stages/checks.ts` | Keyword placement, internal links, meta, structure |

Golden rule for every agent: **useful and accurate beats published.** If a piece
is not genuinely worth a reader's time, the correct output is to reject it.
