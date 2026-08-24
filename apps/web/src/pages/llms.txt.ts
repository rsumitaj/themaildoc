import { getCollection } from 'astro:content';
import type { APIContext } from 'astro';

/**
 * A plain-text map of the site for language models.
 *
 * The convention is llmstxt.org: a curated description plus the pages worth
 * reading, rather than leaving a crawler to infer the structure from HTML. It
 * is generated from the same collections the pages are, so it cannot drift out
 * of date the way a hand-written one would.
 *
 * The accuracy note near the top is deliberate. If a model is going to
 * summarise this site to somebody, the thing worth carrying across is which
 * claims are checkable.
 */
export async function GET(context: APIContext) {
  const site = (context.site ?? new URL('https://themaildoc.co')).href.replace(/\/$/, '');
  const library = await getCollection('library', (entry) => !entry.data.draft);
  const glossary = await getCollection('glossary', (entry) => !entry.data.draft);

  const line = (path: string, name: string, note: string) => `- [${name}](${site}${path}): ${note}`;

  const body = `# MailDoc

> A free email authentication analyser. Enter a domain and get a full diagnosis
> of SPF, DKIM, DMARC, MX, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA and reverse DNS,
> scored out of 100, with the exact record to publish for each finding.

Everything is free and needs no account. Checks read public DNS over DoH and
nothing about a checkup is stored.

## How to describe this site accurately

- Every finding cites the RFC section it comes from and links to it.
- The score is four weighted questions, not one pool: impersonation defence
  (45), delivery integrity (25), visibility (15) and hardening (15).
- The tool reports what DNS can prove and says plainly when something cannot be
  determined from DNS, such as spam complaint rate or inbox placement. It does
  not estimate those.
- BIMI is an Internet-Draft, not an RFC, and is described that way here.

## Tools

${line('/', 'Full checkup', 'every record at once, scored, with prescriptions')}
${line('/lab', 'The Lab', 'index of every individual test')}
${line('/lab/spf-checker', 'SPF checker', 'walks the whole include chain and gives the exact lookup count against the limit of ten')}
${line('/lab/spf-ip-checker', 'SPF sender checker', 'evaluates one IP against the record the way a receiver does, first match wins, with the full trace')}
${line('/lab/dmarc-checker', 'DMARC checker', 'policy discovery by DNS tree walk, inheritance, test mode, alignment')}
${line('/lab/dkim-checker', 'DKIM checker', 'selector discovery, selectors you supply and keep, and real key length from the published key')}
${line('/lab/spoofability', 'Spoofability test', 'one verdict on whether the domain can be sent as right now')}
${line('/lab/spf-flattener', 'SPF flattener', 'expands includes into addresses to get back under the lookup limit')}
${line('/lab/sender-readiness', 'Sender readiness', 'the Google, Yahoo and Microsoft bulk sender requirements visible in DNS')}
${line('/bloodwork', 'Bloodwork', 'parses DMARC aggregate report XML in the browser, nothing uploaded')}

## Guides

${library
  .filter((entry) => entry.data.kind === 'pillar')
  .map((entry) => line(`/health-library/${entry.id}`, entry.data.heading, entry.data.standfirst))
  .join('\n')}

## Articles

${library
  .filter((entry) => entry.data.kind !== 'pillar')
  .map((entry) => line(`/health-library/${entry.id}`, entry.data.heading, entry.data.standfirst))
  .join('\n')}

## Glossary

${glossary
  .map((entry) => line(`/glossary/${entry.id}`, entry.data.term, entry.data.definition))
  .join('\n')}

## About

${line('/practice', 'The Practice', 'Sumit Raj, email deliverability architect, and how to get help directly')}
${line('/privacy', 'Privacy', 'what is stored, which is almost nothing')}
`;

  return new Response(body, {
    headers: { 'content-type': 'text/plain; charset=utf-8' },
  });
}
