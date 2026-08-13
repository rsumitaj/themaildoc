# Launching, indexing and getting found

Everything below is a step somebody has to take by hand. The site's own SEO is
in the code; this is what happens after a deploy.

## The one thing that actually blocks you

A new domain is not in Google because Google has never been told it exists.
There is no penalty and nothing to fix in the code: Google finds new sites
through links from pages it already crawls, and a site with no links has none.

Search Console is the only reliable way to break that circle. Everything else
on this page is secondary to step 1 below.

Expect nothing for two weeks. That is normal.

## Immediately after the domain is live

1. **Google Search Console.** Add `themaildoc.co` as a **domain property**, not
   a URL prefix. It verifies by DNS TXT record and then covers http, https, www
   and every subdomain in one go.
2. **Submit the sitemap**: `https://themaildoc.co/sitemap-index.xml`. There is
   an index plus a child file; submit the index.
3. **Request indexing** for these, in this order. Google honours a small number
   of manual requests a day and these are the pages worth spending them on.
   - `/`
   - `/lab/dmarc-checker`
   - `/lab/spf-checker`
   - `/lab/spoofability`
   - `/health-library/email-authentication-guide`
   - `/health-library/why-are-my-emails-going-to-spam`
   - `/practice`
4. **Bing Webmaster Tools.** Import directly from Search Console rather than
   verifying again. Bing feeds ChatGPT search, which is worth more than its
   share of web traffic suggests.
5. **IndexNow**, for everything except Google:

   ```bash
   pnpm indexnow
   ```

   Bing, Yandex, Seznam and Naver share this endpoint and act on it in hours
   rather than weeks. Bing feeds ChatGPT search, which for a developer tool is
   worth more than its share of the search market suggests. Run it after every
   deploy that adds or changes pages.

6. **Cloudflare Web Analytics.** Enable it in the dashboard for the zone. It
   needs no cookie banner, which is why it is the analytics here.

## What to watch, and when

Nothing happens for a fortnight. That is normal and not a reason to change
anything.

- **Week 2:** pages start appearing under Coverage. Check for anything excluded
  as "Duplicate, Google chose a different canonical", which would mean a
  canonical is wrong.
- **Week 4:** first impressions in Performance. Look at which queries, not how
  many, and write the article the queries are asking for.
- **Week 8:** first positions worth reading. Anything ranking 8 to 20 is a page
  worth improving rather than a new page worth writing.

## What is realistic, and when

Be honest about the competition before spending a month on the wrong keyword.

**"DMARC checker", "SPF checker", "BIMI checker"** are held by Mimecast,
Valimail, EasyDMARC, PowerDMARC, DNSChecker and DMARCLY. These are domains with
years of history and thousands of referring domains. A new site does not take
them in 2026 by being better. Target them, keep the pages excellent, and expect
movement in twelve to eighteen months, driven by links rather than by content.

**What is winnable inside three to six months** is the long tail, where intent
is specific and the incumbents wrote nothing:

- "spf too many dns lookups" and "spf permerror" (we have the article and the
  only free flattener that refuses to emit an incomplete record)
- "dmarc p=none vs quarantine vs reject"
- "_report._dmarc not working" and "dmarc reports not arriving"
- "bimi certificate expired" (nearly every checker reports an expired VMC as
  valid; ours does not, which is a genuine differentiator worth writing about)
- "read dmarc xml report without uploading"
- the 166 condition pages, each of which answers one specific error

The strategy is to win the long tail first, earn links from being the answer,
and let that authority carry the head terms later. It is the only order that
works from zero.

## Where the first links come from

Free tools earn links when somebody answering a question needs one to point at.
The value is in being the answer, not in the submission.

**Directories, one-time:**
- AlternativeTo, listed against MXToolbox and EasyDMARC
- Product Hunt, on a Tuesday or Wednesday
- SaaSHub, Slant
- GitHub topics on the repository: `dmarc`, `spf`, `dkim`, `email-security`,
  `deliverability`

**Communities, ongoing, value first:**
- r/sysadmin, r/DMARC, r/emailmarketing, r/msp
- Server Fault and Stack Overflow, answering SPF lookup-limit and DMARC
  alignment questions properly and linking the tool only where it genuinely
  helps
- Mailop mailing list, for reading more than posting

The rule that matters: answer the question completely in the post itself. A
comment that is only a link gets removed and earns nothing. A comment that
solves somebody's problem and mentions the tool in passing gets upvoted and
quoted for years.

**What not to do:** paid link placements, guest posts on content farms, and
directory blasts. They are detectable, they do not work any more, and this site
is trying to be the credible one.

## The pages that will earn links on their own

These three, because they solve a problem nothing else free solves well:

- **SPF flattener** at `/lab/spf-flattener`. People hit the ten-lookup limit,
  search for it, and need a tool.
- **Bloodwork** at `/bloodwork`. Reading a DMARC XML report without uploading it
  anywhere is genuinely rare.
- **Spoofability** at `/lab/spoofability`. One blunt verdict is quotable in a
  way a chart is not.

Point new content at them.

## Re-check on every deploy

- `curl -s https://themaildoc.co/sitemap-index.xml | head` returns XML.
- `curl -s https://themaildoc.co/robots.txt` points at the sitemap.
- `curl -s https://themaildoc.co/llms.txt | head` describes the site.
- A random article has one `<h1>`, a self-referencing canonical and its JSON-LD.
- Lighthouse on `/` and one tool page, both above 95 for SEO and performance.
