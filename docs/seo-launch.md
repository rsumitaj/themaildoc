# Launching, indexing and getting found

Everything below is a step somebody has to take by hand. The site's own SEO is
in the code; this is what happens after a deploy.

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
5. **Cloudflare Web Analytics.** Enable it in the dashboard for the zone. It
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
