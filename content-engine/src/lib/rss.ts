/**
 * News + trend intake.
 *
 * A curated set of security/email feeds. We fetch, parse (regex — the Workers
 * runtime has no XML DOM), and keep only items that are plausibly about email
 * infrastructure/authentication, so the "news post of the week" is grounded in
 * a real, fresh event rather than an invented topic. No API keys needed.
 */
import { fetchRetry } from './util';

export const FEEDS: { url: string; source: string }[] = [
  { url: 'https://www.bleepingcomputer.com/feed/', source: 'BleepingComputer' },
  { url: 'https://thehackernews.com/feeds/posts/default', source: 'TheHackerNews' },
  { url: 'https://therecord.media/feed', source: 'TheRecord' },
  { url: 'https://krebsonsecurity.com/feed/', source: 'KrebsOnSecurity' },
  { url: 'https://www.darkreading.com/rss.xml', source: 'DarkReading' },
  // Google Trends daily RSS (US); keyless. Signals rising interest.
  { url: 'https://trends.google.com/trending/rss?geo=US', source: 'GoogleTrends' },
];

const RELEVANCE = /\b(email|e-mail|spf|dkim|dmarc|dns|mx|smtp|spoof|phish|bec|deliverab|inbox|mailbox|gmail|outlook|microsoft 365|proofpoint|mimecast|sender|bimi|mta-sts|tls-rpt|domain|dnssec|spam|impersonat|display name|mail server|mailflow)\b/i;

export interface NewsItem { title: string; link: string; source: string; published?: string; summary: string; }

function decode(s: string): string {
  return (s ?? '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ').trim();
}

function parseItems(xml: string, source: string): NewsItem[] {
  const out: NewsItem[] = [];
  const blocks = xml.match(/<(item|entry)\b[\s\S]*?<\/\1>/gi) ?? [];
  for (const b of blocks) {
    const title = decode((b.match(/<title[^>]*>([\s\S]*?)<\/title>/i) ?? [])[1] ?? '');
    let link = (b.match(/<link[^>]*href="([^"]+)"/i) ?? [])[1]
      ?? decode((b.match(/<link[^>]*>([\s\S]*?)<\/link>/i) ?? [])[1] ?? '');
    const published = (b.match(/<(pubDate|updated|published)[^>]*>([\s\S]*?)<\/\1>/i) ?? [])[2];
    const summary = decode(
      (b.match(/<(description|summary|content)[^>]*>([\s\S]*?)<\/\1>/i) ?? [])[2] ?? '',
    ).slice(0, 500);
    if (title && link) out.push({ title, link: link.trim(), source, published, summary });
  }
  return out;
}

export async function fetchNews(maxPerFeed = 12): Promise<NewsItem[]> {
  const results = await Promise.allSettled(
    FEEDS.map(async (f) => {
      const res = await fetchRetry(f.url, { headers: { 'user-agent': 'maildoc-content-engine' } }, { tries: 2, timeoutMs: 15000 });
      if (!res.ok) return [] as NewsItem[];
      return parseItems(await res.text(), f.source).slice(0, maxPerFeed);
    }),
  );
  const items = results.flatMap((r) => (r.status === 'fulfilled' ? r.value : []));
  // Keep only email-infra-relevant items; dedup by link.
  const seen = new Set<string>();
  return items.filter((it) => {
    if (!RELEVANCE.test(`${it.title} ${it.summary}`)) return false;
    if (seen.has(it.link)) return false;
    seen.add(it.link);
    return true;
  });
}
