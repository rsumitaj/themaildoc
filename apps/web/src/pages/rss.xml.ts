import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import type { APIContext } from 'astro';

/**
 * The Health Library as a feed.
 *
 * Worth having for a reason beyond readers: aggregators and a handful of
 * developer directories consume RSS to discover new technical writing, and
 * those are exactly the places a free tool earns its first links.
 */
export async function GET(context: APIContext) {
  const entries = await getCollection('library', (entry) => !entry.data.draft);

  return rss({
    title: 'MailDoc Health Library',
    description:
      'Guides and answers on SPF, DKIM, DMARC and email deliverability, written from the RFCs.',
    site: context.site ?? 'https://themaildoc.co',
    items: entries
      .sort(
        (a, b) =>
          (b.data.published ?? b.data.updated).getTime() -
          (a.data.published ?? a.data.updated).getTime(),
      )
      .map((entry) => ({
        title: entry.data.heading,
        description: entry.data.standfirst,
        link: `/health-library/${entry.id}`,
        pubDate: entry.data.published ?? entry.data.updated,
      })),
    customData: '<language>en-gb</language>',
  });
}
