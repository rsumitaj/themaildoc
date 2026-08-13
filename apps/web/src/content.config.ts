import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
/**
 * `z` from `astro:content` is deprecated in Astro 7, and the deprecation is not
 * cosmetic: the generated `astro:content` types infer an entry's shape through
 * `astro/zod`, so a schema built with the re-export does not match and every
 * `getCollection` call falls back to `any`. That turned seventy real type
 * errors into silence across the article and glossary pages.
 */
import { z } from 'astro/zod';

/**
 * The two content collections, and the SEO fields an entry cannot ship
 * without.
 *
 * Everything here is required on purpose. A missing description or a title
 * over sixty characters is not a build warning somebody notices later, it is a
 * page that goes live wrong and stays wrong until a rank report says so. Zod
 * fails the build instead.
 *
 * `updated` is required for the same reason: Google shows a date on technical
 * content and an article whose date never moves reads as abandoned.
 */
const seoFields = {
  /** Under 60 characters so the SERP does not truncate it. */
  title: z.string().min(15).max(60),
  /** Under 155 for the same reason. */
  description: z.string().min(70).max(155),
  /** The one phrase this page is trying to win. One page, one target. */
  keyword: z.string().min(3),
  updated: z.coerce.date(),
  published: z.coerce.date().optional(),
  /** Rendered on the page and as FAQPage schema. */
  faq: z
    .array(z.object({ q: z.string().min(10), a: z.string().min(40) }))
    .default([]),
  /** Tools this page should send people to, as /lab slugs. */
  tools: z.array(z.string()).default([]),
  /** Other library entries worth reading next, as slugs. */
  related: z.array(z.string()).default([]),
  draft: z.boolean().default(false),
};

const library = defineCollection({
  loader: glob({ base: './src/content/library', pattern: '**/*.md' }),
  schema: z.object({
    ...seoFields,
    /** The H1, which is allowed to differ from the SERP title. */
    heading: z.string().min(10),
    /** One line under the H1. */
    standfirst: z.string().min(40).max(300),
    /**
     * A pillar is a long guide that clusters link up to; a cluster answers one
     * question and links back. Anything else is a plain article.
     */
    kind: z.enum(['pillar', 'cluster']).default('cluster'),
    /** For clusters: the pillar slug this belongs under. */
    pillar: z.string().optional(),
    /** Renders HowTo schema when the article is a set of steps. */
    steps: z.array(z.object({ name: z.string(), text: z.string() })).default([]),
  }),
});

const glossary = defineCollection({
  loader: glob({ base: './src/content/glossary', pattern: '**/*.md' }),
  schema: z.object({
    ...seoFields,
    /** The term itself, as people write it. */
    term: z.string().min(2),
    /** One sentence. This is what goes in the DefinedTerm schema. */
    definition: z.string().min(60).max(400),
    /** Other glossary slugs worth reading beside it. */
    seeAlso: z.array(z.string()).default([]),
  }),
});

export const collections = { library, glossary };
