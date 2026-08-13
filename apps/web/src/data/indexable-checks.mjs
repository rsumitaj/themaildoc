/**
 * Which of the 166 condition pages belong in a search index.
 *
 * All 166 stay on the site. They are what a checkup result links to when it
 * finds something, and a reader who has just been told their record has
 * `DMARC_EDV_MALFORMED_PARTIAL` deserves a page explaining it.
 *
 * Indexing all of them is a different question. They share one template, and
 * roughly half of each page is the same six paragraphs about running the test
 * and reading the guide. Publishing a hundred and sixty-six of those on a
 * domain with no authority yet means three quarters of everything Google sees
 * is near-identical boilerplate, which is how a new site ends up sitting in
 * "Crawled, currently not indexed" for months while the twenty pages that
 * could actually rank wait behind them.
 *
 * So the ones below are indexable, and the rest carry `noindex, follow`: still
 * reachable, still passing their links on, just not competing for crawl budget
 * they were never going to earn back.
 *
 * The rule for being on this list is one thing only: somebody types this into
 * a search box. Either it is the error message a tool showed them, or it is
 * the finding they were told to go and fix. "SPF too many DNS lookups" is a
 * real search. "DMARC v tag out of order" is not.
 */
export const INDEXABLE_CHECKS = new Set([
  // SPF. The lookup limit alone accounts for most of the searching people do.
  'SPF_RECORD_MISSING',
  'SPF_MULTIPLE_RECORDS',
  'SPF_LOOKUP_LIMIT_EXCEEDED',
  'SPF_LOOKUP_APPROACHING_LIMIT',
  'SPF_VOID_LOOKUP_EXCEEDED',
  'SPF_ALL_MISSING',
  'SPF_ALL_TOO_PERMISSIVE',
  'SPF_SOFTFAIL_ADVISORY',
  'SPF_PTR_MECHANISM',
  'SPF_INCLUDE_NXDOMAIN',
  'SPF_REDIRECT_LOOP',
  'SPF_CIRCULAR_INCLUDE',
  'SPF_RECORD_STRING_TOO_LONG',
  'SPF_PRIVATE_IP_IN_SPF',

  // DMARC. Policy questions, not tag syntax.
  'DMARC_RECORD_MISSING',
  'DMARC_P_MISSING',
  'DMARC_P_NONE',
  'DMARC_P_QUARANTINE',
  'DMARC_MULTIPLE_RECORDS',
  'DMARC_RUA_MISSING',
  'DMARC_POLICY_INHERITED',
  'DMARC_WEAKER_SP',
  'DMARC_BLIND_REJECT',
  'DMARC_UNPARSEABLE',
  'DMARC_STALE_TEST_MODE',
  'DMARC_ORG_DOMAIN_IS_PSD',

  // DKIM. Selectors and key strength, which is what people are sent to check.
  'DKIM_RECORD_MISSING',
  'DKIM_SELECTOR_NOT_FOUND',
  'DKIM_KEY_TOO_WEAK',
  'DKIM_KEY_WEAK_1024',
  'DKIM_KEY_REVOKED',
  'DKIM_TESTING_MODE',
  'DKIM_MULTIPLE_RECORDS',
  'DKIM_ALGO_SHA1',

  // Mail routing and the domain itself.
  'MX_MISSING',
  'MX_NULL',
  'MX_POINTS_TO_IP',
  'MX_TARGET_IS_CNAME',
  'MX_SINGLE_POINT_OF_FAILURE',
  'DOMAIN_NXDOMAIN',
  'PTR_MISSING',
  'FCRDNS_FAIL',

  // Transport security and the records a hardening checklist names.
  'DNSSEC_UNSIGNED',
  'DNSSEC_BOGUS',
  'MTASTS_MISSING',
  'MTASTS_MODE_TESTING',
  'MTASTS_MX_MISMATCH',
  'TLSRPT_MISSING',
  'CAA_MISSING',
  'BIMI_MISSING',
  'BIMI_VMC_MISSING',
  'BIMI_DMARC_NOT_ENFORCED',

  // Two report findings people genuinely search for by description.
  'RUA_FORWARDED_MAIL',
  'RUA_READY_FOR_ENFORCEMENT',
]);

/** The URL slug for a condition code, used by the page and the sitemap alike. */
export const slugForCheck = (code) => code.toLowerCase().replace(/_/g, '-');

/** Slugs, for matching a sitemap URL without re-deriving the transform. */
export const INDEXABLE_CHECK_SLUGS = new Set([...INDEXABLE_CHECKS].map(slugForCheck));
