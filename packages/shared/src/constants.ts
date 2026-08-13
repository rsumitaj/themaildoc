/** Free public DNS-over-HTTPS endpoints (JSON API). Order matters: primary first. */
export const DOH_ENDPOINTS = {
  google: 'https://dns.google/resolve',
  cloudflare: 'https://cloudflare-dns.com/dns-query',
} as const;

export type DohProvider = keyof typeof DOH_ENDPOINTS;

/** Per-query network budget. Cloudflare Workers give us 50 subrequests per request. */
export const DEFAULT_QUERY_TIMEOUT_MS = 5_000;
export const DEFAULT_QUERY_RETRIES = 1;

/**
 * Hard ceiling on DNS queries a single engine run may issue. The Workers free
 * tier caps a request at 50 subrequests; SPF is the greediest engine, so it
 * gets a budget well under the cap and reports when it hits it rather than
 * silently truncating.
 */
export const DEFAULT_DNS_QUERY_BUDGET = 25;

/** RFC 7208 §4.6.4 — the limits that make or break an SPF record. */
export const SPF_MAX_DNS_LOOKUPS = 10;
export const SPF_MAX_VOID_LOOKUPS = 2;
/** 9 or 10 lookups: still valid, one vendor away from PermError. */
export const SPF_APPROACHING_LOOKUP_LIMIT = 9;
/**
 * A single `mx` mechanism may resolve at most 10 names — a separate cap from
 * the 10-lookup budget, and one almost no checker tests (RFC 7208 §4.6.4).
 */
export const SPF_MAX_MX_NAMES = 10;
/**
 * Runaway guard for include:/redirect= recursion. Not a product limit.
 *
 * This was 10, borrowed from the lookup limit, and it was the wrong number for
 * the wrong reason. RFC 7208's ten is a budget a *receiver* spends evaluating a
 * message; it says nothing about how far a checker may read. Reusing it meant
 * the chart stopped drawing exactly where a record started being interesting,
 * on the domains whose chains are deep enough to be worth drawing at all.
 *
 * Loops are caught by the ancestor path, not by depth, so this only has to stop
 * a chain that is pathological rather than circular. Thirty is past anything
 * the query budget can reach, which makes the budget the binding constraint and
 * this a backstop that should never fire.
 */
export const SPF_MAX_RECURSION_DEPTH = 30;

/**
 * Nodes one chain may expand to. Also a runaway guard.
 *
 * A diamond-shaped include graph is legitimately re-walked down each path, so
 * a wide record can have many more nodes than it has lookups.
 */
export const SPF_MAX_CHAIN_NODES = 250;

/** DNS wire limits we surface as conditions. */
export const TXT_STRING_MAX_BYTES = 255;
/** Beyond this, a response risks truncation on resolvers without EDNS0. */
export const UDP_TRUNCATION_RISK_BYTES = 450;

/** Domain-name limits (RFC 1035 §2.3.4 / §3.1). */
export const DOMAIN_MAX_LENGTH = 253;
export const DOMAIN_LABEL_MAX_LENGTH = 63;
