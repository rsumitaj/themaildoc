import type { DohProvider } from '@maildoc/shared';

/** Record types the clinic queries. */
export type DnsType =
  | 'A'
  | 'AAAA'
  | 'CNAME'
  | 'MX'
  | 'NS'
  | 'PTR'
  | 'SOA'
  | 'TXT'
  | 'CAA'
  | 'DNSKEY'
  | 'DS'
  | 'TLSA'
  | 'SRV';

export const DNS_TYPE_NUMBERS: Record<DnsType, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DS: 43,
  DNSKEY: 48,
  TLSA: 52,
  CAA: 257,
};

/** DNS RCODEs we distinguish, plus our own transport outcomes. */
export type DnsStatus =
  | 'NOERROR'
  | 'FORMERR'
  | 'SERVFAIL'
  | 'NXDOMAIN'
  | 'NOTIMP'
  | 'REFUSED'
  | 'TIMEOUT'
  | 'ERROR';

/** Operational notes an engine may turn into GENERIC catalog conditions. */
export type ResolverNote =
  | 'PROPAGATION_IN_PROGRESS'
  | 'RESOLVER_TIMEOUT'
  | 'RESOLVER_ERROR'
  | 'BUDGET_EXCEEDED';

/** Whether the queried resolvers told the same story. */
export type Agreement = 'AGREED' | 'DISAGREED' | 'SINGLE';

export interface DnsAnswer {
  name: string;
  type: number;
  ttl: number;
  /** Raw RDATA as the DoH provider rendered it. UNTRUSTED — escape on render. */
  data: string;
}

/**
 * One TXT record, kept as both its DNS character-strings and the concatenated
 * value. SPF and DMARC are defined on the concatenation (RFC 7208 §3.3); the
 * individual string lengths are what surface over-255-byte problems.
 */
export interface TxtRecord {
  strings: string[];
  value: string;
  /** Approximate RDATA size on the wire: 1 length byte per string + payload. */
  bytes: number;
  /**
   * Whether `strings` reflects the real DNS character-strings.
   *
   * Google's DoH returns TXT rdata already concatenated and unquoted, so a
   * long record looks like one huge string that could never exist on the wire;
   * Cloudflare preserves the quoted segments. When this is false, nothing may
   * be concluded about how the record is chunked.
   */
  segmented: boolean;
}

export interface DnsQueryResult {
  name: string;
  type: DnsType;
  status: DnsStatus;
  /** Every answer returned, including CNAMEs in the chain. */
  answers: DnsAnswer[];
  /** Answers matching the queried type. */
  records: DnsAnswer[];
  /** Parsed TXT records (empty for other types). */
  txt: TxtRecord[];
  /** DNSSEC-authenticated data flag from the resolver. */
  authenticated: boolean;
  truncated: boolean;
  /**
   * RFC 7208 §4.6.4 "void lookup": NXDOMAIN, or NOERROR with no records of the
   * queried type.
   */
  isVoid: boolean;
  providers: DohProvider[];
  agreement: Agreement;
  notes: ResolverNote[];
  /** Set when every resolver failed; safe to show, never raw provider text. */
  error?: string;
}

/** Raw DoH JSON (RFC 8484 JSON profile, as served by Google and Cloudflare). */
export interface DohJson {
  Status: number;
  TC?: boolean;
  RD?: boolean;
  RA?: boolean;
  AD?: boolean;
  CD?: boolean;
  Question?: Array<{ name: string; type: number }>;
  Answer?: Array<{ name: string; type: number; TTL?: number; data: string }>;
  Authority?: Array<{ name: string; type: number; TTL?: number; data: string }>;
  Comment?: string;
}

/**
 * Optional shared cache (Cloudflare Cache API in the Worker, a Map in tests).
 * Keeps the free tier honest by collapsing duplicate upstream queries.
 */
export interface DnsCache {
  get(key: string): Promise<DnsQueryResult | undefined> | DnsQueryResult | undefined;
  set(key: string, value: DnsQueryResult, ttlSeconds: number): Promise<void> | void;
}
