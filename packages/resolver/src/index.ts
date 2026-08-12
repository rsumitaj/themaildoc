export { DohResolver } from './resolver.js';
export type { ResolverOptions, QueryOptions } from './resolver.js';

export { queryProvider, dohUrl } from './doh.js';
export type { DohRequestOptions, DohAttempt, FetchLike } from './doh.js';

export { parseCharacterStrings, toTxtRecord } from './txt.js';

export { DNS_TYPE_NUMBERS } from './types.js';
export type {
  Agreement,
  DnsAnswer,
  DnsCache,
  DnsQueryResult,
  DnsStatus,
  DnsType,
  DohJson,
  ResolverNote,
  TxtRecord,
} from './types.js';
