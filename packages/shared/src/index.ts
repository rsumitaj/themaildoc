export type {
  RecordKind,
  RecordStatus,
  Severity,
  TriageLevel,
  VitalsBand,
} from './types.js';

export {
  DOH_ENDPOINTS,
  DEFAULT_QUERY_TIMEOUT_MS,
  DEFAULT_QUERY_RETRIES,
  DEFAULT_DNS_QUERY_BUDGET,
  SPF_MAX_DNS_LOOKUPS,
  SPF_MAX_VOID_LOOKUPS,
  SPF_APPROACHING_LOOKUP_LIMIT,
  SPF_MAX_MX_NAMES,
  SPF_MAX_RECURSION_DEPTH,
  TXT_STRING_MAX_BYTES,
  UDP_TRUNCATION_RISK_BYTES,
  DOMAIN_MAX_LENGTH,
  DOMAIN_LABEL_MAX_LENGTH,
} from './constants.js';
export type { DohProvider } from './constants.js';

export {
  normalizeDomain,
  stripWww,
  toDomain,
  domainRejectionMessage,
} from './domain.js';
export type { DomainResult, DomainRejection } from './domain.js';
