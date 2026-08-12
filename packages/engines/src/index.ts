export { analyzeSpf } from './spf/analyze.js';
export type { SpfEngineOptions } from './spf/analyze.js';
export type { SpfAnalysis, SpfChainNode, SpfNodeStatus } from './spf/types.js';

export {
  parseSpf,
  isSpfRecord,
  looksLikeBrokenSpf,
  isLookupMechanism,
  MECHANISM_NAMES,
  LOOKUP_MECHANISMS,
} from './spf/parse.js';
export type {
  ParsedSpf,
  Qualifier,
  MechanismName,
  SpfTerm,
  SpfMechanism,
  SpfModifier,
  SpfUnknownTerm,
} from './spf/parse.js';

export {
  isValidIpv4,
  isValidIpv6,
  isValidPrefix,
  isPrivateIpv4,
  isPrivateIpv6,
} from './spf/ip.js';
export { containsMacro, isValidMacroString } from './spf/macro.js';

export {
  flattenSpf,
  splitForTxt,
  byteLength,
  TXT_STRING_MAX,
  UDP_SAFE_BYTES,
  RECORD_MAX_BYTES,
} from './spf/flatten.js';
export type {
  FlattenResult,
  FlattenOptions,
  FlattenNote,
  PreservedTerm,
  PreserveReason,
  ExpandedSource,
} from './spf/flatten.js';

export {
  mergeIpv4,
  mergeIpv6,
  ipv4ToInt,
  intToIpv4,
  ipv6ToBigInt,
  bigIntToIpv6,
} from './spf/cidr.js';
export type { CidrBlock } from './spf/cidr.js';

export { healthCheck, DEFAULT_HEALTH_CHECK_BUDGET } from './healthCheck.js';
export type { HealthCheck, HealthCheckOptions, RecordSummary } from './healthCheck.js';

export { assessSpoofability } from './spoofability.js';
export { assessReadiness } from './readiness.js';
export type { Readiness, Requirement, RequirementStatus, ReadinessInput } from './readiness.js';
export type { Spoofability, SpoofVerdict } from './spoofability.js';

export { analyzeDkim, COMMON_SELECTORS } from './dkim/analyze.js';
export type { DkimAnalysis, DkimEngineOptions, DkimKeyRecord } from './dkim/analyze.js';
export { inspectKey, rsaModulusBits, decodeBase64 } from './dkim/key.js';
export type { DkimKey } from './dkim/key.js';

export { analyzeMx } from './mx/analyze.js';
export type { MxAnalysis, MxEngineOptions, MxHost } from './mx/analyze.js';

export { analyzeAddresses, analyzeDnssec } from './address/analyze.js';
export type { AddressAnalysis, DnssecAnalysis } from './address/analyze.js';

export {
  analyzeMtaSts,
  parsePolicy,
  policyCoversHost,
  MTASTS_MAX_AGE_CEILING,
  MTASTS_MAX_AGE_FLOOR,
} from './transport/mtasts.js';
export type { MtaStsAnalysis, MtaStsOptions, MtaStsPolicy, MtaStsMode } from './transport/mtasts.js';

export { analyzeTlsRpt, analyzeBimi, analyzeCaa } from './transport/records.js';
export type { TlsRptAnalysis, BimiAnalysis, CaaAnalysis } from './transport/records.js';

export { analyzePtr, reverseName } from './ptr/analyze.js';
export type { PtrAnalysis, PtrOptions, PtrRecord } from './ptr/analyze.js';

export {
  analyzeDmarc,
  discoverDmarc,
  stepUp,
  parseDmarc,
  parseReportUris,
  isDmarcRecord,
  isValidFo,
  DMARC_MAX_TREE_WALK_QUERIES,
  POLICY_RANK,
  POLICY_VALUES,
  OBSOLETE_TAGS,
} from './dmarc/index.js';
export type {
  DmarcEngineOptions,
  DmarcAnalysis,
  DmarcDiscovery,
  DiscoveryStep,
  DiscoverySource,
  DmarcPolicy,
  ParsedDmarc,
  ReportUri,
  EdvResult,
  EdvStatus,
} from './dmarc/index.js';
