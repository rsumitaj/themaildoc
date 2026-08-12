/**
 * Bloodwork — reading DMARC aggregate (RUA) reports.
 *
 * Everything in this package runs in the BROWSER, never on the Worker. A
 * patient's reports are their data: who mails them, who mails as them, and how
 * much of it there is. That must not travel to our server to be read, and it
 * does not. Keep that constraint — it is a promise on the page, not an
 * implementation detail.
 *
 * The whole path is here: decompress → parse XML safely → normalise the report
 * → recompute alignment → classify every sending source → emit finding codes
 * for the catalog to put words to.
 */

export { parseXml, decodeEntities, XmlError } from './xml.js';
export type { XmlNode } from './xml.js';

export {
  readReportBytes,
  readReportFile,
  sniff,
  DecompressError,
} from './decompress.js';
export type { ReportFile, Format } from './decompress.js';

export { classifyIp, reverseName, expandIpv6, isIpv6 } from './ip.js';
export type { IpKind } from './ip.js';

export {
  parseAggregateReport,
  parseAggregateReports,
  parseReportFilename,
} from './dmarc/parse.js';
export type { ReportFilename } from './dmarc/parse.js';

export { analyzeReports, isAligned, passBand, VERDICTS } from './dmarc/analyze.js';
export type {
  Bloodwork,
  FindingSeed,
  IdentifierSummary,
  PassBand,
  Source,
  SourceVerdict,
} from './dmarc/analyze.js';

export { inferService } from './dmarc/senders.js';

export { ReportParseError } from './dmarc/types.js';
export type {
  AggregateReport,
  AlignmentMode,
  AuthResult,
  Disposition,
  DkimAuthResult,
  PolicyOverride,
  PublishedPolicy,
  ReportRow,
  SpfAuthResult,
} from './dmarc/types.js';
