/**
 * One normalised shape for a DMARC aggregate report, whichever generation of
 * the spec produced it.
 *
 * RFC 9990 obsoletes RFC 7489's reporting half and adds `np`, `t=` and the
 * extension element; the elements everyone actually sends are unchanged. So we
 * read the superset and record what was present, rather than branching on a
 * version the reporters mostly do not send anyway.
 */

/** Every result value the schema allows, plus `unknown` for anything else. */
export type AuthResult =
  | 'pass'
  | 'fail'
  | 'none'
  | 'neutral'
  | 'softfail'
  | 'temperror'
  | 'permerror'
  | 'policy'
  | 'unknown';

export type Disposition = 'none' | 'quarantine' | 'reject' | 'unknown';

/** Relaxed (`r`) or strict (`s`) — RFC 9989 §4.4. */
export type AlignmentMode = 'r' | 's';

export interface PublishedPolicy {
  /** The domain the report is about. */
  domain: string;
  adkim: AlignmentMode;
  aspf: AlignmentMode;
  /** `null` when the reporter omitted it — RFC 9989 §4.8 treats that as none. */
  p: Disposition | null;
  sp: Disposition | null;
  /** DMARCbis: policy for non-existent subdomains. */
  np: Disposition | null;
  /** `null` when unstated, which means 100. */
  pct: number | null;
  fo: string | null;
  /** DMARCbis `t=y` — the domain owner is still testing. */
  testing: boolean;
}

export interface DkimAuthResult {
  domain: string;
  selector: string | null;
  result: AuthResult;
  human: string | null;
}

export interface SpfAuthResult {
  /** The RFC5321.MailFrom domain (or HELO, when the reporter says so). */
  domain: string;
  scope: string | null;
  result: AuthResult;
}

export interface PolicyOverride {
  /** `forwarded`, `sampled_out`, `trusted_forwarder`, `mailing_list`, … */
  type: string;
  comment: string | null;
}

export interface ReportRow {
  sourceIp: string;
  count: number;
  disposition: Disposition;
  /** What the receiver concluded — already alignment-aware (RFC 9990 §3.1.1). */
  evaluated: { dkim: AuthResult; spf: AuthResult };
  overrides: PolicyOverride[];
  headerFrom: string;
  envelopeFrom: string | null;
  envelopeTo: string | null;
  dkim: DkimAuthResult[];
  spf: SpfAuthResult[];
}

export interface AggregateReport {
  reporter: {
    org: string;
    email: string;
    contact: string | null;
    reportId: string;
  };
  /** Unix seconds, as sent. */
  range: { begin: number; end: number };
  /** RFC 9990 §3.1.5 — the reporter telling you it could not do something. */
  errors: string[];
  policy: PublishedPolicy;
  rows: ReportRow[];
  /** Element names inside `<extension>` we did not recognise (§3.2). */
  extensions: string[];
  /** Source file, when the report came from one. */
  source?: string;
}

export class ReportParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReportParseError';
  }
}
