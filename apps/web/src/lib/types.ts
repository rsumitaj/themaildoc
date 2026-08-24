import type { Condition, Vitals } from '@maildoc/catalog/scoring';
import type {
  AddressAnalysis,
  BimiAnalysis,
  CaaAnalysis,
  DkimAnalysis,
  DmarcAnalysis,
  DnssecAnalysis,
  MtaStsAnalysis,
  MxAnalysis,
  PtrAnalysis,
  RecordSummary,
  Spoofability,
  SpfAnalysis,
  SpfErrorCause,
  SpfEvalStep,
  SpfResult,
  TlsRptAnalysis,
} from '@maildoc/engines';

/**
 * The wire contract between the Worker and the browser.
 *
 * Types only — importing engine *values* into an island would ship every
 * RFC parser to every visitor.
 */

export interface CheckSuccess {
  ok: true;
  domain: string;
  checkedAt: string;
  vitals: Vitals;
  spoofability: Spoofability;
  records: RecordSummary[];
  conditions: Condition[];
  detail: {
    spf: SpfAnalysis;
    dmarc: DmarcAnalysis;
    mx: MxAnalysis;
    address: AddressAnalysis;
    dnssec: DnssecAnalysis;
    mtasts: MtaStsAnalysis;
    tlsrpt: TlsRptAnalysis;
    bimi: BimiAnalysis;
    caa: CaaAnalysis;
    ptr: PtrAnalysis;
  };
  meta: {
    queriesUsed: number;
    budget: number;
    partial: boolean;
    /** Whether the budget ran out, as opposed to SPF running past its share. */
    budgetExhausted: boolean;
    notes: string[];
    durationMs: number;
  };
}

/**
 * The standalone SPF chain walk.
 *
 * The checkup's own SPF pass shares fifty subrequests with nine other records,
 * which is not enough for a chain published through a flattening vendor. This
 * comes from a request of its own that spends nearly the whole allowance on the
 * chain, so it is the authoritative one and the result screen prefers it.
 */
export interface SpfSuccess {
  ok: true;
  domain: string;
  found: boolean;
  record: string | null;
  chain: SpfAnalysis['chain'];
  lookupCount: number;
  lookupCountExact: boolean;
  voidLookupCount: number;
  voidCountExact: boolean;
  allQualifier: SpfAnalysis['allQualifier'];
  redirect: string | null;
  status: SpfAnalysis['status'];
  conditions: Condition[];
  meta: { queriesUsed: number; budget: number; notes: string[] };
}

export interface DkimSuccess {
  ok: true;
  domain: string;
  found: boolean;
  keys: DkimAnalysis['keys'];
  probed: string[];
  /**
   * The selectors we were told to check, as opposed to the ones we guessed.
   * Empty means every probe was a guess, which is what makes a miss mean
   * "we guessed wrong" rather than "your key is not published".
   */
  explicit: string[];
  status: DkimAnalysis['status'];
  conditions: Condition[];
  meta: { queriesUsed: number; notes: string[] };
}

/**
 * One address, evaluated against one domain's record the way a receiver does.
 *
 * Distinct from every other SPF response here: the others describe a record,
 * this one is a decision about a sender, and it carries the trace that produced
 * it rather than a chain diagram.
 */
export interface SpfIpSuccess {
  ok: true;
  domain: string;
  ip: string;
  ipVersion: 4 | 6;
  sender: string;
  helo: string;
  result: SpfResult;
  matched: { domain: string; term: string; qualifier: string } | null;
  /** Why an error happened, so the page can say whose problem it is. */
  cause: SpfErrorCause | null;
  /** True when the error condemns the record for every sender, not just this one. */
  breaksEverySender: boolean;
  summary: string;
  trace: SpfEvalStep[];
  lookups: number;
  voidLookups: number;
  complete: boolean;
  meta: { queriesUsed: number; budget: number; notes: string[] };
}

export interface ApiFailure {
  ok: false;
  error: { code: string; message: string };
}

export type CheckResponse = CheckSuccess | ApiFailure;
export type DkimResponse = DkimSuccess | ApiFailure;
export type SpfResponse = SpfSuccess | ApiFailure;
export type SpfIpResponse = SpfIpSuccess | ApiFailure;

export type {
  Condition,
  Vitals,
  RecordSummary,
  Spoofability,
  SpfEvalStep,
  SpfResult,
  SpfErrorCause,
};
