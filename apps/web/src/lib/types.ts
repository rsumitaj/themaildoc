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
    notes: string[];
    durationMs: number;
  };
}

export interface DkimSuccess {
  ok: true;
  domain: string;
  found: boolean;
  keys: DkimAnalysis['keys'];
  probed: string[];
  status: DkimAnalysis['status'];
  conditions: Condition[];
  meta: { queriesUsed: number; notes: string[] };
}

export interface ApiFailure {
  ok: false;
  error: { code: string; message: string };
}

export type CheckResponse = CheckSuccess | ApiFailure;
export type DkimResponse = DkimSuccess | ApiFailure;

export type { Condition, Vitals, RecordSummary, Spoofability };
