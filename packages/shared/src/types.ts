/**
 * Cross-package vocabulary. Kept deliberately tiny and framework-free —
 * `catalog`, `resolver` and `engines` all speak this language.
 */

/** Every record family the clinic can examine. `GENERIC` = not record-specific. */
export type RecordKind =
  | 'SPF'
  | 'DMARC'
  | 'DKIM'
  | 'MX'
  | 'A'
  | 'PTR'
  | 'DNSSEC'
  | 'MTASTS'
  | 'TLSRPT'
  | 'BIMI'
  | 'CAA'
  | 'DANE'
  /** Findings read out of DMARC aggregate reports (Bloodwork), not from DNS. */
  | 'RUA'
  | 'GENERIC';

/** The one severity scale, used by every record (see `catalog/severity`). */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/** Patient-facing triage level a severity maps to. */
export type TriageLevel = 'CRITICAL' | 'URGENT' | 'ATTENTION' | 'MINOR' | 'HEALTHY';

/** Rollup verdict for a single record (RFC-agnostic, used by the record status row). */
export type RecordStatus = 'CRITICAL' | 'ATTENTION' | 'HEALTHY';

/** Vitals band for a 0–100 score. */
export type VitalsBand = 'CRITICAL' | 'AT_RISK' | 'NEEDS_CARE' | 'HEALTHY';
