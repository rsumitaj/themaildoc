import type { RecordKind, Severity, TriageLevel } from '@maildoc/shared';

/**
 * What kind of problem this is. Used for grouping in the chart and for
 * per-record drawers — not shown raw to patients.
 */
export type IssueCategory =
  | 'existence'
  | 'syntax'
  | 'policy'
  | 'lookup'
  | 'alignment'
  | 'reporting'
  | 'transport'
  | 'crypto'
  | 'operational';

/**
 * The canonical shape of every issue MailDoc can diagnose (context/03).
 *
 * Detectors DETECT (they emit a code plus variables); this catalog SUPPLIES the
 * verdict, the reason, the prescription and the weight. Adding a check is one
 * catalog entry plus one detector — never ad-hoc strings inside an engine.
 */
export interface Issue {
  /** Stable, unique, screaming-snake — e.g. `SPF_LOOKUP_LIMIT_EXCEEDED`. */
  readonly code: string;
  readonly record: RecordKind;
  readonly severity: Severity;
  readonly category: IssueCategory;
  /** Short condition title. */
  readonly title: string;
  /** Why it matters, in plain English. */
  readonly why: string;
  /** The prescription — exact and copy-paste oriented. */
  readonly fix: string;
  /** e.g. `RFC 7208 section 4.6.4`. */
  readonly rfc: string;
  /** Patient may dismiss it (advisories only). */
  readonly dismissible?: boolean;
  /**
   * Set when the entry reports a fact rather than a fault, so it costs nothing.
   *
   * A null MX is the example: publishing one is the correct, deliberate way to
   * say a domain receives no mail, and the entry's own text ends "if that is
   * deliberate, it is exactly right". Taking points off for it meant the score
   * disagreed with the sentence beside it.
   */
  readonly scores?: false;
  /** `{placeholder}` names the detector must supply. */
  readonly vars?: readonly string[];
}

/** Values a detector supplies for an issue's `{placeholders}`. */
export type IssueVars = Record<string, string | number>;

/**
 * An issue as actually found on a domain: interpolated, weighted and triaged.
 * This is what the API returns and the chart renders.
 */
export interface Condition {
  readonly code: string;
  readonly record: RecordKind;
  readonly severity: Severity;
  readonly triage: TriageLevel;
  readonly category: IssueCategory;
  readonly title: string;
  readonly why: string;
  readonly fix: string;
  readonly rfc: string;
  /** Points this condition removes from Vitals. */
  readonly deduction: number;
  readonly dismissible: boolean;
  readonly vars: IssueVars;
  /**
   * Optional raw evidence (the offending record, chain path, …).
   * ALWAYS untrusted DNS content — escape before rendering.
   */
  readonly evidence?: string;
}
