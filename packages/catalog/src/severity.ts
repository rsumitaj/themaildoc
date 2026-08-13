import type { Severity, TriageLevel, VitalsBand } from '@maildoc/shared';

/**
 * ONE severity → score mapping, used by every record (context/03).
 * Vitals start at 100 and every condition deducts its severity's weight.
 */
export const SEVERITY_DEDUCTION: Record<Severity, number> = {
  CRITICAL: 40,
  HIGH: 25,
  MEDIUM: 15,
  LOW: 8,
  INFO: 2,
};

/** Severity → triage level (the patient-facing scale). */
export const SEVERITY_TRIAGE: Record<Severity, TriageLevel> = {
  CRITICAL: 'CRITICAL',
  HIGH: 'URGENT',
  MEDIUM: 'ATTENTION',
  LOW: 'MINOR',
  INFO: 'HEALTHY',
};

/** Sentence-case triage label (prose, drawers, tooltips). */
export const TRIAGE_LABEL: Record<TriageLevel, string> = {
  CRITICAL: 'Critical',
  URGENT: 'Urgent',
  ATTENTION: 'Needs attention',
  MINOR: 'Minor',
  HEALTHY: 'Healthy',
};

/**
 * Mono chip label on a condition card.
 * INFO-severity conditions are advisories, so their chip reads NOTE — the word
 * HEALTHY is reserved for a record (or domain) with nothing wrong.
 */
export const TRIAGE_CHIP: Record<TriageLevel, string> = {
  CRITICAL: 'CODE RED',
  URGENT: 'URGENT',
  ATTENTION: 'ATTENTION',
  MINOR: 'MINOR',
  HEALTHY: 'NOTE',
};

/**
 * Triage colours — meaning only, always paired with an icon and a label
 * (WCAG AA).
 *
 * These are custom property references rather than hex, and that is the point.
 * They were literals, which made this file a second copy of the palette that
 * `tokens.css` also defines: two places to change a colour, one of them
 * invisible to the design-token check, and every triage dot on the site frozen
 * to the light theme regardless of what the page around it was doing. Naming
 * the token instead means the dot is whatever the mode says it is, and there is
 * one definition of ambulance red.
 *
 * Every consumer renders these into a DOM that has the stylesheet, so the
 * reference always resolves. Anything drawn outside a document — an image
 * generated at build time — must read the value from `@maildoc/ui` instead.
 */
export const TRIAGE_COLOR: Record<TriageLevel, string> = {
  CRITICAL: 'var(--md-critical)',
  URGENT: 'var(--md-urgent)',
  ATTENTION: 'var(--md-attention)',
  MINOR: 'var(--md-minor)',
  HEALTHY: 'var(--md-healthy)',
};

/** Most severe first — the order conditions are triaged in the chart. */
export const SEVERITY_ORDER: readonly Severity[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO',
] as const;

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function deductionFor(severity: Severity): number {
  return SEVERITY_DEDUCTION[severity];
}

export function triageFor(severity: Severity): TriageLevel {
  return SEVERITY_TRIAGE[severity];
}

/** Vitals verdict copy by band (context/06). */
export const VITALS_VERDICT: Record<VitalsBand, { headline: string; note: string }> = {
  CRITICAL: {
    headline: 'CRITICAL CONDITION',
    note: 'Your domain is exposed right now. Let’s treat this.',
  },
  AT_RISK: {
    headline: 'AT RISK',
    note: 'Serious conditions found. Your deliverability and security are exposed.',
  },
  NEEDS_CARE: {
    headline: 'NEEDS CARE',
    note: 'Some real gaps are hurting you. All treatable, see below.',
  },
  HEALTHY: {
    headline: 'HEALTHY',
    note: 'Clean bill of health, a few minor tune-ups at most.',
  },
};

/** 0–39 critical · 40–64 at risk · 65–84 needs care · 85–100 healthy. */
export function vitalsBand(score: number): VitalsBand {
  if (score >= 85) return 'HEALTHY';
  if (score >= 65) return 'NEEDS_CARE';
  if (score >= 40) return 'AT_RISK';
  return 'CRITICAL';
}
