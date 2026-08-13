import type { TriageLevel } from '@maildoc/shared';

/**
 * Design-system tokens that components need in TypeScript (chart colours,
 * inline SVG strokes, canvas). The CSS custom properties in `tokens.css`
 * remain the source of truth — these are the same values, addressable by name.
 */
export const TRIAGE_VAR: Record<TriageLevel, string> = {
  CRITICAL: '--md-critical',
  URGENT: '--md-urgent',
  ATTENTION: '--md-attention',
  MINOR: '--md-minor',
  HEALTHY: '--md-healthy',
};

/** `var(--md-critical)` — for inline styles and SVG attributes. */
export function triageColorVar(level: TriageLevel): string {
  return `var(${TRIAGE_VAR[level]})`;
}

/** Modifier class for a triage-coloured card, chip or border. */
export function triageClass(level: TriageLevel): string {
  return `is-${level.toLowerCase()}`;
}

/**
 * The brand red, for the two places that cannot read a CSS custom property:
 * the `theme-color` meta tag and anything drawn into an image at build time.
 * Same value as `--md-red`; declared once so the two cannot drift.
 */
export const BRAND_RED = '#e5322d';

export const STYLESHEETS = {
  fonts: '@maildoc/ui/fonts.css',
  tokens: '@maildoc/ui/tokens.css',
  base: '@maildoc/ui/base.css',
  all: '@maildoc/ui/maildoc.css',
} as const;
