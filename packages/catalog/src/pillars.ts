import type { Condition } from './types.js';

/**
 * The four things a Vitals score is actually made of.
 *
 * The old score started at 100 and subtracted every finding's weight from one
 * pool. That is easy to explain and it produced answers that were plainly
 * wrong. `online.sbi.bank.in` scored 0 out of 100 while the same page said
 * "Protected, your domain can't be easily spoofed": four findings worth
 * 40+40+25+25 clamped the pool to zero, and nobody can be more exposed than
 * zero, so a domain that cannot be spoofed at all sat level with a domain that
 * has no DNS whatsoever.
 *
 * The mistake was treating one pool as if every finding competed for it. They
 * do not. "Anyone can send as you" and "your CAA record is missing" are not
 * two sizes of the same problem; they are different questions with different
 * consequences, and a domain can be excellent at one while poor at another.
 *
 * So the score is four questions, each answered out of 100, then weighted:
 *
 *   Impersonation  45  Can somebody send mail as you? RFC 9989, 7208, 6376.
 *   Delivery       25  Will the mail you send actually arrive? RFC 7208, 8301.
 *   Visibility     15  Would you find out? RFC 9990.
 *   Hardening      15  Optional strengthening. RFC 8461, 4033, 8659.
 *
 * Impersonation carries the most weight because it is the one that ends up in
 * a news story. Hardening carries the least because no receiver requires any of
 * it. A pillar cannot fall below zero, so a catastrophe in one place can no
 * longer drag the whole number to nothing.
 */
export type Pillar = 'IMPERSONATION' | 'DELIVERY' | 'VISIBILITY' | 'HARDENING';

export const PILLAR_WEIGHT: Record<Pillar, number> = {
  IMPERSONATION: 45,
  DELIVERY: 25,
  VISIBILITY: 15,
  HARDENING: 15,
};

export const PILLAR_LABEL: Record<Pillar, string> = {
  IMPERSONATION: 'Impersonation defence',
  DELIVERY: 'Delivery integrity',
  VISIBILITY: 'Visibility',
  HARDENING: 'Hardening',
};

export const PILLAR_QUESTION: Record<Pillar, string> = {
  IMPERSONATION: 'Can somebody send mail that looks like it came from you?',
  DELIVERY: 'Will the mail you really send arrive?',
  VISIBILITY: 'Would you find out if either went wrong?',
  HARDENING: 'Optional protections that no receiver requires but good senders publish.',
};

export const PILLAR_ORDER: readonly Pillar[] = [
  'IMPERSONATION',
  'DELIVERY',
  'VISIBILITY',
  'HARDENING',
];

/**
 * Codes whose pillar does not follow from their record and category.
 *
 * Kept small on purpose. If this table starts growing, the defaults below are
 * wrong and should be fixed instead.
 */
const CODE_PILLAR: Record<string, Pillar> = {
  // An unsigned zone is a hardening gap. A zone whose signatures fail is a
  // domain that has stopped resolving for every validating receiver, which is
  // a delivery emergency rather than a missing nicety.
  DNSSEC_BOGUS: 'DELIVERY',
  DNSSEC_DS_MISSING: 'HARDENING',

  // TLS reporting tells you when transport security fails. That is visibility,
  // not the protection itself.
  TLSRPT_MISSING: 'VISIBILITY',

  // A revoked or weak DKIM key is what lets somebody sign as you.
  DKIM_KEY_REVOKED: 'IMPERSONATION',
  DKIM_KEY_WEAK_1024: 'IMPERSONATION',
  DKIM_WILDCARD_KEY: 'IMPERSONATION',

  // We could not finish a lookup. That is our problem, and it belongs to no
  // pillar; it scores nothing either way.
  RESOLVER_TIMEOUT: 'DELIVERY',
  PROPAGATION_IN_PROGRESS: 'DELIVERY',
};

const RECORD_PILLAR: Record<string, Pillar> = {
  MTASTS: 'HARDENING',
  BIMI: 'HARDENING',
  CAA: 'HARDENING',
  DNSSEC: 'HARDENING',
  TLSRPT: 'VISIBILITY',
  MX: 'DELIVERY',
  A: 'DELIVERY',
  PTR: 'DELIVERY',
  GENERIC: 'DELIVERY',
};

/**
 * Which question a finding answers.
 *
 * SPF and DMARC split by what the finding is about rather than which record it
 * sits in: an SPF record that authorises the whole internet is an
 * impersonation problem, while an SPF record that blows the ten-lookup limit is
 * a delivery problem, and they live in the same TXT string.
 */
export function pillarFor(condition: Pick<Condition, 'code' | 'record' | 'category'>): Pillar {
  const override = CODE_PILLAR[condition.code];
  if (override) return override;

  const byRecord = RECORD_PILLAR[condition.record];
  if (byRecord) return byRecord;

  if (condition.record === 'DMARC') {
    // rua, ruf and external destination authorisation are all about whether
    // you can see what is happening, not about whether the policy protects you.
    return condition.category === 'reporting' ? 'VISIBILITY' : 'IMPERSONATION';
  }

  if (condition.record === 'SPF') {
    return condition.category === 'policy' || condition.category === 'existence'
      ? 'IMPERSONATION'
      : 'DELIVERY';
  }

  if (condition.record === 'DKIM') {
    return condition.category === 'crypto' ? 'IMPERSONATION' : 'DELIVERY';
  }

  return 'DELIVERY';
}
