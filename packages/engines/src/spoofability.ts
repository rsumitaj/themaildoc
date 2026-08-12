import type { DmarcAnalysis } from './dmarc/types.js';
import type { SpfAnalysis } from './spf/types.js';

export type SpoofVerdict = 'SPOOFABLE' | 'PARTIAL' | 'PROTECTED';

export interface Spoofability {
  verdict: SpoofVerdict;
  headline: string;
  detail: string;
  /** The specific facts behind the verdict, most important first. */
  reasons: string[];
}

/**
 * Can somebody put this domain in the From header of their mail right now?
 *
 * DMARC is what decides it — SPF alone never stops From-header spoofing,
 * because SPF authenticates the envelope, not the address the recipient sees.
 * So the verdict follows the *effective* DMARC policy: the one receivers really
 * apply, after inheritance (`sp`) and test mode (`t=y`) are taken into account.
 * A domain publishing `p=reject; t=y` is spoofable, and telling it otherwise
 * would be the most expensive mistake this product could make.
 */
export function assessSpoofability(
  domain: string,
  dmarc: DmarcAnalysis,
  spf: SpfAnalysis | null,
): Spoofability {
  const reasons: string[] = [];

  if (!dmarc.found) {
    reasons.push(`${domain} publishes no DMARC record, so receivers have no instruction to refuse forged mail.`);
  } else if (dmarc.ignored) {
    reasons.push('The DMARC record is malformed, so receivers ignore it entirely.');
  } else if (dmarc.testMode && dmarc.appliedPolicy !== 'none') {
    reasons.push(
      `The record asks for p=${dmarc.appliedPolicy}, but t=y tells receivers to apply p=none instead.`,
    );
  } else if (dmarc.appliedPolicy === 'none') {
    reasons.push('DMARC is set to p=none, which reports spoofing but never blocks it.');
  }

  if (dmarc.discovery.source === 'parent' && dmarc.found) {
    reasons.push(
      `The policy is inherited from ${dmarc.discovery.foundAt}, so this domain is governed by its sp value.`,
    );
  }

  if (spf) {
    if (!spf.found) {
      reasons.push('There is no SPF record, so nothing limits which servers may send for you.');
    } else if (spf.allQualifier === '+' || spf.allQualifier === '?') {
      reasons.push(`SPF ends in ${spf.allQualifier}all, which authorises every server on the internet.`);
    } else if (spf.lookupCount > 10) {
      reasons.push(
        `SPF costs ${spf.lookupCount} lookups and returns a permanent error, so SPF authentication fails even for your own servers.`,
      );
    }
  }

  if (dmarc.effectivePolicy === 'reject') {
    return {
      verdict: 'PROTECTED',
      headline: 'Protected, your domain can’t be easily spoofed',
      detail:
        'DMARC is enforced at p=reject, so mail that fails authentication is refused rather than delivered. This is the goal, and you are there.',
      reasons,
    };
  }

  if (dmarc.effectivePolicy === 'quarantine') {
    return {
      verdict: 'PARTIAL',
      headline: 'Partial immunity: spoofed mail still reaches the mailbox',
      detail:
        'Forged mail is sent to the spam folder rather than refused. Recipients can still find it, open it and act on it. One step short of protection.',
      reasons,
    };
  }

  return {
    verdict: 'SPOOFABLE',
    headline: 'Your domain can be spoofed right now',
    detail: `Anyone on the internet can send email that appears to come from ${domain}, and receivers have no instruction to stop it. This is the condition to treat first.`,
    reasons,
  };
}
