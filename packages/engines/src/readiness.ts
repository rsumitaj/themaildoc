/**
 * Bulk-sender readiness — the Google, Yahoo and Microsoft requirements.
 *
 * This file derives everything from analyses that have already run, so it costs
 * no DNS queries and can be computed in the browser. It imports types only,
 * which is what keeps `@maildoc/engines/readiness` small enough to ship to a
 * visitor.
 *
 * The honesty rule matters more here than anywhere else in the product. Three
 * of the requirements — TLS on transmission, one-click unsubscribe, and the
 * spam-complaint rate — cannot be determined from DNS by anyone. Tools that
 * show them as green ticks are guessing. We mark them UNVERIFIABLE and say who
 * can actually check them.
 */

export type RequirementStatus = 'PASS' | 'FAIL' | 'WARN' | 'UNVERIFIABLE';

export interface Requirement {
  id: string;
  title: string;
  status: RequirementStatus;
  /** What we found, or why we cannot know. */
  detail: string;
  /** What to do when it is not passing. */
  fix?: string;
  /** Required of every sender, or only of bulk senders (5,000+ a day). */
  scope: 'all' | 'bulk';
}

export interface Readiness {
  domain: string;
  /** Requirements we could determine, and how many passed. */
  passed: number;
  checkable: number;
  failed: number;
  /** True when nothing checkable is failing. */
  ready: boolean;
  requirements: Requirement[];
}

/** The pieces of a checkup this derivation needs. */
export interface ReadinessInput {
  domain: string;
  spf: {
    found: boolean;
    allQualifier: string | null;
    lookupCount: number;
  };
  dmarc: {
    found: boolean;
    effectivePolicy: 'none' | 'quarantine' | 'reject';
    alignment: { dkim: 'r' | 's'; spf: 'r' | 's' };
    rua: string[];
  };
  dkim: {
    found: boolean;
    /** Smallest key we found, in bits. */
    weakestKey: number | null;
  } | null;
  ptr: {
    checked: number;
    forwardConfirmed: number;
    noOwnServers: boolean;
  };
  mtasts: { announced: boolean };
}

export function assessReadiness(input: ReadinessInput): Readiness {
  const requirements: Requirement[] = [
    spfRequirement(input),
    dkimRequirement(input),
    dmarcRequirement(input),
    alignmentRequirement(input),
    reverseDnsRequirement(input),
    tlsRequirement(input),
    unsubscribeRequirement(),
    spamRateRequirement(),
    formatRequirement(),
  ];

  const checkable = requirements.filter((item) => item.status !== 'UNVERIFIABLE');
  const passed = checkable.filter((item) => item.status === 'PASS').length;
  const failed = checkable.filter((item) => item.status === 'FAIL').length;

  return {
    domain: input.domain,
    passed,
    checkable: checkable.length,
    failed,
    ready: failed === 0,
    requirements,
  };
}

function spfRequirement({ spf }: ReadinessInput): Requirement {
  if (!spf.found) {
    return {
      id: 'spf',
      title: 'SPF record published',
      status: 'FAIL',
      detail: 'No SPF record. Bulk senders are required to authenticate with SPF and DKIM.',
      fix: 'Publish an SPF record listing every service that sends your mail, ending in ~all.',
      scope: 'all',
    };
  }
  if (spf.lookupCount > 10) {
    return {
      id: 'spf',
      title: 'SPF record published',
      status: 'FAIL',
      detail: `SPF is published but costs ${spf.lookupCount} DNS lookups, over the limit of 10. Receivers return a permanent error, so SPF does not pass, which counts as no SPF.`,
      fix: 'Reduce the record under 10 lookups, or flatten stable includes into ip4:/ip6: ranges.',
      scope: 'all',
    };
  }
  if (spf.allQualifier === '+' || spf.allQualifier === '?') {
    return {
      id: 'spf',
      title: 'SPF record published',
      status: 'WARN',
      detail: `SPF ends in ${spf.allQualifier}all, which authorises senders indiscriminately. It passes, and it protects nothing.`,
      fix: 'Change the closing mechanism to ~all, then -all.',
      scope: 'all',
    };
  }
  return {
    id: 'spf',
    title: 'SPF record published',
    status: 'PASS',
    detail: `Published and within the lookup limit (${spf.lookupCount} of 10).`,
    scope: 'all',
  };
}

function dkimRequirement({ dkim }: ReadinessInput): Requirement {
  if (dkim === null) {
    return {
      id: 'dkim',
      title: 'DKIM signing enabled',
      status: 'UNVERIFIABLE',
      detail: 'The DKIM check has not run for this domain yet.',
      scope: 'all',
    };
  }
  if (!dkim.found) {
    return {
      id: 'dkim',
      title: 'DKIM signing enabled',
      status: 'WARN',
      detail:
        'No key answered at the selectors we probe. DKIM has no index in DNS, so this may simply be a selector we do not know, check the DKIM-Signature header of a message you sent.',
      fix: 'If your mail genuinely is not signed, enable DKIM in your provider. Bulk senders are required to have it.',
      scope: 'all',
    };
  }
  if (dkim.weakestKey !== null && dkim.weakestKey < 1024) {
    return {
      id: 'dkim',
      title: 'DKIM signing enabled',
      status: 'FAIL',
      detail: `The weakest key we found is ${dkim.weakestKey} bits. Verifiers must not accept keys below 1024, so those signatures do not count as signed.`,
      fix: 'Rotate to a 2048-bit key.',
      scope: 'all',
    };
  }
  return {
    id: 'dkim',
    title: 'DKIM signing enabled',
    status: 'PASS',
    detail:
      dkim.weakestKey !== null
        ? `Signing keys published, the weakest being ${dkim.weakestKey} bits.`
        : 'Signing keys published.',
    scope: 'all',
  };
}

function dmarcRequirement({ dmarc }: ReadinessInput): Requirement {
  if (!dmarc.found) {
    return {
      id: 'dmarc',
      title: 'DMARC policy published',
      status: 'FAIL',
      detail: 'No DMARC record. Bulk senders must publish one, at minimum p=none.',
      fix: 'Publish _dmarc with v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com and progress from there.',
      scope: 'bulk',
    };
  }
  if (dmarc.rua.length === 0) {
    return {
      id: 'dmarc',
      title: 'DMARC policy published',
      status: 'WARN',
      detail: `Published at p=${dmarc.effectivePolicy}, but with no reporting address you cannot see who sends as you or whether enforcement is safe.`,
      fix: 'Add rua=mailto:dmarc@yourdomain.com.',
      scope: 'bulk',
    };
  }
  return {
    id: 'dmarc',
    title: 'DMARC policy published',
    status: 'PASS',
    detail: `Published and enforcing at p=${dmarc.effectivePolicy}.`,
    scope: 'bulk',
  };
}

function alignmentRequirement({ dmarc, spf, dkim }: ReadinessInput): Requirement {
  if (!dmarc.found) {
    return {
      id: 'alignment',
      title: 'From address aligns with SPF or DKIM',
      status: 'FAIL',
      detail: 'Without DMARC there is no alignment requirement being applied, and none being met.',
      fix: 'Publish DMARC first; alignment is what it measures.',
      scope: 'bulk',
    };
  }

  const canAlign = spf.found || (dkim?.found ?? false);
  if (!canAlign) {
    return {
      id: 'alignment',
      title: 'From address aligns with SPF or DKIM',
      status: 'FAIL',
      detail: 'Neither SPF nor DKIM is in place, so nothing can align with your From address.',
      fix: 'Publish SPF and enable DKIM signing.',
      scope: 'bulk',
    };
  }

  const strict = dmarc.alignment.dkim === 's' || dmarc.alignment.spf === 's';
  return {
    id: 'alignment',
    title: 'From address aligns with SPF or DKIM',
    status: strict ? 'WARN' : 'PASS',
    detail: strict
      ? 'Strict alignment is configured, which requires an exact domain match. Vendors signing with their own domain, and any subdomain sender, will fail.'
      : 'Relaxed alignment with SPF and DKIM in place, the usual, workable configuration.',
    ...(strict
      ? { fix: 'Confirm every sender matches your domain exactly, or switch adkim/aspf to r.' }
      : {}),
    scope: 'bulk',
  };
}

function reverseDnsRequirement({ ptr }: ReadinessInput): Requirement {
  if (ptr.noOwnServers) {
    return {
      id: 'ptr',
      title: 'Sending IPs have valid forward and reverse DNS',
      status: 'UNVERIFIABLE',
      detail:
        'You publish no mail servers of your own, so your sending IPs belong to your provider. Their reverse DNS is their responsibility, and the large providers get it right.',
      scope: 'all',
    };
  }
  if (ptr.checked === 0) {
    return {
      id: 'ptr',
      title: 'Sending IPs have valid forward and reverse DNS',
      status: 'UNVERIFIABLE',
      detail: 'We could not check any addresses for this domain.',
      scope: 'all',
    };
  }
  if (ptr.forwardConfirmed < ptr.checked) {
    return {
      id: 'ptr',
      title: 'Sending IPs have valid forward and reverse DNS',
      status: 'FAIL',
      detail: `${ptr.checked - ptr.forwardConfirmed} of ${ptr.checked} addresses do not confirm both ways. Receivers reject mail from an IP whose reverse DNS does not round-trip.`,
      fix: 'Set the PTR at whoever controls the IP, and make sure that hostname resolves back to the same address.',
      scope: 'all',
    };
  }
  return {
    id: 'ptr',
    title: 'Sending IPs have valid forward and reverse DNS',
    status: 'PASS',
    detail: `${ptr.checked} of ${ptr.checked} addresses confirm in both directions.`,
    scope: 'all',
  };
}

function tlsRequirement({ mtasts }: ReadinessInput): Requirement {
  return {
    id: 'tls',
    title: 'Mail is transmitted over TLS',
    status: 'UNVERIFIABLE',
    detail: mtasts.announced
      ? 'Not determinable from DNS, the requirement is about the connections your servers make, which no external check can see. You do publish an MTA-STS policy, which shows the intent and protects mail coming the other way.'
      : 'Not determinable from DNS, the requirement is about the connections your servers make, which no external check can see. Practically every modern mail platform does this by default.',
    fix: 'Confirm with your sending platform that outbound TLS is on, and publish MTA-STS to protect inbound mail as well.',
    scope: 'all',
  };
}

function unsubscribeRequirement(): Requirement {
  return {
    id: 'unsubscribe',
    title: 'One-click unsubscribe in marketing mail',
    status: 'UNVERIFIABLE',
    detail:
      'This lives in message headers, not DNS, so it cannot be checked from outside. Send yourself a campaign and look for List-Unsubscribe and List-Unsubscribe-Post.',
    fix: 'Every mainstream marketing platform adds these headers, confirm yours is configured to.',
    scope: 'bulk',
  };
}

function spamRateRequirement(): Requirement {
  return {
    id: 'spam-rate',
    title: 'Spam complaint rate below 0.3%',
    status: 'UNVERIFIABLE',
    detail:
      'Only the receiving providers know this. Google Postmaster Tools reports it for Gmail, and it is free. If you send in volume and are not watching it, start there.',
    fix: 'Register your domain with Google Postmaster Tools and Microsoft SNDS.',
    scope: 'bulk',
  };
}

function formatRequirement(): Requirement {
  return {
    id: 'format',
    title: 'Messages are correctly formatted',
    status: 'UNVERIFIABLE',
    detail:
      'Valid From headers, matching envelope and message addresses, and no forged sender. A property of the mail itself rather than the domain.',
    scope: 'all',
  };
}
