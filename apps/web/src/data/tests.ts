/**
 * The Lab's contents, in one place.
 *
 * The nav, the mega-menu, the Lab index and the sitemap all read from here, so
 * a test cannot be listed in one and missing from another — and a link can
 * never point at a page that does not exist, because `href` is only set once
 * the page is built.
 */

export interface LabTestEntry {
  name: string;
  /** Set when the page exists. Absent means it is still being built. */
  href?: string;
  tag: string;
  blurb: string;
}

export interface LabGroup {
  heading: string;
  tests: LabTestEntry[];
}

export const LAB_GROUPS: readonly LabGroup[] = [
  {
    heading: 'Authentication',
    tests: [
      {
        name: 'SPF Test',
        href: '/lab/spf-checker',
        tag: 'RFC 7208',
        blurb: 'Full chain walk with the exact 10-lookup count, plus the void lookups nobody else checks.',
      },
      {
        name: 'SPF Sender Test',
        href: '/lab/spf-ip-checker',
        tag: 'RFC 7208 §4',
        blurb: 'Is this IP allowed to send as you? The evaluation a receiver runs, with the trace.',
      },
      {
        name: 'DMARC Test',
        href: '/lab/dmarc-checker',
        tag: 'RFC 9989',
        blurb: 'Tree-walk discovery, inheritance, test mode and the policy receivers really apply.',
      },
      {
        name: 'DKIM Test',
        href: '/lab/dkim-checker',
        tag: 'RFC 6376',
        blurb: 'Selector discovery and the real key length, read from the published key.',
      },
      {
        name: 'Spoofability',
        href: '/lab/spoofability',
        tag: 'the scary one',
        blurb: 'Can somebody send as you right now? One verdict, no hedging.',
      },
    ],
  },
  {
    heading: 'Infrastructure',
    tests: [
      {
        name: 'MX Lookup',
        href: '/lab/mx-lookup',
        tag: 'RFC 5321',
        blurb: 'Mail exchangers, priorities, and whether each target actually resolves.',
      },
      {
        name: 'DNSSEC Test',
        href: '/lab/dnssec-checker',
        tag: 'RFC 4035',
        blurb: 'Signed, validating, or signed-with-a-broken-chain, the three states that matter.',
      },
      {
        name: 'Reverse DNS',
        href: '/lab/reverse-dns',
        tag: 'PTR · FCrDNS',
        blurb: 'Do your sending IPs resolve back to a name, and does that name resolve forward again?',
      },
      {
        name: 'DNS Records',
        href: '/lab/dns-records',
        tag: 'lookup',
        blurb: 'Every record on one page, the way a mail server reads them.',
      },
    ],
  },
  {
    heading: 'Transport & brand',
    tests: [
      {
        name: 'MTA-STS Test',
        href: '/lab/mta-sts-checker',
        tag: 'RFC 8461',
        blurb: 'Fetches the policy the way a sender does, HTTPS, no redirects, and checks it against your MX.',
      },
      {
        name: 'TLS-RPT Test',
        href: '/lab/tls-rpt-checker',
        tag: 'RFC 8460',
        blurb: 'Are TLS failures being reported to anyone, or happening in silence?',
      },
      {
        name: 'BIMI Test',
        href: '/lab/bimi-checker',
        tag: 'draft',
        blurb: 'Logo, certificate, and the DMARC enforcement BIMI depends on.',
      },
      {
        name: 'CAA Test',
        href: '/lab/caa-checker',
        tag: 'RFC 8659',
        blurb: 'Which certificate authorities may issue for your domain, and which may not.',
      },
    ],
  },
  {
    heading: 'Treatments & reports',
    tests: [
      {
        name: 'SPF Flattener',
        href: '/lab/spf-flattener',
        tag: 'treatment',
        blurb: 'Over the lookup limit? Expand the chain into addresses, with the staleness cost stated up front.',
      },
      {
        name: 'Sender Readiness',
        href: '/lab/sender-readiness',
        tag: 'Google · Yahoo · Microsoft',
        blurb: 'Will the bulk-sender rules reject you? Find out before they do.',
      },
      {
        name: 'Bloodwork',
        href: '/bloodwork',
        tag: 'DMARC reports',
        blurb: 'Read your aggregate reports without a spreadsheet. Parsed in your browser.',
      },
      {
        name: 'DMARC Generator',
        href: '/lab/dmarc-generator',
        tag: 'builder',
        blurb: 'Build a DMARC record with the policy, subdomain rules and reporting you actually want.',
      },
      {
        name: 'SPF Generator',
        href: '/lab/spf-generator',
        tag: 'builder',
        blurb: 'Build an SPF record, with a live count of the lookups you are spending.',
      },
      {
        name: 'MTA-STS Generator',
        href: '/lab/mta-sts-generator',
        tag: 'builder',
        blurb: 'Build the DNS record and the policy file it points at, with a fresh id.',
      },
      {
        name: 'TLS-RPT Generator',
        href: '/lab/tls-rpt-generator',
        tag: 'builder',
        blurb: 'Build the record that gets TLS failures reported to you.',
      },
    ],
  },
];

/** Every Lab page that exists, for the nav and the sitemap. */
export const LIVE_TESTS: LabTestEntry[] = LAB_GROUPS.flatMap((group) =>
  group.tests.filter((test) => test.href !== undefined),
);
