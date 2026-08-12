import { describe, expect, it } from 'vitest';
import { analyzeReports, isAligned } from '../src/dmarc/analyze.js';
import { parseAggregateReport } from '../src/dmarc/parse.js';
import { DMARCBIS, MICROSOFT, SAMPLE } from './fixtures.js';

const sample = analyzeReports([parseAggregateReport(SAMPLE)]);
const codes = (bloodwork = sample): string[] => bloodwork.findings.map((finding) => finding.code);

describe('isAligned', () => {
  it('requires an exact match under strict alignment', () => {
    expect(isAligned('example.com', 'example.com', 's', 'example.com')).toBe(true);
    expect(isAligned('mail.example.com', 'example.com', 's', 'example.com')).toBe(false);
  });

  it('accepts the organisational domain under relaxed alignment', () => {
    expect(isAligned('mail.example.com', 'example.com', 'r', 'example.com')).toBe(true);
    expect(isAligned('bounce.example.com', 'news.example.com', 'r', 'example.com')).toBe(true);
  });

  it('rejects a different domain however relaxed', () => {
    expect(isAligned('forwarder.com', 'example.com', 'r', 'example.com')).toBe(false);
    expect(isAligned('notexample.com', 'example.com', 'r', 'example.com')).toBe(false);
  });

  it('falls back to the registrable domain when the report names no anchor', () => {
    expect(isAligned('mail.example.com', 'example.com', 'r', '')).toBe(true);
    expect(isAligned('example.org', 'example.com', 'r', '')).toBe(false);
  });

  it('is false when either identifier is missing', () => {
    expect(isAligned('', 'example.com', 'r', 'example.com')).toBe(false);
    expect(isAligned('example.com', '', 'r', 'example.com')).toBe(false);
  });
});

describe('analyzeReports — the sample report', () => {
  it('counts every message once', () => {
    expect(sample.volume).toBe(1672);
    expect(sample.domain).toBe('example.com');
    expect(sample.sources).toHaveLength(5);
  });

  it('separates what the receiver said from what the evidence shows', () => {
    // Google recorded 1,630 as passing. 15 of those were a forwarded message
    // credited to forwarder.com's SPF, which is not aligned with example.com.
    expect(sample.reportedPass).toBe(1630);
    expect(sample.aligned).toBe(1615);
    expect(sample.passRate).toBe(96.6);
    expect(sample.reportedPassRate).toBe(97.5);
    expect(sample.disagreements).toBe(15);
    expect(codes()).toContain('RUA_REPORTER_DISAGREES');
  });

  it('classifies every source for what it is', () => {
    const byIp = new Map(sample.sources.map((source) => [source.ip, source]));

    expect(byIp.get('209.85.220.41')?.verdict).toBe('AUTHORIZED');
    expect(byIp.get('198.51.100.42')?.verdict).toBe('AUTHORIZED');
    // Forged: nothing aligned, nothing of yours in the auth results.
    expect(byIp.get('203.0.113.99')?.verdict).toBe('UNAUTHENTICATED');
    // Relayed: your signature broke, an unrelated domain's SPF passed.
    expect(byIp.get('192.0.2.50')?.verdict).toBe('FORWARDED');
    // A list that stripped SPF but left the signature intact — still yours.
    expect(byIp.get('10.0.0.1')?.verdict).toBe('AUTHORIZED');
  });

  it('totals the volume behind each verdict', () => {
    expect(sample.totals).toEqual({
      AUTHORIZED: 1615,
      FORWARDED: 15,
      MISCONFIGURED: 0,
      UNAUTHENTICATED: 42,
    });
  });

  it('names the platform from the report’s own evidence', () => {
    const byIp = new Map(sample.sources.map((source) => [source.ip, source]));
    expect(byIp.get('209.85.220.41')?.service).toBe('Google Workspace');
    expect(byIp.get('198.51.100.42')?.service).toBe('Resend');
    expect(byIp.get('203.0.113.99')?.service).toBeNull();
  });

  it('records the alignment of each identifier, not just its result', () => {
    const forwarded = sample.sources.find((source) => source.ip === '192.0.2.50');
    expect(forwarded?.dkim[0]).toMatchObject({ domain: 'example.com', aligned: true, result: 'fail' });
    expect(forwarded?.spf[0]).toMatchObject({ domain: 'forwarder.com', aligned: false, result: 'pass' });
    expect(forwarded?.overrides[0]?.type).toBe('forwarded');
  });

  it('reports the forged mail as blocked, because the policy blocked it', () => {
    expect(codes()).toContain('RUA_UNAUTHENTICATED_BLOCKED');
    expect(codes()).not.toContain('RUA_UNAUTHENTICATED_DELIVERED');
    const blocked = sample.findings.find((f) => f.code === 'RUA_UNAUTHENTICATED_BLOCKED');
    expect(blocked?.vars).toMatchObject({ count: 42, policy: 'reject' });
  });

  it('flags the addresses that prove this is sample data', () => {
    expect(codes()).toContain('RUA_SAMPLE_DATA');
    expect(codes()).toContain('RUA_PRIVATE_SOURCE_IP');
    expect(codes()).toContain('RUA_SHORT_WINDOW');
  });

  it('does not accuse a healthy domain of misconfiguration', () => {
    expect(codes()).not.toContain('RUA_OWN_MAIL_FAILING');
    expect(codes()).not.toContain('RUA_NOTHING_ALIGNED');
    expect(codes()).not.toContain('RUA_PCT_PARTIAL');
  });

  it('explains the forwarded message rather than calling it an attack', () => {
    expect(codes()).toContain('RUA_FORWARDED_MAIL');
    expect(codes()).toContain('RUA_DKIM_BROKEN_IN_TRANSIT');
    expect(codes()).toContain('RUA_POLICY_OVERRIDDEN');
  });
});

describe('analyzeReports — policy judgement', () => {
  it('calls out a partial rollout', () => {
    const microsoft = analyzeReports([parseAggregateReport(MICROSOFT)]);
    expect(codes(microsoft)).toContain('RUA_PCT_PARTIAL');
    expect(codes(microsoft)).toContain('RUA_POLICY_NONE_UNPROTECTED');
  });

  it('calls out testing mode and a weaker subdomain policy', () => {
    const yahoo = analyzeReports([parseAggregateReport(DMARCBIS)]);
    expect(codes(yahoo)).toContain('RUA_TESTING_MODE');
    expect(codes(yahoo)).toContain('RUA_SUBDOMAIN_POLICY_WEAKER');
  });

  it('does not recommend enforcement off a single day of data', () => {
    // p=none and 100% aligned, but one report covering one day.
    const clean = analyzeReports([
      parseAggregateReport(`<feedback>
        <report_metadata><org_name>x</org_name><date_range><begin>1000</begin><end>87400</end></date_range></report_metadata>
        <policy_published><domain>a.com</domain><p>none</p></policy_published>
        <record><row><source_ip>1.2.3.4</source_ip><count>900</count>
          <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
          <identifiers><header_from>a.com</header_from></identifiers>
          <auth_results><dkim><domain>a.com</domain><selector>s</selector><result>pass</result></dkim></auth_results>
        </record></feedback>`),
    ]);

    expect(clean.passRate).toBe(100);
    expect(codes(clean)).not.toContain('RUA_READY_FOR_ENFORCEMENT');
    expect(codes(clean)).toContain('RUA_POLICY_NONE_UNPROTECTED');
  });

  it('recommends enforcement once the evidence earns it', () => {
    const reports = Array.from({ length: 8 }, (_, day) =>
      parseAggregateReport(`<feedback>
        <report_metadata><org_name>r${day}</org_name>
          <date_range><begin>${1000 + day * 86_400}</begin><end>${1000 + (day + 1) * 86_400}</end></date_range>
        </report_metadata>
        <policy_published><domain>a.com</domain><p>none</p></policy_published>
        <record><row><source_ip>1.2.3.4</source_ip><count>100</count>
          <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
          <identifiers><header_from>a.com</header_from></identifiers>
          <auth_results><dkim><domain>a.com</domain><selector>s</selector><result>pass</result></dkim></auth_results>
        </record></feedback>`),
    );

    const ready = analyzeReports(reports);
    expect(ready.volume).toBe(800);
    expect(ready.range.days).toBe(8);
    expect(codes(ready)).toContain('RUA_READY_FOR_ENFORCEMENT');
    expect(codes(ready)).not.toContain('RUA_POLICY_NONE_UNPROTECTED');
    expect(codes(ready)).not.toContain('RUA_SHORT_WINDOW');
  });
});

describe('analyzeReports — the dangerous cases', () => {
  const failing = (policy: string, disposition: string) => `<feedback>
    <report_metadata><org_name>r</org_name><date_range><begin>0</begin><end>86400</end></date_range></report_metadata>
    <policy_published><domain>a.com</domain><p>${policy}</p></policy_published>
    <record><row><source_ip>198.18.0.9</source_ip><count>400</count>
      <policy_evaluated><disposition>${disposition}</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
      <identifiers><header_from>a.com</header_from></identifiers>
      <auth_results><spf><domain>attacker.net</domain><result>fail</result></spf></auth_results>
    </record></feedback>`;

  it('is loudest when forged mail is being delivered', () => {
    const exposed = analyzeReports([parseAggregateReport(failing('none', 'none'))]);
    expect(exposed.totals.UNAUTHENTICATED).toBe(400);
    expect(codes(exposed)).toContain('RUA_UNAUTHENTICATED_DELIVERED');
    expect(codes(exposed)).toContain('RUA_NOTHING_ALIGNED');
  });

  it('says so when an enforcing policy is being ignored', () => {
    const leaking = analyzeReports([parseAggregateReport(failing('reject', 'none'))]);
    expect(codes(leaking)).toContain('RUA_UNAUTHENTICATED_LEAKING');
    expect(codes(leaking)).not.toContain('RUA_UNAUTHENTICATED_DELIVERED');
  });

  it('separates your own broken senders from strangers', () => {
    const broken = analyzeReports([
      parseAggregateReport(`<feedback>
        <report_metadata><org_name>r</org_name><date_range><begin>0</begin><end>86400</end></date_range></report_metadata>
        <policy_published><domain>a.com</domain><p>none</p></policy_published>
        <record><row><source_ip>203.0.113.7</source_ip><count>50</count>
          <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
          <identifiers><header_from>a.com</header_from></identifiers>
          <auth_results><dkim><domain>a.com</domain><selector>bad</selector><result>fail</result></dkim></auth_results>
        </record></feedback>`),
    ]);

    expect(broken.sources[0]?.verdict).toBe('MISCONFIGURED');
    expect(codes(broken)).toContain('RUA_OWN_MAIL_FAILING');
    expect(codes(broken)).not.toContain('RUA_UNAUTHENTICATED_DELIVERED');
  });

  it('warns about senders that would not survive a forward', () => {
    const spfOnly = analyzeReports([
      parseAggregateReport(`<feedback>
        <report_metadata><org_name>r</org_name><date_range><begin>0</begin><end>86400</end></date_range></report_metadata>
        <policy_published><domain>a.com</domain><p>quarantine</p></policy_published>
        <record><row><source_ip>93.184.216.34</source_ip><count>500</count>
          <policy_evaluated><disposition>none</disposition><dkim>none</dkim><spf>pass</spf></policy_evaluated></row>
          <identifiers><header_from>a.com</header_from></identifiers>
          <auth_results><spf><domain>a.com</domain><result>pass</result></spf></auth_results>
        </record></feedback>`),
    ]);

    expect(codes(spfOnly)).toContain('RUA_SPF_ONLY_SOURCE');
    expect(codes(spfOnly)).toContain('RUA_READY_FOR_REJECT');
  });
});

describe('analyzeReports — merging files', () => {
  it('merges reporters, windows and sources into one picture', () => {
    const merged = analyzeReports([
      parseAggregateReport(SAMPLE),
      parseAggregateReport(MICROSOFT),
      parseAggregateReport(DMARCBIS),
    ]);

    expect(merged.reportCount).toBe(3);
    expect(merged.reporters.map((reporter) => reporter.org)).toContain('Enterprise Outlook');
    expect(merged.volume).toBe(1672 + 310 + 200);
    expect(merged.range.begin).toBe(1_706_572_800);
    expect(merged.range.end).toBe(1_706_832_000);
    expect(merged.timeline).toHaveLength(3);
    // Google's report is the most recent, so its policy is the live one.
    expect(merged.policy.p).toBe('reject');
    expect(codes(merged)).toContain('RUA_POLICY_CHANGED');
    expect(codes(merged)).toContain('RUA_REPORTER_ERROR');
  });

  it('refuses to analyse nothing', () => {
    expect(() => analyzeReports([])).toThrow(/no reports/);
  });
});
