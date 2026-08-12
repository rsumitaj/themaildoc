import { describe, expect, it } from 'vitest';
import {
  parseAggregateReport,
  parseAggregateReports,
  parseReportFilename,
} from '../src/dmarc/parse.js';
import { ReportParseError } from '../src/dmarc/types.js';
import { DMARCBIS, MICROSOFT, SAMPLE } from './fixtures.js';

describe('parseAggregateReport', () => {
  const report = parseAggregateReport(SAMPLE, 'google.com!example.com!1706745600!1706832000.xml');

  it('reads the reporter and the window', () => {
    expect(report.reporter.org).toBe('Google Inc.');
    expect(report.reporter.email).toBe('noreply-dmarc-support@google.com');
    expect(report.reporter.reportId).toBe('12345678901234567890');
    expect(report.range).toEqual({ begin: 1_706_745_600, end: 1_706_832_000 });
    expect(report.source).toContain('google.com!example.com');
  });

  it('reads the published policy', () => {
    expect(report.policy).toMatchObject({
      domain: 'example.com',
      adkim: 'r',
      aspf: 'r',
      p: 'reject',
      sp: 'reject',
      np: null,
      pct: 100,
      testing: false,
    });
  });

  it('reads every record with its counts and dispositions', () => {
    expect(report.rows).toHaveLength(5);
    expect(report.rows.reduce((total, row) => total + row.count, 0)).toBe(1672);
    expect(report.rows.map((row) => row.disposition)).toEqual([
      'none',
      'none',
      'reject',
      'quarantine',
      'none',
    ]);
  });

  it('keeps the authentication detail, not just the summary', () => {
    const forwarded = report.rows[3];
    expect(forwarded?.sourceIp).toBe('192.0.2.50');
    expect(forwarded?.evaluated).toEqual({ dkim: 'fail', spf: 'pass' });
    expect(forwarded?.dkim[0]).toEqual({
      domain: 'example.com',
      selector: 'google',
      result: 'fail',
      human: 'signature verification failed',
    });
    expect(forwarded?.spf[0]?.domain).toBe('forwarder.com');
    expect(forwarded?.envelopeTo).toBe('recipient.com');
  });

  it('reads policy override reasons', () => {
    expect(report.rows[3]?.overrides).toEqual([
      { type: 'forwarded', comment: 'Message was forwarded by known forwarder' },
    ]);
    expect(report.rows[4]?.overrides).toEqual([{ type: 'mailing_list', comment: null }]);
  });

  it('refuses a file that is not an aggregate report', () => {
    expect(() => parseAggregateReport('<html><body>hi</body></html>')).toThrow(ReportParseError);
    expect(() => parseAggregateReport('<html/>')).toThrow(/not a DMARC aggregate report/);
  });

  it('refuses a report shell with nothing in it', () => {
    expect(() => parseAggregateReport('<feedback><version>1</version></feedback>')).toThrow(
      /nothing in it to read/,
    );
  });
});

describe('reporter variations', () => {
  it('reads a namespaced report and defaults the alignment tags', () => {
    const report = parseAggregateReport(MICROSOFT);
    // RFC 9989 §4.7: relaxed is the default for both adkim and aspf.
    expect(report.policy.adkim).toBe('r');
    expect(report.policy.aspf).toBe('r');
    expect(report.policy.domain).toBe('example.com'); // trailing dot and case removed
    expect(report.policy.pct).toBe(50);
    expect(report.rows[0]?.sourceIp).toBe('2a01:111:f400:7e1a::711');
    expect(report.rows[0]?.spf[0]?.scope).toBe('mfrom');
  });

  it('reads the DMARCbis additions', () => {
    const report = parseAggregateReport(DMARCBIS);
    expect(report.policy.np).toBe('reject');
    expect(report.policy.testing).toBe(true);
    expect(report.policy.adkim).toBe('s');
    expect(report.errors).toEqual(['Could not resolve the reporting address on first attempt']);
    expect(report.extensions).toEqual(['something-new']);
  });

  it('treats a missing p as absent rather than inventing one', () => {
    // RFC 9989 §4.8 — a record without p is read as none; the parser records
    // what was there and lets the analyzer decide what it means.
    const report = parseAggregateReport(
      '<feedback><policy_published><domain>a.com</domain></policy_published>' +
        '<record><row><source_ip>1.2.3.4</source_ip><count>1</count></row></record></feedback>',
    );
    expect(report.policy.p).toBeNull();
    expect(report.policy.pct).toBeNull();
  });
});

describe('parseAggregateReports', () => {
  it('keeps the readable files and explains the rest', () => {
    const result = parseAggregateReports([
      { name: 'one.xml', xml: SAMPLE },
      { name: 'broken.xml', xml: '<feedback><record>' },
      { name: 'two.xml', xml: MICROSOFT },
    ]);

    expect(result.reports).toHaveLength(2);
    expect(result.failures).toHaveLength(1);
    expect(result.failures[0]?.name).toBe('broken.xml');
  });
});

describe('parseReportFilename', () => {
  it('reads the receiver, domain and window off the name', () => {
    expect(parseReportFilename('google.com!example.com!1706745600!1706832000.xml.gz')).toEqual({
      receiver: 'google.com',
      domain: 'example.com',
      begin: 1_706_745_600,
      end: 1_706_832_000,
    });
  });

  it('returns null for anything else', () => {
    expect(parseReportFilename('report.xml')).toBeNull();
    expect(parseReportFilename('a!b!notanumber!x.xml')).toBeNull();
  });
});
