import { child, childList, intOf, parseXml, textOf, XmlError, type XmlNode } from '../xml.js';
import {
  ReportParseError,
  type AggregateReport,
  type AlignmentMode,
  type AuthResult,
  type Disposition,
  type DkimAuthResult,
  type PolicyOverride,
  type PublishedPolicy,
  type ReportRow,
  type SpfAuthResult,
} from './types.js';

/**
 * Read one aggregate report into the normalised shape.
 *
 * Every field is read defensively. Reporters disagree about optional elements,
 * about capitalisation, and about whether `<pct>` is a number — and a report
 * that is 99% readable should give you 99% of the picture, not an error page.
 * Only a file that is not a DMARC report at all is refused.
 */
export function parseAggregateReport(xml: string, source?: string): AggregateReport {
  let root: XmlNode;
  try {
    root = parseXml(xml);
  } catch (caught) {
    if (caught instanceof XmlError) throw new ReportParseError(caught.message);
    throw caught;
  }

  if (root.name !== 'feedback') {
    throw new ReportParseError(
      `That file's root element is <${root.name}>, not <feedback>, it is not a DMARC aggregate report.`,
    );
  }

  const metadata = child(root, 'report_metadata');
  const published = child(root, 'policy_published');
  const rows = childList(root, 'record').map(readRow);

  if (!published && rows.length === 0) {
    throw new ReportParseError(
      'That file is shaped like a report but carries no policy and no records, there is nothing in it to read.',
    );
  }

  const report: AggregateReport = {
    reporter: {
      org: textOf(metadata, 'org_name') || 'Unnamed reporter',
      email: textOf(metadata, 'email'),
      contact: textOf(metadata, 'extra_contact_info') || null,
      reportId: textOf(metadata, 'report_id'),
    },
    range: readRange(child(metadata, 'date_range')),
    errors: childList(metadata, 'error')
      .map((node) => node.text)
      .filter(Boolean),
    policy: readPolicy(published),
    rows,
    extensions: readExtensions(root),
    ...(source === undefined ? {} : { source }),
  };

  return report;
}

/** RFC 9990 §3.2 — record what a reporter added without pretending to read it. */
function readExtensions(root: XmlNode): string[] {
  const container = child(root, 'extensions') ?? child(root, 'extension');
  if (!container) return [];
  return [...new Set(container.children.map((node) => node.name))];
}

/** Parse several files at once, keeping the ones that read. */
export function parseAggregateReports(
  files: readonly { name: string; xml: string }[],
): { reports: AggregateReport[]; failures: { name: string; message: string }[] } {
  const reports: AggregateReport[] = [];
  const failures: { name: string; message: string }[] = [];

  for (const file of files) {
    try {
      reports.push(parseAggregateReport(file.xml, file.name));
    } catch (caught) {
      failures.push({
        name: file.name,
        message: caught instanceof Error ? caught.message : 'This file could not be read.',
      });
    }
  }

  return { reports, failures };
}

function readRange(node: XmlNode | undefined): { begin: number; end: number } {
  const begin = intOf(node, 'begin') ?? 0;
  const end = intOf(node, 'end') ?? 0;
  return { begin, end: end >= begin ? end : begin };
}

function readPolicy(node: XmlNode | undefined): PublishedPolicy {
  return {
    domain: textOf(node, 'domain').toLowerCase().replace(/\.$/, ''),
    adkim: alignment(textOf(node, 'adkim')),
    aspf: alignment(textOf(node, 'aspf')),
    p: disposition(textOf(node, 'p')) ?? null,
    sp: disposition(textOf(node, 'sp')) ?? null,
    np: disposition(textOf(node, 'np')) ?? null,
    pct: readPct(node),
    fo: textOf(node, 'fo') || null,
    testing: /^y(es)?$/i.test(textOf(node, 't') || textOf(node, 'testing')),
  };
}

function readPct(node: XmlNode | undefined): number | null {
  const value = intOf(node, 'pct');
  if (value === null) return null;
  return Math.min(100, Math.max(0, value));
}

function readRow(node: XmlNode): ReportRow {
  const row = child(node, 'row');
  const evaluated = child(row, 'policy_evaluated');
  const identifiers = child(node, 'identifiers');
  const auth = child(node, 'auth_results');

  return {
    sourceIp: textOf(row, 'source_ip').trim(),
    count: Math.max(0, intOf(row, 'count') ?? 0),
    disposition: disposition(textOf(evaluated, 'disposition')) ?? 'unknown',
    evaluated: {
      dkim: authResult(textOf(evaluated, 'dkim')),
      spf: authResult(textOf(evaluated, 'spf')),
    },
    overrides: readOverrides(evaluated),
    headerFrom: normaliseDomain(textOf(identifiers, 'header_from')),
    envelopeFrom: normaliseDomain(textOf(identifiers, 'envelope_from')) || null,
    envelopeTo: normaliseDomain(textOf(identifiers, 'envelope_to')) || null,
    dkim: childList(auth, 'dkim').map(readDkim),
    spf: childList(auth, 'spf').map(readSpf),
  };
}

function readOverrides(evaluated: XmlNode | undefined): PolicyOverride[] {
  return childList(evaluated, 'reason').map((node) => ({
    type: textOf(node, 'type').toLowerCase() || 'unspecified',
    comment: textOf(node, 'comment') || null,
  }));
}

function readDkim(node: XmlNode): DkimAuthResult {
  return {
    domain: normaliseDomain(textOf(node, 'domain')),
    selector: textOf(node, 'selector') || null,
    result: authResult(textOf(node, 'result')),
    human: textOf(node, 'human_result') || null,
  };
}

function readSpf(node: XmlNode): SpfAuthResult {
  return {
    domain: normaliseDomain(textOf(node, 'domain')),
    scope: textOf(node, 'scope').toLowerCase() || null,
    result: authResult(textOf(node, 'result')),
  };
}

const RESULTS: readonly AuthResult[] = [
  'pass',
  'fail',
  'none',
  'neutral',
  'softfail',
  'temperror',
  'permerror',
  'policy',
];

function authResult(raw: string): AuthResult {
  const value = raw.trim().toLowerCase();
  // Some reporters still send the pre-standard spellings.
  if (value === 'hardfail') return 'fail';
  if (value === 'temperror' || value === 'error') return 'temperror';
  return (RESULTS as readonly string[]).includes(value) ? (value as AuthResult) : 'unknown';
}

function disposition(raw: string): Disposition | null {
  const value = raw.trim().toLowerCase();
  if (value === 'none' || value === 'quarantine' || value === 'reject') return value;
  return null;
}

function alignment(raw: string): AlignmentMode {
  // RFC 9989 §4.7: relaxed is the default for both.
  return raw.trim().toLowerCase() === 's' ? 's' : 'r';
}

function normaliseDomain(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Aggregate reports are named
 * `receiver!policy-domain!begin!end[!unique].extension` (RFC 9990 §3.5.2), so
 * the filename alone tells you who sent it and what window it covers — useful
 * before a single byte is decompressed.
 */
export interface ReportFilename {
  receiver: string;
  domain: string;
  begin: number;
  end: number;
}

export function parseReportFilename(name: string): ReportFilename | null {
  const base = name.replace(/\.(xml|gz|zip)$/gi, '').replace(/\.(xml)$/i, '');
  const parts = base.split('!');
  if (parts.length < 4) return null;

  const begin = Number.parseInt(parts[2] ?? '', 10);
  const end = Number.parseInt(parts[3] ?? '', 10);
  if (!Number.isFinite(begin) || !Number.isFinite(end)) return null;

  return {
    receiver: (parts[0] ?? '').toLowerCase(),
    domain: (parts[1] ?? '').toLowerCase(),
    begin,
    end,
  };
}
