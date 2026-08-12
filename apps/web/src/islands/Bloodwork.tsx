import { useMemo, useRef, useState } from 'preact/hooks';
import { createFinding } from '@maildoc/catalog/bloodwork';
import { sortConditions } from '@maildoc/catalog/scoring';
import {
  analyzeReports,
  parseAggregateReports,
  readReportFile,
  reverseName,
  type Bloodwork as Analysis,
  type Disposition,
  type IdentifierSummary,
  type Source,
  type SourceVerdict,
} from '@maildoc/report-parsers';
import { ConditionCard } from './Chart';
import { AlertIcon, ArrowIcon, CrossIcon, ShieldIcon, TickIcon } from './Icons';

/**
 * Bloodwork — your DMARC aggregate reports, read here in this tab.
 *
 * Not one byte of a report is uploaded: the file is decompressed, parsed,
 * analysed and rendered in the browser, and the page makes no request to our
 * server at any point after it loads. That is a promise on the page, so it is
 * enforced by there being no code here that could break it.
 *
 * Everything rendered is attacker-controlled text — a report is written by
 * whoever received your mail, and the domains inside it are chosen by whoever
 * sent it. All of it goes through JSX text nodes.
 */

const VERDICT_LABEL: Record<SourceVerdict, string> = {
  AUTHORIZED: 'Authorised',
  FORWARDED: 'Forwarded',
  MISCONFIGURED: 'Yours, broken',
  UNAUTHENTICATED: 'Not authenticated',
};

const VERDICT_TONE: Record<SourceVerdict, string> = {
  AUTHORIZED: 'is-healthy',
  FORWARDED: 'is-minor',
  MISCONFIGURED: 'is-urgent',
  UNAUTHENTICATED: 'is-critical',
};

const VERDICT_COLOR: Record<SourceVerdict, string> = {
  AUTHORIZED: 'var(--md-healthy)',
  FORWARDED: 'var(--md-minor)',
  MISCONFIGURED: 'var(--md-urgent)',
  UNAUTHENTICATED: 'var(--md-critical)',
};

const VERDICT_MEANING: Record<SourceVerdict, string> = {
  AUTHORIZED:
    'Passed DMARC with an identifier that belongs to you. This is your mail, arriving as it should.',
  FORWARDED:
    'Relayed on the way, a mailing list or an auto-forward. Your signature or envelope changed in transit, which is normal and not an attack. Worth confirming against your own senders.',
  MISCONFIGURED:
    'Claims your domain and fails anyway. This is a sender of yours with a broken key, a missing selector or an address absent from SPF, and it is the mail you lose the day you enforce.',
  UNAUTHENTICATED:
    'Nothing here belongs to you: no aligned signature, no aligned envelope. Somebody else is putting your domain in the From line.',
};

const BAND_TONE: Record<Analysis['band'], string> = {
  HEALTHY: 'is-healthy',
  NEEDS_CARE: '',
  AT_RISK: '',
  CRITICAL: 'is-critical',
};

const BAND_VERDICT: Record<Analysis['band'], string> = {
  HEALTHY: 'CLEAN RESULTS',
  NEEDS_CARE: 'MINOR ABNORMALITIES',
  AT_RISK: 'ABNORMAL RESULTS',
  CRITICAL: 'CRITICAL RESULTS',
};

const DISPOSITION_LABEL: Record<Disposition, string> = {
  none: 'delivered',
  quarantine: 'quarantined',
  reject: 'rejected',
  unknown: 'not recorded',
};

const POLICY_MEANING: Record<string, string> = {
  none: 'Receivers report on failures and deliver them anyway.',
  quarantine: 'Receivers put failing mail in the spam folder.',
  reject: 'Receivers refuse failing mail at the door.',
};

const OVERRIDE_MEANING: Record<string, string> = {
  forwarded: 'the receiver recognised this as forwarded mail',
  sampled_out: 'your pct tag excluded this message from the policy',
  trusted_forwarder: 'the receiver trusts this relay',
  mailing_list: 'the receiver recognised a mailing list',
  local_policy: 'the receiver applied its own rules instead',
  other: 'the receiver gave a reason of its own',
};

export default function Bloodwork() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [dragging, setDragging] = useState(false);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [failures, setFailures] = useState<{ name: string; message: string }[]>([]);
  const [loaded, setLoaded] = useState<string[]>([]);
  const [names, setNames] = useState<Record<string, string>>({});
  const [resolving, setResolving] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  async function examine(files: File[]): Promise<void> {
    if (files.length === 0) return;

    setBusy(true);
    setError('');
    setFailures([]);
    setNames({});

    try {
      const documents: { name: string; xml: string }[] = [];
      const broken: { name: string; message: string }[] = [];

      for (const file of files) {
        try {
          documents.push(...(await readReportFile(file)));
        } catch (caught) {
          broken.push({ name: file.name, message: message(caught) });
        }
      }

      const parsed = parseAggregateReports(documents);
      const allFailures = [...broken, ...parsed.failures];

      if (parsed.reports.length === 0) {
        setAnalysis(null);
        setLoaded([]);
        // One message, not two: the banner says it, so the list stays empty
        // unless there are several different reasons worth listing.
        setFailures(allFailures.length > 1 ? allFailures : []);
        setError(
          allFailures.length > 1
            ? 'None of those files could be read as DMARC reports.'
            : (allFailures[0]?.message ??
              'None of those files were DMARC aggregate reports. Drop the attachment exactly as it arrived.'),
        );
        return;
      }

      setFailures(allFailures);

      setAnalysis(analyzeReports(parsed.reports));
      setLoaded(documents.map((document) => document.name));
      setOpen(null);
    } catch (caught) {
      setError(message(caught));
      setAnalysis(null);
    } finally {
      setBusy(false);
    }
  }

  async function loadSample(): Promise<void> {
    setBusy(true);
    setError('');
    try {
      const response = await fetch('/sample-dmarc-report.xml');
      const xml = await response.text();
      const parsed = parseAggregateReports([{ name: 'sample-dmarc-report.xml', xml }]);
      if (parsed.reports.length === 0) throw new Error('The sample report could not be read.');
      setAnalysis(analyzeReports(parsed.reports));
      setLoaded(['sample-dmarc-report.xml']);
      setFailures([]);
      setNames({});
      setOpen(null);
    } catch (caught) {
      setError(message(caught));
    } finally {
      setBusy(false);
    }
  }

  /**
   * Optional: ask a public resolver what each sending address calls itself.
   *
   * It is a button rather than automatic because it is the one thing on this
   * page that leaves the tab. The reports stay here; only the IP addresses go,
   * and they go to Cloudflare's resolver rather than to us.
   */
  async function identify(): Promise<void> {
    if (!analysis) return;
    setResolving(true);

    const targets = analysis.sources
      .filter((source) => source.kind === 'public')
      .slice(0, 40)
      .map((source) => source.ip);

    const found: Record<string, string> = {};
    await Promise.all(
      targets.map(async (ip) => {
        const query = reverseName(ip);
        if (!query) return;
        try {
          const response = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query)}&type=PTR`,
            { headers: { accept: 'application/dns-json' } },
          );
          const data = (await response.json()) as { Answer?: { type: number; data: string }[] };
          const answer = data.Answer?.find((entry) => entry.type === 12);
          if (answer) found[ip] = answer.data.replace(/\.$/, '');
        } catch {
          // A resolver that will not answer is not a reason to lose the page.
        }
      }),
    );

    setNames(found);
    setResolving(false);
  }

  const findings = useMemo(() => {
    if (!analysis) return [];
    return sortConditions(
      analysis.findings.map((seed) =>
        createFinding(seed.code, seed.vars, seed.evidence === undefined ? {} : { evidence: seed.evidence }),
      ),
    );
  }, [analysis]);

  return (
    <div>
      <div
        class={`md-drop ${dragging ? 'is-over' : ''} ${busy ? 'is-busy' : ''}`}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          void examine([...(event.dataTransfer?.files ?? [])]);
        }}
      >
        <input
          ref={input}
          type="file"
          multiple
          accept=".xml,.gz,.zip,text/xml,application/gzip,application/zip"
          class="md-drop__input"
          onChange={(event) => {
            const picked = (event.target as HTMLInputElement).files;
            void examine([...(picked ?? [])]);
          }}
        />
        <p class="md-drop__title">
          {busy ? 'Examining…' : 'Drop your DMARC reports here'}
        </p>
        <p class="md-drop__note">
          .xml, .xml.gz or .zip, exactly as they arrived. Drop as many as you like, they merge into
          one picture.
        </p>
        <div class="md-drop__actions">
          <button type="button" class="md-btn" onClick={() => input.current?.click()} disabled={busy}>
            Choose files
            <ArrowIcon size={16} />
          </button>
          <button type="button" class="md-linkbtn" onClick={() => void loadSample()} disabled={busy}>
            or read a sample report
          </button>
        </div>
        <p class="md-drop__privacy">
          <ShieldIcon size={14} /> Read in this tab. Your reports are never uploaded.
        </p>
      </div>

      {error && (
        <p class="md-error" role="alert">
          {error}
        </p>
      )}

      {failures.length > 0 && (
        <div class="md-bwfailures">
          {failures.map((failure) => (
            <p key={failure.name}>
              <span class="md-mono">{failure.name}</span>, {failure.message}
            </p>
          ))}
        </div>
      )}

      {analysis && (
        <Results
          analysis={analysis}
          findings={findings}
          loaded={loaded}
          names={names}
          resolving={resolving}
          onIdentify={() => void identify()}
          open={open}
          onOpen={(ip) => setOpen(open === ip ? null : ip)}
        />
      )}
    </div>
  );
}

interface ResultsProps {
  analysis: Analysis;
  findings: ReturnType<typeof createFinding>[];
  loaded: string[];
  names: Record<string, string>;
  resolving: boolean;
  onIdentify: () => void;
  open: string | null;
  onOpen: (ip: string) => void;
}

function Results({
  analysis,
  findings,
  loaded,
  names,
  resolving,
  onIdentify,
  open,
  onOpen,
}: ResultsProps) {
  const { policy, totals, volume } = analysis;

  return (
    <div class="md-result md-bw">
      <header class="md-bw__head">
        <div>
          <div class="md-chart__head">
            <span class="md-chart__label">BLOODWORK</span>
            <span class="md-chart__domain">{policy.domain || 'your domain'}</span>
          </div>
          <p class="md-chart__meta">
            {count(volume)} messages · {dateRange(analysis.range)} ·{' '}
            {analysis.reportCount === 1 ? '1 report' : `${analysis.reportCount} reports`} from{' '}
            {analysis.reporters.map((reporter) => reporter.org).join(', ')}
          </p>
        </div>
      </header>

      <div class="md-bw__top">
        <div class={`md-vitals ${BAND_TONE[analysis.band]}`}>
          <div class="md-vitals__cap">ALIGNED &amp; AUTHENTICATED</div>
          <div class="md-vitals__score">
            {analysis.passRate}
            <span class="md-vitals__den">%</span>
          </div>
          <div class="md-vitals__verdict">{BAND_VERDICT[analysis.band]}</div>
          <div class="md-vitals__note">
            {count(analysis.aligned)} of {count(volume)} messages carried an identifier that is
            provably yours.
          </div>
        </div>

        <div class="md-bw__split">
          <h3>Where your mail came from</h3>
          <div class="md-bwbar" role="img" aria-label="Volume by verdict">
            {(['AUTHORIZED', 'FORWARDED', 'MISCONFIGURED', 'UNAUTHENTICATED'] as SourceVerdict[])
              .filter((verdict) => totals[verdict] > 0)
              .map((verdict) => (
                <span
                  key={verdict}
                  class="md-bwbar__seg"
                  style={{
                    width: `${(totals[verdict] / Math.max(1, volume)) * 100}%`,
                    background: VERDICT_COLOR[verdict],
                  }}
                  title={`${VERDICT_LABEL[verdict]}, ${count(totals[verdict])}`}
                />
              ))}
          </div>
          <ul class="md-bwlegend">
            {(['AUTHORIZED', 'FORWARDED', 'MISCONFIGURED', 'UNAUTHENTICATED'] as SourceVerdict[]).map(
              (verdict) => (
                <li key={verdict}>
                  <span class="md-dot" style={{ color: VERDICT_COLOR[verdict] }} />
                  <span class="md-bwlegend__label">{VERDICT_LABEL[verdict]}</span>
                  <span class="md-bwlegend__value">
                    {count(totals[verdict])}
                    <em>{percent(totals[verdict], volume)}</em>
                  </span>
                </li>
              ),
            )}
          </ul>
          {analysis.reportedPass !== analysis.aligned && (
            <p class="md-bw__caveat">
              The receivers recorded {percent(analysis.reportedPass, volume)} as passing. We count{' '}
              {percent(analysis.aligned, volume)}, because {count(analysis.disagreements)} of those
              messages have no identifier in the report that belongs to you, see the sources below.
            </p>
          )}
        </div>
      </div>

      {analysis.timeline.length >= 3 && <Trend analysis={analysis} />}

      <PolicyCard analysis={analysis} />

      <section class="md-bwsection">
        <div class="md-bwsection__head">
          <h3>Every source that sent as you</h3>
          <button type="button" class="md-linkbtn" onClick={onIdentify} disabled={resolving}>
            {resolving ? 'Resolving…' : 'Identify these senders'}
          </button>
        </div>
        <p class="md-bwsection__note">
          Ranked by volume. Open one to see the authentication the receiver recorded, exactly as it
          recorded it. "Identify" asks a public resolver what each address calls itself, it sends
          the addresses only, never the report.
        </p>

        <div class="md-bwtable" role="table">
          <div class="md-bwrow md-bwrow--head" role="row">
            <span role="columnheader">Source</span>
            <span role="columnheader">Volume</span>
            <span role="columnheader">SPF</span>
            <span role="columnheader">DKIM</span>
            <span role="columnheader">Verdict</span>
          </div>
          {analysis.sources.map((source) => (
            <SourceRow
              key={source.ip}
              source={source}
              hostname={names[source.ip]}
              open={open === source.ip}
              onOpen={() => onOpen(source.ip)}
            />
          ))}
        </div>
      </section>

      <section class="md-bwsection">
        <h3>What this means</h3>
        <p class="md-bwsection__note">
          {findings.length === 0
            ? 'Nothing in these reports needs treatment.'
            : 'Read top to bottom, the most serious first.'}
        </p>
        <div class="md-conditions">
          {findings.map((finding) => (
            <ConditionCard key={finding.code} condition={finding} />
          ))}
        </div>
      </section>

      <p class="md-bw__files">
        Read locally: {loaded.map((name) => name).join(', ')}
      </p>

      <p class="md-testresult__more">
        Reports describe last week's mail.{' '}
        <a href={`/health-library?domain=${encodeURIComponent(policy.domain)}`}>Run the full checkup</a> to see
        what {policy.domain || 'your domain'} publishes today.
      </p>
    </div>
  );
}

/**
 * One bar per report, ordered by its window.
 *
 * Only drawn from three reports up: two points is not a trend, and a chart
 * that implies one from a single day is the sort of thing people make policy
 * decisions on.
 */
function Trend({ analysis }: { analysis: Analysis }) {
  const peak = Math.max(...analysis.timeline.map((entry) => entry.volume), 1);

  return (
    <section class="md-bwsection">
      <h3>How this changed over the window</h3>
      <p class="md-bwsection__note">
        Each bar is one report. Height is volume; the filled part is the mail that aligned.
      </p>
      <div class="md-bwtrend">
        {analysis.timeline.map((entry) => (
          <div
            key={entry.begin}
            class="md-bwtrend__col"
            title={`${dateRange({ begin: entry.begin, end: entry.begin, days: 1 })}, ${count(
              entry.volume,
            )} messages, ${percent(entry.aligned, entry.volume)} aligned`}
          >
            <span class="md-bwtrend__bar" style={{ height: `${(entry.volume / peak) * 100}%` }}>
              <span
                class="md-bwtrend__fill"
                style={{ height: `${(entry.aligned / Math.max(1, entry.volume)) * 100}%` }}
              />
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

function PolicyCard({ analysis }: { analysis: Analysis }) {
  const { policy } = analysis;
  const p = policy.p ?? 'none';

  const rows: { label: string; value: string; meaning: string }[] = [
    {
      label: 'p',
      value: p,
      meaning: POLICY_MEANING[p] ?? 'Receivers were given a policy we do not recognise.',
    },
    {
      label: 'sp',
      value: policy.sp ?? `inherits ${p}`,
      meaning: policy.sp
        ? `Subdomains: ${POLICY_MEANING[policy.sp]?.toLowerCase() ?? 'a policy of their own.'}`
        : 'Subdomains inherit the policy above.',
    },
    {
      label: 'pct',
      value: policy.pct === null ? '100' : String(policy.pct),
      meaning:
        policy.pct === null || policy.pct === 100
          ? 'The policy applies to all failing mail.'
          : `Only about ${policy.pct}% of failing mail is treated; the rest is delivered.`,
    },
    {
      label: 'adkim',
      value: policy.adkim,
      meaning:
        policy.adkim === 's'
          ? 'DKIM alignment is strict: the signing domain must match the From domain exactly.'
          : 'DKIM alignment is relaxed: a subdomain signature still aligns.',
    },
    {
      label: 'aspf',
      value: policy.aspf,
      meaning:
        policy.aspf === 's'
          ? 'SPF alignment is strict: the envelope domain must match the From domain exactly.'
          : 'SPF alignment is relaxed: a subdomain envelope still aligns.',
    },
  ];

  if (policy.np) {
    rows.push({
      label: 'np',
      value: policy.np,
      meaning: 'Applies to subdomains that do not exist, the ones attackers invent.',
    });
  }
  if (policy.testing) {
    rows.push({
      label: 't',
      value: 'y',
      meaning: 'Marked as testing, so receivers may treat your policy as advisory.',
    });
  }

  return (
    <section class="md-bwsection">
      <h3>The policy the receivers saw</h3>
      <p class="md-bwsection__note">
        Read out of the reports themselves, not from DNS, this is what was live while this mail was
        being sent.
      </p>
      <div class="md-bwpolicy">
        {rows.map((row) => (
          <div class="md-bwpolicy__row" key={row.label}>
            <span class="md-mono md-bwpolicy__tag">
              {row.label}={row.value}
            </span>
            <span class="md-bwpolicy__meaning">{row.meaning}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

interface SourceRowProps {
  source: Source;
  hostname: string | undefined;
  open: boolean;
  onOpen: () => void;
}

function SourceRow({ source, hostname, open, onOpen }: SourceRowProps) {
  const spf = best(source.spf);
  const dkim = best(source.dkim);

  return (
    <div class={`md-bwentry ${open ? 'is-open' : ''}`}>
      <button type="button" class="md-bwrow" onClick={onOpen} aria-expanded={open}>
        <span class="md-bwrow__source">
          <span class="md-mono md-bwrow__ip">{source.ip}</span>
          <span class="md-bwrow__meta">
            {hostname ? <span class="md-mono">{hostname}</span> : null}
            {source.service ? <span class="md-bwrow__hint">likely {source.service}</span> : null}
            {source.kind !== 'public' ? (
              <span class="md-bwrow__hint">{source.kind} address</span>
            ) : null}
          </span>
        </span>
        <span class="md-bwrow__volume">
          <strong>{count(source.volume)}</strong>
          <em>{source.share}%</em>
        </span>
        <Mark identifier={spf} label="SPF" />
        <Mark identifier={dkim} label="DKIM" />
        <span class="md-bwrow__verdict">
          <span class={`md-chip ${VERDICT_TONE[source.verdict]}`}>
            {VERDICT_LABEL[source.verdict]}
          </span>
          {source.mixed && <span class="md-bwrow__hint">mixed</span>}
        </span>
      </button>

      {open && <SourceDetail source={source} />}
    </div>
  );
}

function Mark({ identifier, label }: { identifier: IdentifierSummary | null; label: string }) {
  if (!identifier) {
    return (
      <span class="md-bwmark" title={`No ${label} result recorded`}>
        <span class="md-bwmark__none">, </span>
      </span>
    );
  }

  const good = identifier.result === 'pass' && identifier.aligned;
  const title = identifier.aligned
    ? `${label} ${identifier.result} for ${identifier.domain}, aligned`
    : `${label} ${identifier.result} for ${identifier.domain}, not aligned with your domain`;

  return (
    <span class={`md-bwmark ${good ? 'is-good' : 'is-bad'}`} title={title}>
      {good ? <TickIcon size={13} /> : <CrossIcon size={13} />}
      <span class="md-bwmark__domain">{identifier.domain || ', '}</span>
    </span>
  );
}

function SourceDetail({ source }: { source: Source }) {
  const dispositions = (Object.keys(source.dispositions) as Disposition[]).filter(
    (key) => source.dispositions[key] > 0,
  );

  return (
    <div class="md-bwdetail">
      <p class="md-bwdetail__lead">
        <span class={`md-bwdetail__icon ${VERDICT_TONE[source.verdict]}`}>
          {source.verdict === 'AUTHORIZED' ? <ShieldIcon size={16} /> : <AlertIcon size={16} />}
        </span>
        {VERDICT_MEANING[source.verdict]}
      </p>

      <dl class="md-bwdetail__grid">
        <div>
          <dt>What receivers did</dt>
          <dd>
            {dispositions
              .map((key) => `${count(source.dispositions[key])} ${DISPOSITION_LABEL[key]}`)
              .join(' · ')}
          </dd>
        </div>
        <div>
          <dt>From addresses used</dt>
          <dd class="md-mono">{source.headerFroms.join(', ') || 'not recorded'}</dd>
        </div>
        <div>
          <dt>Reported by</dt>
          <dd>{source.reporters.join(', ')}</dd>
        </div>
        <div>
          <dt>Aligned volume</dt>
          <dd>
            {count(source.aligned)} of {count(source.volume)}
          </dd>
        </div>
      </dl>

      <h4>Authentication the receiver recorded</h4>
      <table class="md-bwauth">
        <thead>
          <tr>
            <th>Check</th>
            <th>Domain</th>
            <th>Selector</th>
            <th>Result</th>
            <th>Aligned</th>
            <th>Messages</th>
          </tr>
        </thead>
        <tbody>
          {[
            ...source.spf.map((entry) => ({ kind: 'SPF', entry })),
            ...source.dkim.map((entry) => ({ kind: 'DKIM', entry })),
          ].map(({ kind, entry }) => (
            <tr key={`${kind}-${entry.domain}-${entry.selector ?? ''}-${entry.result}`}>
              <td class="md-mono">{kind}</td>
              <td class="md-mono">{entry.domain || ', '}</td>
              <td class="md-mono">{entry.selector ?? ', '}</td>
              <td class="md-mono">{entry.result}</td>
              <td>
                <span class={`md-chip ${entry.aligned ? 'is-healthy' : 'is-critical'}`}>
                  {entry.aligned ? 'aligned' : 'not aligned'}
                </span>
              </td>
              <td class="md-mono">{count(entry.volume)}</td>
            </tr>
          ))}
          {source.spf.length === 0 && source.dkim.length === 0 && (
            <tr>
              <td colSpan={6}>
                The receiver recorded no authentication results at all for this source.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {source.overrides.length > 0 && (
        <>
          <h4>Why the policy was not applied</h4>
          <ul class="md-bwreasons">
            {source.overrides.map((override) => (
              <li key={override.type}>
                <span class="md-mono">{override.type}</span>, {' '}
                {OVERRIDE_MEANING[override.type] ?? 'the receiver gave a reason of its own'}
                {override.comment ? `: ${override.comment}` : ''} ({count(override.volume)}{' '}
                messages)
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

/* Small helpers ------------------------------------------------------------ */

function best(identifiers: readonly IdentifierSummary[]): IdentifierSummary | null {
  if (identifiers.length === 0) return null;
  const aligned = identifiers.find((entry) => entry.aligned && entry.result === 'pass');
  return aligned ?? identifiers[0] ?? null;
}

function count(value: number): string {
  return value.toLocaleString('en-US');
}

function percent(part: number, total: number): string {
  if (total <= 0) return '0%';
  return `${Math.round((part / total) * 1000) / 10}%`;
}

function dateRange(range: { begin: number; end: number; days: number }): string {
  if (!range.begin) return 'window not recorded';
  const format = (seconds: number) =>
    new Date(seconds * 1000).toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      timeZone: 'UTC',
    });
  const from = format(range.begin);
  const to = format(range.end || range.begin);
  return from === to ? from : `${from} to ${to}`;
}

function message(caught: unknown): string {
  return caught instanceof Error && caught.message
    ? caught.message
    : 'That file couldn’t be read. Let’s try another.';
}
