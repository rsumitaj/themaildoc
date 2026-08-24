import { useEffect, useRef, useState } from 'preact/hooks';
import { finalizeCheckup } from '@maildoc/engines/finalize';
import type {
  CheckResponse,
  CheckSuccess,
  DkimResponse,
  DkimSuccess,
  SpfResponse,
  SpfSuccess,
} from '../lib/types';
import { CrossIcon, TickIcon } from './Icons';
import { ChartConsult, CleanBill, ConditionCard, RecordRow, SpoofBanner } from './Chart';
import { CheckupForm } from './CheckupForm';
import { ScoreExplainer } from './Explain';
import { SpfTree } from './SpfTree';
import { VitalsMonitor } from './Vitals';

/**
 * The diagnosis, read here in the Health Library.
 *
 * The examination is not theatre: each line resolves when its result actually
 * arrives. The core records come back together from /api/check, and DKIM
 * genuinely lands later because it has its own endpoint, so the DKIM line
 * ticking last is the truth rather than a delay we invented.
 */

type Phase = 'idle' | 'examining' | 'done' | 'error';

interface ExamRow {
  key: string;
  label: string;
  state: 'pending' | 'ok' | 'bad';
}

const CORE_ROWS: ReadonlyArray<{ key: string; label: string }> = [
  { key: 'SPF', label: 'SPF authentication' },
  { key: 'DMARC', label: 'DMARC policy' },
  { key: 'MX', label: 'Mail servers' },
  { key: 'DNSSEC', label: 'DNSSEC' },
  { key: 'A', label: 'Address records' },
];

const DKIM_ROW = { key: 'DKIM', label: 'DKIM signing' };

const initialRows = (): ExamRow[] =>
  [...CORE_ROWS, DKIM_ROW].map((row) => ({ ...row, state: 'pending' as const }));

export default function Checkup() {
  const [initial, setInitial] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [message, setMessage] = useState('');
  const [rows, setRows] = useState<ExamRow[]>(initialRows);
  const [core, setCore] = useState<CheckSuccess | null>(null);
  const [dkim, setDkim] = useState<DkimSuccess | null>(null);
  /** The deep chain walk, when it lands. Authoritative over the checkup's own. */
  const [deepSpf, setDeepSpf] = useState<SpfSuccess | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  /**
   * Arriving with ?domain= runs the checkup, which is how the homepage hands
   * over and how a shared link works. `popstate` covers the back button.
   */
  useEffect(() => {
    const run = () => {
      const fromUrl = new URLSearchParams(location.search).get('domain');
      if (!fromUrl) return;
      setInitial(fromUrl);
      void examine(fromUrl);
    };

    if (!started.current) {
      started.current = true;
      run();
    }

    addEventListener('popstate', run);
    return () => removeEventListener('popstate', run);
  }, []);

  async function examine(domain: string) {
    setPhase('examining');
    setMessage('');
    setRows(initialRows());
    setCore(null);
    setDkim(null);
    setDeepSpf(null);

    const query = `domain=${encodeURIComponent(domain)}`;

    // Both requests leave together; each updates its own lines as it lands.
    const corePromise = fetch(`/api/check?${query}`)
      .then((response) => response.json() as Promise<CheckResponse>)
      .then((data) => {
        if (!data.ok) throw new Error(data.error.message);
        setCore(data);
        setRows((current) =>
          current.map((row) => {
            const record = data.records.find((entry) => entry.record === row.key);
            if (!record) return row;
            return { ...row, state: record.status === 'CRITICAL' ? 'bad' : 'ok' };
          }),
        );
        return data;
      });

    /**
     * The chain, walked in a request of its own.
     *
     * A Worker gets fifty subrequests and the checkup spends most of them on
     * the nine other records, so an include chain published through a
     * flattening vendor ran out part way down. This one spends nearly the whole
     * allowance on the chain alone. It lands after the checkup and replaces
     * what the checkup found, the same way DKIM already does, so nobody waits
     * on it to see their score.
     */
    const spfPromise = fetch(`/api/check/spf?${query}`)
      .then((response) => response.json() as Promise<SpfResponse>)
      .then((data) => {
        if (data.ok) setDeepSpf(data);
      })
      .catch(() => {
        // The checkup's own chain is already on screen. Losing the deeper walk
        // costs depth, never the result.
      });

    const dkimPromise = fetch(`/api/check/dkim?${query}`)
      .then((response) => response.json() as Promise<DkimResponse>)
      .then((data) => {
        if (!data.ok) return;
        setDkim(data);
        setRows((current) =>
          current.map((row) =>
            row.key === 'DKIM'
              ? { ...row, state: data.status === 'CRITICAL' ? 'bad' : 'ok' }
              : row,
          ),
        );
      })
      .catch(() => {
        // DKIM is a bonus: never let it take the chart down.
        setRows((current) =>
          current.map((row) => (row.key === 'DKIM' ? { ...row, state: 'ok' } : row)),
        );
      });

    try {
      await corePromise;
      // All three left together, so waiting on the other two costs the slower
      // of them rather than the sum. Neither can fail the checkup: DKIM and the
      // deep chain both swallow their own errors above.
      await Promise.all([dkimPromise, spfPromise]);
      setPhase('done');
      if (new URLSearchParams(location.search).get('domain') !== domain) {
        history.pushState(null, '', `?domain=${encodeURIComponent(domain)}`);
      }
      requestAnimationFrame(() =>
        resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      );
    } catch (error) {
      setPhase('error');
      setMessage(
        error instanceof Error && error.message
          ? error.message
          : 'The checkup couldn’t complete. Let’s try again.',
      );
    }
  }

  /**
   * One merge, in the package, for every consumer.
   *
   * This used to happen here — conditions concatenated, deduped and re-scored
   * inline — which meant the result screen was the only place in the product
   * that knew what a finished checkup looked like. `/api/check` recorded a
   * score without DKIM, the readiness page read an SPF chain the deep walk had
   * already superseded, and the spoof banner kept the reasons the bounded walk
   * produced. `finalizeCheckup` is now the single answer to "what did we
   * actually find", and this screen is one of its callers rather than its
   * owner.
   */
  const final = core ? finalizeCheckup({ core, deepSpf, dkim }) : null;

  /**
   * The number we recorded is corrected to the number that was read.
   *
   * `/api/check` wrote the row before DKIM and the full chain existed, and both
   * can only add findings, so what it wrote is never worse than the truth.
   *
   * Gated on the examination having settled rather than on both legs having
   * landed, because a leg that failed is never going to land and the score on
   * screen is final either way. Both later fetches swallow their own errors, so
   * reaching `done` means nothing further is coming, and what gets recorded is
   * what the visitor read. Sent quietly: nothing on this page depends on it and
   * nobody is shown a failure to bookkeep.
   */
  useEffect(() => {
    if (phase !== 'done' || !final) return;

    void fetch('/api/checkup/score', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        domain: final.domain,
        score: final.vitals.score,
        band: final.vitals.band,
        spoofable: final.spoofability.verdict,
      }),
      keepalive: true,
    }).catch(() => {
      // Our bookkeeping, not their diagnosis.
    });
  }, [phase, final?.domain, final?.vitals.score]);

  /** The chain to draw, and the count that goes with it. */
  const chain = deepSpf?.chain
    ? { node: deepSpf.chain, lookupCount: deepSpf.lookupCount, exact: deepSpf.lookupCountExact }
    : core?.detail.spf.chain
      ? {
          node: core.detail.spf.chain,
          lookupCount: core.detail.spf.lookupCount,
          exact: core.detail.spf.lookupCountExact,
        }
      : null;

  return (
    <div>
      <CheckupForm
        key={initial}
        initial={initial}
        busy={phase === 'examining'}
        onExamine={(domain) => void examine(domain)}
      />

      {phase === 'error' && (
        <p class="md-error" role="alert">
          {message}
        </p>
      )}

      {phase === 'examining' && (
        <div class="md-exam" role="status" aria-live="polite">
          {rows.map((row) => (
            <div class={`md-exam__row ${row.state === 'pending' ? 'is-pending' : ''}`} key={row.key}>
              <span class="md-exam__mark">
                {row.state === 'pending' && <span class="md-exam__spinner" />}
                {row.state === 'ok' && <TickIcon size={15} class="" />}
                {row.state === 'bad' && <CrossIcon size={15} />}
              </span>
              <span style={{ color: row.state === 'bad' ? 'var(--md-red)' : undefined }}>
                {row.state === 'pending' ? `Examining ${row.label}…` : row.label}
              </span>
            </div>
          ))}
        </div>
      )}

      {phase === 'done' && final && (
        <div ref={resultRef} class="md-result" style={{ paddingTop: 'var(--md-space-8)' }}>
          <div class="md-chart__head">
            <span class="md-chart__label">DIAGNOSIS</span>
            <span class="md-chart__domain">{final.domain}</span>
          </div>
          <p class="md-chart__meta">
            Examined just now · {final.conditions.length}{' '}
            {final.conditions.length === 1 ? 'condition' : 'conditions'} found ·{' '}
            {final.queriesUsed} DNS lookups
            {final.partial ? ' · partial result' : ''}
          </p>

          <div class="md-chart">
            <div>
              <VitalsMonitor vitals={final.vitals} />
              <ScoreExplainer
                conditions={final.conditions}
                spoofability={final.spoofability.verdict}
              />
            </div>

            <div>
              <SpoofBanner spoofability={final.spoofability} />
              <RecordRow records={final.records} />

              <div class="md-conditions">
                {final.conditions.length === 0 ? (
                  <CleanBill />
                ) : (
                  final.conditions.map((condition) => (
                    <ConditionCard key={condition.code + condition.title} condition={condition} />
                  ))
                )}
              </div>

              {chain && (
                <SpfTree
                  chain={chain.node}
                  lookupCount={chain.lookupCount}
                  exact={chain.exact}
                />
              )}

              <ChartConsult
                domain={final.domain}
                vitals={final.vitals}
                spoofability={final.spoofability}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
