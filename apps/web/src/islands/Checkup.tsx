import { useEffect, useRef, useState } from 'preact/hooks';
import { dedupeConditions, sortConditions, vitals as computeVitals } from '@maildoc/catalog/scoring';
import type { CheckResponse, CheckSuccess, Condition, DkimResponse } from '../lib/types';
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
  const [dkimConditions, setDkimConditions] = useState<Condition[]>([]);
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
    setDkimConditions([]);

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

    const dkimPromise = fetch(`/api/check/dkim?${query}`)
      .then((response) => response.json() as Promise<DkimResponse>)
      .then((data) => {
        if (!data.ok) return;
        setDkimConditions(data.conditions);
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
      await dkimPromise;
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

  const conditions: Condition[] = core
    ? sortConditions(dedupeConditions([...core.conditions, ...dkimConditions]))
    : [];
  // Re-scored in the browser so DKIM's findings count toward Vitals, using the
  // same arithmetic the Worker used.
  // The verdict has to come along. Without it the headline number is scored
  // one way and the explainer below it another, which is how a page ends up
  // showing 53 above an explanation that adds up to 65.
  const scored = core
    ? computeVitals(conditions, { spoofability: core.spoofability.verdict })
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

      {phase === 'done' && core && scored && (
        <div ref={resultRef} class="md-result" style={{ paddingTop: 'var(--md-space-8)' }}>
          <div class="md-chart__head">
            <span class="md-chart__label">DIAGNOSIS</span>
            <span class="md-chart__domain">{core.domain}</span>
          </div>
          <p class="md-chart__meta">
            Examined just now · {conditions.length}{' '}
            {conditions.length === 1 ? 'condition' : 'conditions'} found · {core.meta.queriesUsed} DNS
            lookups{core.meta.partial ? ' · partial result' : ''}
          </p>

          <div class="md-chart">
            <div>
              <VitalsMonitor vitals={scored} />
              <ScoreExplainer conditions={conditions} spoofability={core.spoofability.verdict} />
            </div>

            <div>
              <SpoofBanner spoofability={core.spoofability} />
              <RecordRow records={core.records} />

              <div class="md-conditions">
                {conditions.length === 0 ? (
                  <CleanBill />
                ) : (
                  conditions.map((condition) => (
                    <ConditionCard key={condition.code + condition.title} condition={condition} />
                  ))
                )}
              </div>

              {core.detail.spf.chain && (
                <SpfTree
                  chain={core.detail.spf.chain}
                  lookupCount={core.detail.spf.lookupCount}
                  exact={core.detail.spf.lookupCountExact}
                />
              )}

              <ChartConsult
                domain={core.domain}
                vitals={scored}
                spoofability={core.spoofability}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
