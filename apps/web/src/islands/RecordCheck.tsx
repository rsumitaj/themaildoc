import { useEffect, useRef, useState } from 'preact/hooks';
import { TRIAGE_COLOR, vitals as computeVitals } from '@maildoc/catalog/scoring';
import { domainRejectionMessage, normalizeDomain } from '@maildoc/shared';
import type { CheckResponse, CheckSuccess, Condition, DkimResponse } from '../lib/types';
import { ArrowIcon, StethoscopeIcon } from './Icons';
import { CleanBill, ConditionCard } from './Chart';
import { SpfTree } from './SpfTree';
import { Explain, ScoreExplainer } from './Explain';

/**
 * A single-record test, for the Lab pages.
 *
 * It runs the same checkup as the home page and shows one record's findings.
 * That is deliberate: one engine, one set of results, no second implementation
 * of the truth that could drift from the first. The full chart is one click
 * away for anyone who wants the rest.
 */

type Phase = 'idle' | 'examining' | 'done' | 'error';

export interface RecordCheckProps {
  /** Which record this page is about. */
  record: string;
  /** Patient-facing name, e.g. "SPF authentication". */
  label: string;
  /** Verb for the button, e.g. "Check my SPF". */
  action: string;
  /** DKIM has its own endpoint. */
  endpoint?: 'check' | 'dkim';
}

export default function RecordCheck({ record, label, action, endpoint = 'check' }: RecordCheckProps) {
  const [input, setInput] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<CheckSuccess | null>(null);
  const [conditions, setConditions] = useState<Condition[]>([]);
  const [summary, setSummary] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<string | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    const fromUrl = new URLSearchParams(location.search).get('domain');
    if (fromUrl) {
      started.current = true;
      setInput(fromUrl);
      void examine(fromUrl);
    }
  }, []);

  async function examine(raw: string) {
    const normalized = normalizeDomain(raw);
    if (!normalized.ok) {
      setPhase('error');
      setMessage(domainRejectionMessage(normalized.reason));
      return;
    }

    const domain = normalized.domain;
    setPhase('examining');
    setMessage('');
    setResult(null);
    setConditions([]);
    setSummary(null);
    setEvidence(null);

    try {
      const path = endpoint === 'dkim' ? '/api/check/dkim' : '/api/check';
      const response = await fetch(`${path}?domain=${encodeURIComponent(domain)}`);

      if (endpoint === 'dkim') {
        const data = (await response.json()) as DkimResponse;
        if (!data.ok) throw new Error(data.error.message);
        setConditions(data.conditions);
        setSummary(
          data.found
            ? `${data.keys.length} key${data.keys.length === 1 ? '' : 's'} found at ${data.keys.map((key) => key.selector).join(', ')}`
            : `No key at ${data.probed.length} common selectors`,
        );
        setEvidence(data.keys[0]?.record ?? null);
      } else {
        const data = (await response.json()) as CheckResponse;
        if (!data.ok) throw new Error(data.error.message);
        setResult(data);
        setConditions(data.conditions.filter((condition) => condition.record === record));
        const entry = data.records.find((item) => item.record === record);
        setSummary(entry?.summary ?? null);
        setEvidence(recordEvidence(data, record));
      }

      setPhase('done');
      history.replaceState(null, '', `?domain=${encodeURIComponent(domain)}`);
      requestAnimationFrame(() =>
        resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      );
    } catch (error) {
      setPhase('error');
      setMessage(
        error instanceof Error && error.message
          ? error.message
          : 'The checkup couldn’t complete, let’s try again.',
      );
    }
  }

  const onSubmit = (event: Event) => {
    event.preventDefault();
    if (phase === 'examining') return;
    const form = event.currentTarget as HTMLFormElement;
    const typed = new FormData(form).get('domain');
    const value = typeof typed === 'string' && typed.trim() !== '' ? typed : input;
    setInput(value);
    void examine(value);
  };

  const scored = phase === 'done' ? computeVitals(conditions) : null;

  return (
    <div>
      <form class="diagbox" onSubmit={onSubmit}>
        <div class="inrow">
          <span class="pre md-mono" aria-hidden="true">
            https://
          </span>
          <label class="md-visually-hidden" for="domain">
            Your domain
          </label>
          <input
            id="domain"
            name="domain"
            type="text"
            class="md-mono"
            placeholder="yourcompany.com"
            autocomplete="off"
            autocapitalize="off"
            spellcheck={false}
            inputMode="url"
            value={input}
            onInput={(event) => setInput((event.target as HTMLInputElement).value)}
          />
          <button class="md-btn" type="submit" disabled={phase === 'examining'}>
            {phase === 'examining' ? 'Examining…' : action}
            {phase !== 'examining' && <ArrowIcon size={16} />}
          </button>
        </div>

        <p class="note">
          <StethoscopeIcon size={15} class="noteicon" />
          <span>
            Free, instant, no signup. This test reads your live DNS the way a receiving server does.
          </span>
        </p>

        {phase === 'error' && (
          <p class="md-error" role="alert">
            {message}
          </p>
        )}
      </form>

      {phase === 'done' && scored && (
        <div ref={resultRef} class="md-result md-testresult">
          <div class="md-testresult__head">
            <span
              class="md-dot"
              style={{ color: conditions.length === 0 ? TRIAGE_COLOR.HEALTHY : TRIAGE_COLOR[conditions[0]?.triage ?? 'HEALTHY'] }}
            />
            <div>
              <h2>
                {label} for {result?.domain ?? input}
              </h2>
              {summary && <p class="md-testresult__summary">{summary}</p>}
            </div>
            <span class="md-testresult__score md-mono">
              {scored.score}/100 · {record} only
              <Explain label="this score">
                100 minus the weight of each condition found on this record alone. It is not your
                domain's Vitals, which counts every record together.
              </Explain>
            </span>
          </div>

          {evidence && <pre class="md-testresult__record">{evidence}</pre>}

          {record === 'SPF' && result?.detail.spf.chain && (
            <SpfTree
              chain={result.detail.spf.chain}
              lookupCount={result.detail.spf.lookupCount}
              exact={result.detail.spf.lookupCountExact}
            />
          )}

          <ScoreExplainer conditions={conditions} />

          <div class="md-conditions">
            {conditions.length === 0 ? (
              <CleanBill />
            ) : (
              conditions.map((condition) => (
                <ConditionCard key={condition.code + condition.title} condition={condition} />
              ))
            )}
          </div>

          <p class="md-testresult__more">
            This page checks {label.toLowerCase()} only.{' '}
            <a href={`/checkup?domain=${encodeURIComponent(result?.domain ?? input)}`}>
              Run the full checkup
            </a>{' '}
            to see every record together, with a Vitals score for the whole domain.
          </p>

        </div>
      )}
    </div>
  );
}

/** The published record for the panel above the conditions. */
function recordEvidence(data: CheckSuccess, record: string): string | null {
  switch (record) {
    case 'SPF':
      return data.detail.spf.record;
    case 'DMARC':
      return data.detail.dmarc.record;
    case 'MX':
      return data.detail.mx.hosts.map((host) => `${host.priority} ${host.host}`).join('\n') || null;
    case 'MTASTS':
      return data.detail.mtasts.policyText ?? data.detail.mtasts.record ?? null;
    case 'TLSRPT':
      return data.detail.tlsrpt.record;
    case 'BIMI':
      return data.detail.bimi.record;
    case 'CAA':
      return data.detail.caa.record;
    case 'PTR':
      return (
        data.detail.ptr.checked
          .map((entry) => `${entry.ip} → ${entry.pointer ?? 'no PTR record'}`)
          .join('\n') || null
      );
    default:
      return null;
  }
}
