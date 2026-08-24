import { useEffect, useRef, useState } from 'preact/hooks';
import { domainRejectionMessage, normalizeDomain } from '@maildoc/shared';
import type { SpfEvalStep, SpfIpResponse, SpfIpSuccess } from '../lib/types';
import { ArrowIcon, CrossIcon, StethoscopeIcon, TickIcon } from './Icons';

/**
 * "Can this server send as me?" — the question a bounce message raises.
 *
 * Every other SPF tool here describes a record. This one evaluates it against
 * one address, which is what a receiver does, and shows the terms it walked in
 * the order it walked them. Somebody adding a new sending platform can see
 * whether the include they pasted actually covers the address the platform
 * gave them, and somebody staring at a rejection can see which mechanism
 * produced it.
 */

type Phase = 'idle' | 'checking' | 'done' | 'error';

/** The seven results, with the words a person can act on. */
const RESULTS = {
  pass: {
    label: 'Pass',
    tone: 'is-healthy',
    meaning: 'Authorised. Receivers accept this as coming from the domain.',
  },
  fail: {
    label: 'Fail',
    tone: 'is-critical',
    meaning: 'Not authorised, and the record asks receivers to reject the mail.',
  },
  softfail: {
    label: 'SoftFail',
    tone: 'is-attention',
    meaning: 'Not authorised, and the record asks receivers to accept it and mark it.',
  },
  neutral: {
    label: 'Neutral',
    tone: 'is-minor',
    meaning: 'The record says nothing either way, which receivers treat as no policy.',
  },
  none: {
    label: 'None',
    tone: 'is-urgent',
    meaning: 'No SPF record is published, so nothing authorises anybody.',
  },
  permerror: {
    label: 'PermError',
    tone: 'is-critical',
    meaning: 'A receiver gave up before reaching an answer.',
  },
  temperror: {
    label: 'TempError',
    tone: 'is-urgent',
    meaning: 'A lookup did not answer. This is a DNS condition, not a verdict.',
  },
} as const;

/**
 * The mark beside each step, as an icon rather than a glyph.
 *
 * The design system has real icons and forbids pictographs in production, and a
 * text tick renders in a different weight on every platform beside SVG that
 * does not.
 */
function OutcomeMark({ outcome }: { outcome: SpfEvalStep['outcome'] }) {
  if (outcome === 'match') return <TickIcon size={14} class="" />;
  if (outcome === 'error') return <CrossIcon size={14} />;
  return <span class="md-trace__dot" />;
}

/**
 * How far to indent for depth.
 *
 * Capped, because a chain can nest ten deep and ten indents is most of a phone.
 * Past the fourth level the "in <domain>" label carries the nesting instead.
 */
const MAX_INDENT = 4;

export default function SpfIpCheck() {
  const [domain, setDomain] = useState('');
  const [ip, setIp] = useState('');
  const [sender, setSender] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<SpfIpSuccess | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  /** Arriving with ?domain=&ip= runs the check, so a result is shareable. */
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const params = new URLSearchParams(location.search);
    const fromUrl = params.get('domain');
    const ipFromUrl = params.get('ip');
    if (fromUrl) setDomain(fromUrl);
    if (ipFromUrl) setIp(ipFromUrl);
    if (fromUrl && ipFromUrl) void check(fromUrl, ipFromUrl, params.get('sender') ?? '');
  }, []);

  async function check(rawDomain: string, rawIp: string, rawSender: string) {
    const normalized = normalizeDomain(rawDomain);
    if (!normalized.ok) {
      setPhase('error');
      setMessage(domainRejectionMessage(normalized.reason));
      return;
    }
    if (rawIp.trim() === '') {
      setPhase('error');
      setMessage('Give us the IP address that sent the mail.');
      return;
    }

    setPhase('checking');
    setMessage('');
    setResult(null);

    const query = new URLSearchParams({ domain: normalized.domain, ip: rawIp.trim() });
    if (rawSender.trim() !== '') query.set('sender', rawSender.trim());

    try {
      const response = await fetch(`/api/spf/ip?${query.toString()}`);
      const data = (await response.json()) as SpfIpResponse;
      if (!data.ok) throw new Error(data.error.message);

      setResult(data);
      setPhase('done');
      history.replaceState(null, '', `?${query.toString()}`);
      requestAnimationFrame(() =>
        resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      );
    } catch (caught) {
      setPhase('error');
      setMessage(
        caught instanceof Error && caught.message
          ? caught.message
          : 'The check couldn’t complete. Let’s try again.',
      );
    }
  }

  const onSubmit = (event: Event) => {
    event.preventDefault();
    if (phase === 'checking') return;
    void check(domain, ip, sender);
  };

  const verdict = result ? RESULTS[result.result] : null;

  return (
    <div>
      <form class="diagbox" onSubmit={onSubmit}>
        <div class="inrow">
          <span class="pre md-mono" aria-hidden="true">
            https://
          </span>
          <label class="md-visually-hidden" for="domain">
            The domain the mail claimed to come from
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
            value={domain}
            onInput={(event) => setDomain((event.target as HTMLInputElement).value)}
          />
        </div>

        <div class="inrow" style={{ marginTop: 'var(--md-space-3)' }}>
          <span class="pre md-mono" aria-hidden="true">
            from
          </span>
          <label class="md-visually-hidden" for="ip">
            The IP address that connected
          </label>
          <input
            id="ip"
            name="ip"
            type="text"
            class="md-mono"
            placeholder="203.0.113.9"
            autocomplete="off"
            autocapitalize="off"
            spellcheck={false}
            value={ip}
            onInput={(event) => setIp((event.target as HTMLInputElement).value)}
          />
          <button class="md-btn" type="submit" disabled={phase === 'checking'}>
            {phase === 'checking' ? 'Checking…' : 'Check this sender'}
            {phase !== 'checking' && <ArrowIcon size={16} />}
          </button>
        </div>

        {/*
          The envelope sender only matters when the record uses sender macros,
          which is rare enough that asking everybody for it would be noise and
          common enough that leaving it out would give the wrong answer to the
          domains that do. Optional, and labelled with why.
        */}
        <details class="md-optional">
          <summary>Envelope sender, if the record uses macros</summary>
          <div class="inrow" style={{ marginTop: 'var(--md-space-3)' }}>
            <span class="pre md-mono" aria-hidden="true">
              MAIL FROM
            </span>
            <label class="md-visually-hidden" for="sender">
              The envelope sender address
            </label>
            <input
              id="sender"
              name="sender"
              type="text"
              class="md-mono"
              placeholder="bounces@yourcompany.com"
              autocomplete="off"
              autocapitalize="off"
              spellcheck={false}
              value={sender}
              onInput={(event) => setSender((event.target as HTMLInputElement).value)}
            />
          </div>
          <p class="note">
            Left blank we use <code>postmaster@yourcompany.com</code>, which is what a receiver uses
            when the envelope sender is empty. It changes the answer only for records containing
            <code>%{'{'}l{'}'}</code> or <code>%{'{'}s{'}'}</code>.
          </p>
        </details>

        <p class="note">
          <StethoscopeIcon size={15} class="noteicon" />
          <span>
            Free, instant, no signup. This evaluates your live record the way a receiving server
            does, first match wins.
          </span>
        </p>

        {phase === 'error' && (
          <p class="md-error" role="alert">
            {message}
          </p>
        )}
      </form>

      {phase === 'done' && result && verdict && (
        <div ref={resultRef} class="md-result md-testresult">
          <div class="md-testresult__head">
            <div>
              <h2>
                <span class="md-mono">{result.ip}</span> sending as{' '}
                <span class="md-mono">{result.domain}</span>
              </h2>
              <p class="md-testresult__summary">{result.summary}</p>
            </div>
            <span class={`md-chip ${verdict.tone}`}>{verdict.label}</span>
          </div>

          <p class="md-verdictline">{verdict.meaning}</p>

          {/*
            The two permanent errors need different sentences, because they send
            somebody to do different things. Over the lookup limit, the record is
            broken for every sender and needs rewriting today. Out of void
            lookups, the record is usually doing exactly what it was built to do
            and this address is simply not one it knows.
          */}
          {result.result === 'permerror' && (
            <p class={`md-scope ${result.breaksEverySender ? 'is-critical' : 'is-attention'}`}>
              {result.breaksEverySender ? (
                <>
                  <strong>This affects every sender.</strong> Your own mail servers fail this record
                  too. It needs fixing before anything else on the domain is worth looking at.
                </>
              ) : (
                <>
                  <strong>This is about this address, not your record.</strong> Records that look up
                  a name per sender return empty answers for addresses they do not know, and three
                  empty answers is a permanent error. Senders the record does know are unaffected.
                </>
              )}
            </p>
          )}

          {!result.complete && (
            <p class="md-error" role="status">
              A lookup did not finish, so this is what we could establish rather than the whole
              answer. Try again in a moment.
            </p>
          )}

          <h3 class="md-tracehead">
            How a receiver got there
            <span class="md-mono">
              {result.lookups} of 10 lookups
              {result.voidLookups > 0 ? ` · ${result.voidLookups} void` : ''}
            </span>
          </h3>

          {/*
            The trace stops where a receiver stops. A record with twenty terms
            and a match on the second shows two rows, because the other eighteen
            were never read and pretending otherwise would misrepresent the cost.
          */}
          <ol class="md-trace">
            {result.trace.map((step, index) => (
              <li
                key={`${step.domain}-${step.term}-${index}`}
                class={`md-trace__step is-${step.outcome}`}
                style={{
                  paddingLeft: `calc(var(--md-space-4) * ${Math.min(step.depth, MAX_INDENT) + 1})`,
                }}
              >
                <span class="md-trace__mark" aria-hidden="true">
                  <OutcomeMark outcome={step.outcome} />
                </span>
                <div>
                  <code class="md-trace__term">{step.term}</code>
                  {step.depth > 0 && <span class="md-trace__where">in {step.domain}</span>}
                  <p class="md-trace__detail">{step.detail}</p>
                </div>
              </li>
            ))}
          </ol>

          <p class="md-testresult__more">
            This checks one sender against the record as published.{' '}
            <a href={`/lab/spf-checker?domain=${encodeURIComponent(result.domain)}`}>
              Check the record itself
            </a>{' '}
            for the chain, the lookup count and every condition on it.
          </p>
        </div>
      )}
    </div>
  );
}
