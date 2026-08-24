import { useEffect, useRef, useState } from 'preact/hooks';
import { recordScore, TRIAGE_COLOR } from '@maildoc/catalog/scoring';
import { domainRejectionMessage, normalizeDomain } from '@maildoc/shared';
import type { Condition, DkimResponse, DkimSuccess } from '../lib/types';
import { CleanBill, ConditionCard } from './Chart';
import { ArrowIcon, CrossIcon, StethoscopeIcon, TickIcon } from './Icons';
import { Explain, RecordScoreExplainer } from './Explain';

/**
 * DKIM, checked at the selectors that are actually yours.
 *
 * DNS gives no index of selectors. Without a signed message in front of you,
 * every checker on the internet guesses, and a guess that misses reports "no
 * DKIM" for a domain that signs everything it sends. That result is worse than
 * useless: it sends somebody to configure DKIM they already have.
 *
 * So the selectors are the feature. Read one off a DKIM-Signature header, add
 * it here, and a miss stops meaning "we guessed wrong" and starts meaning "the
 * key that signs your mail is not published", which is a fault worth acting on.
 * Most domains have more than one, because most domains have more than one
 * sender: marketing signs with one, the helpdesk with another, the
 * transactional provider with a third, and a rotation that half-finished shows
 * up as exactly one of them missing.
 *
 * They are kept in this browser and nowhere else. There is no account to
 * attach them to, and a list of a domain's selectors on our server would be a
 * record of who checks what, which `/privacy` promises not to hold.
 */

type Phase = 'idle' | 'checking' | 'done' | 'error';

const STORAGE_PREFIX = 'maildoc.dkim.selectors.';
/** Each selector is a subrequest, and the endpoint accepts no more than this. */
const MAX_SELECTORS = 10;

/** A selector is one or more DNS labels (RFC 6376 §3.1). */
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function isValidSelector(value: string): boolean {
  if (value === '' || value.length > 253) return false;
  return value.split('.').every((label) => LABEL.test(label));
}

/**
 * Saved selectors for one domain.
 *
 * Keyed by domain because they are a property of the domain, not of the
 * visitor: somebody who checks three clients' domains wants three lists, not
 * one merged one. Failures are swallowed — a browser with storage disabled
 * loses the memory, never the tool.
 */
function loadSaved(domain: string): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_PREFIX + domain);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((entry): entry is string => typeof entry === 'string')
      .map((entry) => entry.trim().toLowerCase())
      .filter(isValidSelector)
      .slice(0, MAX_SELECTORS);
  } catch {
    return [];
  }
}

function save(domain: string, selectors: readonly string[]): void {
  try {
    if (selectors.length === 0) localStorage.removeItem(STORAGE_PREFIX + domain);
    else localStorage.setItem(STORAGE_PREFIX + domain, JSON.stringify(selectors));
  } catch {
    /* storage disabled or full; the tool still works for this visit */
  }
}

export default function DkimSelectors() {
  const [input, setInput] = useState('');
  const [selectors, setSelectors] = useState<string[]>([]);
  const [draft, setDraft] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<DkimSuccess | null>(null);
  /** The domain the current selector list belongs to. */
  const [owner, setOwner] = useState('');
  const resultRef = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const params = new URLSearchParams(location.search);
    const fromUrl = params.get('domain');
    if (!fromUrl) return;

    const normalized = normalizeDomain(fromUrl);
    if (!normalized.ok) return;

    setInput(fromUrl);
    /**
     * A link may carry selectors, which is how somebody hands a colleague the
     * exact check they ran. They join the saved list rather than replacing it,
     * because a link should not quietly delete what this browser remembered.
     */
    const fromLink = (params.get('selectors') ?? '')
      .split(',')
      .map((entry) => entry.trim().toLowerCase())
      .filter(isValidSelector);

    const merged = [...new Set([...loadSaved(normalized.domain), ...fromLink])].slice(
      0,
      MAX_SELECTORS,
    );
    setSelectors(merged);
    setOwner(normalized.domain);
    if (merged.length > 0) save(normalized.domain, merged);
    void check(fromUrl, merged);
  }, []);

  /** Switching domains swaps in that domain's own remembered list. */
  function adoptDomain(domain: string): string[] {
    if (domain === owner) return selectors;
    const saved = loadSaved(domain);
    setSelectors(saved);
    setOwner(domain);
    return saved;
  }

  function addSelector(raw: string) {
    const selector = raw.trim().toLowerCase();
    if (!isValidSelector(selector)) {
      setMessage(
        'A selector is the s= value from a DKIM-Signature header, like "google" or "selector1".',
      );
      setPhase('error');
      return;
    }
    if (selectors.includes(selector)) {
      setDraft('');
      return;
    }
    if (selectors.length >= MAX_SELECTORS) {
      setMessage(`Ten selectors is as many as one check will probe.`);
      setPhase('error');
      return;
    }

    const next = [...selectors, selector];
    setSelectors(next);
    setDraft('');
    setMessage('');
    if (phase === 'error') setPhase('idle');
    if (owner) save(owner, next);
  }

  function removeSelector(selector: string) {
    const next = selectors.filter((entry) => entry !== selector);
    setSelectors(next);
    if (owner) save(owner, next);
  }

  async function check(rawDomain: string, useSelectors: readonly string[]) {
    const normalized = normalizeDomain(rawDomain);
    if (!normalized.ok) {
      setPhase('error');
      setMessage(domainRejectionMessage(normalized.reason));
      return;
    }

    setPhase('checking');
    setMessage('');
    setResult(null);

    const query = new URLSearchParams({ domain: normalized.domain });
    if (useSelectors.length > 0) query.set('selectors', useSelectors.join(','));

    try {
      const response = await fetch(`/api/check/dkim?${query.toString()}`);
      const data = (await response.json()) as DkimResponse;
      if (!data.ok) throw new Error(data.error.message);

      setResult(data);
      setPhase('done');
      history.replaceState(null, '', `?${query.toString()}`);

      /**
       * A selector we guessed and found is worth remembering, because next time
       * it turns a guess into a known one and the miss beside it becomes
       * meaningful. Only the ones that answered: saving a guess that missed
       * would manufacture a fault on the next run.
       */
      if (useSelectors.length === 0 && data.found) {
        const discovered = data.keys
          .map((key) => key.selector)
          .filter((selector) => selector !== '*' && isValidSelector(selector))
          .slice(0, MAX_SELECTORS);
        if (discovered.length > 0) {
          setSelectors(discovered);
          setOwner(normalized.domain);
          save(normalized.domain, discovered);
        }
      }

      requestAnimationFrame(() =>
        resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      );
    } catch (caught) {
      setPhase('error');
      setMessage(
        caught instanceof Error && caught.message
          ? caught.message
          : 'The DKIM check couldn’t complete. Let’s try again.',
      );
    }
  }

  const onSubmit = (event: Event) => {
    event.preventDefault();
    if (phase === 'checking') return;
    const normalized = normalizeDomain(input);
    if (!normalized.ok) {
      setPhase('error');
      setMessage(domainRejectionMessage(normalized.reason));
      return;
    }
    void check(input, adoptDomain(normalized.domain));
  };

  const conditions: Condition[] = result?.conditions ?? [];
  const score = result ? recordScore(conditions) : null;
  /** Which selectors were asked for and did not answer. */
  const missing = result
    ? result.probed.filter((selector) => !result.keys.some((key) => key.selector === selector))
    : [];
  const guessed = result ? result.explicit.length === 0 : false;

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
          <button class="md-btn" type="submit" disabled={phase === 'checking'}>
            {phase === 'checking' ? 'Examining…' : 'Check my DKIM'}
            {phase !== 'checking' && <ArrowIcon size={16} />}
          </button>
        </div>

        <div class="md-selectors">
          <div class="md-selectors__head">
            <span>Your selectors</span>
            <Explain label="a selector">
              The <code>s=</code> value in a DKIM-Signature header. Open a message you sent, view
              its full headers, and read it off the line beginning{' '}
              <code>DKIM-Signature:</code>. DNS has no index of selectors, so this is the only
              reliable way to know yours.
            </Explain>
          </div>

          {selectors.length > 0 && (
            <ul class="md-selectors__list">
              {selectors.map((selector) => (
                <li key={selector}>
                  <code>{selector}</code>
                  <button
                    type="button"
                    class="md-selectors__remove"
                    onClick={() => removeSelector(selector)}
                  >
                    <span class="md-visually-hidden">Remove {selector}</span>
                    <span aria-hidden="true">×</span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          <div class="md-selectors__add">
            <label class="md-visually-hidden" for="selector">
              Add a selector
            </label>
            <input
              id="selector"
              name="selector"
              type="text"
              class="md-mono"
              placeholder="google"
              autocomplete="off"
              autocapitalize="off"
              spellcheck={false}
              value={draft}
              onInput={(event) => setDraft((event.target as HTMLInputElement).value)}
              onKeyDown={(event) => {
                if (event.key !== 'Enter') return;
                // Enter adds a selector rather than submitting the form, which
                // would run a check with the field's contents still unsaved.
                event.preventDefault();
                addSelector(draft);
              }}
            />
            <button
              type="button"
              class="md-btn is-ghost"
              onClick={() => addSelector(draft)}
              disabled={draft.trim() === ''}
            >
              Add
            </button>
          </div>

          <p class="md-selectors__note">
            {selectors.length === 0
              ? 'With none saved we probe the selectors common providers use, and a miss means we guessed wrong rather than that you have no DKIM.'
              : 'Kept in this browser only. A miss on a selector you added means the key that signs your mail is not published.'}
          </p>
        </div>

        <p class="note">
          <StethoscopeIcon size={15} class="noteicon" />
          <span>
            Free, instant, no signup. This reads the published key and measures it, rather than
            checking that a record exists.
          </span>
        </p>

        {phase === 'error' && (
          <p class="md-error" role="alert">
            {message}
          </p>
        )}
      </form>

      {phase === 'done' && result && score !== null && (
        <div ref={resultRef} class="md-result md-testresult">
          <div class="md-testresult__head">
            <span
              class="md-dot"
              style={{
                color: TRIAGE_COLOR[conditions[0]?.triage ?? 'HEALTHY'],
              }}
            />
            <div>
              <h2>DKIM signing for {result.domain}</h2>
              <p class="md-testresult__summary">
                {result.found
                  ? `${result.keys.length} key${result.keys.length === 1 ? '' : 's'} found at ${result.keys.map((key) => key.selector).join(', ')}`
                  : guessed
                    ? `No key at ${result.probed.length} common selectors. That means we guessed and missed, not that you have no DKIM.`
                    : `No key at ${result.probed.join(', ')}.`}
              </p>
            </div>
            <span class="md-testresult__score md-mono">
              {score}/100 · DKIM only
              <Explain label="this score">
                100 minus the weight of each condition found on this record alone. It is not your
                domain's Vitals, which counts every record together.
              </Explain>
            </span>
          </div>

          {/*
            One row per selector, because the question is per selector. A domain
            with three senders and one broken key needs to see which one, and a
            single summary line cannot say it.
          */}
          <ul class="md-keylist">
            {result.keys.map((key) => (
              <li key={key.selector} class="md-keylist__row is-found">
                <TickIcon size={15} class="" />
                <code>{key.selector}</code>
                <span class="md-keylist__detail">
                  {key.revoked
                    ? 'revoked, the key was withdrawn'
                    : key.key
                      ? `${key.key.algorithm === 'ed25519' ? 'Ed25519' : 'RSA'} ${key.key.bits}-bit`
                      : 'published, key unreadable'}
                </span>
              </li>
            ))}
            {missing.map((selector) => (
              <li key={selector} class="md-keylist__row is-missing">
                <CrossIcon size={15} />
                <code>{selector}</code>
                <span class="md-keylist__detail">
                  {guessed ? 'nothing published, and it was a guess' : 'nothing published here'}
                </span>
              </li>
            ))}
          </ul>

          {result.keys[0]?.record && (
            <pre class="md-testresult__record">{result.keys[0].record}</pre>
          )}

          <RecordScoreExplainer conditions={conditions} record="DKIM" />

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
            This page checks DKIM only.{' '}
            <a href={`/checkup?domain=${encodeURIComponent(result.domain)}`}>
              Run the full checkup
            </a>{' '}
            to see every record together, with a Vitals score for the whole domain.
          </p>
        </div>
      )}
    </div>
  );
}
