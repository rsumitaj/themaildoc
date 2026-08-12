import { useState } from 'preact/hooks';
import { DomainForm, rememberDomain, useDomainRunner, validateDomain } from './DomainForm';
import { CopyBox } from './CopyBox';

/**
 * SPF flattening, with the trade stated before the copy button.
 *
 * A flattened record is a snapshot. It authorises the addresses your providers
 * used at the moment it was generated, and it does not update itself when they
 * change. Every flattener does this; most of them mention it underneath the
 * result, after you have already pasted it. It goes above here.
 */

const PRESERVE_REASON: Record<string, string> = {
  PER_MESSAGE:
    'evaluated against the connecting IP for every message, so it has no fixed set of addresses',
  MACRO: 'contains a macro, so it expands differently for every message',
  UNRESOLVED: 'did not resolve, so folding it in would have dropped a sender',
  BUDGET: 'we ran out of lookups before reaching it',
};

interface Expanded {
  term: string;
  ipv4: number;
  ipv6: number;
}

interface FlattenSuccess {
  ok: true;
  domain: string;
  original: string | null;
  flattened: string | null;
  strings: string[];
  lookupsBefore: number;
  lookupsAfter: number;
  bytesBefore: number;
  bytesAfter: number;
  ipv4: string[];
  ipv6: string[];
  expanded: Expanded[];
  preserved: { term: string; reason: string }[];
  complete: boolean;
  notes: string[];
}

type FlattenResponse = FlattenSuccess | { ok: false; error: { code: string; message: string } };

export default function Flatten() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<FlattenSuccess | null>(null);

  async function examine(raw: string) {
    const checked = validateDomain(raw);
    if ('error' in checked) {
      setError(checked.error);
      setResult(null);
      return;
    }

    setBusy(true);
    setError('');

    try {
      const response = await fetch(`/api/flatten?domain=${encodeURIComponent(checked.domain)}`);
      const data = (await response.json()) as FlattenResponse;
      if (!data.ok) throw new Error(data.error.message);

      setResult(data);
      rememberDomain(checked.domain);
    } catch (caught) {
      setError(
        caught instanceof Error && caught.message
          ? caught.message
          : 'The flattener couldn’t complete. Let’s try again.',
      );
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  useDomainRunner(examine);

  return (
    <div>
      <DomainForm
        action="Flatten my SPF"
        note="Expands every include, a and mx into the addresses behind them. Reads live DNS."
        busy={busy}
        onExamine={(domain) => void examine(domain)}
      />

      {error && (
        <p class="md-error" role="alert">
          {error}
        </p>
      )}

      {result && <Result result={result} />}
    </div>
  );
}

function Result({ result }: { result: FlattenSuccess }) {
  const saved = result.lookupsBefore - result.lookupsAfter;
  const noRecord = result.notes.includes('NO_RECORD');
  const alreadySmall = result.notes.includes('ALREADY_SMALL');

  if (noRecord) {
    return (
      <div class="md-result md-testresult">
        <div class="md-testresult__head">
          <span class="md-dot" style={{ color: 'var(--md-critical)' }} />
          <div>
            <h2>No SPF record on {result.domain}</h2>
            <p class="md-testresult__summary">
              There is nothing to flatten. Publish an SPF record first, then come back if it grows
              past ten lookups.
            </p>
          </div>
        </div>
        <p class="md-testresult__more">
          <a href="/lab/spf-generator">Build an SPF record</a> or{' '}
          <a href={`/health-library?domain=${encodeURIComponent(result.domain)}`}>
            run the full checkup
          </a>
          .
        </p>
      </div>
    );
  }

  return (
    <div class="md-result md-testresult">
      <div class="md-testresult__head">
        <span
          class="md-dot"
          style={{ color: result.complete ? 'var(--md-healthy)' : 'var(--md-critical)' }}
        />
        <div>
          <h2>SPF flattening for {result.domain}</h2>
          <p class="md-testresult__summary">
            {result.lookupsBefore} DNS lookups today, {result.lookupsAfter} after flattening
            {saved > 0 ? `, ${saved} fewer` : ''}.
          </p>
        </div>
      </div>

      <div class="md-flatcount">
        <div>
          <span class="md-flatcount__n">{result.lookupsBefore}</span>
          <span class="md-flatcount__l">lookups now</span>
        </div>
        <div class={result.lookupsAfter > 10 ? 'is-bad' : 'is-good'}>
          <span class="md-flatcount__n">{result.lookupsAfter}</span>
          <span class="md-flatcount__l">after</span>
        </div>
        <div>
          <span class="md-flatcount__n">{result.ipv4.length + result.ipv6.length}</span>
          <span class="md-flatcount__l">addresses folded in</span>
        </div>
        <div>
          <span class="md-flatcount__n">{result.bytesAfter}</span>
          <span class="md-flatcount__l">bytes</span>
        </div>
      </div>

      {alreadySmall && (
        <p class="md-flatnote">
          This record is already inside the limit. Flattening it would trade a working record for
          one you have to maintain by hand. Leave it alone.
        </p>
      )}

      {!result.complete && (
        <p class="md-error" role="alert">
          We could not resolve everything in this chain, so there is no record to copy. Publishing a
          partial one would silently drop the senders we could not reach.{' '}
          {result.preserved
            .filter((entry) => entry.reason === 'UNRESOLVED')
            .map((entry) => entry.term)
            .join(', ')}
        </p>
      )}

      <h3 class="md-flath">Before you copy this</h3>
      <ul class="md-flatwarn">
        <li>
          A flattened record is a snapshot of the addresses your providers used just now. When they
          add or move an IP, your record still says the old one and that mail starts failing SPF.
        </li>
        <li>
          Re-run this whenever you add a sender, and at least every quarter. Nothing tells you when
          it goes stale.
        </li>
        <li>
          Flattening is a workaround for the ten lookup limit, not a cleanup. Removing a vendor you
          no longer use is always the better fix.
        </li>
      </ul>

      {result.flattened && (
        <>
          <h3 class="md-flath">Your flattened record</h3>
          <CopyBox
            value={result.flattened}
            label={`${result.bytesAfter} bytes${result.strings.length > 1 ? `, split into ${result.strings.length} strings` : ''}`}
          />

          {result.strings.length > 1 && (
            <>
              <p class="md-flatnote">
                This is longer than a single TXT string can be, so it must be published as{' '}
                {result.strings.length} character-strings inside one record. Most DNS panels do this
                for you when you paste the whole thing. If yours does not, enter them in this order.
              </p>
              {result.strings.map((string, index) => (
                <CopyBox key={index} value={string} label={`String ${index + 1}`} />
              ))}
            </>
          )}
        </>
      )}

      {result.original && (
        <>
          <h3 class="md-flath">What you publish today</h3>
          <pre class="md-testresult__record">{result.original}</pre>
        </>
      )}

      {result.expanded.length > 0 && (
        <>
          <h3 class="md-flath">Where the addresses came from</h3>
          <div class="md-flatsources">
            {result.expanded.map((source) => (
              <div key={source.term} class="md-flatsource">
                <span class="md-mono">{source.term}</span>
                <span class="md-flatsource__n">
                  {source.ipv4} IPv4{source.ipv6 > 0 ? `, ${source.ipv6} IPv6` : ''}
                </span>
              </div>
            ))}
          </div>
        </>
      )}

      {result.preserved.length > 0 && (
        <>
          <h3 class="md-flath">Kept as they were</h3>
          <ul class="md-flatwarn">
            {result.preserved.map((entry) => (
              <li key={entry.term}>
                <span class="md-mono">{entry.term}</span> was left in place because it{' '}
                {PRESERVE_REASON[entry.reason] ?? 'could not be expanded'}.
              </li>
            ))}
          </ul>
        </>
      )}

      <p class="md-testresult__more">
        <a href={`/lab/spf-checker?domain=${encodeURIComponent(result.domain)}`}>
          See the full chain
        </a>{' '}
        to decide what to remove before you flatten anything.
      </p>
    </div>
  );
}
