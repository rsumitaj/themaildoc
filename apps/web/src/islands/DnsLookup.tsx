import { useState } from 'preact/hooks';
import { DomainForm, rememberDomain, useDomainRunner, validateDomain } from './DomainForm';

/**
 * A plain DNS record lookup.
 *
 * Every value here is untrusted DNS content rendered as a JSX text node — no
 * innerHTML anywhere on this page, because a TXT record is the easiest place
 * on the internet to hide a script tag.
 */

interface Answer {
  type: string;
  status: string;
  ttl: number | null;
  records: string[];
}

interface LookupSuccess {
  ok: true;
  domain: string;
  answers: Answer[];
  meta: { queriesUsed: number };
}

type LookupResponse = LookupSuccess | { ok: false; error: { code: string; message: string } };

const TYPES = ['ALL', 'A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'DNSKEY', 'DS'] as const;

export default function DnsLookup() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<LookupSuccess | null>(null);
  const [type, setType] = useState<string>('ALL');

  async function examine(raw: string, recordType = type) {
    const checked = validateDomain(raw);
    if ('error' in checked) {
      setError(checked.error);
      setResult(null);
      return;
    }

    setBusy(true);
    setError('');

    try {
      const query =
        `domain=${encodeURIComponent(checked.domain)}` +
        (recordType === 'ALL' ? '' : `&type=${encodeURIComponent(recordType)}`);
      const response = await fetch(`/api/lookup?${query}`);
      const data = (await response.json()) as LookupResponse;
      if (!data.ok) throw new Error(data.error.message);

      setResult(data);
      rememberDomain(checked.domain);
    } catch (caught) {
      setError(
        caught instanceof Error && caught.message
          ? caught.message
          : 'The lookup couldn’t complete, let’s try again.',
      );
    } finally {
      setBusy(false);
    }
  }

  useDomainRunner(examine);

  return (
    <div>
      <DomainForm
        action="Look up records"
        note="Reads live DNS through two independent resolvers. Free, instant, no signup."
        busy={busy}
        onExamine={(domain) => void examine(domain)}
      />

      <div class="md-types" role="group" aria-label="Record type">
        {TYPES.map((option) => (
          <button
            key={option}
            type="button"
            class={`md-type ${type === option ? 'is-active' : ''}`}
            onClick={() => {
              setType(option);
              if (result) void examine(result.domain, option);
            }}
          >
            {option}
          </button>
        ))}
      </div>

      {error && (
        <p class="md-error" role="alert">
          {error}
        </p>
      )}

      {result && (
        <div class="md-result md-testresult">
          <div class="md-testresult__head">
            <span class="md-dot" style={{ color: 'var(--md-healthy)' }} />
            <div>
              <h2>DNS records for {result.domain}</h2>
              <p class="md-testresult__summary">
                {result.answers.reduce((total, answer) => total + answer.records.length, 0)} records
                across {result.answers.length} type
                {result.answers.length === 1 ? '' : 's'}
              </p>
            </div>
          </div>

          {result.answers.map((answer) => (
            <div key={answer.type} class="md-answer">
              <div class="md-answer__head">
                <span class="md-mono">{answer.type}</span>
                <span class="md-mono md-answer__meta">
                  {answer.status}
                  {answer.ttl !== null ? ` · TTL ${answer.ttl}s` : ''}
                </span>
              </div>
              {answer.records.length === 0 ? (
                <p class="md-answer__empty">No records published.</p>
              ) : (
                answer.records.map((record) => (
                  <pre key={record} class="md-testresult__record">
                    {record}
                  </pre>
                ))
              )}
            </div>
          ))}

          <p class="md-testresult__more">
            Records are what is published. <a href={`/health-library?domain=${encodeURIComponent(result.domain)}`}>
              Run the full checkup
            </a>{' '}
            to find out whether they are correct.
          </p>
        </div>
      )}
    </div>
  );
}
