import { useState } from 'preact/hooks';
import { sortConditions, vitals as computeVitals } from '@maildoc/catalog/scoring';
import type { Condition } from '../lib/types';
import { CleanBill, ConditionCard } from './Chart';
import { DomainForm, rememberDomain, useDomainRunner, validateDomain } from './DomainForm';
import { ScoreExplainer } from './Explain';
import { CrossIcon, TickIcon } from './Icons';

/**
 * BIMI, judged on what the URLs actually serve.
 *
 * The record is two links. Every other checker reads the record and calls it
 * valid, which is why a domain whose certificate expired months ago still gets
 * a green tick elsewhere. This fetches both, checks the SVG against the profile
 * providers require, and reads the certificate's real expiry date.
 */

interface AssetReport {
  ok: boolean;
  failure?: string;
  detail?: string;
  bytes?: number;
  tinyPs?: boolean;
  hasTitle?: boolean;
  square?: boolean;
  viewBox?: string | null;
  forbidden?: string[];
  certificates?: number;
  notBefore?: string | null;
  notAfter?: string | null;
  daysRemaining?: number | null;
  issuer?: string | null;
}

interface BimiSuccess {
  ok: true;
  domain: string;
  found: boolean;
  record: string | null;
  logo: string | null;
  authority: string | null;
  declined: boolean;
  logoReport: AssetReport | null;
  certReport: AssetReport | null;
  dmarcPolicy: string | null;
  conditions: Condition[];
}

type BimiResponse = BimiSuccess | { ok: false; error: { code: string; message: string } };

const date = (iso: string | null | undefined): string =>
  iso ? new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) : 'not stated';

export default function Bimi() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<BimiSuccess | null>(null);

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
      const response = await fetch(`/api/bimi?domain=${encodeURIComponent(checked.domain)}`);
      const data = (await response.json()) as BimiResponse;
      if (!data.ok) throw new Error(data.error.message);

      setResult(data);
      rememberDomain(checked.domain);
    } catch (caught) {
      setError(
        caught instanceof Error && caught.message
          ? caught.message
          : 'The BIMI check couldn’t complete. Let’s try again.',
      );
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  useDomainRunner(examine);

  const conditions = result ? sortConditions(result.conditions) : [];
  const scored = result ? computeVitals(conditions) : null;

  return (
    <div>
      <DomainForm
        action="Check my BIMI"
        note="Reads the record, then fetches the logo and the certificate the way a mailbox does."
        busy={busy}
        onExamine={(domain) => void examine(domain)}
      />

      {error && (
        <p class="md-error" role="alert">
          {error}
        </p>
      )}

      {result && scored && (
        <div class="md-result md-testresult">
          <div class="md-testresult__head">
            <span
              class="md-dot"
              style={{ color: conditions.length === 0 ? 'var(--md-healthy)' : 'var(--md-critical)' }}
            />
            <div>
              <h2>Brand indicator for {result.domain}</h2>
              <p class="md-testresult__summary">
                {!result.found
                  ? 'No BIMI record published'
                  : result.declined
                    ? 'Published, and declining to show a logo'
                    : `${result.logoReport?.ok ? 'Logo loads' : 'Logo does not load'}, ${
                        result.certReport?.ok ? 'certificate loads' : 'certificate does not load'
                      }`}
              </p>
            </div>
            <span class="md-testresult__score md-mono">{scored.score}/100 · BIMI only</span>
          </div>

          {result.record && <pre class="md-testresult__record">{result.record}</pre>}

          {(result.logoReport || result.certReport) && (
            <div class="md-bimi">
              {result.logoReport && (
                <section class="md-bimi__panel">
                  <h3>The logo</h3>
                  {result.logoReport.ok && result.logo ? (
                    <>
                      <div class="md-bimi__previews">
                        {[80, 60, 40].map((size) => (
                          <figure key={size}>
                            <img src={result.logo as string} width={size} height={size} alt="" loading="lazy" />
                            <figcaption class="md-mono">{size}px</figcaption>
                          </figure>
                        ))}
                      </div>
                      <dl class="md-bimi__facts">
                        <Fact label="Profile" ok={result.logoReport.tinyPs === true}>
                          {result.logoReport.tinyPs ? 'SVG Tiny 1.2 Portable/Secure' : 'not tiny-ps'}
                        </Fact>
                        <Fact label="Square" ok={result.logoReport.square === true}>
                          {result.logoReport.viewBox ?? 'no viewBox'}
                        </Fact>
                        <Fact label="Title" ok={result.logoReport.hasTitle === true}>
                          {result.logoReport.hasTitle ? 'present' : 'missing'}
                        </Fact>
                        <Fact label="Size" ok={(result.logoReport.bytes ?? 0) <= 32 * 1024}>
                          {`${Math.round((result.logoReport.bytes ?? 0) / 1024)}KB of 32KB`}
                        </Fact>
                      </dl>
                    </>
                  ) : (
                    <p class="md-bimi__fail">
                      Did not load: {result.logoReport.detail ?? result.logoReport.failure}
                    </p>
                  )}
                </section>
              )}

              {result.certReport && (
                <section class="md-bimi__panel">
                  <h3>The certificate</h3>
                  {result.certReport.ok ? (
                    <dl class="md-bimi__facts">
                      <Fact label="Issued by" ok>
                        {result.certReport.issuer ?? 'not stated'}
                      </Fact>
                      <Fact label="Valid from" ok>
                        {date(result.certReport.notBefore)}
                      </Fact>
                      <Fact
                        label="Expires"
                        ok={(result.certReport.daysRemaining ?? 0) > 45}
                      >
                        {date(result.certReport.notAfter)}
                        {typeof result.certReport.daysRemaining === 'number' && (
                          <span class="md-bimi__days">
                            {result.certReport.daysRemaining < 0
                              ? ` (expired ${Math.abs(result.certReport.daysRemaining)} days ago)`
                              : ` (${result.certReport.daysRemaining} days left)`}
                          </span>
                        )}
                      </Fact>
                      <Fact label="Chain" ok={(result.certReport.certificates ?? 0) > 1}>
                        {`${result.certReport.certificates ?? 0} certificates`}
                      </Fact>
                    </dl>
                  ) : (
                    <p class="md-bimi__fail">
                      Did not load: {result.certReport.detail ?? result.certReport.failure}
                    </p>
                  )}
                </section>
              )}
            </div>
          )}

          {result.dmarcPolicy && (
            <p class="md-bimi__policy">
              DMARC is at <span class="md-mono">p={result.dmarcPolicy}</span>.{' '}
              {result.dmarcPolicy === 'quarantine' || result.dmarcPolicy === 'reject'
                ? 'That is enforcing, which BIMI requires.'
                : 'BIMI is ignored below quarantine, so no provider will show the logo whatever else is correct.'}
            </p>
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
            This page checks brand indicator only.{' '}
            <a href={`/health-library?domain=${encodeURIComponent(result.domain)}`}>
              Run the full checkup
            </a>{' '}
            to see every record together, with a Vitals score for the whole domain.
          </p>
        </div>
      )}
    </div>
  );
}

function Fact({
  label,
  ok,
  children,
}: {
  label: string;
  ok: boolean;
  children: preact.ComponentChildren;
}) {
  return (
    <div class={`md-bimi__fact ${ok ? 'is-ok' : 'is-bad'}`}>
      <dt>{label}</dt>
      <dd>
        {ok ? <TickIcon size={12} /> : <CrossIcon size={12} />}
        <span>{children}</span>
      </dd>
    </div>
  );
}
