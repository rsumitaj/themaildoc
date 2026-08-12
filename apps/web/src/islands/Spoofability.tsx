import { useState } from 'preact/hooks';
import type { CheckResponse, CheckSuccess } from '../lib/types';
import { DomainForm, rememberDomain, useDomainRunner, validateDomain } from './DomainForm';
import { SpoofBanner } from './Chart';

/**
 * The spoofability verdict on its own.
 *
 * One question, one answer, and the reasoning underneath it. The verdict comes
 * from the same engine as the full chart — it follows the *effective* DMARC
 * policy, so a domain publishing p=reject with t=y is told the truth.
 */
export default function Spoofability() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<CheckSuccess | null>(null);

  async function examine(raw: string) {
    const checked = validateDomain(raw);
    if ('error' in checked) {
      setError(checked.error);
      setResult(null);
      return;
    }

    setBusy(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch(`/api/check?domain=${encodeURIComponent(checked.domain)}`);
      const data = (await response.json()) as CheckResponse;
      if (!data.ok) throw new Error(data.error.message);
      setResult(data);
      rememberDomain(checked.domain);
    } catch (caught) {
      setError(
        caught instanceof Error && caught.message
          ? caught.message
          : 'The checkup couldn’t complete. Let’s try again.',
      );
    } finally {
      setBusy(false);
    }
  }

  useDomainRunner(examine);

  const dmarc = result?.detail.dmarc;
  const spf = result?.detail.spf;

  return (
    <div>
      <DomainForm
        action="Can I be spoofed?"
        note="One question, answered from your live DNS. Free, and no signup."
        busy={busy}
        onExamine={(domain) => void examine(domain)}
      />

      {error && (
        <p class="md-error" role="alert">
          {error}
        </p>
      )}

      {result && dmarc && spf && (
        <div class="md-result md-testresult">
          <SpoofBanner spoofability={result.spoofability} />

          <div class="md-records">
            <div class="md-record">
              <div class="md-record__head">DMARC</div>
              <div class="md-record__label">
                {dmarc.found ? `Published, p=${dmarc.policy}` : 'Not published'}
              </div>
              <div class="md-record__summary">
                {dmarc.found
                  ? dmarc.testMode
                    ? `Test mode is on, so receivers apply p=none whatever the record says.`
                    : `Receivers apply p=${dmarc.effectivePolicy}.`
                  : 'Nothing tells receivers what to do with forged mail.'}
              </div>
            </div>

            <div class="md-record">
              <div class="md-record__head">SPF</div>
              <div class="md-record__label">
                {spf.found ? `Ends in ${spf.allQualifier ?? 'no all'}` : 'Not published'}
              </div>
              <div class="md-record__summary">
                {spf.found
                  ? `${spf.lookupCount} of 10 lookups used.`
                  : 'Nothing limits which servers may send for you.'}
              </div>
            </div>

            <div class="md-record">
              <div class="md-record__head">SUBDOMAINS</div>
              <div class="md-record__label">
                {dmarc.found ? `sp=${dmarc.subdomainPolicy}` : 'Unprotected'}
              </div>
              <div class="md-record__summary">
                {dmarc.found && dmarc.subdomainPolicy === dmarc.policy
                  ? 'Subdomains inherit the same protection.'
                  : 'Subdomains are the easier target when they are weaker than the domain.'}
              </div>
            </div>
          </div>

          <p class="md-testresult__more">
            <a href={`/checkup?domain=${encodeURIComponent(result.domain)}`}>Run the full checkup</a> to see
            every record behind this verdict, each with its prescription.
          </p>

        </div>
      )}
    </div>
  );
}
