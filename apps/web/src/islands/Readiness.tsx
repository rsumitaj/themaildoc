import { useState } from 'preact/hooks';
import { assessReadiness, type Readiness } from '@maildoc/engines/readiness';
import type { CheckResponse, CheckSuccess, DkimResponse } from '../lib/types';
import { DomainForm, rememberDomain, useDomainRunner, validateDomain } from './DomainForm';
import { CrossIcon, TickIcon } from './Icons';

/**
 * Bulk-sender readiness against the Google, Yahoo and Microsoft rules.
 *
 * The requirements that cannot be determined from DNS are shown as exactly
 * that, and excluded from the count. A checklist that shows nine green ticks
 * when only six were actually checked is a lie the sender finds out about from
 * their bounce rate.
 */

const STATUS_LABEL = {
  PASS: 'Pass',
  FAIL: 'Fail',
  WARN: 'Check',
  UNVERIFIABLE: 'Not checkable',
} as const;

const STATUS_CLASS = {
  PASS: 'is-healthy',
  FAIL: 'is-critical',
  WARN: 'is-attention',
  UNVERIFIABLE: 'is-minor',
} as const;

export default function ReadinessCheck() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [domain, setDomain] = useState('');

  async function examine(raw: string) {
    const checked = validateDomain(raw);
    if ('error' in checked) {
      setError(checked.error);
      setReadiness(null);
      return;
    }

    setBusy(true);
    setError('');
    setReadiness(null);

    try {
      const query = `domain=${encodeURIComponent(checked.domain)}`;
      const [core, dkim] = await Promise.all([
        fetch(`/api/check?${query}`).then((response) => response.json() as Promise<CheckResponse>),
        fetch(`/api/check/dkim?${query}`).then(
          (response) => response.json() as Promise<DkimResponse>,
        ),
      ]);

      if (!core.ok) throw new Error(core.error.message);

      setReadiness(assessReadiness(toInput(core, dkim)));
      setDomain(checked.domain);
      rememberDomain(checked.domain);
    } catch (caught) {
      setError(
        caught instanceof Error && caught.message
          ? caught.message
          : 'The checkup couldn’t complete, let’s try again.',
      );
    } finally {
      setBusy(false);
    }
  }

  useDomainRunner(examine);

  const groups = readiness
    ? [
        { heading: 'Required of every sender', scope: 'all' as const },
        { heading: 'Required of bulk senders (5,000+ a day)', scope: 'bulk' as const },
      ]
    : [];

  return (
    <div>
      <DomainForm
        action="Check my readiness"
        note="Measured against the Google, Yahoo and Microsoft sender rules. Free, no signup."
        busy={busy}
        onExamine={(value) => void examine(value)}
      />

      {error && (
        <p class="md-error" role="alert">
          {error}
        </p>
      )}

      {readiness && (
        <div class="md-result md-testresult">
          <div class="md-testresult__head">
            <span
              class="md-dot"
              style={{ color: readiness.ready ? 'var(--md-healthy)' : 'var(--md-critical)' }}
            />
            <div>
              <h2>Sender readiness for {domain}</h2>
              <p class="md-testresult__summary">
                {readiness.passed} of {readiness.checkable} checkable requirements pass
                {readiness.failed > 0 ? `, ${readiness.failed} failing` : ''}.
              </p>
            </div>
          </div>

          {groups.map((group) => (
            <div key={group.scope} class="md-labgroup">
              <h2>{group.heading}</h2>
              <div class="md-reqlist">
                {readiness.requirements
                  .filter((requirement) => requirement.scope === group.scope)
                  .map((requirement) => (
                    <div key={requirement.id} class="md-req">
                      <span class={`md-chip ${STATUS_CLASS[requirement.status]}`}>
                        {requirement.status === 'PASS' ? (
                          <TickIcon size={11} />
                        ) : requirement.status === 'FAIL' ? (
                          <CrossIcon size={11} />
                        ) : null}
                        {STATUS_LABEL[requirement.status]}
                      </span>
                      <div>
                        <h3>{requirement.title}</h3>
                        <p>{requirement.detail}</p>
                        {requirement.fix && requirement.status !== 'PASS' && (
                          <p class="md-req__fix">
                            <span class="md-condition__rxlabel">Rx</span> {requirement.fix}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          ))}

          <p class="md-testresult__more">
            <a href={`/health-library?domain=${encodeURIComponent(domain)}`}>Run the full checkup</a> for the
            records behind each of these, with the fix for every one.
          </p>

        </div>
      )}
    </div>
  );
}

/** Reshape two API responses into what the readiness engine needs. */
function toInput(core: CheckSuccess, dkim: DkimResponse) {
  const keys = dkim.ok ? dkim.keys : [];
  const sizes = keys.map((key) => key.key?.bits).filter((bits): bits is number => typeof bits === 'number');

  return {
    domain: core.domain,
    spf: {
      found: core.detail.spf.found,
      allQualifier: core.detail.spf.allQualifier,
      lookupCount: core.detail.spf.lookupCount,
    },
    dmarc: {
      found: core.detail.dmarc.found,
      effectivePolicy: core.detail.dmarc.effectivePolicy,
      alignment: core.detail.dmarc.alignment,
      rua: core.detail.dmarc.rua,
    },
    dkim: dkim.ok
      ? { found: dkim.found, weakestKey: sizes.length > 0 ? Math.min(...sizes) : null }
      : null,
    ptr: {
      checked: core.detail.ptr.checked.length,
      forwardConfirmed: core.detail.ptr.checked.filter((entry) => entry.forwardConfirmed).length,
      noOwnServers: core.detail.ptr.noOwnServers,
    },
    mtasts: { announced: core.detail.mtasts.announced },
  };
}
