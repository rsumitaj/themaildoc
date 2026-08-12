import { useState } from 'preact/hooks';
import { TRIAGE_CHIP, TRIAGE_COLOR, triageFor } from '@maildoc/catalog/scoring';
import type { Condition, RecordSummary, Spoofability } from '../lib/types';
import { AlertIcon, ShieldIcon } from './Icons';

/**
 * The chart: what is wrong, why it matters, and the prescription.
 *
 * Everything rendered here is derived from DNS the patient does not control
 * the contents of, so it all goes through JSX text nodes — never
 * dangerouslySetInnerHTML. That is the XSS boundary for this whole product.
 */

const STATUS_TRIAGE = {
  CRITICAL: 'CRITICAL',
  ATTENTION: 'ATTENTION',
  HEALTHY: 'HEALTHY',
} as const;

export function RecordRow({ records }: { records: RecordSummary[] }) {
  return (
    <div class="md-records">
      {records.map((record) => {
        const triage = STATUS_TRIAGE[record.status];
        return (
          <div class="md-record" key={record.record}>
            <div class="md-record__head">
              <span class="md-dot" style={{ color: TRIAGE_COLOR[triage] }} />
              {record.record}
            </div>
            <div class="md-record__label">{record.label}</div>
            <div class="md-record__summary">{record.summary}</div>
          </div>
        );
      })}
    </div>
  );
}

export function SpoofBanner({ spoofability }: { spoofability: Spoofability }) {
  const tone =
    spoofability.verdict === 'PROTECTED'
      ? 'is-good'
      : spoofability.verdict === 'PARTIAL'
        ? 'is-partial'
        : 'is-bad';

  return (
    <section class={`md-spoof ${tone}`} aria-label="Spoofability">
      <span class="md-spoof__icon">
        {spoofability.verdict === 'PROTECTED' ? <ShieldIcon size={22} /> : <AlertIcon size={22} />}
      </span>
      <div>
        <div class="md-spoof__title">{spoofability.headline}</div>
        <div class="md-spoof__detail">{spoofability.detail}</div>
        {spoofability.reasons.length > 0 && (
          <ul class="md-spoof__reasons">
            {spoofability.reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard access can be refused; the text is on screen either way.
    }
  };

  return (
    <button type="button" class="md-copy" onClick={copy} aria-label="Copy the prescription">
      {copied ? 'copied' : 'copy Rx'}
    </button>
  );
}

export interface ConditionCardProps {
  condition: Condition;
}

export function ConditionCard({ condition }: ConditionCardProps) {
  const triage = triageFor(condition.severity);
  const tone = triage.toLowerCase();

  return (
    <article class={`md-condition is-${tone}`}>
      <div class="md-condition__top">
        <h3 class="md-condition__title">{condition.title}</h3>
        <span class={`md-chip is-${tone}`}>{TRIAGE_CHIP[triage]}</span>
      </div>

      <p class="md-condition__why">{condition.why}</p>

      {condition.evidence && (
        <div class="md-condition__evidence" title="The record as published">
          {condition.evidence}
        </div>
      )}

      <div class="md-condition__rx">
        <span class="md-condition__rxtext">
          <span class="md-condition__rxlabel">Rx</span>
          {condition.fix}
        </span>
        <CopyButton text={condition.fix} />
      </div>

      <div class="md-condition__foot">
        <RfcLink citation={condition.rfc} />
        <a href={`/library/checks/${condition.code.toLowerCase().replace(/_/g, '-')}`}>
          {condition.code}
        </a>
      </div>
    </article>
  );
}

export function CleanBill() {
  return (
    <article class="md-condition is-healthy">
      <div class="md-condition__top">
        <h3 class="md-condition__title">Clean bill of health</h3>
        <span class="md-chip is-healthy">DISCHARGED</span>
      </div>
      <p class="md-condition__why">
        Nothing to treat. Every record we examined is published correctly and doing its job, which
        is rarer than it should be.
      </p>
    </article>
  );
}

/**
 * The citation, as a link to the exact section it names.
 *
 * People who care whether a finding is real want to check it, and asking them
 * to search for "RFC 9989 section 4.7" themselves is a small insult to the
 * only audience that will ever look. The anchor format is the one the RFC
 * Editor publishes, so these land on the paragraph rather than the top of a
 * hundred-page document.
 *
 * BIMI has no RFC. It is still an Internet-Draft, and drafts move, so that one
 * is left as plain text rather than pointed at a URL that will rot.
 */
function RfcLink({ citation }: { citation: string }) {
  const match = /^RFC (\d+) (?:section ([\d.]+)|Appendix ([A-Z](?:\.\d+)*))$/.exec(citation);
  if (!match) return <span>{citation}</span>;

  const anchor = match[2] ? `section-${match[2]}` : `appendix-${match[3]}`;

  return (
    <a
      class="md-condition__rfc"
      href={`https://www.rfc-editor.org/rfc/rfc${match[1]}#${anchor}`}
      target="_blank"
      rel="noopener noreferrer"
    >
      {citation}
    </a>
  );
}
