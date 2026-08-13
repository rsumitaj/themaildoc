import { useId, useState } from 'preact/hooks';
import { scoreBreakdown, type SpoofVerdict } from '@maildoc/catalog/scoring';
import type { Condition } from '../lib/types';

/**
 * An explanation attached to a thing on screen.
 *
 * A `title` attribute would be simpler and would be invisible on every phone
 * and to most screen readers. This is a real button with real state, so it
 * works with a mouse, a keyboard and a thumb.
 */
export function Explain({ label, children }: { label: string; children: preact.ComponentChildren }) {
  const [open, setOpen] = useState(false);
  const id = useId();

  return (
    <span class="md-explain">
      <button
        type="button"
        class="md-explain__button"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(!open)}
      >
        <span aria-hidden="true">?</span>
        <span class="md-visually-hidden">What does {label} mean?</span>
      </button>
      {open && (
        <span class="md-explain__body" id={id} role="note">
          {children}
        </span>
      )}
    </span>
  );
}

const SEVERITY_ROWS: ReadonlyArray<{ triage: string; tone: string; deduction: number; meaning: string }> = [
  {
    triage: 'CODE RED',
    tone: 'is-critical',
    deduction: 40,
    meaning: 'Mail is being lost or anyone can send as you. Fix today.',
  },
  {
    triage: 'URGENT',
    tone: 'is-urgent',
    deduction: 25,
    meaning: 'Working now, but one change away from breaking, or leaving you open.',
  },
  {
    triage: 'ATTENTION',
    tone: 'is-attention',
    deduction: 15,
    meaning: 'Costing you delivery or protection you have already paid for.',
  },
  { triage: 'MINOR', tone: 'is-minor', deduction: 8, meaning: 'Worth tidying when you are next in DNS.' },
  { triage: 'NOTE', tone: 'is-healthy', deduction: 2, meaning: 'Informational. Often deliberate.' },
];

const BANDS: ReadonlyArray<{ range: string; name: string; meaning: string }> = [
  { range: '85 to 100', name: 'Healthy', meaning: 'Nothing serious. A few tune-ups at most.' },
  { range: '65 to 84', name: 'Needs care', meaning: 'Real gaps costing you delivery or exposure.' },
  { range: '40 to 64', name: 'At risk', meaning: 'Authentication is not doing its job.' },
  { range: '0 to 39', name: 'Critical', meaning: 'Exposed right now.' },
];

/**
 * Why a missing record holds a pillar down, in one clause each.
 *
 * Subtraction cannot say "you have nothing": every finding is a fault in
 * something published, so a domain publishing nothing collects almost no
 * findings and keeps almost all of its marks. These are the three cases where
 * absence itself is the answer to the question, and each one names what a
 * receiver can no longer do.
 */
const ABSENCE_REASON: Record<string, string> = {
  DOMAIN_NXDOMAIN: 'this domain does not resolve at all, so there is no zone to score.',
  DMARC_RECORD_MISSING:
    'with no DMARC record, a receiver has no instruction to refuse forged mail and no report is ever sent to you.',
  SPF_RECORD_MISSING:
    'with no SPF record, nothing states which servers may send for you.',
};

/**
 * How the score was produced, in full.
 *
 * Collapsed by default because most people want the number. Open, it is the
 * entire model with this domain's own arithmetic in it, so anybody can check
 * the result rather than take it on trust.
 */
export function ScoreExplainer({
  conditions,
  spoofability,
}: {
  conditions: readonly Condition[];
  spoofability?: SpoofVerdict;
}) {
  const [open, setOpen] = useState(false);

  const sum = scoreBreakdown(conditions, spoofability ? { spoofability } : {});

  return (
    <div class="md-scorewhy">
      <button
        type="button"
        class="md-scorewhy__toggle"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        How this score works
        <span aria-hidden="true">{open ? '\u2212' : '+'}</span>
      </button>

      {open && (
        <div class="md-scorewhy__body">
          <p>
            The score is four questions, not one list. Each is answered out of 100 from the findings
            that belong to it, then counted by how much it matters. A domain can be excellent at one
            and poor at another, and a single bad answer can no longer drag the whole number to
            nothing.
          </p>

          <h4>This domain, in full</h4>
          <table class="md-scorewhy__table">
            <thead>
              <tr>
                <th>Question</th>
                <th>Score</th>
                <th>Counts for</th>
                <th>Contributes</th>
              </tr>
            </thead>
            <tbody>
              {sum.pillars.map((pillar) => (
                <tr key={pillar.pillar}>
                  <td>
                    <strong>{pillar.label}</strong>
                    <span class="md-scorewhy__q">{pillar.question}</span>
                    {pillar.findings.length > 0 && (
                      <span class="md-scorewhy__codes md-mono">
                        {pillar.findings
                          .map((finding) => `${finding.code} \u2212${finding.deduction}`)
                          .join(', ')}
                      </span>
                    )}
                    {/*
                      A ceiling nobody can see is indistinguishable from a
                      fudge, and this whole table exists so the number can be
                      checked rather than believed. If a pillar was held down
                      because a record is absent, it says which record.
                    */}
                    {pillar.ceiling !== null && !pillar.floored && (
                      <span class="md-scorewhy__q">
                        Held at {pillar.ceiling.limit}: {ABSENCE_REASON[pillar.ceiling.code]}
                      </span>
                    )}
                    {pillar.floored && (
                      <span class="md-scorewhy__q">
                        Raised to {pillar.score}: your DMARC policy stops impersonation whatever else
                        is missing.
                      </span>
                    )}
                  </td>
                  <td class="md-mono">{pillar.score}</td>
                  <td class="md-mono">{pillar.weight}%</td>
                  <td class="md-mono">
                    {Math.round((pillar.score * pillar.weight) / 100)}
                  </td>
                </tr>
              ))}
              <tr>
                <td>
                  <strong>Your Vitals</strong>
                  {sum.capped && (
                    <span class="md-scorewhy__q">
                      Held at {sum.score} because the domain can still be sent as. The weighted total
                      was {sum.weighted}.
                    </span>
                  )}
                </td>
                <td class="md-mono">
                  <strong>{sum.score}</strong>
                </td>
                <td />
                <td />
              </tr>
            </tbody>
          </table>

          <h4>Why these four, and why those weights</h4>
          <ul>
            <li>
              <strong>Impersonation defence counts for 45.</strong> It is the one that ends up in a
              news story, and it is the only question a DMARC policy actually answers. RFC 9989.
            </li>
            <li>
              <strong>Delivery integrity counts for 25.</strong> Blowing the ten-lookup limit or
              publishing an unreachable mail server costs you real mail. RFC 7208 section 4.6.4.
            </li>
            <li>
              <strong>Visibility counts for 15.</strong> Reporting is how you find out about both of
              the above before somebody tells you. RFC 9990.
            </li>
            <li>
              <strong>Hardening counts for 15.</strong> MTA-STS, DNSSEC, CAA and BIMI make a domain
              better and no receiver requires any of them.
            </li>
          </ul>

          <h4>What each finding costs its own pillar</h4>
          <table class="md-scorewhy__table">
            <thead>
              <tr>
                <th>Condition</th>
                <th>Costs</th>
                <th>Means</th>
              </tr>
            </thead>
            <tbody>
              {SEVERITY_ROWS.map((row) => (
                <tr key={row.triage}>
                  <td>
                    <span class={`md-chip ${row.tone}`}>{row.triage}</span>
                  </td>
                  <td class="md-mono">\u2212{row.deduction}</td>
                  <td>{row.meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h4>What the number means</h4>
          <table class="md-scorewhy__table">
            <tbody>
              {BANDS.map((band) => (
                <tr key={band.name}>
                  <td class="md-mono">{band.range}</td>
                  <td>
                    <strong>{band.name}</strong>
                  </td>
                  <td>{band.meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h4>Four rules that stop the number lying</h4>
          <ul>
            <li>
              <strong>Each problem is charged once.</strong> Three selectors carrying the same weak
              key is one fix, not three. The chart still lists every instance.
            </li>
            <li>
              <strong>A pillar stops at zero.</strong> It cannot go negative and borrow against the
              others, which is how a protected domain used to end up scoring nothing at all.
            </li>
            <li>
              <strong>The score can never contradict the verdict.</strong> If your DMARC policy
              refuses unauthenticated mail, the impersonation score cannot read as though it does
              not. If anyone can send as you, no amount of tidy hardening lifts you out of critical.
            </li>
            <li>
              <strong>Nothing that is correct costs anything.</strong> A null MX on a domain that
              receives no mail, or strict alignment you chose on purpose, is reported and charged
              nothing.
            </li>
          </ul>

          <p class="md-scorewhy__foot">
            The score covers what your DNS publishes today. It does not include anything from your
            DMARC reports, because those describe last week's mail and a quiet week would flatter a
            broken domain.
          </p>
        </div>
      )}
    </div>
  );
}
