import { useId, useState } from 'preact/hooks';
import { scoreBreakdown } from '@maildoc/catalog/scoring';
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
 * How the score was produced, in full.
 *
 * Collapsed by default because most people want the number. Open, it is the
 * whole model: nothing here is weighted by anything except the table below.
 */
export function ScoreExplainer({ conditions }: { conditions: readonly Condition[] }) {
  const [open, setOpen] = useState(false);
  const sum = scoreBreakdown(conditions);

  return (
    <div class="md-scorewhy">
      <button
        type="button"
        class="md-scorewhy__toggle"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        How this score works
        <span aria-hidden="true">{open ? '−' : '+'}</span>
      </button>

      {open && (
        <div class="md-scorewhy__body">
          <p>
            Every domain starts at 100. Each condition below subtracts a fixed amount, set by how
            much damage it does. Nothing is weighted by anything else, so the same problem costs the
            same on every domain.
          </p>

          <h4>This domain, in full</h4>
          <table class="md-scorewhy__table">
            <tbody>
              <tr>
                <td>Starting score</td>
                <td class="md-mono">100</td>
              </tr>
              <tr>
                <td>
                  {sum.charged.filter((entry) => !entry.hardening && !entry.minor).length}{' '}
                  authentication and delivery conditions
                </td>
                <td class="md-mono">−{sum.core}</td>
              </tr>
              {sum.charged.some((entry) => entry.minor && !entry.hardening) && (
                <tr>
                  <td>
                    {sum.charged.filter((entry) => entry.minor && !entry.hardening).length} minor
                    findings
                    {sum.minor > sum.minorCharged
                      ? ` (worth ${sum.minor}, capped at ${sum.minorCharged})`
                      : ''}
                  </td>
                  <td class="md-mono">−{sum.minorCharged}</td>
                </tr>
              )}
              {sum.charged.some((entry) => entry.hardening) && (
                <tr>
                  <td>
                    {sum.charged.filter((entry) => entry.hardening).length} optional hardening gaps
                    {sum.hardening > sum.hardeningCharged
                      ? ` (worth ${sum.hardening}, capped at ${sum.hardeningCharged})`
                      : ''}
                  </td>
                  <td class="md-mono">−{sum.hardeningCharged}</td>
                </tr>
              )}
              <tr>
                <td>
                  <strong>Your Vitals</strong>
                </td>
                <td class="md-mono">
                  <strong>{sum.score}</strong>
                </td>
              </tr>
            </tbody>
          </table>

          <h4>What each condition costs</h4>

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
                  <td class="md-mono">−{row.deduction}</td>
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

          <h4>Three rules that stop the number lying</h4>
          <ul>
            <li>
              <strong>Each problem is charged once.</strong> Three selectors carrying the same weak
              key is one fix, not three. The chart still lists every instance.
            </li>
            <li>
              <strong>Minor findings are capped at 20 points between all of them.</strong> Six
              small things is 48 points otherwise, which put a domain enforcing p=reject with valid
              SPF and DKIM into the critical band on tidiness alone.
            </li>
            <li>
              <strong>Optional hardening is capped at 25 points between all of it.</strong> MTA-STS,
              TLS-RPT, BIMI, CAA, DNSSEC and IPv6 make a domain better and no receiver requires
              them. Uncapped, they pushed well-run domains down beside domains with nothing.
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
