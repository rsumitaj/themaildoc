import { useEffect, useState } from 'preact/hooks';
import { TRIAGE_CHIP, TRIAGE_COLOR, triageFor, type Vitals } from '@maildoc/catalog/scoring';
import type { Severity } from '@maildoc/shared';
import { Explain } from './Explain';

/**
 * The Vitals monitor — a hospital readout, not a donut chart.
 *
 * The number counts up because a score that lands instantly reads as a form
 * field; one that climbs reads as a measurement being taken. It is the only
 * animation on this screen that exists for feel rather than function, and it
 * is skipped entirely when the visitor asks for reduced motion.
 */

const BAND_COLOR: Record<Vitals['band'], string> = {
  CRITICAL: 'var(--md-critical)',
  AT_RISK: 'var(--md-urgent)',
  NEEDS_CARE: 'var(--md-attention)',
  HEALTHY: 'var(--md-healthy)',
};

/**
 * One trace per band, and none of them is a flat line.
 *
 * A flatline means the patient is dead, which is both the wrong message about
 * a domain that merely needs a DMARC record and a direct breach of the voice
 * rule in CONVENTIONS.md. The rhythm degrades instead: healthy beats are tall
 * and evenly spaced, and they get shorter, sparser and more erratic as the
 * score drops.
 */
const EKG: Record<Vitals['band'], string> = {
  HEALTHY:
    'M4 17 H54 L62 17 L70 4 L80 30 L88 17 H130 L138 17 L146 4 L156 30 L164 17 H206 L214 17 L222 4 L232 30 L240 17 H256',
  NEEDS_CARE: 'M4 17 H62 L70 17 L78 7 L88 27 L96 17 H150 L158 17 L166 6 L176 28 L184 17 H256',
  AT_RISK: 'M4 17 H86 L94 17 L102 10 L110 24 L118 17 H188 L196 17 L204 11 L212 25 L220 17 H256',
  CRITICAL:
    'M4 17 H70 L76 17 L82 12 L88 22 L94 15 L100 19 L106 17 H176 L182 17 L188 13 L194 21 L200 17 H256',
};

function useCountUp(target: number): number {
  const [value, setValue] = useState(0);

  useEffect(() => {
    const reduced =
      typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) {
      setValue(target);
      return;
    }

    let frame = 0;
    const start = performance.now();
    const duration = 700;

    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / duration);
      // Ease out: fast at first, settling at the end, like a needle.
      const eased = 1 - (1 - progress) ** 3;
      setValue(Math.round(target * eased));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target]);

  return value;
}

export function VitalsMonitor({ vitals }: { vitals: Vitals }) {
  const shown = useCountUp(vitals.score);
  const color = BAND_COLOR[vitals.band];
  const tone =
    vitals.band === 'HEALTHY' ? 'is-healthy' : vitals.band === 'CRITICAL' ? 'is-critical' : '';

  const counts = (Object.entries(vitals.counts) as Array<[Severity, number]>).filter(
    ([, count]) => count > 0,
  );

  return (
    <section class={`md-vitals ${tone}`} aria-labelledby="vitals-heading">
      <h2 class="md-vitals__cap" id="vitals-heading">
        VITALS
        <Explain label="the Vitals score">
          Four questions, not one list: can somebody send as you, will your own mail arrive, would
          you find out, and what optional hardening is in place. Each is answered out of 100 and
          then weighted, so a domain can be excellent at one and poor at another. A record you have
          not published at all holds down the questions it would have answered. Open "How this score
          works" below for your domain's exact arithmetic.
        </Explain>
      </h2>

      <div
        class="md-vitals__score"
        style={{ color }}
        role="status"
        aria-label={`${vitals.score} out of 100. ${vitals.headline}.`}
      >
        {shown}
      </div>
      <div class="md-vitals__den">out of 100</div>

      <svg class="md-vitals__ekg" viewBox="0 0 260 34" preserveAspectRatio="none" aria-hidden="true">
        <path
          d={EKG[vitals.band]}
          fill="none"
          stroke={color}
          stroke-width="2.5"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
      </svg>

      <div class="md-vitals__verdict" style={{ background: color }}>
        {vitals.headline}
      </div>
      <p class="md-vitals__note">{vitals.note}</p>

      {counts.length > 0 && (
        <div class="md-vitals__counts">
          {counts.map(([severity, count]) => {
            const triage = triageFor(severity);
            return (
              <span key={severity} class={`md-chip is-${triage.toLowerCase()}`}>
                <span class="md-dot" style={{ color: TRIAGE_COLOR[triage] }} />
                {count} {TRIAGE_CHIP[triage]}
              </span>
            );
          })}
        </div>
      )}
    </section>
  );
}
