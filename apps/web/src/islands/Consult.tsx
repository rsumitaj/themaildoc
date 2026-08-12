import { useEffect, useState } from 'preact/hooks';
import { HELP_OPTIONS } from '../lib/leads';
import { ArrowIcon, TickIcon } from './Icons';

/**
 * The consultation request form.
 *
 * Every "Consult an expert" in the product ends here, so it asks for as little
 * as it can get away with — a name, an address, and what is wrong. The domain
 * and the score come along automatically when the patient arrived from a
 * result, because "example.com, 32/100, spoofable" is the difference between a
 * generic reply and a useful one.
 */

interface Prefill {
  domain: string;
  score: string;
  band: string;
  spoofable: string;
}

export default function Consult() {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState('');
  /** Which field the error belongs to, so it is shown where the fix is. */
  const [badField, setBadField] = useState('');
  const [prefill, setPrefill] = useState<Prefill>({
    domain: '',
    score: '',
    band: '',
    spoofable: '',
  });

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    setPrefill({
      domain: params.get('domain') ?? '',
      score: params.get('score') ?? '',
      band: params.get('band') ?? '',
      spoofable: params.get('spoofable') ?? '',
    });
  }, []);

  async function submit(event: Event): Promise<void> {
    event.preventDefault();
    if (busy) return;

    // Read the form, not component state: autofill sets values without ever
    // firing an input event.
    const form = event.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const value = (key: string) => String(data.get(key) ?? '');

    setBusy(true);
    setError('');
    setBadField('');

    try {
      const response = await fetch('/api/consult', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          name: value('name'),
          email: value('email'),
          company: value('company'),
          domain: value('domain'),
          helpWith: value('helpWith'),
          message: value('message'),
          website: value('website'),
          vitalsScore: prefill.score,
          vitalsBand: prefill.band,
          spoofable: prefill.spoofable,
          sourcePage: document.referrer ? new URL(document.referrer).pathname : location.pathname,
        }),
      });

      const result = (await response.json()) as {
        ok: boolean;
        error?: { message: string; field?: string };
      };

      if (!result.ok) {
        // Put the message next to the input that has to change, and move the
        // cursor there. An error under the button makes people hunt.
        const field = result.error?.field ?? '';
        setBadField(field);
        setError(result.error?.message ?? 'That didn’t send.');
        const input = form.elements.namedItem(field);
        if (input instanceof HTMLElement) input.focus();
        return;
      }

      setDone(true);
      form.reset();
    } catch (caught) {
      setError(
        caught instanceof Error && caught.message
          ? caught.message
          : 'That didn’t send. Write to support@themaildoc.co and we’ll pick it up there.',
      );
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div class="md-consultform is-done" role="status">
        <span class="md-consultform__tick">
          <TickIcon size={26} />
        </span>
        <h3>Received.</h3>
        <p>
          A person reads these, not an autoresponder. You will hear back at the address you gave
          us, usually within a working day, with something specific about your domain rather than a
          brochure.
        </p>
        <p class="md-consultform__small">
          in the meantime the prescriptions on your chart are yours to use. Nothing here is held
          back for paying clients.
        </p>
      </div>
    );
  }

  return (
    <form class="md-consultform" onSubmit={(event) => void submit(event)} noValidate>
      <h3>Book a consultation.</h3>
      <p class="md-consultform__lead">
        Bring your chart. We will tell you what to fix first, what can wait, and what will break if
        you change it in the wrong order, before anything touches your DNS.
      </p>

      {prefill.domain && (
        <p class="md-consultform__context md-mono">
          Attaching your result for {prefill.domain}
          {prefill.score ? `, Vitals ${prefill.score}/100` : ''}
          {prefill.spoofable === 'SPOOFABLE' ? ' · spoofable' : ''}
        </p>
      )}

      <div class="md-consultform__row">
        <label class={`md-field ${badField === 'name' ? 'is-bad' : ''}`}>
          <span>Your name</span>
          <input
            name="name"
            type="text"
            required
            autocomplete="name"
            maxLength={120}
            aria-invalid={badField === 'name'}
            aria-describedby={badField === 'name' ? 'name-error' : undefined}
          />
          {badField === 'name' && (
            <span class="md-field__error" id="name-error">
              {error}
            </span>
          )}
        </label>
        <label class={`md-field ${badField === 'email' ? 'is-bad' : ''}`}>
          <span>Email</span>
          <input
            name="email"
            type="email"
            required
            autocomplete="email"
            maxLength={254}
            aria-invalid={badField === 'email'}
            aria-describedby={badField === 'email' ? 'email-error' : undefined}
          />
          {badField === 'email' && (
            <span class="md-field__error" id="email-error">
              {error}
            </span>
          )}
        </label>
      </div>

      <div class="md-consultform__row">
        <label class="md-field">
          <span>
            Company <em>optional</em>
          </span>
          <input name="company" type="text" autocomplete="organization" maxLength={160} />
        </label>
        <label class="md-field">
          <span>
            Domain <em>optional</em>
          </span>
          <input
            name="domain"
            type="text"
            placeholder="company.com"
            value={prefill.domain}
            maxLength={253}
          />
        </label>
      </div>

      <label class="md-field">
        <span>What do you need help with?</span>
        <select name="helpWith" required>
          {HELP_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>

      <label class="md-field">
        <span>
          Anything else <em>optional</em>
        </span>
        <textarea
          name="message"
          rows={4}
          maxLength={4000}
          placeholder="What changed, what you have tried, and what is at stake."
        />
      </label>

      {/* Not shown to anyone; filled in by the bots that do not read CSS. */}
      <div class="md-consultform__trap" aria-hidden="true">
        <label>
          Website
          <input name="website" type="text" tabIndex={-1} autocomplete="off" />
        </label>
      </div>

      {error && badField !== 'name' && badField !== 'email' && (
        <p class="md-error" role="alert">
          {error}
        </p>
      )}

      <button type="submit" class="md-btn" disabled={busy}>
        {busy ? 'Sending…' : 'Request a consultation'}
        {!busy && <ArrowIcon size={16} />}
      </button>

      <p class="md-consultform__small">
        We use this to reply to you and for nothing else. No list, no newsletter, no third party.
        See the <a href="/privacy">privacy page</a> for exactly what is stored, or write to{' '}
        <a href="mailto:support@themaildoc.co">support@themaildoc.co</a> if you would rather.
      </p>
    </form>
  );
}
