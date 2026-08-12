import { useState } from 'preact/hooks';
import { domainRejectionMessage, normalizeDomain, tidyDomainInput } from '@maildoc/shared';
import { ArrowIcon, StethoscopeIcon } from './Icons';

/**
 * The checkup input.
 *
 * One definition of this form, used by the homepage and by the results page,
 * so the two can never drift into looking or behaving differently. The
 * homepage hands the domain to a navigation; the results page runs it.
 */

export interface CheckupFormProps {
  initial?: string;
  busy?: boolean;
  /** Receives a normalised domain. Never called with invalid input. */
  onExamine: (domain: string) => void;
}

export function CheckupForm({ initial = '', busy = false, onExamine }: CheckupFormProps) {
  const [input, setInput] = useState(initial);
  const [error, setError] = useState('');

  const onSubmit = (event: Event) => {
    event.preventDefault();
    if (busy) return;

    // Read the field itself rather than component state: a browser autofill or
    // a password manager can set the value without firing an input event, and
    // the domain someone can see in the box is the one we must examine.
    const form = event.currentTarget as HTMLFormElement;
    const typed = new FormData(form).get('domain');
    const value = typeof typed === 'string' && typed.trim() !== '' ? typed : input;
    setInput(value);

    const normalized = normalizeDomain(value);
    if (!normalized.ok) {
      setError(domainRejectionMessage(normalized.reason));
      return;
    }

    setError('');
    onExamine(normalized.domain);
  };

  return (
    <form class="diagbox" onSubmit={onSubmit}>
      <div class="inrow">
        <span class="pre md-mono" aria-hidden="true">
          https://
        </span>
        <label class="md-visually-hidden" for="domain">
          Your domain
        </label>
        <input
          id="domain"
          name="domain"
          type="text"
          class="md-mono"
          placeholder="yourcompany.com"
          autocomplete="off"
          autocapitalize="off"
          spellcheck={false}
          inputMode="url"
          value={input}
          onInput={(event) => {
            const field = event.target as HTMLInputElement;
            const tidied = tidyDomainInput(field.value);
            // Only write back when something was actually removed, so the
            // caret does not jump while somebody is still typing.
            if (tidied !== field.value) field.value = tidied;
            setInput(tidied);
          }}
          aria-describedby="checkup-note"
        />
        <button class="md-btn" type="submit" disabled={busy}>
          {busy ? 'Examining…' : 'Diagnose my domain'}
          {!busy && <ArrowIcon size={16} />}
        </button>
      </div>

      <p class="note" id="checkup-note">
        <StethoscopeIcon size={15} class="noteicon" />
        <span>
          A full checkup in about 5 seconds. <b>See what Gmail, Outlook and an attacker see.</b> No signup.
        </span>
      </p>

      {error && (
        <p class="md-error" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}
