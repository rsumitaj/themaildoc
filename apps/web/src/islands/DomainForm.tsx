import { useEffect, useRef, useState } from 'preact/hooks';
import { domainRejectionMessage, normalizeDomain } from '@maildoc/shared';
import { ArrowIcon, StethoscopeIcon } from './Icons';

/**
 * The domain input, shared by every tool that takes one.
 *
 * Extracted so the four tools cannot drift apart: same validation, same
 * autofill-proof submit, same `?domain=` behaviour that makes a result
 * linkable and re-runnable.
 */
export interface DomainFormProps {
  action: string;
  note: string;
  busy: boolean;
  onExamine: (domain: string) => void;
}

export function useDomainRunner(run: (domain: string) => Promise<void>) {
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    const fromUrl = new URLSearchParams(location.search).get('domain');
    if (fromUrl) {
      started.current = true;
      void run(fromUrl);
    }
  }, []);
}

export function rememberDomain(domain: string): void {
  history.replaceState(null, '', `?domain=${encodeURIComponent(domain)}`);
}

/** Validate before spending a request. Returns null when the input is unusable. */
export function validateDomain(raw: string): { domain: string } | { error: string } {
  const normalized = normalizeDomain(raw);
  if (!normalized.ok) return { error: domainRejectionMessage(normalized.reason) };
  return { domain: normalized.domain };
}

/**
 * Tidy what somebody pasted, as they paste it.
 *
 * The field already accepted a full URL and cleaned it up on submit, so this
 * always worked. It just looked as though it would not: the box carries a
 * static `https://` in front of it, so pasting an address straight out of the
 * browser bar showed `https:// https://bank.example.com/login` and read as an
 * error before anyone pressed the button.
 *
 * Only the obviously-removable parts go here. Trailing dots, ports, unicode
 * and the rest are the validator's job, and stripping them mid-keystroke would
 * fight the person typing.
 */
function tidyAsTyped(raw: string): string {
  return raw
    .replace(/^\s+/, '')
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    .replace(/^www\.(?=[^.]+\.[^.]+)/i, '')
    .replace(/^[^/@\s]*@/, '')
    .replace(/[/?#].*$/, '');
}

export function DomainForm({ action, note, busy, onExamine }: DomainFormProps) {
  const [value, setValue] = useState('');

  useEffect(() => {
    const fromUrl = new URLSearchParams(location.search).get('domain');
    if (fromUrl) setValue(tidyAsTyped(fromUrl));
  }, []);

  const onSubmit = (event: Event) => {
    event.preventDefault();
    if (busy) return;
    // Read the field, not component state: autofill can set a value without
    // ever firing an input event.
    const form = event.currentTarget as HTMLFormElement;
    const typed = new FormData(form).get('domain');
    const next = tidyAsTyped(typeof typed === 'string' && typed.trim() !== '' ? typed : value);
    setValue(next);
    onExamine(next);
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
          value={value}
          onInput={(event) => {
            const field = event.target as HTMLInputElement;
            const tidied = tidyAsTyped(field.value);
            // Only write back when something was actually removed, so the
            // caret does not jump around while somebody is still typing.
            if (tidied !== field.value) field.value = tidied;
            setValue(tidied);
          }}
        />
        <button class="md-btn" type="submit" disabled={busy}>
          {busy ? 'Examining…' : action}
          {!busy && <ArrowIcon size={16} />}
        </button>
      </div>

      <p class="note">
        <StethoscopeIcon size={15} class="noteicon" />
        <span>{note}</span>
      </p>
    </form>
  );
}
