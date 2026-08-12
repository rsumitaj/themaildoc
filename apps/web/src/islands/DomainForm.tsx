import { useEffect, useRef, useState } from 'preact/hooks';
import { domainRejectionMessage, normalizeDomain, tidyDomainInput } from '@maildoc/shared';
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

export function DomainForm({ action, note, busy, onExamine }: DomainFormProps) {
  const [value, setValue] = useState('');

  useEffect(() => {
    const fromUrl = new URLSearchParams(location.search).get('domain');
    if (fromUrl) setValue(tidyDomainInput(fromUrl));
  }, []);

  const onSubmit = (event: Event) => {
    event.preventDefault();
    if (busy) return;
    // Read the field, not component state: autofill can set a value without
    // ever firing an input event.
    const form = event.currentTarget as HTMLFormElement;
    const typed = new FormData(form).get('domain');
    const next = tidyDomainInput(typeof typed === 'string' && typed.trim() !== '' ? typed : value);
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
            const tidied = tidyDomainInput(field.value);
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
