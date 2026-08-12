import { useState } from 'preact/hooks';

/**
 * A record with a copy button.
 *
 * Shared by the flattener and the generators so the thing people actually take
 * away from this site behaves the same everywhere.
 */
export function CopyBox({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard access can be refused; the text is on screen either way.
    }
  };

  return (
    <div class="md-copybox">
      <pre class="md-testresult__record is-big">{value}</pre>
      <div class="md-copybox__foot">
        {label && <span class="md-copybox__label">{label}</span>}
        <button type="button" class="md-copy" onClick={copy}>
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
    </div>
  );
}
