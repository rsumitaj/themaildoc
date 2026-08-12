import { useState } from 'preact/hooks';

/**
 * Record generators.
 *
 * Read-only and entirely client-side: you fill a form, you get a record to
 * paste. Nothing is sent anywhere, nothing is stored, and the tool never
 * touches your DNS — which is also why it can afford to be blunt about the
 * settings that will hurt you.
 */

export type GeneratorKind = 'dmarc' | 'spf' | 'mta-sts' | 'tls-rpt';

interface Props {
  kind: GeneratorKind;
}

const POLICIES = ['none', 'quarantine', 'reject'] as const;

export default function Generator({ kind }: Props) {
  const [domain, setDomain] = useState('yourcompany.com');

  // DMARC
  const [policy, setPolicy] = useState<(typeof POLICIES)[number]>('none');
  const [subPolicy, setSubPolicy] = useState<'inherit' | (typeof POLICIES)[number]>('inherit');
  const [rua, setRua] = useState('dmarc@yourcompany.com');
  const [strict, setStrict] = useState(false);
  const [rejectNonExistent, setRejectNonExistent] = useState(true);

  // SPF
  const [includes, setIncludes] = useState('_spf.google.com');
  const [ips, setIps] = useState('');
  const [hard, setHard] = useState(false);

  // MTA-STS
  const [mode, setMode] = useState<'testing' | 'enforce'>('testing');
  const [mx, setMx] = useState('mail.yourcompany.com');

  // TLS-RPT
  const [tlsRua, setTlsRua] = useState('tlsrpt@yourcompany.com');

  const clean = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '') || 'yourcompany.com';

  const output = build();
  const lookups = kind === 'spf' ? countLookups() : null;

  function build(): { host: string; type: string; value: string; note?: string } {
    switch (kind) {
      case 'dmarc': {
        const parts = [`v=DMARC1`, `p=${policy}`];
        if (subPolicy !== 'inherit') parts.push(`sp=${subPolicy}`);
        if (rejectNonExistent) parts.push('np=reject');
        if (rua.trim()) {
          parts.push(
            `rua=${rua
              .split(',')
              .map((address) => `mailto:${address.trim()}`)
              .filter((entry) => entry !== 'mailto:')
              .join(',')}`,
          );
        }
        if (strict) parts.push('adkim=s', 'aspf=s');
        return { host: `_dmarc.${clean}`, type: 'TXT', value: `${parts.join('; ')};` };
      }

      case 'spf': {
        const terms = ['v=spf1'];
        for (const ip of ips.split(/[\s,]+/).filter(Boolean)) {
          terms.push(`${ip.includes(':') ? 'ip6' : 'ip4'}:${ip}`);
        }
        for (const include of includes.split(/[\s,]+/).filter(Boolean)) {
          terms.push(`include:${include}`);
        }
        terms.push(hard ? '-all' : '~all');
        return { host: clean, type: 'TXT', value: terms.join(' ') };
      }

      case 'mta-sts': {
        const hosts = mx.split(/[\s,]+/).filter(Boolean);
        const policyFile = [
          'version: STSv1',
          `mode: ${mode}`,
          ...hosts.map((host) => `mx: ${host}`),
          'max_age: 604800',
        ].join('\n');
        return {
          host: `_mta-sts.${clean}`,
          type: 'TXT',
          value: `v=STSv1; id=${stamp()}`,
          note: policyFile,
        };
      }

      case 'tls-rpt':
        return {
          host: `_smtp._tls.${clean}`,
          type: 'TXT',
          value: `v=TLSRPTv1; rua=mailto:${tlsRua.trim() || `tlsrpt@${clean}`}`,
        };
    }
  }

  function countLookups(): number {
    return includes.split(/[\s,]+/).filter(Boolean).length;
  }

  return (
    <div class="md-generator">
      <div class="md-gen__form">
        <label class="md-field">
          <span>Your domain</span>
          <input
            class="md-mono"
            value={domain}
            onInput={(event) => setDomain((event.target as HTMLInputElement).value)}
          />
        </label>

        {kind === 'dmarc' && (
          <>
            <label class="md-field">
              <span>Policy</span>
              <select
                value={policy}
                onChange={(event) =>
                  setPolicy((event.target as HTMLSelectElement).value as typeof policy)
                }
              >
                <option value="none">none, monitor only, start here</option>
                <option value="quarantine">quarantine, send failures to spam</option>
                <option value="reject">reject, refuse failures outright</option>
              </select>
            </label>

            <label class="md-field">
              <span>Subdomain policy</span>
              <select
                value={subPolicy}
                onChange={(event) =>
                  setSubPolicy((event.target as HTMLSelectElement).value as typeof subPolicy)
                }
              >
                <option value="inherit">inherit the policy above</option>
                <option value="none">none</option>
                <option value="quarantine">quarantine</option>
                <option value="reject">reject</option>
              </select>
            </label>

            <label class="md-field">
              <span>Reports to (comma separated)</span>
              <input
                class="md-mono"
                value={rua}
                onInput={(event) => setRua((event.target as HTMLInputElement).value)}
              />
            </label>

            <label class="md-check">
              <input
                type="checkbox"
                checked={rejectNonExistent}
                onChange={(event) =>
                  setRejectNonExistent((event.target as HTMLInputElement).checked)
                }
              />
              <span>Reject mail from subdomains that do not exist (np=reject)</span>
            </label>

            <label class="md-check">
              <input
                type="checkbox"
                checked={strict}
                onChange={(event) => setStrict((event.target as HTMLInputElement).checked)}
              />
              <span>Strict alignment, only if every sender uses your exact domain</span>
            </label>
          </>
        )}

        {kind === 'spf' && (
          <>
            <label class="md-field">
              <span>Provider includes (comma separated)</span>
              <input
                class="md-mono"
                value={includes}
                onInput={(event) => setIncludes((event.target as HTMLInputElement).value)}
              />
            </label>

            <label class="md-field">
              <span>Your own sending IPs (optional)</span>
              <input
                class="md-mono"
                placeholder="203.0.113.10, 2001:db8::1"
                value={ips}
                onInput={(event) => setIps((event.target as HTMLInputElement).value)}
              />
            </label>

            <label class="md-check">
              <input
                type="checkbox"
                checked={hard}
                onChange={(event) => setHard((event.target as HTMLInputElement).checked)}
              />
              <span>End in -all, only once you are sure every sender is listed</span>
            </label>
          </>
        )}

        {kind === 'mta-sts' && (
          <>
            <label class="md-field">
              <span>Mode</span>
              <select
                value={mode}
                onChange={(event) =>
                  setMode((event.target as HTMLSelectElement).value as typeof mode)
                }
              >
                <option value="testing">testing, report failures, deliver anyway</option>
                <option value="enforce">enforce, require TLS</option>
              </select>
            </label>

            <label class="md-field">
              <span>Mail hosts (comma separated, from your MX)</span>
              <input
                class="md-mono"
                value={mx}
                onInput={(event) => setMx((event.target as HTMLInputElement).value)}
              />
            </label>
          </>
        )}

        {kind === 'tls-rpt' && (
          <label class="md-field">
            <span>Send TLS reports to</span>
            <input
              class="md-mono"
              value={tlsRua}
              onInput={(event) => setTlsRua((event.target as HTMLInputElement).value)}
            />
          </label>
        )}
      </div>

      <div class="md-gen__out">
        <Field label="Host / name" value={output.host} />
        <Field label="Type" value={output.type} />
        <Field label="Value" value={output.value} big />

        {output.note && (
          <Field
            label={`Policy file, serve at https://mta-sts.${clean}/.well-known/mta-sts.txt`}
            value={output.note}
            big
          />
        )}

        {kind === 'spf' && lookups !== null && (
          <p class={`md-gen__hint ${lookups > 10 ? 'is-bad' : ''}`}>
            {lookups > 10
              ? `${lookups} includes, already over the 10-lookup limit before your providers' own records are counted.`
              : `${lookups} of your 10 DNS lookups used by these includes. Each provider may use more inside its own record.`}
          </p>
        )}

        {kind === 'dmarc' && policy === 'none' && (
          <p class="md-gen__hint">
            p=none reports without protecting. That is the right place to start. Set a reminder to
            come back in a month.
          </p>
        )}

        {kind === 'mta-sts' && (
          <p class="md-gen__hint">
            Publish the policy file first and confirm it loads with no redirect. The DNS record tells
            senders to go looking for it.
          </p>
        )}
      </div>
    </div>
  );
}

function Field({ label, value, big = false }: { label: string; value: string; big?: boolean }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* the value is on screen either way */
    }
  };

  return (
    <div class="md-gen__field">
      <div class="md-gen__label">
        <span>{label}</span>
        <button type="button" class="md-copy" onClick={copy}>
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
      <pre class={`md-testresult__record ${big ? 'is-big' : ''}`}>{value}</pre>
    </div>
  );
}

/** MTA-STS ids must change whenever the policy does; a timestamp is the convention. */
function stamp(): string {
  const now = new Date();
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}`;
}
