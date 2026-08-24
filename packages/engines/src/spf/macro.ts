/**
 * SPF macro validation (RFC 7208 §7).
 *
 * We never expand macros — expansion depends on the connecting client — but a
 * malformed macro changes how receivers read the record, so we check the shape.
 */

/** `%{` letter [digits] ['r'] [delimiters] `}` */
const MACRO_EXPAND = /^%\{[slodipvhcrt](\d{1,3})?r?[.\-+,/_=]*\}/i;

export function containsMacro(value: string): boolean {
  return value.includes('%');
}

/**
 * True when every `%` in the string starts a legal macro, `%%`, `%_` or `%-`.
 */
export function isValidMacroString(value: string): boolean {
  let index = 0;
  while (index < value.length) {
    if (value[index] !== '%') {
      index += 1;
      continue;
    }
    const next = value[index + 1];
    if (next === '%' || next === '_' || next === '-') {
      index += 2;
      continue;
    }
    if (next !== '{') return false;

    const closing = value.indexOf('}', index);
    if (closing === -1) return false;
    if (!MACRO_EXPAND.test(value.slice(index, closing + 1))) return false;
    index = closing + 1;
  }
  return true;
}

/**
 * What a macro expands to, for one message.
 *
 * Validation above asks whether a macro is well formed. This asks what it says,
 * which is a question nothing in the product could answer until there was an IP
 * to answer it about. `exists:%{i}._spf.%{d}` is not a name; it is a name per
 * connecting client, and the IP check is the first thing here that knows which
 * client.
 */
export interface MacroContext {
  /** The connecting IP, already normalised. */
  ip: string;
  ipVersion: 4 | 6;
  /** The domain currently being evaluated, which changes as the chain is walked. */
  domain: string;
  /** MAIL FROM, or postmaster@<helo> when the envelope sender is empty (§2.4). */
  sender: string;
  /** The HELO/EHLO name the client gave. */
  helo: string;
}

/**
 * `%{i}` for IPv6 is the dotted nibble form, not the address as written
 * (RFC 7208 §7.2). `2001:db8::1` is thirty-two nibbles separated by dots, which
 * is also the form the reverse tree uses.
 */
function dottedNibbles(address: string): string {
  const groups = expandIpv6Groups(address);
  if (groups === null) return address;
  return groups
    .map((group) => group.toString(16).padStart(4, '0'))
    .join('')
    .split('')
    .join('.');
}

/** The eight 16-bit groups of an IPv6 address, or null if it is not one. */
function expandIpv6Groups(address: string): number[] | null {
  const clean = address.trim().toLowerCase().replace(/%.*$/, '');
  if (clean.split('::').length > 2) return null;

  const [left = '', right = ''] = clean.includes('::') ? clean.split('::') : [clean, ''];

  const parse = (part: string): number[] | null => {
    if (!part) return [];
    const out: number[] = [];
    for (const piece of part.split(':')) {
      if (!piece) return null;
      if (piece.includes('.')) {
        const octets = piece.split('.').map(Number);
        if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
          return null;
        }
        out.push(
          ((octets[0] as number) << 8) | (octets[1] as number),
          ((octets[2] as number) << 8) | (octets[3] as number),
        );
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(piece)) return null;
      out.push(Number.parseInt(piece, 16));
    }
    return out;
  };

  const head = parse(left);
  const tail = clean.includes('::') ? parse(right) : [];
  if (!head || !tail) return null;

  if (clean.includes('::')) {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    return [...head, ...new Array<number>(missing).fill(0), ...tail];
  }
  return head.length === 8 ? head : null;
}

/** The value of one macro letter, before any transformer is applied (§7.2). */
function macroValue(letter: string, context: MacroContext): string | null {
  switch (letter) {
    case 's':
      return context.sender;
    case 'l':
      return context.sender.split('@')[0] ?? '';
    case 'o':
      return context.sender.split('@').slice(1).join('@');
    case 'd':
      return context.domain;
    case 'i':
      return context.ipVersion === 4 ? context.ip : dottedNibbles(context.ip);
    case 'v':
      return context.ipVersion === 4 ? 'in-addr' : 'ip6';
    case 'h':
      return context.helo;
    /**
     * `c`, `r` and `t` are legal only inside `exp=` text (§7.1), and `p`
     * requires a validated reverse lookup that RFC 7208 §7.3 tells senders not
     * to publish and receivers to treat as expensive. None of them can appear
     * in a mechanism we evaluate, so rather than guess a value, the expansion
     * fails and the caller reports the term as unevaluable. Guessing here would
     * mean querying a name the receiver never queries.
     */
    default:
      return null;
  }
}

/**
 * Apply the transformers: keep the rightmost N parts, optionally reversed,
 * split on any of the delimiters and rejoined with a dot (§7.1).
 */
function transform(value: string, digits: string, reverse: boolean, delimiters: string): string {
  const separators = delimiters === '' ? '.' : delimiters;
  const parts = value.split(new RegExp(`[${separators.replace(/[.\-+,/_=\\\]^]/g, '\\$&')}]`));
  const ordered = reverse ? [...parts].reverse() : parts;
  if (digits === '') return ordered.join('.');

  const keep = Number(digits);
  // "0" is not a legal count; the ABNF requires a non-zero DIGIT.
  if (!Number.isInteger(keep) || keep < 1) return ordered.join('.');
  return ordered.slice(Math.max(0, ordered.length - keep)).join('.');
}

/** An expansion that could not be performed, and why, in one word. */
export type MacroFailure = 'UNSUPPORTED_MACRO' | 'MALFORMED';

export interface MacroExpansion {
  ok: boolean;
  value: string;
  failure?: MacroFailure;
}

/**
 * Expand a macro-string against one connection (RFC 7208 §7).
 *
 * Uppercase letters expand exactly as their lowercase equivalents and are then
 * URL-escaped (§7.1), which matters because the escaped form is what a receiver
 * puts in the query it actually sends.
 */
export function expandMacros(value: string, context: MacroContext): MacroExpansion {
  let out = '';
  let index = 0;

  while (index < value.length) {
    const char = value[index];

    if (char !== '%') {
      out += char;
      index += 1;
      continue;
    }

    const next = value[index + 1];
    if (next === '%') {
      out += '%';
      index += 2;
      continue;
    }
    if (next === '_') {
      out += ' ';
      index += 2;
      continue;
    }
    if (next === '-') {
      out += '%20';
      index += 2;
      continue;
    }
    if (next !== '{') return { ok: false, value, failure: 'MALFORMED' };

    const closing = value.indexOf('}', index);
    if (closing === -1) return { ok: false, value, failure: 'MALFORMED' };

    const body = value.slice(index + 2, closing);
    const match = /^([slodipvhcrt])(\d{1,3})?(r)?([.\-+,/_=]*)$/i.exec(body);
    if (!match) return { ok: false, value, failure: 'MALFORMED' };

    const letter = match[1] as string;
    const resolved = macroValue(letter.toLowerCase(), context);
    if (resolved === null) return { ok: false, value, failure: 'UNSUPPORTED_MACRO' };

    const expanded = transform(resolved, match[2] ?? '', match[3] !== undefined, match[4] ?? '');
    // An uppercase letter means URL-escape the result (§7.1).
    out += letter === letter.toUpperCase() ? encodeURIComponent(expanded) : expanded;
    index = closing + 1;
  }

  /**
   * A domain-spec longer than 253 characters is left-truncated to the longest
   * suffix that fits, on a label boundary (§7.3). Receivers do this rather than
   * failing, so a checker that fails here would report a different answer from
   * the one the domain actually gets.
   */
  if (out.length > 253) {
    const labels = out.split('.');
    while (labels.length > 1 && labels.join('.').length > 253) labels.shift();
    out = labels.join('.');
  }

  return { ok: true, value: out };
}
