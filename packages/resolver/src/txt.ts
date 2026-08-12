import type { TxtRecord } from './types.js';

/**
 * Split DoH TXT RDATA into its DNS character-strings.
 *
 * A TXT record is a sequence of length-prefixed strings, each at most 255
 * bytes, which DoH renders as quoted, space-separated segments:
 *
 *     "v=spf1 include:_spf.example.com " "ip4:203.0.113.0/24 -all"
 *
 * Getting this wrong is the classic long-SPF bug: joining the segments with a
 * space (or reading only the first one) silently changes the record. We keep
 * the segments intact and let callers concatenate per RFC 7208 §3.3.
 */
export function parseCharacterStrings(data: string): string[] {
  const strings: string[] = [];
  let sawQuote = false;
  let index = 0;

  while (index < data.length) {
    if (data[index] !== '"') {
      index += 1;
      continue;
    }
    sawQuote = true;
    index += 1;
    let buffer = '';
    while (index < data.length && data[index] !== '"') {
      if (data[index] === '\\') {
        const escape = data.slice(index + 1, index + 4);
        if (/^\d{3}$/.test(escape)) {
          // \DDD decimal escape (RFC 1035 §5.1)
          buffer += String.fromCharCode(Number.parseInt(escape, 10));
          index += 4;
          continue;
        }
        buffer += data[index + 1] ?? '';
        index += 2;
        continue;
      }
      buffer += data[index];
      index += 1;
    }
    index += 1; // closing quote
    strings.push(buffer);
  }

  if (!sawQuote) {
    const trimmed = data.trim();
    return trimmed ? [trimmed] : [];
  }
  return strings;
}

/**
 * Build a TXT record from DoH RDATA. The value is the character-strings
 * concatenated with NO separator, exactly as a receiver assembles them.
 */
export function toTxtRecord(data: string): TxtRecord {
  const strings = parseCharacterStrings(data);
  return {
    strings,
    value: strings.join(''),
    bytes: strings.reduce((total, part) => total + part.length + 1, 0),
    // Only a provider that renders the quotes is telling us how the record is
    // actually chunked on the wire.
    segmented: data.includes('"'),
  };
}
