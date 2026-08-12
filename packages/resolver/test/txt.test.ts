import { describe, expect, it } from 'vitest';
import { parseCharacterStrings, toTxtRecord } from '../src/index.js';

describe('parseCharacterStrings', () => {
  it('reads a single quoted string', () => {
    expect(parseCharacterStrings('"v=spf1 -all"')).toEqual(['v=spf1 -all']);
  });

  it('keeps multi-string records as separate character-strings', () => {
    const data = '"v=spf1 include:_spf.example.com " "ip4:203.0.113.0/24 -all"';
    expect(parseCharacterStrings(data)).toEqual([
      'v=spf1 include:_spf.example.com ',
      'ip4:203.0.113.0/24 -all',
    ]);
  });

  it('accepts unquoted rdata from resolvers that omit quotes', () => {
    expect(parseCharacterStrings('v=spf1 -all')).toEqual(['v=spf1 -all']);
  });

  it('unescapes quotes, backslashes and decimal escapes', () => {
    expect(parseCharacterStrings('"say \\"hi\\""')).toEqual(['say "hi"']);
    expect(parseCharacterStrings('"a\\\\b"')).toEqual(['a\\b']);
    expect(parseCharacterStrings('"a\\032b"')).toEqual(['a b']);
  });

  it('returns nothing for empty rdata', () => {
    expect(parseCharacterStrings('')).toEqual([]);
    expect(parseCharacterStrings('""')).toEqual(['']);
  });
});

describe('toTxtRecord', () => {
  it('concatenates character-strings with NO separator (RFC 7208 §3.3)', () => {
    const record = toTxtRecord('"v=spf1 include:_spf.example.com " "ip4:203.0.113.0/24 -all"');
    expect(record.value).toBe('v=spf1 include:_spf.example.com ip4:203.0.113.0/24 -all');
    expect(record.strings).toHaveLength(2);
  });

  it('does not invent a space between segments split mid-token', () => {
    const record = toTxtRecord('"v=spf1 include:_spf.exa" "mple.com -all"');
    expect(record.value).toBe('v=spf1 include:_spf.example.com -all');
  });

  it('measures approximate wire size including length bytes', () => {
    const record = toTxtRecord('"abc" "de"');
    expect(record.bytes).toBe(7);
  });

  it('marks rdata as segmented only when the provider kept the quotes', () => {
    expect(toTxtRecord('"abc" "de"').segmented).toBe(true);
    expect(toTxtRecord('abcde').segmented).toBe(false);
  });
});
