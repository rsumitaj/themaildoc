import { describe, expect, it } from 'vitest';
import { child, childList, decodeEntities, intOf, parseXml, textOf, XmlError } from '../src/xml.js';

describe('parseXml', () => {
  it('reads elements, attributes and text', () => {
    const root = parseXml('<a id="1"><b>hello</b><b>world</b><c/></a>');
    expect(root.name).toBe('a');
    expect(root.attrs.id).toBe('1');
    expect(childList(root, 'b').map((node) => node.text)).toEqual(['hello', 'world']);
    expect(child(root, 'c')?.children).toEqual([]);
  });

  it('drops namespace prefixes and lowercases names', () => {
    const root = parseXml('<dmarc:Feedback><Report_Metadata/></dmarc:Feedback>');
    expect(root.name).toBe('feedback');
    expect(child(root, 'report_metadata')).toBeDefined();
  });

  it('handles comments, declarations and CDATA', () => {
    const root = parseXml('<?xml version="1.0"?><a><!-- note --><b><![CDATA[a < b & c]]></b></a>');
    expect(textOf(root, 'b')).toBe('a < b & c');
  });

  it('decodes only the predefined entities', () => {
    expect(decodeEntities('a &amp; b &lt;c&gt; &#65; &#x42;')).toBe('a & b <c> A B');
  });

  it('leaves an unknown entity as written rather than resolving it', () => {
    // The XXE defence in one assertion: &xxe; is seven characters, not a file.
    expect(decodeEntities('&xxe;')).toBe('&xxe;');
    const root = parseXml('<a>&xxe;</a>');
    expect(root.text).toBe('&xxe;');
  });

  it('refuses a file that declares entities', () => {
    const attack =
      '<!DOCTYPE feedback [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><feedback>&xxe;</feedback>';
    expect(() => parseXml(attack)).toThrow(XmlError);
    expect(() => parseXml(attack)).toThrow(/RFC 9990/);
  });

  it('steps over a DOCTYPE that declares nothing', () => {
    expect(parseXml('<!DOCTYPE feedback><feedback><a>1</a></feedback>').name).toBe('feedback');
  });

  it('rejects mismatched and unclosed tags', () => {
    expect(() => parseXml('<a><b></a>')).toThrow(/Expected <\/b>/);
    expect(() => parseXml('<a><b>')).toThrow(/still open/);
    expect(() => parseXml('   ')).toThrow(/no XML at all/);
  });

  it('keeps a > inside an attribute value', () => {
    const root = parseXml('<a note="1 > 0"><b/></a>');
    expect(root.attrs.note).toBe('1 > 0');
    expect(root.children).toHaveLength(1);
  });

  it('reads integers, and says null rather than NaN', () => {
    const root = parseXml('<a><n>42</n><bad>x</bad></a>');
    expect(intOf(root, 'n')).toBe(42);
    expect(intOf(root, 'bad')).toBeNull();
    expect(intOf(root, 'missing')).toBeNull();
  });
});
