/**
 * A deliberately small XML reader, written for one job: DMARC aggregate
 * reports that arrive from strangers.
 *
 * RFC 9990 §8.1 says it out loud — report content is an attack surface. So
 * there is no DTD processing, no entity declarations, no external references
 * and no network access anywhere in this file. An `&xxe;` inside a report
 * stays the five literal characters it arrived as. Nothing here touches the
 * DOM either: this runs in the patient's own browser and everything it returns
 * is rendered as a text node.
 *
 * It is not a general-purpose XML parser and does not pretend to be. It reads
 * elements, attributes, text, CDATA and comments, which is the whole of the
 * schema in RFC 9990 Appendix A.
 */

export interface XmlNode {
  /** Local name, lowercased, namespace prefix removed. */
  readonly name: string;
  readonly attrs: Record<string, string>;
  readonly children: XmlNode[];
  /** Character data directly inside this element, trimmed. */
  readonly text: string;
}

export class XmlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'XmlError';
  }
}

/** Refuse anything a browser tab has no business holding in memory twice. */
const MAX_CHARS = 48 * 1024 * 1024;
const MAX_DEPTH = 100;

interface Building {
  name: string;
  attrs: Record<string, string>;
  children: Building[];
  text: string;
}

export function parseXml(source: string): XmlNode {
  if (source.length > MAX_CHARS) {
    throw new XmlError('That file is too large to open in a browser tab.');
  }

  let at = source.charCodeAt(0) === 0xfeff ? 1 : 0;
  const stack: Building[] = [];
  let root: Building | null = null;

  while (at < source.length) {
    const open = source.indexOf('<', at);
    if (open === -1) break;

    if (open > at) {
      const top = stack[stack.length - 1];
      if (top) top.text += decodeEntities(source.slice(at, open));
    }

    if (source.startsWith('<!--', open)) {
      at = after(source, '-->', open + 4, 'a comment');
      continue;
    }

    if (source.startsWith('<![CDATA[', open)) {
      const end = source.indexOf(']]>', open + 9);
      if (end === -1) throw new XmlError('This file ends in the middle of a CDATA block.');
      const top = stack[stack.length - 1];
      if (top) top.text += source.slice(open + 9, end);
      at = end + 3;
      continue;
    }

    if (source.startsWith('<?', open)) {
      at = after(source, '?>', open + 2, 'a declaration');
      continue;
    }

    if (/^<!doctype/i.test(source.slice(open, open + 9))) {
      at = skipDoctype(source, open);
      continue;
    }

    if (source.startsWith('</', open)) {
      const end = source.indexOf('>', open);
      if (end === -1) throw new XmlError('This file ends in the middle of a closing tag.');
      const name = localName(source.slice(open + 2, end).trim());
      const top = stack.pop();
      if (!top) throw new XmlError(`Found </${name}> with nothing open.`);
      if (top.name !== name) throw new XmlError(`Expected </${top.name}> but found </${name}>.`);
      at = end + 1;
      continue;
    }

    const tag = readTag(source, open);
    const node: Building = { name: tag.name, attrs: tag.attrs, children: [], text: '' };
    const parent = stack[stack.length - 1];

    if (parent) parent.children.push(node);
    else if (root) throw new XmlError('This file contains more than one root element.');
    else root = node;

    if (!tag.selfClosing) {
      if (stack.length >= MAX_DEPTH) throw new XmlError('This file is nested too deeply to read.');
      stack.push(node);
    } else if (!parent && !root) {
      root = node;
    }

    at = tag.end;
  }

  if (stack.length > 0) {
    throw new XmlError(`This file ends with <${stack[stack.length - 1]?.name}> still open.`);
  }
  if (!root) throw new XmlError('This file contains no XML at all.');

  return freeze(root);
}

function after(source: string, marker: string, from: number, what: string): number {
  const end = source.indexOf(marker, from);
  if (end === -1) throw new XmlError(`This file ends in the middle of ${what}.`);
  return end + marker.length;
}

/**
 * Step over a DOCTYPE without acting on any of it — except an entity
 * declaration, which is refused loudly. A report has no legitimate reason to
 * declare entities, and every reason someone else might want it to.
 */
function skipDoctype(source: string, open: number): number {
  const close = source.indexOf('>', open);
  if (close === -1) throw new XmlError('This file ends in the middle of a DOCTYPE.');

  const bracket = source.indexOf('[', open);
  if (bracket === -1 || bracket > close) return close + 1;

  const subsetEnd = source.indexOf(']', bracket);
  if (subsetEnd === -1) throw new XmlError('This file ends in the middle of a DOCTYPE.');

  if (/<!ENTITY/i.test(source.slice(bracket, subsetEnd))) {
    throw new XmlError(
      'This report declares XML entities. We refuse those, it is the standard way a report file carries an attack (RFC 9990 §8.1).',
    );
  }

  const end = source.indexOf('>', subsetEnd);
  if (end === -1) throw new XmlError('This file ends in the middle of a DOCTYPE.');
  return end + 1;
}

interface Tag {
  name: string;
  attrs: Record<string, string>;
  selfClosing: boolean;
  end: number;
}

function readTag(source: string, open: number): Tag {
  let at = open + 1;
  const nameStart = at;
  while (at < source.length && !isTagBreak(source.charAt(at))) at += 1;

  const name = localName(source.slice(nameStart, at));
  if (!name) throw new XmlError('This file contains a tag with no name.');

  const attrs: Record<string, string> = {};

  while (at < source.length) {
    while (at < source.length && isSpace(source.charAt(at))) at += 1;
    const char = source.charAt(at);

    if (char === '>') return { name, attrs, selfClosing: false, end: at + 1 };
    if (char === '/') {
      if (source.charAt(at + 1) !== '>') throw new XmlError(`Malformed tag <${name}>.`);
      return { name, attrs, selfClosing: true, end: at + 2 };
    }
    if (char === '') break;

    const attrStart = at;
    while (at < source.length && !isAttrBreak(source.charAt(at))) at += 1;
    const attrName = localName(source.slice(attrStart, at));
    if (!attrName) throw new XmlError(`Malformed attribute in <${name}>.`);

    while (at < source.length && isSpace(source.charAt(at))) at += 1;
    if (source.charAt(at) !== '=') {
      attrs[attrName] = '';
      continue;
    }

    at += 1;
    while (at < source.length && isSpace(source.charAt(at))) at += 1;
    const quote = source.charAt(at);
    if (quote !== '"' && quote !== "'") {
      throw new XmlError(`Attribute ${attrName} in <${name}> has an unquoted value.`);
    }

    const valueEnd = source.indexOf(quote, at + 1);
    if (valueEnd === -1) throw new XmlError('This file ends in the middle of an attribute.');
    attrs[attrName] = decodeEntities(source.slice(at + 1, valueEnd));
    at = valueEnd + 1;
  }

  throw new XmlError('This file ends in the middle of a tag.');
}

function isSpace(char: string): boolean {
  return char === ' ' || char === '\t' || char === '\n' || char === '\r';
}

function isTagBreak(char: string): boolean {
  return isSpace(char) || char === '/' || char === '>';
}

function isAttrBreak(char: string): boolean {
  return isTagBreak(char) || char === '=';
}

/** `dmarc:feedback` and `FEEDBACK` are both `feedback`. */
function localName(raw: string): string {
  const trimmed = raw.trim();
  const colon = trimmed.lastIndexOf(':');
  return (colon === -1 ? trimmed : trimmed.slice(colon + 1)).toLowerCase();
}

const NAMED: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
};

/**
 * The five predefined entities and numeric references — nothing else.
 * An unknown `&whatever;` is returned exactly as written rather than resolved,
 * which is the entire XXE defence in one line.
 */
export function decodeEntities(raw: string): string {
  if (!raw.includes('&')) return raw;

  return raw.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match, body: string) => {
    const key = body.toLowerCase();
    const named = NAMED[key];
    if (named !== undefined) return named;

    if (key.startsWith('#')) {
      const code = key.startsWith('#x') ? parseInt(key.slice(2), 16) : parseInt(key.slice(1), 10);
      if (Number.isFinite(code) && code > 0 && code <= 0x10ffff) {
        try {
          return String.fromCodePoint(code);
        } catch {
          return match;
        }
      }
    }

    return match;
  });
}

function freeze(node: Building): XmlNode {
  return {
    name: node.name,
    attrs: node.attrs,
    children: node.children.map(freeze),
    text: node.text.trim(),
  };
}

/* Readers — every one total, so a malformed report loses a field, not the page. */

export function child(node: XmlNode | undefined, name: string): XmlNode | undefined {
  return node?.children.find((candidate) => candidate.name === name);
}

export function childList(node: XmlNode | undefined, name: string): XmlNode[] {
  return node ? node.children.filter((candidate) => candidate.name === name) : [];
}

/** Text of a named child, or `''`. */
export function textOf(node: XmlNode | undefined, name: string): string {
  return child(node, name)?.text ?? '';
}

/** Integer value of a named child, or `null` when absent or not a number. */
export function intOf(node: XmlNode | undefined, name: string): number | null {
  const raw = textOf(node, name);
  if (!raw) return null;
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) ? value : null;
}
