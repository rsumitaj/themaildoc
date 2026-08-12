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
