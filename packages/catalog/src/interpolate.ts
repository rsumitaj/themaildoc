import type { IssueVars } from './types.js';

const TOKEN = /\{([a-z0-9_]+)\}/gi;

/**
 * Fill `{placeholder}` tokens from a detector's vars.
 *
 * An unsupplied token is left intact rather than blanked — a visible
 * `{count}` is a bug the catalog consistency tests catch, whereas a silently
 * empty sentence is one nobody notices.
 */
export function interpolate(template: string, vars: IssueVars = {}): string {
  return template.replace(TOKEN, (token, name: string) => {
    const value = vars[name];
    return value === undefined || value === null ? token : String(value);
  });
}

/** Every `{placeholder}` referenced by a template, in order of first use. */
export function tokensIn(template: string): string[] {
  const found = new Set<string>();
  for (const match of template.matchAll(TOKEN)) found.add(match[1] as string);
  return [...found];
}
