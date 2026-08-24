/** Small shared helpers. No dependencies — everything runs on the Workers runtime. */

export const nowIso = (): string => new Date().toISOString();

export function uid(prefix = ''): string {
  return prefix + crypto.randomUUID().replace(/-/g, '').slice(0, 20);
}

/** A URL-safe slug from a title, deduped by the caller against ce_seen. */
export function slugify(input: string): string {
  return input
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/[\s_]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60)
    .replace(/-$/g, '');
}

export function randomSecret(bytes = 24): string {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** fetch with timeout, retry and exponential backoff for flaky upstreams. */
export async function fetchRetry(
  url: string,
  init: RequestInit = {},
  opts: { tries?: number; timeoutMs?: number; backoffMs?: number } = {},
): Promise<Response> {
  const { tries = 3, timeoutMs = 20000, backoffMs = 600 } = opts;
  let lastErr: unknown;
  for (let i = 0; i < tries; i++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...init, signal: ctrl.signal });
      clearTimeout(t);
      // Retry on 429/5xx; return anything else (incl. 4xx the caller inspects).
      if (res.status === 429 || res.status >= 500) {
        if (i < tries - 1) {
          const retryAfter = Number(res.headers.get('retry-after')) * 1000;
          await sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : backoffMs * 2 ** i);
          continue;
        }
      }
      return res;
    } catch (err) {
      clearTimeout(t);
      lastErr = err;
      if (i < tries - 1) await sleep(backoffMs * 2 ** i);
    }
  }
  throw lastErr ?? new Error(`fetch failed: ${url}`);
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Extract the first fenced ```json or raw JSON object/array from LLM text. */
export function extractJson<T = unknown>(text: string): T {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const raw = fenced ? fenced[1] : text;
  const start = raw!.search(/[[{]/);
  if (start === -1) throw new Error('no JSON found in model output');
  // Walk to the matching closing bracket to tolerate trailing prose.
  const open = raw![start];
  const close = open === '{' ? '}' : ']';
  let depth = 0;
  for (let i = start; i < raw!.length; i++) {
    const c = raw![i];
    if (c === open) depth++;
    else if (c === close) {
      depth--;
      if (depth === 0) return JSON.parse(raw!.slice(start, i + 1)) as T;
    }
  }
  throw new Error('unterminated JSON in model output');
}
