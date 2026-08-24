/**
 * Minimal Gemini REST client for the Workers runtime.
 *
 * One free API key drives every AI step (scoring, drafting, critique). We keep
 * temperature low for checks and moderate for drafting, force JSON when we need
 * structured output, and retry/backoff on the free tier's rate limits.
 */
import { fetchRetry, extractJson } from './util';

const BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

export interface GenOpts {
  system?: string;
  json?: boolean;
  temperature?: number;
  maxOutputTokens?: number;
}

export class Gemini {
  constructor(private apiKey: string, private model: string) {}

  async text(prompt: string, opts: GenOpts = {}): Promise<string> {
    const url = `${BASE}/${this.model}:generateContent?key=${this.apiKey}`;
    const body: Record<string, unknown> = {
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: opts.temperature ?? 0.6,
        maxOutputTokens: opts.maxOutputTokens ?? 4096,
        ...(opts.json ? { responseMimeType: 'application/json' } : {}),
      },
    };
    if (opts.system) body.systemInstruction = { parts: [{ text: opts.system }] };

    const res = await fetchRetry(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }, { tries: 4, timeoutMs: 45000 });

    if (!res.ok) {
      throw new Error(`Gemini ${res.status}: ${(await res.text()).slice(0, 300)}`);
    }
    const data = (await res.json()) as any;
    const cand = data?.candidates?.[0];
    if (!cand) {
      const reason = data?.promptFeedback?.blockReason ?? 'no_candidate';
      throw new Error(`Gemini returned no candidate (${reason})`);
    }
    if (cand.finishReason && cand.finishReason !== 'STOP' && cand.finishReason !== 'MAX_TOKENS') {
      throw new Error(`Gemini finishReason ${cand.finishReason}`);
    }
    const text = (cand.content?.parts ?? []).map((p: any) => p.text ?? '').join('');
    if (!text.trim()) throw new Error('Gemini returned empty text');
    return text;
  }

  /** Generate and parse JSON, tolerating stray prose around it. */
  async json<T = unknown>(prompt: string, opts: GenOpts = {}): Promise<T> {
    const raw = await this.text(prompt, { ...opts, json: true, temperature: opts.temperature ?? 0.2 });
    try {
      return JSON.parse(raw) as T;
    } catch {
      return extractJson<T>(raw);
    }
  }
}
