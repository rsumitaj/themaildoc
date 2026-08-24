/**
 * Transactional email via Resend (free tier). Used only to send you the
 * approval email. If you would rather send through your own infrastructure —
 * fitting, since deliverability is the product — swap this one function.
 */
import { fetchRetry } from './util';

export async function sendEmail(args: {
  apiKey: string; from: string; to: string; subject: string; html: string;
}): Promise<{ ok: boolean; id?: string; error?: string }> {
  const res = await fetchRetry('https://api.resend.com/emails', {
    method: 'POST',
    headers: { authorization: `Bearer ${args.apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify({ from: args.from, to: [args.to], subject: args.subject, html: args.html }),
  }, { tries: 3 });
  const data = (await res.json().catch(() => ({}))) as any;
  if (!res.ok) return { ok: false, error: data?.message ?? `resend ${res.status}` };
  return { ok: true, id: data?.id };
}
