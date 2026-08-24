/**
 * Commit a single markdown file to the site repo via the GitHub Contents API.
 *
 * This is the publish action: on your approval, the finished article (with
 * draft:false) is committed to CONTENT_DIR on GITHUB_BRANCH, which your normal
 * build/deploy then ships. Creating and updating are the same call; we look up
 * the existing sha first so a re-publish updates in place instead of failing.
 */
import { fetchRetry } from './util';

function toBase64Utf8(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

const headers = (token: string) => ({
  authorization: `Bearer ${token}`,
  accept: 'application/vnd.github+json',
  'user-agent': 'maildoc-content-engine',
  'x-github-api-version': '2022-11-28',
});

export async function getFileSha(repo: string, path: string, branch: string, token: string): Promise<string | null> {
  const url = `https://api.github.com/repos/${repo}/contents/${encodeURI(path)}?ref=${encodeURIComponent(branch)}`;
  const res = await fetchRetry(url, { headers: headers(token) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GitHub get ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return ((await res.json()) as any).sha as string;
}

export async function commitFile(args: {
  repo: string; path: string; branch: string; token: string; content: string; message: string;
}): Promise<{ commitSha: string; htmlUrl: string }> {
  const sha = await getFileSha(args.repo, args.path, args.branch, args.token);
  const url = `https://api.github.com/repos/${args.repo}/contents/${encodeURI(args.path)}`;
  const res = await fetchRetry(url, {
    method: 'PUT',
    headers: { ...headers(args.token), 'content-type': 'application/json' },
    body: JSON.stringify({
      message: args.message,
      content: toBase64Utf8(args.content),
      branch: args.branch,
      ...(sha ? { sha } : {}),
    }),
  }, { tries: 2 });
  if (!res.ok) throw new Error(`GitHub commit ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const data = (await res.json()) as any;
  return { commitSha: data.commit?.sha ?? '', htmlUrl: data.content?.html_url ?? '' };
}
