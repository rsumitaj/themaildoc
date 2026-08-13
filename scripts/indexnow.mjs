/**
 * Submit every URL in the sitemap to IndexNow.
 *
 * Bing, Yandex, Seznam and Naver share one endpoint and act on it in hours
 * rather than the weeks Google takes to find a new site on its own. Google does
 * not participate, so this is not a substitute for Search Console; it is the
 * half of the problem that can be solved with a script.
 *
 * Bing also feeds ChatGPT search, which for a developer tool is worth more
 * than its share of the search market suggests.
 *
 * The key is proved by hosting it at the root of the domain, which is why the
 * matching file exists in `apps/web/public/`.
 *
 *   pnpm indexnow
 */
const KEY = '5d9c3cb10e2494b08b386772bce34fb2';
const HOST = 'themaildoc.co';

const sitemap = await (await fetch(`https://${HOST}/sitemap-0.xml`)).text();
const urlList = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);

if (urlList.length === 0) {
  console.error('No URLs in the sitemap. Is the site deployed?');
  process.exit(1);
}

const response = await fetch('https://api.indexnow.org/IndexNow', {
  method: 'POST',
  headers: { 'content-type': 'application/json; charset=utf-8' },
  body: JSON.stringify({
    host: HOST,
    key: KEY,
    keyLocation: `https://${HOST}/${KEY}.txt`,
    urlList,
  }),
});

// 200 and 202 both mean accepted. 403 means the key file is not reachable yet,
// which on a fresh deploy usually means waiting a minute and running it again.
console.log(`IndexNow: ${response.status} ${response.statusText} for ${urlList.length} URLs`);
if (!response.ok) console.log(await response.text());
