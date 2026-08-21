/**
 * tests/check-vercel-shape.mjs — will Vercel actually hand our handler a Web Request?
 *
 * THE BUG THIS EXISTS FOR. The first cut of vercel/api/entry.mjs was
 * `export default toWebHandler(...)` — a bare default-exported function. Vercel decides the
 * calling convention by INSPECTING THE EXPORT, and a bare function is the classic
 * `(req, res)` Node signature, not a Web handler. Every request would have thrown on
 * `new URL(request.url)` and then hung, because the returned Response was discarded and
 * `res` was never ended. One of three advertised deploy targets, dead on its first request.
 *
 * The detection below is copied from @vercel/node's own launcher
 * (dist/bundling-handler.js), so this test asks Vercel's question rather than ours.
 *
 *     node tests/check-vercel-shape.mjs
 */
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const unwrapDefaults = (m) => (m && m.default !== undefined ? m.default : m);

process.env.AGENT_ENTRY_SEED_HEX = process.env.AGENT_ENTRY_SEED_HEX || '3d'.repeat(32);
process.env.AGENT_ENTRY_BASE_URL = 'https://shop.example';
process.env.KV_REST_API_URL = 'http://127.0.0.1:59999';
process.env.KV_REST_API_TOKEN = 'unused-for-a-card-fetch';

const listener = unwrapDefaults(await import('../vercel/api/entry.mjs'));

const isWebHandler =
  HTTP_METHODS.some((m) => typeof listener[m] === 'function') ||
  typeof listener.fetch === 'function';

let failed = false;
const check = (cond, label, detail = '') => {
  if (cond) console.log(`ok: ${label}`);
  else { failed = true; console.log(`FAIL: ${label}${detail ? `  (${detail})` : ''}`); }
};

check(isWebHandler,
  "Vercel detects the export as a WEB handler (it will pass a Request)",
  'a bare default function would be called as (req, res) and hang');

if (isWebHandler) {
  const res = await listener.fetch(
    new Request('https://shop.example/.well-known/agent-card.json'));
  check(res.status === 200, 'invoked the way Vercel invokes it, the card is served',
    `status ${res.status}`);
  const card = await res.json();
  check(typeof card.did === 'string' && card.did.startsWith('did:key:'),
    'the served card names a did:key', JSON.stringify(card).slice(0, 80));
}

process.exit(failed ? 1 : 0);
