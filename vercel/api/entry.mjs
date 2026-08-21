/**
 * api/entry.mjs — the Agent Entry, as a Vercel Function.
 *
 * `vercel.json` rewrites every path this door owns to here, because the card lives under
 * `/.well-known/` and the door is a POST to the site root — neither of which is a file.
 *
 * WHY THE EXPORT IS AN OBJECT WITH `fetch`, AND NOT A BARE FUNCTION.
 *
 * Vercel decides which calling convention to use by INSPECTING THE EXPORT: its launcher
 * looks for `.fetch` or a named HTTP-method export, and treats anything else that is
 * callable as the classic `(req, res)` Node signature. A bare `export default (request) =>
 * Response` therefore does NOT get a Web `Request` — it gets `(VercelRequest,
 * VercelResponse)`, so `new URL(request.url)` throws on the bare path, the returned
 * `Response` is discarded, and `res` is never ended, so the invocation hangs. Every
 * request fails, on the first try.
 *
 * That was the shape of the first cut here, and it was caught by an audit that read
 * @vercel/node's launcher rather than trusting the docs. `{ fetch }` is what makes Vercel
 * hand us the Web `Request` this handler is written for — the same object Netlify
 * Functions v2 passes directly.
 */
import { buildEntry, toWebHandler } from '../lib/handler.mjs';
import { restKvStore } from '../lib/rest-kv-store.mjs';

let ENTRY = null;
const handler = toWebHandler(() => {
  if (!ENTRY) ENTRY = buildEntry(process.env, restKvStore(process.env));
  return ENTRY;
});

export default { fetch: handler };
