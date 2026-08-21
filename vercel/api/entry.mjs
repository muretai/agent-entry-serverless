/**
 * api/entry.mjs — the Agent Entry, as a Vercel Function.
 *
 * `vercel.json` rewrites every path this door owns to here, because the card lives under
 * `/.well-known/` and the door is a POST to the site root — neither of which is a file.
 */
import { buildEntry, toWebHandler } from '../../shared/handler.mjs';
import { restKvStore } from '../../shared/rest-kv-store.mjs';

let ENTRY = null;
export default toWebHandler(() => {
  if (!ENTRY) ENTRY = buildEntry(process.env, restKvStore(process.env));
  return ENTRY;
});
