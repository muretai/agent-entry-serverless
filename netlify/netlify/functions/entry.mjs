/**
 * netlify/functions/entry.mjs — the Agent Entry, as a Netlify Function (v2).
 *
 * The `config.path` export is Netlify's own routing: it claims the three card paths and the
 * site root without a redirect file, so the door and its routes cannot drift apart.
 */
import { getStore } from '@netlify/blobs';
import { buildEntry, toWebHandler } from '../../lib/handler.mjs';
import { blobStore } from '../../lib/blob-store.mjs';

let ENTRY = null;
export default toWebHandler(() => {
  if (!ENTRY) {
    ENTRY = buildEntry(process.env, blobStore(getStore('agent-entry')));
  }
  return ENTRY;
});

export const config = {
  path: ['/', '/.well-known/agent-card.json', '/.well-known/agent.json',
         '/.well-known/agent-card.sig.json'],
};
