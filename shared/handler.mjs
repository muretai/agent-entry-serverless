/**
 * handler.mjs — one Agent Entry handler, in the shape both Vercel and Netlify speak.
 *
 * Vercel Functions and Netlify Functions v2 both take a Web `Request` and return a Web
 * `Response`, so the adapter is written once here and each platform directory supplies only
 * two things: its own store, and its own routing config. Writing it twice would mean two
 * copies of the same argument about bytes and headers, drifting.
 *
 * WHAT THIS FILE REFUSES TO DO. It does not decode the request body. The signature covers
 * the exact bytes the sender sent, and `await request.text()` followed by re-encoding is a
 * round trip through a decoder that can change them. `arrayBuffer()` is the only safe read.
 */

import { createAgentEntry } from './muretai-agent-entry.mjs';

/**
 * Build the entry. Kept module-level in each platform file so an instance that stays warm
 * reuses it; nothing that matters across requests lives in it — that is the store's job.
 *
 * @param {object} env    the platform's environment object (process.env, usually).
 * @param {object} store  the state adapter for this platform.
 * @param {function} [responder]  what your site says back.
 */
export function buildEntry(env, store, responder) {
  if (!env.AGENT_ENTRY_SEED_HEX) {
    throw new Error(
      'AGENT_ENTRY_SEED_HEX is not set. This is the private key: set it as an encrypted '
      + 'environment variable in the platform dashboard, never in a committed file.');
  }
  if (!env.AGENT_ENTRY_BASE_URL) {
    throw new Error(
      'AGENT_ENTRY_BASE_URL is not set. It is signed into the Agent Card, and a visitor '
      + 'REFUSES a card that names an origin other than the one they dialled — so there is '
      + 'no safe default, and a preview URL here will fail on your production domain.');
  }
  return createAgentEntry({
    seedHex: env.AGENT_ENTRY_SEED_HEX,
    baseUrl: env.AGENT_ENTRY_BASE_URL,
    name: env.AGENT_ENTRY_NAME || 'Agent Entry',
    description: env.AGENT_ENTRY_DESCRIPTION
      || 'Send a signed A2A message and get a signed reply.',
    store,
    responder: responder || ((envelope) =>
      env.AGENT_ENTRY_REPLY
      || `Thanks — your message reached ${env.AGENT_ENTRY_NAME || 'this site'} and a human `
         + 'will read it.'),
  });
}

/**
 * Turn a built entry into a Web `Request` -> `Response` function.
 *
 * @param {() => object} getEntry  called per request; throw inside it to report a
 *                                 configuration problem without describing internals to a
 *                                 stranger.
 */
export function toWebHandler(getEntry) {
  return async function handler(request) {
    let entry;
    try {
      entry = getEntry();
    } catch (e) {
      // The OPERATOR needs the detail (it is in the log); a stranger gets a status line.
      console.error('agent-entry configuration error:', e.message);
      return new Response(JSON.stringify({ error: 'not configured' }), {
        status: 503, headers: { 'Content-Type': 'application/json' } });
    }

    const url = new URL(request.url);
    const headers = {};
    for (const [k, v] of request.headers) headers[k.toLowerCase()] = v;
    // RAW BYTES, never text: the signature covers exactly what was sent.
    const body = request.method === 'POST' || request.method === 'PUT'
      ? new Uint8Array(await request.arrayBuffer())
      : new Uint8Array(0);

    const out = await entry.handleRequestAsync(request.method, url.pathname, headers, body);
    return new Response(out.status === 204 ? null : out.body,
      { status: out.status, headers: out.headers });
  };
}
