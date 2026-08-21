/**
 * worker.mjs — an Agent Entry on Cloudflare Workers.
 *
 * The whole door is the library; this file is the adapter. It does three things and
 * nothing else: build the entry once per isolate, translate a `Request` into the library's
 * `(method, path, headers, body)` call, and translate the answer back.
 *
 * TWO THINGS THAT WILL BITE YOU, both learned the hard way and both cheap to avoid:
 *
 * 1. `AGENT_ENTRY_BASE_URL` MUST be the public address a visitor dials. It is signed into
 *    the Agent Card, and a visitor REFUSES a card that names anything other than the origin
 *    they actually dialled. Get it wrong and every verification fails on their machine with
 *    nothing visibly wrong on yours.
 *
 * 2. Cloudflare's Browser Integrity Check (a ZONE setting, on by default on the free plan)
 *    403s clients whose user agent looks automated — which is every agent. Your site looks
 *    perfect in a browser while no agent can reach it. If you put this behind a zone you
 *    control, add an exception matching on HOST, METHOD AND PATH ONLY, never on user agent.
 *    And do not test with `curl`: it sends its own agent string and sails straight through
 *    the check that is blocking everyone else.
 */

import { createAgentEntry } from './muretai-agent-entry.mjs';
import { kvStore } from './store.mjs';

/** Built once per isolate. The entry itself holds no state that matters across requests —
 *  that is what the KV store is for — so reusing it is a pure saving. */
let ENTRY = null;

function entryFor(env) {
  if (ENTRY) return ENTRY;
  if (!env.AGENT_ENTRY_SEED_HEX) {
    throw new Error(
      'AGENT_ENTRY_SEED_HEX is not set. This is the private key: put it in a SECRET '
      + '(`wrangler secret put AGENT_ENTRY_SEED_HEX`), never in wrangler.toml, which is a '
      + 'file you commit.');
  }
  if (!env.AGENT_ENTRY_BASE_URL) {
    throw new Error(
      'AGENT_ENTRY_BASE_URL is not set. It is signed into the card and a visitor requires '
      + 'the card to name the origin they dialled, so there is no safe default.');
  }
  ENTRY = createAgentEntry({
    seedHex: env.AGENT_ENTRY_SEED_HEX,
    baseUrl: env.AGENT_ENTRY_BASE_URL,
    name: env.AGENT_ENTRY_NAME || 'Agent Entry',
    description: env.AGENT_ENTRY_DESCRIPTION
      || 'Send a signed A2A message and get a signed reply.',
    store: kvStore(env.AGENT_ENTRY_KV),
    responder: (envelope) => respond(envelope, env),
  });
  return ENTRY;
}

/**
 * What your site says back. Replace this with your own logic — a lookup, a price, an
 * availability. `envelope.peer_did` is the VERIFIED sender: the signature has already been
 * checked by the time you see it.
 *
 * Deliberately not a model call. If you want a generated answer, call your own model here,
 * where you decide the budget — a door that reached for one on every inbound message would
 * hand a stranger your bill.
 */
async function respond(envelope, env) {
  return env.AGENT_ENTRY_REPLY
    || `Thanks — your message reached ${env.AGENT_ENTRY_NAME || 'this site'} and a human `
       + 'will read it.';
}

export default {
  async fetch(request, env) {
    let entry;
    try {
      entry = entryFor(env);
    } catch (e) {
      // A misconfigured door must say so to its OPERATOR (in the log) without describing
      // its own internals to a stranger.
      console.error('agent-entry configuration error:', e.message);
      return new Response(JSON.stringify({ error: 'not configured' }), {
        status: 503, headers: { 'Content-Type': 'application/json' } });
    }

    const url = new URL(request.url);
    const headers = {};
    for (const [k, v] of request.headers) headers[k.toLowerCase()] = v;
    // The library takes raw BYTES. Handing it a decoded string would re-encode the body and
    // change the very bytes the signature covers.
    const body = request.method === 'POST'
      ? new Uint8Array(await request.arrayBuffer())
      : new Uint8Array(0);

    const out = await entry.handleRequestAsync(request.method, url.pathname, headers, body);
    return new Response(out.body, { status: out.status, headers: out.headers });
  },
};
