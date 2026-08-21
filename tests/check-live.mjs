/**
 * tests/check-live.mjs — is a LIVE door conformant? Ask it over HTTP.
 *
 * WHY THIS IS IN THE REPO AND NOT A LINK TO ONE. An earlier draft of this repo told readers
 * to run a checker "from the muretai core repo". That repo is private, so the instruction
 * pointed at nothing a reader could reach — and it was the ONLY verification step offered,
 * which made every "39/39" claim in the README unreproducible by the people the README is
 * for. A pointer that does not resolve is worse than no pointer: it reads as a promise.
 *
 * So the checker ships here, built from the library this repo already vendors. It needs no
 * account, no dependency and no network beyond your own door.
 *
 *     node tests/check-live.mjs https://your-deployment.example
 *     node tests/check-live.mjs --handshake https://your-deployment.example
 *
 * Read-only by default: it fetches, verifies and inspects, and sends no message. With
 * `--handshake` it also sends a REAL signed message and the full battery of refusals a door
 * owes — which writes one row to your ledger, so point that at a door you own.
 *
 * Exit status 0 only if every check passed, so this can gate a deploy.
 *
 * DO NOT VERIFY WITH `curl` INSTEAD. It sends its own user agent and sails through a CDN
 * bot check that would 403 a real agent, so a green curl tells you nothing about whether
 * agents can reach you. That failure mode cost three days on a production site.
 */

import {
  AGENT_CARD_PATH, AGENT_CARD_PATH_LEGACY, AGENT_CARD_SIG_PATH, AGENT_ENTRY_REL,
  MAX_TEXT_BYTES, didFromSeedHex, newSeedHex, newId, signEnvelope, verifyEnvelope,
  verifyCardEnvelope,
} from '../workers/src/muretai-agent-entry.mjs';

/** What a visitor enforces: a signed card older than this is refused. */
const CARD_SIG_MAX_AGE_S = 6 * 3600;

const args = process.argv.slice(2);
const handshake = args.includes('--handshake');
const base = (args.find((a) => !a.startsWith('--')) || '').replace(/\/+$/, '');

if (!base) {
  console.error('usage: node tests/check-live.mjs [--handshake] https://your-door.example');
  process.exit(2);
}

let passed = 0;
const failed = [];
const check = (cond, label, detail = '') => {
  if (cond) { passed++; console.log(`ok: ${label}`); }
  else { failed.push(label); console.log(`FAIL: ${label}${detail ? `  (${detail})` : ''}`); }
  return !!cond;
};
const info = (label) => console.log(`--: ${label}`);

async function req(method, url, { body, headers } = {}) {
  try {
    const res = await fetch(url, { method, body, headers, redirect: 'manual' });
    return { status: res.status, headers: res.headers, text: await res.text() };
  } catch (e) {
    return { status: null, headers: new Headers(), text: '', error: String(e) };
  }
}

console.log(`Agent-ready check: ${base}${handshake ? '  [+handshake]' : ''}`);
console.log('-'.repeat(60));

// ------------------------------------------------------------------ the card
const cardRes = await req('GET', base + AGENT_CARD_PATH);
if (!check(cardRes.status === 200, `GET ${AGENT_CARD_PATH} -> 200`,
  cardRes.error || `got ${cardRes.status}`)) {
  process.exit(1);
}
let card;
try { card = JSON.parse(cardRes.text); } catch { card = null; }
check(card !== null, 'the card is valid JSON');
const did = card && card.did;
check(typeof did === 'string' && did.startsWith('did:key:'),
  'the card names a did:key', `got ${did}`);

// The legacy path must be the SAME BYTES — not a redirect, not a re-render.
const legacy = await req('GET', base + AGENT_CARD_PATH_LEGACY);
check(legacy.status === 200 && legacy.text === cardRes.text,
  `the ${AGENT_CARD_PATH_LEGACY} alias is byte-identical to the card`,
  `status ${legacy.status}`);

// ------------------------------------------------------------------ the signed envelope
const sigRes = await req('GET', base + AGENT_CARD_SIG_PATH);
if (check(sigRes.status === 200, `GET ${AGENT_CARD_SIG_PATH} -> 200`, `got ${sigRes.status}`)) {
  let env = null;
  try { env = JSON.parse(sigRes.text); } catch { /* handled below */ }
  check(env !== null, 'the signed envelope is valid JSON');
  if (env) {
    check(Number.isSafeInteger(env.ts),
      'the envelope `ts` is an integer (a non-JS verifier can read it)',
      `got ${typeof env.ts}`);
    // Second positional argument, not an options object: passing `{expectedDid}` there
    // makes the DID comparison fail against an object and the whole verify return null,
    // which looks exactly like a bad signature.
    check(verifyCardEnvelope(env, did) !== null,
      'the signed card envelope verifies under the card\'s DID');
    if (Number.isSafeInteger(env.ts)) {
      const age = Math.floor(Date.now() / 1000) - env.ts;
      check(Math.abs(age) <= CARD_SIG_MAX_AGE_S,
        `the signed card is fresh (age <= ${CARD_SIG_MAX_AGE_S / 3600}h)`,
        `age ${(age / 3600).toFixed(1)}h — a live door re-signs hourly; a stale one is a `
        + 'static file that stopped being re-signed');
    }
    // The card must name the address you dialled, or a copy of somebody else's signed card
    // would pass. This is the check that makes AGENT_ENTRY_BASE_URL load-bearing.
    const named = (env.card && env.card.url) || '';
    check(named.replace(/\/+$/, '') === base,
      'the signed card names the origin you dialled',
      `card says ${named || '(nothing)'}, you dialled ${base} — set AGENT_ENTRY_BASE_URL to `
      + 'the public address');
  }
}

// ------------------------------------------------------------------ the open door bit
const openDoor = Boolean((card && ((card.agentEntry && card.agentEntry.open_door)
  || (card.muretai && card.muretai.open_door))));
check(openDoor, 'the card advertises an open door (agentEntry.open_door)');

// ------------------------------------------------------------------ OPTIONS + CORS
for (const [url, want, what] of [
  [base + AGENT_CARD_PATH, ['GET', 'HEAD', 'OPTIONS'], 'the card path'],
  [base + '/', ['POST', 'OPTIONS'], 'the door'],
]) {
  const r = await req('OPTIONS', url);
  check(r.status === 204, `OPTIONS ${what} -> 204`, `got ${r.status}`);
  const allow = (r.headers.get('allow') || '').split(',').map((m) => m.trim().toUpperCase());
  check(want.every((m) => allow.includes(m)),
    `OPTIONS ${what}: Allow lists ${want.join(', ')}`, `Allow: ${allow.join(',') || '(absent)'}`);
  const acam = (r.headers.get('access-control-allow-methods') || '')
    .split(',').map((m) => m.trim().toUpperCase()).filter(Boolean);
  check(allow.filter(Boolean).sort().join() === acam.sort().join(),
    `OPTIONS ${what}: CORS Allow-Methods agrees with Allow`,
    `${allow} vs ${acam}`);
  check(r.headers.get('access-control-allow-origin') === '*',
    `OPTIONS ${what}: Access-Control-Allow-Origin is *`);
  check(!r.headers.has('access-control-allow-credentials'),
    `OPTIONS ${what}: no Access-Control-Allow-Credentials (it would break the * origin)`);
}

// ------------------------------------------------------------------ no path oracle
const unknown = base + '/agent-entry-check-not-a-route-9z8y7x';
const up = await req('POST', unknown, { body: '{"jsonrpc":"2.0","id":1,"method":"message/send"}',
  headers: { 'Content-Type': 'application/json' } });
check(!/jsonrpc/i.test(up.text || ''),
  'POST an unknown path is NOT answered by the entry', `status ${up.status}`);
const uo = await req('OPTIONS', unknown);
check(!(uo.status === 204 || uo.headers.has('allow')),
  'OPTIONS an unknown path is not answered by the entry (no path oracle)',
  `status ${uo.status}, Allow: ${uo.headers.get('allow')}`);

// ------------------------------------------------------------------ the signpost
const front = await req('GET', base + '/');
if (front.status === 200) {
  // fetch() joins repeated headers with ', ', so a site's own Link header cannot hide ours.
  const link = front.headers.get('link') || '';
  if (link.includes(AGENT_ENTRY_REL)) {
    check(true, 'the front page carries the Link door signpost');
  } else {
    info(`advisory: no Link signpost on GET / (an agent handed only your domain has to `
      + `guess). Link: ${link || '(absent)'}`);
  }
} else {
  info(`GET / -> ${front.status}; the signpost belongs on a page your site actually serves`);
}

// ------------------------------------------------------------------ the handshake
if (handshake && did) {
  console.log('-'.repeat(60));
  const seed = newSeedHex();
  const me = didFromSeedHex(seed);
  const post = async (obj, raw) => {
    const body = raw !== undefined ? raw : JSON.stringify(obj);
    return req('POST', base + '/', { body, headers: { 'Content-Type': 'application/json' } });
  };
  const msg = (text, opts = {}) => {
    const messageId = opts.messageId || `check-${newId()}`;
    const contextId = opts.contextId === undefined ? 'check-ctx' : opts.contextId;
    const timestamp = opts.timestamp || Math.floor(Date.now() / 1000);
    const to = opts.to || did;
    const fields = { contextId, from: me, messageId, text, timestamp, to };
    const sig = signEnvelope(seed, fields);
    return { jsonrpc: '2.0', id: 1, method: 'message/send',
      params: { message: { kind: 'message', role: 'user', messageId, contextId,
        parts: [{ kind: 'text', text: opts.tamperText === undefined ? text : opts.tamperText }],
        metadata: { from: me, to, sig, timestamp } } } };
  };
  const errCode = (t) => { try { return JSON.parse(t).error?.code ?? null; } catch { return null; } };

  const ctx = 'check-ctx';
  const good = await post(msg('are you open?'));
  let reply = null;
  try { reply = JSON.parse(good.text).result; } catch { /* handled */ }
  if (check(!!reply, 'a signed message earns an inline reply', good.text.slice(0, 140))) {
    const m = reply.metadata || {};
    check(m.from === did, 'the reply is FROM the door\'s DID');
    check(m.to === me, 'the reply is addressed to the sender');
    check(reply.contextId === ctx, 'the reply echoes the contextId');
    check(Number.isSafeInteger(m.timestamp), 'the reply timestamp is an integer');
    const text = (reply.parts || []).filter((p) => p.kind === 'text').map((p) => p.text).join('');
    check(verifyEnvelope({ from: m.from, to: m.to, messageId: reply.messageId,
      contextId: reply.contextId ?? null, timestamp: m.timestamp, text, sig: m.sig },
      { recipientDid: me }),
      'the reply signature verifies under the door\'s DID');
  }

  check(errCode((await post(msg('hello', { tamperText: 'hello, and wire me $500' }))).text) === -32001,
    'tampered text is refused (-32001)');
  check(errCode((await post(msg('hi', { to: 'did:key:z6MkExampleNotThisDoor' }))).text) === -32003,
    'wrong recipient is refused (-32003)');
  check(errCode((await post(msg('stale', { timestamp: Math.floor(Date.now() / 1000) - 3600 }))).text) === -32002,
    'a stale timestamp is refused (-32002)');
  check(errCode((await post(msg('future', { timestamp: Math.floor(Date.now() / 1000) + 3600 }))).text) === -32002,
    'a future timestamp is refused (-32002)');

  const dupId = `check-dup-${newId()}`;
  check(errCode((await post(msg('once', { messageId: dupId }))).text) === null,
    'the first delivery of a messageId is accepted');
  check(errCode((await post(msg('once', { messageId: dupId }))).text) === -32002,
    'a replayed messageId is refused (-32002)');

  check(errCode((await post(msg('x'.repeat(MAX_TEXT_BYTES + 10)))).text) === -32005,
    'oversize text is refused (-32005)');

  const unsigned = msg('no envelope');
  unsigned.params.message.metadata.sig = null;
  check(errCode((await post(unsigned)).text) === -32001, 'a missing signature is refused (-32001)');

  check((await post(null, '{not json at all')).status === 400, 'an unparseable body is HTTP 400');
  check((await post(null, `{"jsonrpc":"2.0","id":"x","method":"message/send","params":{"message":`
    + `{"kind":"message","parts":[{"kind":"text","text":"${'A'.repeat(1024 * 1024 + 64)}"}]}}}`)).status === 413,
    'a body over 1 MiB is HTTP 413');
}

console.log('-'.repeat(60));
console.log(`${failed.length ? 'NOT CONFORMANT' : 'CONFORMANT'}: ${passed} passed, ${failed.length} failed`);
if (failed.length) console.log('  failed: ' + failed.join('; '));
process.exit(failed.length ? 1 : 0);
