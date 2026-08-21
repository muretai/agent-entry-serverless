/**
 * web/agent-entry/muretai-agent-entry.mjs
 * THE AGENT ENTRY — one dependency-free Node file that makes a website agent-reachable.
 *
 * Why this exists:
 *   Muretai's adoption bottleneck is that BOTH ends had to run a node. A site does not want
 *   a daemon, a key store or an inbox loop; it wants an endpoint. This module is that half:
 *   drop it on an origin you already have, and a visiting agent can (1) verify from your
 *   Agent Card that this DID really owns this origin, (2) POST a signed A2A message, and
 *   (3) get YOUR signed reply back in the same HTTP response. First contact IS account
 *   creation — there is no signup form, because the sender's did:key already is the account.
 *
 * Zero dependencies, forever: `node:crypto`, `node:http`, `node:buffer` only. No npm, no
 * build step, no transpiler. Node 20+ (native ed25519 / x25519 / hkdfSync / chacha20-poly1305).
 *
 * THE BYTES ARE THE CONTRACT. Every signed payload here must be byte-identical to what
 * Python's `shared/crypto.canonical` produces, or the signature is unverifiable and the only
 * diagnostic anyone gets is "signature verification failed". The pinned bytes live in
 * `testdata/wire_vectors.json`; `test_agent_entry_contract.py` Part 3 re-derives all of them
 * through this file. If you change anything under CANONICAL JSON, run that suite first.
 *
 *   import { createAgentEntry } from './muretai-agent-entry.mjs';
 *   createAgentEntry({ seedHex, name: 'Example Studio', baseUrl: 'https://studio.example',
 *                    responder: (env) => `You said: ${env.text}` }).listen(8788);
 *
 * See examples/agent_entry_server.mjs for the ~50-line file a site actually copies.
 */

import {
  createHash, createPrivateKey, createPublicKey, createCipheriv, createDecipheriv,
  diffieHellman, hkdfSync, randomBytes, sign as nodeSign, verify as nodeVerify,
} from 'node:crypto';
import { createServer } from 'node:http';
import { Buffer } from 'node:buffer';

// ---------------------------------------------------------------- protocol constants

export const PROTOCOL_VERSION = '0.2';
/** `text` ceiling in UTF-8 BYTES (shared/protocol.MAX_TEXT_BYTES). Bytes, not characters:
 *  a limit in characters is not a limit on what anyone has to store. */
export const MAX_TEXT_BYTES = 64 * 1024;
/** HTTP body ceiling. Anything larger is refused with 413 BEFORE the JSON parser sees it. */
export const MAX_BODY_BYTES = 1024 * 1024;
/** Accepted clock skew, seconds, either direction (agent/inbox.CLOCK_WINDOW). */
export const CLOCK_WINDOW_S = 300;
/** How long a messageId is remembered for replay refusal, seconds. */
export const REPLAY_TTL_S = 600;
/** The signed card envelope is re-minted at most this often (Inbox.CARD_SIG_REFRESH). */
export const CARD_SIG_REFRESH_S = 3600;
/** Signed replies per minute the ANONYMOUS lane may cost this agent entry, in total.
 *  Unauthenticated, so without a bound it is a signing oracle: a stranger spends an Ed25519
 *  signature (and a backend call) per request forever and nothing can attribute the cost.
 *  Per-ENTRY, not per-IP — behind a proxy the source address is whatever the last hop
 *  wrote. Must match `ANON_RATE_PER_MIN` in examples/agent_entry_reference.py: one contract,
 *  two implementations, one bound. */
export const ANON_RATE_PER_MIN = 30;
/** Ceilings on the SIGNED lane: replies per minute per ACCOUNT, and per minute for the
 *  whole entry. Both default ON.
 *
 *  WHY A SIGNED SENDER NEEDS A BOUND AT ALL. The reason not to have one used to be that a
 *  signed sender "is attributable, and every one of them is already in the ledger". Both
 *  clauses are true and neither is load-bearing: the ledger is never read back before the
 *  responder runs, so attribution is RECORDED and never ENFORCED — and attribution to a
 *  did:key minted thirty seconds ago and never reused is attribution to nothing, because
 *  holding one costs nothing. That is the correct, deliberate property of a permissionless
 *  door (this card TELLS strangers to mint one, with runnable code), so the bound has to
 *  come from somewhere else. Naming a caller is a precondition for limiting it, never a
 *  substitute for limiting it.
 *
 *  WHY TWO TIERS. Verifying a signature is ~40 microseconds; what the ceiling protects is
 *  whatever the operator put behind `responder`, which may be a model call costing seconds
 *  and real money. Per-ACCOUNT (the T102-resolved account, so an owner's devices share one
 *  budget exactly as their ledger row does) stops one peer, honest or not, from taking the
 *  whole door. It CANNOT stop a flood from fresh keys — free identity defeats per-identity
 *  metering by definition — which is what the whole-entry ceiling is for. Ship both or
 *  neither; each one alone has an obvious hole.
 *
 *  Defaults are deliberately generous: no conversational peer meets them, and a site whose
 *  responder calls a model should lower them. A reference implementation's defaults are the
 *  deployed posture of everyone who copies it. Must match examples/agent_entry_reference.py:
 *  one contract, two implementations, one bound. */
export const SIGNED_RATE_PER_MIN = 60;
export const SIGNED_RATE_PER_MIN_TOTAL = 600;
/** How many domains one card may advertise (agent/domainstore.MAX_CARD_DOMAINS, and the
 *  same ceiling shared/protocol.build_agent_card applies to a node's card). Every name
 *  listed is an outbound HTTPS fetch this entry asks strangers to make, so the cap bounds
 *  the work an entry can push onto its visitors — not how many domains a site may own.
 *  Must match `MAX_CARD_DOMAINS` in examples/agent_entry_reference.py. */
export const MAX_CARD_DOMAINS = 5;

export const AGENT_CARD_PATH = '/.well-known/agent-card.json';
export const AGENT_CARD_PATH_LEGACY = '/.well-known/agent.json';
export const AGENT_CARD_SIG_PATH = '/.well-known/agent-card.sig.json';

/** The name of the ONE way in this door accepts today — the card's `securitySchemes` key,
 *  its `type`, and the `scheme` of the refusal's `accepts[]` entry are all this string. The
 *  card and the refusal MUST name the same scheme or a visitor learns one thing from the
 *  menu and another from the door. Must match `SIGNED_ENVELOPE_SCHEME` in
 *  examples/agent_entry_reference.py. */
export const SIGNED_ENVELOPE_SCHEME = 'did-key-ed25519';

/** The stable link relation that names an agent door, emitted on the notice route (and the
 *  one line a SITE adds to its own front page to coexist with an entry — see
 *  docs/AGENT_ENTRY.md). An ABSOLUTE URI on purpose: RFC 8288 §2.1.2 allows a bare token
 *  only for an IANA-registered relation, so `rel="agent-entry"` would be non-conformant and
 *  a strict parser is entitled to drop it. Must match `AGENT_ENTRY_REL` in
 *  examples/agent_entry_reference.py. */
export const AGENT_ENTRY_REL = 'https://muretai.net/rel/agent-entry';

/** Where a keyless visitor is sent to learn how to mint an identity and sign. It rides in
 *  the card AND in the refusal, so an agent that has only one of the two still has the URL.
 *
 *  EMPTY MEANS OMITTED, and that is the safe default. NEVER EMIT A URL THAT DOES NOT
 *  RESOLVE: a real third-party agent (2026-08-18 proof run) received the complete
 *  requirement object, printed every field of it, went straight to `howTo`, hit a 404 and
 *  stopped — "since the provided 'howTo' link is broken, I have no way to get this
 *  information" — while holding `identity`, `signedFields`, `canonicalization`,
 *  `signature`, `timestamp` and `recipient` in the object it had just printed. A dangling
 *  pointer OUT-COMPETES the data beside it and reads as terminal. So the field is emitted
 *  only when this constant is set, and it is set only AFTER the page is live: ship the page
 *  first, or ship no pointer. Verified live before this value was set (200 at the URL
 *  below, 404 at a control path under the same prefix); `entry-howto-resolves` in
 *  .claude/skills/ship-check/checks.py re-checks it on every ship report. Must match
 *  `FIRST_KNOCK_URL` in examples/agent_entry_reference.py.
 *
 *  DEFAULT EMPTY, and the paragraph above is why: this file already calls empty "the safe
 *  default" and then shipped a vendor's docs host as the value, so every door built from it
 *  stamped that host into its own public card. A reference implementation names no host —
 *  the recipe travels IN the refusal (the contract suite strips every `http` value and
 *  requires what is left to still be a complete recipe), and the worked example now travels
 *  in the package itself as `conformance/`. Pass `howToUrl` to point at a page you operate;
 *  ship the page FIRST and verify it 200s, because a dangling pointer is the one failure
 *  measured here. */
export const FIRST_KNOCK_URL = '';

/** `Allow:` per RESOURCE, not per server. RFC 9110 §10.2.1 makes `Allow` a statement about
 *  the target resource, and §15.5.6 REQUIRES it on a 405 — a generic list is a wrong answer
 *  to a right question, and on a guest mount it would also claim verbs on addresses the SITE
 *  owns. HEAD is listed wherever GET is (RFC 9110 §9.3.2 makes it mandatory alongside GET,
 *  and both twins have always answered it). Wherever `Allow` is emitted,
 *  `Access-Control-Allow-Methods` is set to the SAME value (`allowHeaders`) — the two are
 *  one fact for two readers, and a response carrying `Allow: POST, OPTIONS` beside the
 *  origin-wide `Access-Control-Allow-Methods: GET, POST, OPTIONS` contradicts itself in one
 *  message. Everywhere else (a card GET, a signed reply, a 404) the CORS default stands.
 *  Must match the `ALLOW_*` constants in examples/agent_entry_reference.py. */
export const ALLOW_CARD = 'GET, HEAD, OPTIONS';
/** A guest mount's door: the entry owns the POST and nothing else there. */
export const ALLOW_DOOR = 'POST, OPTIONS';
/** A site-owning mount: ONE address that is both the human notice (GET) and the door (POST),
 *  so the truthful Allow is the union — listing only the GET half would hide the very door
 *  the card names. */
export const ALLOW_MOUNT = 'GET, HEAD, POST, OPTIONS';

/**
 * The machine-readable terms of THIS door, in one object used on BOTH surfaces: the card's
 * `securitySchemes` entry (before the knock) and the `accepts[]` array of the no-envelope
 * refusal (after it). One object, two surfaces, so the two can never drift apart — the
 * property a visitor's test can assert without knowing what the scheme string is.
 *
 * The shape is x402's lesson turned into an identity vocabulary: a refusal that is the
 * SPECIFICATION of what to do next, as an ARRAY so "sign", "arrive with an introduction"
 * and later "pay" are siblings in one frame rather than three bespoke refusals.
 *
 * Everything a keyless visitor needs is here on purpose — the acceptance bar is that an
 * agent holding ONLY this object, plus the crypto tooling on any machine, can mint a
 * did:key, sign correctly and be answered on its NEXT post. That is why `recipient` is
 * present (nobody can address a message without it) and why the canonicalization rule is
 * spelled out rather than merely named.
 *
 * IT IS WRITTEN IN THE IMPERATIVE, and that is the fix a proof run bought (2026-08-18).
 * Every field above was already correct and complete, and a real third-party agent read
 * them, restated them accurately, and STOPPED: "since I don't have a way to generate
 * cryptographic keys within this environment, I am stuck" — with `node` and `python3`
 * both installed. A requirement object that describes a FORMAT tells a keyless visitor
 * what it lacks; it does not tell it to ACT. So `instruction` leads with the sentence
 * that unblocks a general-purpose agent — MAKE A KEY NOW, nobody's permission is needed,
 * any crypto library will do — and every descriptive string below gained an imperative
 * PREFIX. The old value of each is still a SUBSTRING of the new one, so a client that
 * substring-matched on the format text keeps matching; no field was removed or renamed,
 * and `howTo` is the only one whose presence is conditional (see FIRST_KNOCK_URL).
 *
 * IT TEACHES THE CARRIER AS WELL AS THE SIGNATURE, and that is the fix proof run 3 bought
 * (2026-08-18, `exampleRequest`). The recipe was walked end to end — a third-party agent ran
 * `identityCode`, minted a computed DID, signed the six canonical fields — and TWO runs were
 * still refused, holding a correct key, a correct DID and correct signed bytes, on the A2A
 * ENVELOPE: "not an A2A message object", "messageId must be a non-empty string". `in`
 * ("params.message.metadata") plus six `signedFields` reads as "put these six in metadata",
 * which is exactly what they built. One of them named the gap precisely: "the agent card is
 * ambiguous on the precise nesting of messageId… This is a guess at a format, which goes
 * against the rules." So the complete body a door accepts is emitted BESIDE `in` — the
 * counter-example on the very next line of the object whose reading caused the mistake.
 *
 * `exampleRequest` IS A NESTED OBJECT, NOT A JSON STRING, and the choice is the same law
 * again. A string of JSON arrives on the wire as `{\"jsonrpc\":\"2.0\",…}` — every quote
 * escaped — and every agent in every proof run met this door through `curl`, i.e. reading
 * the RAW response. An escaped document has to be UNESCAPED before it can be copied, which
 * is one more transformation performed in the model's head, which is the precise failure
 * mode base58-as-a-formula already cost two runs. A nested object IS the artifact: it
 * renders as the thing to send, and `JSON.stringify(way.exampleRequest)` is a body. Nesting
 * costs nothing here — the block already sits two levels deep under `securitySchemes`, and
 * `signedFields` is already a non-string value, so no consumer needs a new capability.
 *
 * A copier fills FIVE `<…>` blanks (messageId, text, from, timestamp, sig); `to` is already
 * this door's DID, `contextId` is already `null`, and `id`/`kind`/`role`/`parts` are already
 * correct. `contextId: null` is deliberate and doubles as the answer to "what do I send when
 * I have no conversation yet" — the same clause `canonicalization` now states in words.
 *
 * Must match `signed_envelope_requirement` in examples/agent_entry_reference.py field for
 * field, string for string: the card and the refusal are one object, and two twins that
 * teach a keyless visitor differently are two doors.
 */
export function signedEnvelopeRequirement(did, endpoint = '', howTo = FIRST_KNOCK_URL) {
  const requirement = {
    scheme: SIGNED_ENVELOPE_SCHEME,
    instruction: 'Generate an Ed25519 keypair NOW, locally, and knock again with it. You '
      + 'need no account, no registration and no permission from this site: any crypto '
      + 'library on the machine you are already running on will do (node:crypto '
      + 'generateKeyPairSync("ed25519"), Python cryptography or PyNaCl, Go crypto/ed25519, '
      + 'libsodium). Then work down the fields below in order - derive your did:key '
      + '(identity), build the canonical bytes over signedFields (canonicalization), sign '
      + 'them (signature), address the message to recipient with a fresh timestamp - and '
      + 'POST the same request again. Having no key yet is the normal starting state, not '
      + 'a refusal: minting one is step 1, and it is a few lines of code. The COMPLETE '
      + 'request body to POST is exampleRequest below: copy it and fill in its five <...> '
      + 'blanks. The A2A envelope AROUND your signature is checked too, so send that shape '
      + 'and do not improvise one. KEEP THE PRIVATE HALF: write it to a file only you '
      + 'can read (mode 600). It is the whole of your identity - this site will address '
      + 'you by the did:key you derive from it, losing it makes you a stranger here, and '
      + 'the same seed is what later upgrades you into a full muretai node with this SAME '
      + 'address rather than a second one.',
    in: 'params.message.metadata',
    // THE CARRIER, not just the signature. `in` tells you where the six envelope fields go
    // and says nothing about the message that carries them, and two proof-run agents read it
    // as the whole answer: they put the six in `metadata` and were refused on the A2A object
    // itself ("not an A2A message object", "messageId must be a non-empty string") while
    // holding a correct key and correct signed bytes. This is the body, whole, next to the
    // line that misled them. A NESTED OBJECT on purpose (see the note above): a JSON string
    // of JSON arrives escaped, and an agent reading a raw curl response would have to
    // unescape it in its head before it could copy it.
    exampleRequest: {
      jsonrpc: '2.0',
      id: 1,
      method: 'message/send',
      params: {
        message: {
          kind: 'message',
          role: 'user',
          messageId: '<a fresh unique string, e.g. a UUID>',
          // Already filled in, and it is the answer to "what if I have no conversation
          // yet": null. It is still one of the six signed fields; never omit it.
          contextId: null,
          parts: [{ kind: 'text', text: '<your message>' }],
          metadata: {
            from: '<your did:key>',
            to: did,
            timestamp: '<integer epoch seconds - a JSON number, not this string>',
            sig: '<base64 signature over the canonical six fields>',
          },
        },
      },
    },
    recipient: did,
    // WHERE to send it. Everything else in this object describes the MESSAGE — the six
    // signed fields, the canonical bytes, the whole example body — and none of it said
    // the address, so a first-time caller guessed. Measured 2026-08-19 (L1 dogfooding,
    // fresh-user run): the guess was `/rpc`, the most plausible path for a JSON-RPC
    // body, which on muretai.com is the RELAY transport. It reads `to`/`from`/`blob`/
    // `sig` off the TOP level, finds none of them in an A2A envelope, and answers
    // `{"error":"bad signature"}` — a routing mismatch reported as a crypto failure, at
    // the exact moment the caller has the least context to tell the two apart. They
    // went off to re-check canonicalization, base64 padding and clock skew; none of it
    // was wrong. One field costs nothing and removes the guess.
    endpoint,
    identity: 'Derive your DID from the public key you just generated and send it as '
      + 'metadata.from: did:key:z + base58btc(0xed01 || <32-byte Ed25519 public key>)',
    // RUN this, do not write the address by hand. Measured 2026-08-18: a real agent minted a
    // correct keypair, then "converted" the bytes in its head and produced the DOOR'S OWN DID
    // with two characters changed — three times — and signed correct bytes under an address
    // that was never its own. base58btc was the one step in this recipe stated as a formula
    // instead of made runnable, and it is exactly the step a language model fabricates.
    identityCode: 'Run this; do not encode base58btc by hand. node, no packages, `pub` = the '
      + '32 raw public-key bytes: '
      + "const A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; "
      + 'let n=0n; for (const b of Buffer.concat([Buffer.from([0xed,0x01]),pub])) '
      + 'n=n*256n+BigInt(b); '
      + "let s=''; while (n>0n) { s=A[Number(n%58n)]+s; n/=58n; } "
      + "const did='did:key:z'+s;   // 0xed leads, so no leading-zero '1' case can arise",
    signedFields: ['contextId', 'from', 'messageId', 'text', 'timestamp', 'to'],
    // The trailing clause is proof run 3's third fix: the verifier has always signed
    // `contextId ?? null`, and "exactly those six fields" never said what a visitor with no
    // conversation yet is supposed to put there. One run spent an entire refusal deducing
    // it. The previous value is still a PREFIX of this one, so a substring matcher on the
    // format text keeps matching.
    canonicalization: 'Build the bytes to sign as a JSON object of exactly those six '
      + 'fields, keys sorted by Unicode code point, separators "," and ":", no whitespace, '
      + 'non-ASCII literal, UTF-8. When you have no conversation yet, contextId is JSON '
      + 'null - it is still one of the six and is still signed, so never omit it (see '
      + 'exampleRequest, which already has it right)',
    signature: 'Sign those bytes with your private key and set metadata.sig = base64 '
      + '(standard alphabet, padded) of the 64-byte Ed25519 signature over those bytes',
    timestamp: 'Set metadata.timestamp = integer epoch seconds, within 300 s of this '
      + 'entry\'s clock',
  };
  // Emitted ONLY when it is known to resolve — an unresolvable pointer out-competes every
  // field beside it (see FIRST_KNOCK_URL). Appended last so the object's other bytes and
  // their positions do not move when a site turns the pointer off.
  if (howTo) requirement.howTo = howTo;
  return requirement;
}

/** The User-Agent FAMILY table — OBSERVATION AND SIGNPOSTING, NEVER IDENTITY. A UA string
 *  is written by the client, so nothing here may ever affect `verified`, a ledger row, a
 *  rate lane or any refusal verdict (that is the Web Bot Auth / signed-envelope layer's
 *  job). What it buys: an owner-facing count of who is knocking (`stats()`), and a `Link`
 *  signpost on the notice route for the families that are AI agents.
 *
 *  Ordered, FIRST MATCH WINS, and the order is load-bearing twice: real crawler UAs start
 *  with "Mozilla/5.0 …" so every bot needle must come before `mozilla`, and GPTBot's UA
 *  contains "openai.com/gptbot" so `gptbot` must come before `openai`. Needles are matched
 *  as substrings after an ASCII-ONLY lowercase fold (`asciiLower`, not `toLowerCase()` —
 *  Unicode case folding differs between runtimes and none of these needles needs it).
 *  FIXED table, deliberately not an option: an option would invite making UA matter, and
 *  the fixed table is what bounds the stats keyspace — an attacker-chosen UA string must
 *  never become a key. Must match `UA_FAMILIES` in examples/agent_entry_reference.py:
 *  one contract, two implementations, one verdict per string. */
export const UA_FAMILIES = [
  ['claude-user', 'claude-user'],
  ['claudebot', 'claudebot'],
  ['gptbot', 'gptbot'],
  ['chatgpt-user', 'openai'],
  ['openai', 'openai'],
  ['perplexity', 'perplexity'],
  ['google-extended', 'google-extended'],
  ['muretai-node', 'muretai-node'],
  ['curl', 'curl'],
  ['mozilla', 'browser'],
];

/** The families that read as an AI agent — the ones the notice route signposts with a
 *  `Link` header. `muretai-node` is deliberately absent: its Outbox already walks the
 *  well-known card paths, so a signpost buys it nothing. Must match the same set in
 *  examples/agent_entry_reference.py. */
export const AI_AGENT_FAMILIES = new Set([
  'claude-user', 'claudebot', 'gptbot', 'openai', 'perplexity', 'google-extended',
]);

/** ASCII-only lowercase fold. NOT `toLowerCase()`: Unicode casing is runtime- and
 *  locale-shaped (the Turkish-I class of surprise), and no needle in the table needs it —
 *  folding only A-Z is what makes the same UA string classify identically in both twins. */
function asciiLower(s) {
  let out = '';
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    out += (c >= 65 && c <= 90) ? String.fromCharCode(c + 32) : s[i];
  }
  return out;
}

/** UA string -> family. Absent/empty/non-string -> 'none'; no needle matched -> 'other'.
 *  Total on untrusted input, and the RETURN VALUE is always one of the twelve fixed
 *  family names — never a substring of the input (bounded stats keyspace). */
export function uaFamily(ua) {
  if (typeof ua !== 'string' || !ua) return 'none';
  const folded = asciiLower(ua);
  for (const [needle, family] of UA_FAMILIES) {
    if (folded.includes(needle)) return family;
  }
  return 'other';
}

/** The FIRST User-Agent value out of a headers mapping, or null. Case-insensitive key
 *  scan so an in-process host can pass any casing; Node's own `req.headers` already
 *  lowercases keys and keeps only the FIRST user-agent of a duplicated pair — the Python
 *  twin's `email.Message.get` does the same, which is the parity this relies on. A
 *  non-string value (an array, a number) reads as absent, never coerced. */
function uaOf(headers) {
  if (!headers || typeof headers !== 'object') return null;
  for (const key of Object.keys(headers)) {
    if (asciiLower(key) === 'user-agent') {
      const v = headers[key];
      return typeof v === 'string' ? v : null;
    }
  }
  return null;
}

const CARD_ENVELOPE_VERSION = 1;
const CARD_ENVELOPE_TYPE = 'agentcard';

/** JSON-RPC + Muretai L2 error objects, message strings included — a client greps these. */
export const ERRORS = {
  PARSE_ERROR: { code: -32700, message: 'Parse error' },
  INVALID_REQUEST: { code: -32600, message: 'Invalid Request' },
  METHOD_NOT_FOUND: { code: -32601, message: 'Method not found' },
  INVALID_PARAMS: { code: -32602, message: 'Invalid params' },
  INTERNAL_ERROR: { code: -32603, message: 'Internal error' },
  UNAUTHENTICATED: { code: -32001, message: 'Signature verification failed' },
  REPLAY_REJECTED: { code: -32002, message: 'Replay or stale message' },
  WRONG_RECIPIENT: { code: -32003, message: 'Message not addressed to me' },
  RATE_LIMITED: { code: -32004, message: 'Rate limited' },
  MESSAGE_TOO_LARGE: { code: -32005, message: 'Message text too large' },
};

// ================================================================ CANONICAL JSON
//
// Reproduces, byte for byte:
//   json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False,
//              allow_nan=False).encode("utf-8")
//
// The four traps, each pinned by a case in testdata/wire_vectors.json:
//   1. KEY ORDER is by UNICODE CODE POINT. JavaScript's default string sort compares
//      UTF-16 code UNITS, which disagrees for astral characters (U+1F600 sorts BEFORE
//      U+FFFD by unit, AFTER it by code point). `codePointCompare` below is deliberate.
//   2. NON-ASCII STAYS LITERAL (ensure_ascii=False). JSON.stringify already does this,
//      but most hand-rolled canonicalizers \u-escape and are then wrong for every
//      Japanese message on the network.
//   3. Python's ESCAPE SET is exactly: the seven shorthands (" \ \b \f \n \r \t), every
//      other control char < 0x20 as lowercase \u00xx — and NOTHING else. `/` and DEL
//      (0x7F) are NOT escaped. Many JSON writers escape both; that is a silent break.
//   4. NUMBERS. Only integers inside +/-(2**53-1) and ordinary fractional floats are
//      emitted; anything whose rendering differs between Python and JavaScript THROWS
//      rather than producing bytes only Python can verify (see numberHazards in the
//      vectors: 1.0, -0.0, 1e-07, 1e+16, 2**53+1 …).

const ESCAPES = new Map([
  ['"', '\\"'], ['\\', '\\\\'], ['\b', '\\b'], ['\f', '\\f'],
  ['\n', '\\n'], ['\r', '\\r'], ['\t', '\\t'],
]);
// eslint-disable-next-line no-control-regex
const NEEDS_ESCAPE = /[\u0000-\u001f"\\]/;

function encodeString(s) {
  if (!NEEDS_ESCAPE.test(s)) return `"${s}"`;
  let out = '"';
  for (const ch of s) {                       // iterates by CODE POINT, not code unit
    const shorthand = ESCAPES.get(ch);
    if (shorthand !== undefined) { out += shorthand; continue; }
    const cp = ch.codePointAt(0);
    if (cp < 0x20) out += `\\u${cp.toString(16).padStart(4, '0')}`;   // lowercase hex
    else out += ch;                            // '/' and DEL included: NOT escaped
  }
  return out + '"';
}

function encodeNumber(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) {
    // allow_nan=False. NaN/Infinity are not JSON (RFC 8259) and no two languages agree
    // on a spelling — refuse to sign them rather than emit a token nobody can check.
    throw new TypeError(`canonicalJSON: non-finite number (${n})`);
  }
  if (Number.isInteger(n)) {
    if (!Number.isSafeInteger(n)) {
      // Not a formatting mismatch — SILENT DATA CORRUPTION. Python has arbitrary
      // precision; a JS Number rounds. Signed integers stay inside +/-(2**53-1).
      throw new RangeError(`canonicalJSON: integer outside +/-(2**53-1) (${n})`);
    }
    return String(n);                          // -0 renders "0", same as Python's int 0
  }
  const rendered = String(n);
  if (rendered.includes('e') || rendered.includes('E')) {
    // Python zero-pads and always signs the exponent (1e-07); JS writes 1e-7. And the
    // thresholds at which each switches to exponent notation differ (Python 1e16, JS 1e21).
    throw new RangeError(`canonicalJSON: float needs exponent notation (${rendered}) — `
      + 'Python and JavaScript spell it differently; use an integer');
  }
  if (Math.abs(n) < 1e-4) {
    // Python's repr switches to exponent below 1e-4 while JS still writes decimals.
    throw new RangeError(`canonicalJSON: float too small to render identically (${rendered})`);
  }
  return rendered;
}

/** Compare two strings by UNICODE CODE POINT (Python's `str` order), not UTF-16 unit. */
function codePointCompare(a, b) {
  if (a === b) return 0;
  let i = 0, j = 0;
  while (i < a.length && j < b.length) {
    const ca = a.codePointAt(i), cb = b.codePointAt(j);
    if (ca !== cb) return ca < cb ? -1 : 1;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  if (i >= a.length && j < b.length) return -1;   // a is a prefix of b
  if (j >= b.length && i < a.length) return 1;
  return 0;
}

function encodeValue(v) {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'string': return encodeString(v);
    case 'number': return encodeNumber(v);
    case 'boolean': return v ? 'true' : 'false';
    case 'bigint':
      // A BigInt would render exactly, but it can also exceed 2**53-1 silently on the
      // way back in through JSON.parse. Refuse, like every other unrenderable number.
      throw new TypeError('canonicalJSON: BigInt is not representable on this wire');
    case 'object': break;
    default:
      throw new TypeError(`canonicalJSON: cannot encode ${typeof v}`);
  }
  if (Array.isArray(v)) return `[${v.map(encodeValue).join(',')}]`;
  const keys = Object.keys(v).sort(codePointCompare);
  const parts = [];
  for (const k of keys) {
    const val = v[k];
    if (val === undefined) {
      // Python has no `undefined`: a key whose value is undefined would silently vanish
      // from JSON.stringify and change the signed bytes. Say so instead.
      throw new TypeError(`canonicalJSON: key ${JSON.stringify(k)} is undefined`);
    }
    parts.push(`${encodeString(k)}:${encodeValue(val)}`);
  }
  return `{${parts.join(',')}}`;
}

/** Canonical JSON STRING (UTF-8 when encoded) for `value`. Throws on anything whose
 *  bytes would differ from Python's. */
export function canonicalJSON(value) {
  return encodeValue(value);
}

/** Canonical JSON as a UTF-8 Buffer — the bytes that actually get signed. */
export function canonicalBytes(value) {
  const s = canonicalJSON(value);
  assertEncodable(s);
  return Buffer.from(s, 'utf8');
}

/** Refuse lone surrogates. Python's `.encode("utf-8")` RAISES on them; Node silently
 *  substitutes U+FFFD, which would sign different bytes than the sender believes. */
function assertEncodable(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('lone surrogate in payload');
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new TypeError('lone surrogate in payload');
    }
  }
}

// ================================================================ Ed25519 (node:crypto)
//
// Node wants DER, not raw bytes. These two prefixes are the whole trick:
//   PKCS#8 private = 302e020100300506032b657004220420 || <32-byte seed>
//   SPKI    public = 302a300506032b6570032100        || <32-byte public key>
// (0x2b6570 is OID 1.3.101.112 = Ed25519; 0x2b656e is 1.3.101.110 = X25519.)

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function seedBuffer(seedHex) {
  if (typeof seedHex !== 'string') throw new TypeError('seed must be a 64-char hex string');
  const seed = Buffer.from(seedHex.trim(), 'hex');
  if (seed.length !== 32) throw new TypeError('seed must be 32 bytes (64 hex chars)');
  return seed;
}

function ed25519PrivateKey(seedHex) {
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seedBuffer(seedHex)]),
    format: 'der', type: 'pkcs8',
  });
}

function ed25519PublicKey(publicRaw) {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicRaw]),
    format: 'der', type: 'spki',
  });
}

/** Raw 32-byte Ed25519 public key for a seed. */
export function publicKeyFromSeedHex(seedHex) {
  const pub = createPublicKey(ed25519PrivateKey(seedHex));
  return pub.export({ format: 'der', type: 'spki' }).subarray(ED25519_SPKI_PREFIX.length);
}

/** Raw Ed25519 signature over `message` (Buffer|string), as a Buffer. */
export function signBytes(seedHex, message) {
  const m = Buffer.isBuffer(message) ? message : Buffer.from(String(message), 'utf8');
  return nodeSign(null, m, ed25519PrivateKey(seedHex));
}

/** Verify a raw Ed25519 signature. Never throws — bad key/sig bytes answer false. */
export function verifyBytes(publicRaw, signature, message) {
  try {
    if (!Buffer.isBuffer(publicRaw) || publicRaw.length !== 32) return false;
    if (!Buffer.isBuffer(signature) || signature.length !== 64) return false;
    const m = Buffer.isBuffer(message) ? message : Buffer.from(String(message), 'utf8');
    return nodeVerify(null, m, ed25519PublicKey(publicRaw), signature);
  } catch {
    return false;
  }
}

/** A fresh 32-byte identity seed as hex. THIS IS THE PRIVATE KEY — never log or ship it. */
export function newSeedHex() {
  return randomBytes(32).toString('hex');
}

/** A fresh message/correlation id (same shape as Python's uuid4().hex). */
export function newId() {
  return randomBytes(16).toString('hex');
}

// ================================================================ base58btc + did:key

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_INDEX = new Map([...B58].map((c, i) => [c, BigInt(i)]));
/** Every legitimate base58 here (a DID is ~48 chars) is far under this. The cap guards the
 *  O(n^2) bignum loop from an attacker-chosen `from` field — the decoder runs BEFORE any
 *  signature check, so an unbounded input is free CPU exhaustion (shared/crypto:184). */
const MAX_B58_LEN = 512;
const MULTICODEC_ED25519 = Buffer.from([0xed, 0x01]);

function b58encode(data) {
  let n = 0n;
  for (const b of data) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    const r = n % 58n;
    n /= 58n;
    out = B58[Number(r)] + out;
  }
  let pad = 0;
  for (const b of data) { if (b === 0) pad++; else break; }
  return '1'.repeat(pad) + out;
}

function b58decode(s) {
  if (typeof s !== 'string') throw new TypeError('base58: not a string');
  if (s.length > MAX_B58_LEN) throw new RangeError('base58 input too long');
  let n = 0n;
  for (const ch of s) {
    const v = B58_INDEX.get(ch);
    if (v === undefined) throw new TypeError(`base58: bad character ${JSON.stringify(ch)}`);
    n = n * 58n + v;
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const raw = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  let pad = 0;
  for (const ch of s) { if (ch === '1') pad++; else break; }
  return Buffer.concat([Buffer.alloc(pad), raw]);
}

/** 32-byte Ed25519 public key (hex or Buffer) -> `did:key:z…`. */
export function didFromPublicKeyHex(publicHex) {
  const pub = Buffer.isBuffer(publicHex) ? publicHex : Buffer.from(publicHex, 'hex');
  if (pub.length !== 32) throw new TypeError('an ed25519 public key is 32 bytes');
  return 'did:key:z' + b58encode(Buffer.concat([MULTICODEC_ED25519, pub]));
}

/** `did:key:z…` -> 32-byte Ed25519 public key, hex. Enforces the 0xed01 multicodec and the
 *  34-byte total: with did:key the DID IS the key, so this is the whole "key lookup". */
export function publicKeyHexFromDid(did) {
  return publicKeyFromDid(did).toString('hex');
}

function publicKeyFromDid(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new TypeError(`unsupported DID method: ${String(did).slice(0, 32)}`);
  }
  const raw = b58decode(did.slice('did:key:z'.length));
  if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) {
    throw new TypeError('not an ed25519 did:key');
  }
  return raw.subarray(2);
}

/** The did:key a seed controls. */
export function didFromSeedHex(seedHex) {
  return didFromPublicKeyHex(publicKeyFromSeedHex(seedHex));
}

// ================================================================ the signing envelope

/** The SIX frozen signed fields, canonicalized (shared/crypto.signing_payload). Nothing
 *  else is signed: `replyTo`, `auto`, `group`, `vc` … all ride as UNSIGNED metadata.
 *  `timestamp` is passed through AS GIVEN — never coerced, because the type on the wire
 *  IS the type in the signed bytes (send ints; verify whatever arrived). */
export function signingPayload(fields) {
  return canonicalJSON({
    contextId: fields.contextId ?? null,
    from: fields.from,
    messageId: fields.messageId,
    text: fields.text,
    timestamp: fields.timestamp,
    to: fields.to,
  });
}

/** base64 (standard alphabet, WITH padding) of the Ed25519 signature over the six fields. */
export function signEnvelope(seedHex, fields) {
  if (!seedHex) throw new TypeError('signEnvelope: no seed (this agent entry cannot sign)');
  const payload = signingPayload(fields);
  assertEncodable(payload);
  return signBytes(seedHex, Buffer.from(payload, 'utf8')).toString('base64');
}

/** Question 1 ONLY: does `sig` verify under the key DERIVED FROM `from`, over the six
 *  fields? Total and fail-closed — a malformed DID, bad base64, unrenderable number or
 *  short signature all answer false rather than throwing. */
export function verifyEnvelopeSignature(fields) {
  try {
    if (!fields || typeof fields !== 'object') return false;
    // `from` (the key) and `sig` must be there; `to` may be the EMPTY STRING — that is how
    // an anonymous-lane reply is addressed ("signed by me, to nobody in particular"), and
    // refusing it here would make core's own walk-in answer read as unsigned.
    if (!fields.from || !fields.sig || typeof fields.to !== 'string') return false;
    const payload = signingPayload(fields);
    assertEncodable(payload);
    const sig = Buffer.from(String(fields.sig), 'base64');
    if (sig.length !== 64) return false;
    return verifyBytes(publicKeyFromDid(fields.from), sig, Buffer.from(payload, 'utf8'));
  } catch {
    return false;
  }
}

/**
 * Is this envelope an authentic statement ADDRESSED TO ME? Two questions, not one:
 *
 *   1. does `sig` verify under the key derived FROM `from`? With did:key the DID IS the
 *      key, so `from` is never taken as a label — that mistake is how a client ends up
 *      accepting a valid signature by a DIFFERENT identity than the one it displays
 *      (wire_vectors `reject.message/from-not-signer`, the crown-jewel case);
 *   2. is `to` the recipient I am? A signature that verifies FOR SOMEONE ELSE is still a
 *      perfectly valid signature — it is just not my mail. `wire_vectors
 *      reject.message/wrong-recipient` is exactly that: `mustReject: true` even though
 *      the signature checks out, because in core the "to == me" half lives one layer up
 *      (agent/inbox.verify -> WRONG_RECIPIENT).
 *
 * A module-level function has no "me", so the recipient must be NAMED by the caller —
 * `verifyEnvelope(fields, { recipientDid })`, or `recipientDid` on the fields object.
 * An unnamed recipient is UNKNOWN, and unknown fails closed: an envelope nobody claims
 * cannot be verified as theirs. When you deliberately want question 1 alone (auditing a
 * stored message, say), call `verifyEnvelopeSignature`.
 *
 * Never throws.
 */
export function verifyEnvelope(fields, opts = {}) {
  try {
    if (!fields || typeof fields !== 'object') return false;
    const recipient = opts.recipientDid ?? opts.me ?? fields.recipientDid ?? null;
    if (typeof recipient !== 'string' || !recipient) return false;
    if (fields.to !== recipient) return false;
    return verifyEnvelopeSignature(fields);
  } catch {
    return false;
  }
}

// ================================================================ Web Bot Auth (RFC 9421 subset, verify-only) — T107
//
// The INBOUND half only: did the holder of one of the keys this entry was GIVEN sign
// THIS request, for THIS authority, as a `web-bot-auth` request? It mirrors EXACTLY the
// subset shared/webbotauth.py::verify_request implements — no more (content digests,
// @query-param, per-item parameters and every other RFC 9421 feature are refused, not
// ignored) and no less. The two are pinned to one fixture, testdata/wba_vectors.json:
// a vector one twin accepts and the other refuses is a red suite. Verification is
// BYTE-FAITHFUL, not canonical: the signature base is rebuilt from the RECEIVED
// `@signature-params` text, so a peer who orders or spaces parameters differently still
// verifies (signing is canonical, verifying is byte-faithful — the shared/jws.py split).
//
// One rule governs every caller in this file: WBA never changes a verdict — it only
// ever ADDS identity (`wba_did` on the backend envelope, a `wbaVisits` count). Absent,
// invalid, expired, unknown-key and tampered all behave exactly like "no WBA".

const WBA_TAG_REQUEST = 'web-bot-auth';
/** RFC 9421's HTTP-signature-registry name — NOT JOSE's "EdDSA". Same curve, two
 *  registries; mixing the spellings is a silent interop failure. */
const WBA_ALG = 'ed25519';
/** Tolerance for the peer's clock being ahead, applied to `created` only. */
const WBA_CLOCK_SKEW = 300;
/** The loosest accepted `expires - created`: these headers are a bearer credential
 *  while they live (webbotauth.REQUEST_SIG_WINDOW + CLOCK_SKEW). */
const WBA_MAX_REQUEST_LIFETIME = 600;
/** Refuse to even tokenize an absurd header — bounds parser work on hostile input. */
const WBA_MAX_HEADER_CHARS = 8192;
/** Standard base64, padded — what Python's base64.b64decode(validate=True) accepts.
 *  Node's Buffer.from(s, 'base64') silently IGNORES invalid characters and tolerates
 *  any padding, which is the classic twin-divergence; pre-validating is what keeps one
 *  Signature value from being two different byte strings. */
const WBA_B64_STANDARD = /^[A-Za-z0-9+/]*={0,2}$/;
/** Unpadded base64url — what shared/jws.unb64url accepts for a JWK `x` ("+", "/" and
 *  "=" refused; a length ≡ 1 (mod 4) has no byte decoding). */
const WBA_B64URL = /^[A-Za-z0-9_-]*$/;

/** Serialize an RFC 8941 sf-string: quoted, `\` and `"` escaped — the only two escapes
 *  the RFC defines. */
function wbaSfString(s) {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

/** Python str.strip()'s default whitespace set, exactly — NOT String.prototype.trim().
 *  The two runtimes disagree at the edges (Python also strips \x1c-\x1f and \x85; JS
 *  also strips U+FEFF), and a covered header value the twins trim differently is a
 *  signature base only one of them can rebuild. */
const WBA_PY_WS_CLASS = '[\\t\\n\\v\\f\\r \\x1c-\\x1f\\x85\\xa0\\u1680'
  + '\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]+';
const WBA_PY_WS = new RegExp(`^${WBA_PY_WS_CLASS}|${WBA_PY_WS_CLASS}$`, 'g');
function wbaPyStrip(s) {
  return s.replace(WBA_PY_WS, '');
}

function wbaIsKeyFirst(ch) { return (ch >= 'a' && ch <= 'z') || ch === '*'; }
function wbaIsKeyRest(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
    || ch === '_' || ch === '-' || ch === '.' || ch === '*';
}

/** An RFC 8941 key (a dictionary label or a parameter name) -> [key, next] or null. */
function wbaParseKey(s, i) {
  if (i >= s.length || !wbaIsKeyFirst(s[i])) return null;
  let j = i + 1;
  while (j < s.length && wbaIsKeyRest(s[j])) j += 1;
  return [s.slice(i, j), j];
}

/** A quoted sf-string. Only `\"` and `\\` are escapes; every other character must be
 *  printable ASCII — rejecting the rest is what keeps one byte string from having two
 *  spellings. */
function wbaParseSfString(s, i) {
  if (i >= s.length || s[i] !== '"') return null;
  i += 1;
  let out = '';
  while (i < s.length) {
    const ch = s[i];
    if (ch === '\\') {
      i += 1;
      if (i >= s.length || (s[i] !== '"' && s[i] !== '\\')) return null;
      out += s[i];
      i += 1;
    } else if (ch === '"') {
      return [out, i + 1];
    } else if (ch >= ' ' && ch <= '~') {
      out += ch;
      i += 1;
    } else {
      return null;
    }
  }
  return null;
}

/** An sf-integer: optional `-`, at most 15 ASCII digits (safely inside 2^53). */
function wbaParseInteger(s, i) {
  let j = i;
  if (j < s.length && s[j] === '-') j += 1;
  let k = j;
  while (k < s.length && s[k] >= '0' && s[k] <= '9') k += 1;
  if (k === j || (k - j) > 15) return null;
  return [parseInt(s.slice(i, k), 10), k];
}

/** The only parameter value types in this profile: sf-string and sf-integer. */
function wbaParseBareItem(s, i) {
  if (i < s.length && s[i] === '"') return wbaParseSfString(s, i);
  return wbaParseInteger(s, i);
}

/** `*( ";" *SP key [ "=" bare-item ] )`. A repeated name is REFUSED rather than
 *  last-wins; a valueless parameter is boolean true. */
function wbaParseParams(s, i) {
  const params = new Map();
  while (i < s.length && s[i] === ';') {
    i += 1;
    while (i < s.length && s[i] === ' ') i += 1;
    const gotKey = wbaParseKey(s, i);
    if (gotKey === null) return null;
    const name = gotKey[0];
    i = gotKey[1];
    if (params.has(name)) return null;
    if (i < s.length && s[i] === '=') {
      const val = wbaParseBareItem(s, i + 1);
      if (val === null) return null;
      params.set(name, val[0]);
      i = val[1];
    } else {
      params.set(name, true);
    }
  }
  return [params, i];
}

/** The covered components: `"(" *SP [ sf-string *( 1*SP sf-string ) *SP ] ")"`.
 *  Per-item parameters are refused — they change what a component MEANS, and a profile
 *  that does not implement them must not silently ignore them. */
function wbaParseInnerList(s, i) {
  if (i >= s.length || s[i] !== '(') return null;
  i += 1;
  const items = [];
  for (;;) {
    while (i < s.length && s[i] === ' ') i += 1;
    if (i >= s.length) return null;
    if (s[i] === ')') return [items, i + 1];
    const got = wbaParseSfString(s, i);
    if (got === null) return null;
    i = got[1];
    if (i < s.length && s[i] !== ' ' && s[i] !== ')') return null;  // incl. ';' per-item
    items.push(got[0]);
  }
}

function wbaSkipOws(s, i) {
  while (i < s.length && (s[i] === ' ' || s[i] === '\t')) i += 1;
  return i;
}

/** Parse a `Signature-Input` value into entries, PRESERVING the raw text of each
 *  entry's value — RFC 9421 signs that text, so rebuilding it from the parsed
 *  structure would only work for peers who serialize exactly as we do. */
function wbaParseSignatureInput(value) {
  const s = value;
  const n = s.length;
  let i = wbaSkipOws(s, 0);
  if (i >= n) return null;
  const entries = [];
  for (;;) {
    const gotKey = wbaParseKey(s, i);
    if (gotKey === null) return null;
    const label = gotKey[0];
    i = gotKey[1];
    if (i >= n || s[i] !== '=') return null;
    i += 1;
    const start = i;
    const gotList = wbaParseInnerList(s, i);
    if (gotList === null) return null;
    const components = gotList[0];
    i = gotList[1];
    const gotParams = wbaParseParams(s, i);
    if (gotParams === null) return null;
    const params = gotParams[0];
    i = gotParams[1];
    entries.push({ label, components, params, signatureParams: s.slice(start, i) });
    i = wbaSkipOws(s, i);
    if (i >= n) return entries;
    if (s[i] !== ',') return null;
    i = wbaSkipOws(s, i + 1);
    if (i >= n) return null;                 // trailing comma
  }
}

/** Parse a `Signature` value: `label=:<standard base64>:` entries. */
function wbaParseSignature(value) {
  const s = value;
  const n = s.length;
  let i = wbaSkipOws(s, 0);
  if (i >= n) return null;
  const out = [];
  for (;;) {
    const got = wbaParseKey(s, i);
    if (got === null) return null;
    const label = got[0];
    i = got[1];
    if (i + 1 >= n || s[i] !== '=' || s[i + 1] !== ':') return null;
    i += 2;
    const end = s.indexOf(':', i);
    if (end < 0) return null;
    const b64 = s.slice(i, end);
    if (!WBA_B64_STANDARD.test(b64) || b64.length % 4 !== 0) return null;
    const raw = Buffer.from(b64, 'base64');
    i = end + 1;
    if (i < n && s[i] === ';') return null;   // parameters on a signature member
    out.push([label, raw]);
    i = wbaSkipOws(s, i);
    if (i >= n) return out;
    if (s[i] !== ',') return null;
    i = wbaSkipOws(s, i + 1);
    if (i >= n) return null;
  }
}

/** The `(Signature-Input, Signature)` pair as verifiable entries, or null. Duplicate
 *  labels, a label present in one header but not the other, and every unexpected byte
 *  return null — each is a case where two implementations could disagree about what
 *  was signed. Never throws. */
function wbaParseSignatureHeaders(sigInput, sig) {
  try {
    if (typeof sigInput !== 'string' || typeof sig !== 'string') return null;
    if (sigInput.length > WBA_MAX_HEADER_CHARS || sig.length > WBA_MAX_HEADER_CHARS) {
      return null;
    }
    const entries = wbaParseSignatureInput(sigInput);
    const sigs = wbaParseSignature(sig);
    if (entries === null || sigs === null) return null;
    const labels = entries.map((e) => e.label);
    if (new Set(labels).size !== labels.length) return null;
    const byLabel = new Map();
    for (const [label, raw] of sigs) {
      if (byLabel.has(label)) return null;
      byLabel.set(label, raw);
    }
    if (byLabel.size !== labels.length) return null;
    for (const label of labels) { if (!byLabel.has(label)) return null; }
    for (const e of entries) e.sig = byLabel.get(e.label);
    return entries;
  } catch {
    return null;
  }
}

/** Case-insensitive header lookup over a plain mapping. A non-string value (an array,
 *  a number) reads as absent, never coerced. */
function wbaHeaderGet(headers, name) {
  if (!headers || typeof headers !== 'object') return null;
  for (const key of Object.keys(headers)) {
    if (asciiLower(key) === name) {
      const v = headers[key];
      return typeof v === 'string' ? v : null;
    }
  }
  return null;
}

/** The 32 raw key bytes of an Ed25519 OKP JWK, or null — the strict gate every
 *  untrusted key passes through (mirrors shared/webbotauth.public_from_jwk). */
function wbaPublicFromJwk(jwk) {
  try {
    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) return null;
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return null;
    const x = jwk.x;
    if (typeof x !== 'string') return null;
    if (!WBA_B64URL.test(x) || x.length % 4 === 1) return null;
    const raw = Buffer.from(x, 'base64url');
    return raw.length === 32 ? raw : null;
  } catch {
    return null;
  }
}

/** RFC 7638 thumbprint of an Ed25519 public key — the `keyid` on the wire. Built from
 *  the CANONICAL re-encoding of the key bytes, so a differently-spelled (but valid) `x`
 *  still names the same key. The literal member order crv,kty,x IS Python's
 *  sort_keys+compact form (x is base64url, so no JSON escaping can differ). */
function wbaThumbprint(publicRaw) {
  const payload = `{"crv":"Ed25519","kty":"OKP","x":"${publicRaw.toString('base64url')}"}`;
  return createHash('sha256').update(payload, 'utf8').digest('base64url');
}

/** Resolve each covered component to the value to re-sign over, or null. `@authority`
 *  comes from the VERIFIER (our canonical baseUrl) — never from the message; every
 *  other derived component is refused; header values are stripped with Python's set. */
function wbaComponentValues(components, authority, headers) {
  const out = [];
  const seen = new Set();
  for (const name of components) {
    if (typeof name !== 'string' || name !== asciiLower(name) || seen.has(name)) {
      return null;
    }
    seen.add(name);
    if (name === '@authority') {
      out.push([name, authority]);
    } else if (name.startsWith('@')) {
      return null;
    } else {
      const value = wbaHeaderGet(headers, name);
      if (value === null) return null;
      out.push([name, wbaPyStrip(value)]);
    }
  }
  return out;
}

/** The exact bytes covered by the signature (RFC 9421 §2.5): one `"name": value` line
 *  per component, then `"@signature-params": <received text>`, LF-joined, no trailing
 *  newline. */
function wbaSignatureBase(pairs, paramsText) {
  const lines = pairs.map(([name, value]) => `${wbaSfString(asciiLower(name))}: ${value}`);
  lines.push(`${wbaSfString('@signature-params')}: ${paramsText}`);
  return Buffer.from(lines.join('\n'), 'utf8');
}

/** One parsed entry, checked end to end against one key. Order matters only for cost:
 *  the cheap policy checks run before the Ed25519 verification. */
function wbaEntryVerifies(entry, { keyid, publicRaw, authority, headers, now }) {
  const params = entry.params;
  if (params.get('keyid') !== keyid || params.get('tag') !== WBA_TAG_REQUEST) return false;
  const alg = params.get('alg');
  if (alg !== undefined && alg !== WBA_ALG) return false;
  const created = params.get('created');
  const expires = params.get('expires');
  if (!Number.isInteger(created) || !Number.isInteger(expires)) return false;
  if (created > now + WBA_CLOCK_SKEW || now >= expires) return false;
  if (expires <= created || (expires - created) > WBA_MAX_REQUEST_LIFETIME) return false;
  const components = entry.components || [];
  // Without @authority the signature says nothing about WHERE it was served.
  if (!components.includes('@authority')) return false;
  const pairs = wbaComponentValues(components, authority, headers);
  if (pairs === null) return false;
  return verifyBytes(publicRaw, entry.sig, wbaSignatureBase(pairs, entry.signatureParams));
}

/** The DID that signed this inbound request, or null. Never throws. `jwks` is a
 *  directory document ({keys:[…]}) already established as trustworthy — who the keys
 *  belong to was decided before this was called (DECISION 2: keys are GIVEN, never
 *  fetched on the hot path). Mirrors shared/webbotauth.verify_request exactly;
 *  testdata/wba_vectors.json holds the two to one verdict per input. */
export function wbaVerifyRequest(headers, { authority, jwks, now } = {}) {
  try {
    const entries = wbaParseSignatureHeaders(
      wbaHeaderGet(headers, 'signature-input') || '',
      wbaHeaderGet(headers, 'signature') || '');
    if (!entries || !entries.length) return null;
    const keys = (jwks && typeof jwks === 'object' && !Array.isArray(jwks))
      ? jwks.keys : null;
    if (!Array.isArray(keys)) return null;
    const auth = wbaPyStrip(String(authority || '')).toLowerCase();
    if (!auth) return null;
    const moment = Math.floor(
      (now === undefined || now === null) ? Date.now() / 1000 : now);
    for (const jwk of keys) {
      const publicRaw = wbaPublicFromJwk(jwk);
      if (publicRaw === null) continue;
      const keyid = wbaThumbprint(publicRaw);
      for (const entry of entries) {
        if (wbaEntryVerifies(entry, { keyid, publicRaw, authority: auth,
                                      headers, now: moment })) {
          return didFromPublicKeyHex(publicRaw);
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

// ================================================================ device-key binding v2 (T102)
//
// The ACCOUNT layer: a message may carry a countersigned DeviceKeyBinding v2 in
// metadata.binding proving its device DID belongs to an OWNER DID. This is the JS twin of
// shared/keybinding.verify_device_binding_v2 + the agent entry's account resolution, byte-pinned
// by testdata/wire_vectors.json `bindingV2`.
//
// Two signatures, over the SAME canonical bytes: the OWNER (root) signs, and the DEVICE
// countersigns — the countersignature is what stops a foreign owner claiming someone else's
// device. `typ` lives INSIDE the signed bytes (domain separation), and ts/validUntil are
// INTEGERS (a float's repr is not reproducible cross-language). Unlike the Python reference
// there is no "P-256 owner without a backend → unbound" branch: node:crypto verifies P-256
// natively, so a P-256 owner binding is fully checked here — the documented, expected
// asymmetry (the stdlib Python path treats the very same binding as unbound).

/** `typ` of the countersigned account binding (shared/keybinding.BINDING_V2_TYP). */
export const BINDING_V2_TYP = 'muretai/devicebinding/2';

// SPKI DER prefix for a P-256 public key carrying a COMPRESSED SEC1 point (33 bytes). OpenSSL
// (node:crypto) accepts compressed points, so the did:key point embeds directly — no
// decompression. 0x2a8648ce3d0201 = id-ecPublicKey, 0x2a8648ce3d030107 = prime256v1.
const P256_SPKI_PREFIX = Buffer.from(
  '3039301306072a8648ce3d020106082a8648ce3d030107032200', 'hex');

/** did:key → { curve, key }: ('ed25519', 32-byte pubkey) or ('p256', 33-byte compressed
 *  point). Curve-agnostic sibling of `publicKeyFromDid` (which is ed25519-only, for the
 *  message envelope that is always ed25519). Throws on anything else. */
function decodeDidKey(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new TypeError(`unsupported DID method: ${String(did).slice(0, 32)}`);
  }
  const raw = b58decode(did.slice('did:key:z'.length));
  if (raw.length === 34 && raw[0] === 0xed && raw[1] === 0x01) {
    return { curve: 'ed25519', key: raw.subarray(2) };       // 0xed01 multicodec
  }
  if (raw.length === 35 && raw[0] === 0x80 && raw[1] === 0x24) {
    return { curve: 'p256', key: raw.subarray(2) };          // varint(0x1200) = p256-pub
  }
  throw new TypeError('unsupported did:key multicodec (not ed25519 or p256)');
}

/** Verify an ES256 signature over `message` for a 33-byte compressed P-256 point. Accepts
 *  both encodings clients emit (shared/crypto.p256_verify): raw r||s (64 bytes, WebCrypto /
 *  IEEE P1363) and ASN.1 DER (Secure Enclave / WebAuthn). Never throws. */
function p256Verify(compPoint, signature, message) {
  try {
    if (!Buffer.isBuffer(compPoint) || compPoint.length !== 33) return false;
    const key = createPublicKey({
      key: Buffer.concat([P256_SPKI_PREFIX, compPoint]), format: 'der', type: 'spki' });
    if (signature.length === 64) {
      return nodeVerify('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, signature);
    }
    return nodeVerify('sha256', message, key, signature);    // DER (Secure Enclave)
  } catch {
    return false;
  }
}

/** Curve-dispatching signature verify against a did:key — the binding's owner may be
 *  ed25519 OR p256; the device is always ed25519. Total and fail-closed. */
function verifyDidSig(did, signature, message) {
  try {
    const { curve, key } = decodeDidKey(did);
    if (curve === 'ed25519') return verifyBytes(key, signature, message);
    if (curve === 'p256') return p256Verify(key, signature, message);
    return false;
  } catch {
    return false;
  }
}

/** Canonical bytes BOTH keys sign — exactly the five declared fields
 *  (shared/keybinding._binding_v2_payload). `canonicalBytes` sorts keys by code point, so
 *  the object order here is irrelevant; the emitted bytes are
 *  {"deviceDid":…,"rootDid":…,"ts":…,"typ":…,"validUntil":…}. */
function bindingV2Payload(rootDid, deviceDid, ts, validUntil) {
  return canonicalBytes({ typ: BINDING_V2_TYP, rootDid, deviceDid, ts, validUntil });
}

/**
 * Verify a v2 binding — the twin of shared/keybinding.verify_device_binding_v2. TOTAL on
 * untrusted input (returns false, never throws). All must hold: typ matches; rootDid and
 * deviceDid are non-empty strings; ts/validUntil are safe integers; `expectedDeviceDid`
 * (when given) matches deviceDid (anti-copy pin); `now` given + validUntil non-zero → not
 * expired; the OWNER signed the canonical five fields; the DEVICE countersigned the same.
 */
export function verifyDeviceBindingV2(binding, { now = null, expectedDeviceDid = null } = {}) {
  try {
    if (!binding || typeof binding !== 'object') return false;
    if (binding.typ !== BINDING_V2_TYP) return false;
    const { rootDid, deviceDid, ts, validUntil } = binding;
    if (typeof rootDid !== 'string' || !rootDid) return false;
    if (typeof deviceDid !== 'string' || !deviceDid) return false;
    if (!Number.isSafeInteger(ts) || !Number.isSafeInteger(validUntil)) return false;
    if (expectedDeviceDid !== null && deviceDid !== expectedDeviceDid) return false;
    if (now !== null && validUntil !== 0 && now > validUntil) return false;
    const sig = Buffer.from(String(binding.sig ?? ''), 'base64');
    const deviceSig = Buffer.from(String(binding.deviceSig ?? ''), 'base64');
    const payload = bindingV2Payload(rootDid, deviceDid, ts, validUntil);
    return verifyDidSig(rootDid, sig, payload) && verifyDidSig(deviceDid, deviceSig, payload);
  } catch {
    return false;
  }
}

// ================================================================ signed Agent Card envelope

/** The canonical bytes a card envelope signs: {card, ts, typ, v} (shared/cardpub).
 *  `ts` MUST be an INTEGER epoch — a float `ts` renders through Python's repr and is,
 *  by construction, unverifiable outside Python. */
export function cardEnvelopePayload(card, ts) {
  return canonicalJSON({ card, ts, typ: CARD_ENVELOPE_TYPE, v: CARD_ENVELOPE_VERSION });
}

/** Wrap `card` in the signed envelope served at /.well-known/agent-card.sig.json. */
export function makeCardEnvelope(seedHex, card, ts) {
  if (!Number.isSafeInteger(ts)) {
    throw new TypeError('card envelope ts must be an INTEGER epoch (a float is Python-only)');
  }
  const payload = cardEnvelopePayload(card, ts);
  assertEncodable(payload);
  return {
    v: CARD_ENVELOPE_VERSION,
    typ: CARD_ENVELOPE_TYPE,
    card,
    ts,
    sig: signBytes(seedHex, Buffer.from(payload, 'utf8')).toString('base64'),
  };
}

/** Verify a card envelope; returns the inner card or null. `expectedDid` is the
 *  anti-substitution check — a signature only proves "X signed X's card". */
export function verifyCardEnvelope(envelope, expectedDid = null) {
  try {
    if (!envelope || typeof envelope !== 'object') return null;
    if (envelope.typ !== CARD_ENVELOPE_TYPE) return null;
    const { card, ts, sig } = envelope;
    if (!card || typeof card !== 'object' || !card.did || sig == null || ts == null) return null;
    if (expectedDid !== null && card.did !== expectedDid) return null;
    const raw = Buffer.from(String(sig), 'base64');
    if (raw.length !== 64) return null;
    const payload = cardEnvelopePayload(card, ts);
    assertEncodable(payload);
    return verifyBytes(publicKeyFromDid(card.did), raw, Buffer.from(payload, 'utf8'))
      ? card : null;
  } catch {
    return null;
  }
}

// ================================================================ cryptobox (X25519 + ChaCha20)
//
// STATIC-STATIC sealed box (shared/cryptobox.py). The X25519 key is a pure function of the
// SAME Ed25519 seed the agent already holds, so there is no second key to provision:
//   x25519_private = sha256("agentnet-x25519:" || ed25519_seed)
//   shared         = X25519(my_private, their_public)                    (raw ECDH)
//   key            = HKDF-SHA256(shared, salt=32 zero bytes, info="agentnet-box-v1", 32)
//   blob           = base64(nonce[12] || ciphertext || tag[16])
// salt=None in Python's HKDF means "HashLen zero bytes", hence Buffer.alloc(32).

const BOX_INFO = Buffer.from('agentnet-box-v1', 'utf8');
const BOX_SALT = Buffer.alloc(32);
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function x25519PrivateRaw(seedHex) {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from('agentnet-x25519:', 'utf8'), seedBuffer(seedHex)]))
    .digest();
}

function x25519PrivateKey(seedHex) {
  return createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, x25519PrivateRaw(seedHex)]),
    format: 'der', type: 'pkcs8',
  });
}

/** The X25519 public key (hex) a peer needs to seal a box to this seed. Safe to publish. */
export function encPubHex(seedHex) {
  const pub = createPublicKey(x25519PrivateKey(seedHex));
  return pub.export({ format: 'der', type: 'spki' })
    .subarray(X25519_SPKI_PREFIX.length).toString('hex');
}

function boxKey(seedHex, theirPubHex) {
  const theirPub = Buffer.from(String(theirPubHex), 'hex');
  if (theirPub.length !== 32) throw new TypeError('peer X25519 public key must be 32 bytes');
  const shared = diffieHellman({
    privateKey: x25519PrivateKey(seedHex),
    publicKey: createPublicKey({
      key: Buffer.concat([X25519_SPKI_PREFIX, theirPub]), format: 'der', type: 'spki',
    }),
  });
  return Buffer.from(hkdfSync('sha256', shared, BOX_SALT, BOX_INFO, 32));
}

/** Encrypt to the holder of `theirPubHex`. Returns base64(nonce || ciphertext || tag).
 *  A fresh random nonce per call, so the output is never reproducible — which is why the
 *  wire vectors pin only the OPEN direction. */
export function seal(seedHex, theirPubHex, plaintext, ad = Buffer.alloc(0)) {
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
  const aad = Buffer.isBuffer(ad) ? ad : Buffer.from(String(ad), 'utf8');
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('chacha20-poly1305', boxKey(seedHex, theirPubHex), nonce,
    { authTagLength: TAG_BYTES });
  if (aad.length) cipher.setAAD(aad, { plaintextLength: pt.length });
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  return Buffer.concat([nonce, ct, cipher.getAuthTag()]).toString('base64');
}

/** Decrypt a box sealed by the matching peer. Returns a Buffer, or **null on ANY failure**
 *  (bad base64, truncated blob, wrong key, AD mismatch, auth-tag failure) — the caller's
 *  verification path stays branch-simple, exactly like shared/cryptobox.open_box. */
export function openBox(seedHex, theirPubHex, blobB64, ad = Buffer.alloc(0)) {
  try {
    const raw = Buffer.from(String(blobB64), 'base64');
    if (raw.length < NONCE_BYTES + TAG_BYTES) return null;
    const nonce = raw.subarray(0, NONCE_BYTES);
    const ct = raw.subarray(NONCE_BYTES, raw.length - TAG_BYTES);
    const tag = raw.subarray(raw.length - TAG_BYTES);
    const aad = Buffer.isBuffer(ad) ? ad : Buffer.from(String(ad), 'utf8');
    const decipher = createDecipheriv('chacha20-poly1305', boxKey(seedHex, theirPubHex), nonce,
      { authTagLength: TAG_BYTES });
    decipher.setAuthTag(tag);
    if (aad.length) decipher.setAAD(aad, { plaintextLength: ct.length });
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    return null;
  }
}

// ================================================================ reach-back through a relay
//
// The inline reply answers the visitor who is holding the HTTP connection. Everything the
// site wants to say LATER ("your booking is confirmed") goes the other way: sealed to the
// visitor's X25519 key and deposited at a relay, which stores and forwards it. The relay
// never sees plaintext — it only checks that the routing fields are signed.

/** Build the A2A message object (shared/protocol.Message.to_a2a) for `fields`. */
function toA2A({ role, text, messageId, contextId, timestamp, from, to, sig, replyTo }) {
  const metadata = { timestamp, from, to, sig };
  if (replyTo) metadata.replyTo = replyTo;
  return {
    kind: 'message',
    role,
    parts: [{ kind: 'text', text }],
    messageId,
    contextId: contextId ?? null,
    metadata,
  };
}

/**
 * Seal a signed `message/send` request to `toDid` and deposit it at `relayUrl`.
 *
 * The deposit body is `{to, from, from_enc, id, blob, sig}` where
 * `sig = Ed25519(to + "|" + from + "|" + id + "|" + blob)` over those UTF-8 bytes — NOT
 * canonical JSON. It proves the routing fields and the opaque blob were not altered in
 * transit while leaving the relay unable to read anything.
 *
 * Resolves `{status, queued, ...body}`; never throws for a non-2xx — the caller decides.
 */
export async function depositToRelay(relayUrl, { seedHex, toDid, toEncPub, text,
  contextId = null, timestamp = null, auto = false } = {}) {
  const from = didFromSeedHex(seedHex);
  const messageId = newId();
  const ts = timestamp ?? nowEpoch();
  const sig = signEnvelope(seedHex, { from, to: toDid, messageId, contextId,
    timestamp: ts, text });
  const message = toA2A({ role: 'user', text, messageId, contextId, timestamp: ts,
    from, to: toDid, sig });
  if (auto) message.metadata.auto = true;
  const rpc = { jsonrpc: '2.0', id: newId(), method: 'message/send', params: { message } };
  // JSON.stringify (not canonical JSON) is correct for the SEALED body: only signed
  // payloads need canonical form, and the AEAD tag already binds these bytes exactly.
  const blob = seal(seedHex, toEncPub, JSON.stringify(rpc));
  const id = newId();
  const depositSig = signBytes(seedHex,
    Buffer.from(`${toDid}|${from}|${id}|${blob}`, 'utf8')).toString('base64');

  const res = await fetch(relayUrl.replace(/\/+$/, '') + '/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ to: toDid, from, from_enc: encPubHex(seedHex), id, blob,
      sig: depositSig }),
  });
  const raw = await res.text();
  let body = {};
  try { body = raw ? JSON.parse(raw) : {}; } catch { body = { raw }; }
  return { status: res.status, queued: body.queued === true, messageId, ...body };
}

// ================================================================ the agent entry

function nowEpoch() {
  return Math.floor(Date.now() / 1000);
}

let OVERSIZE_SENTINEL = null;
/** A body one byte over the ceiling — the cheapest thing that makes `handlePost` answer 413.
 *  Shared and read-only: it is never parsed, only measured. */
function oversizeSentinel() {
  if (OVERSIZE_SENTINEL === null) OVERSIZE_SENTINEL = Buffer.alloc(MAX_BODY_BYTES + 1);
  return OVERSIZE_SENTINEL;
}

/** messageId dedup with a TTL and a hard cap, so a stranger cannot grow it without bound. */
class ReplayGuard {
  constructor(ttlSeconds = REPLAY_TTL_S, cap = 20000) {
    this.ttl = ttlSeconds * 1000;
    this.cap = cap;
    this.seen = new Map();               // messageId -> expiry (ms). Insertion-ordered.
    this.inserts = 0;
  }

  /** True if this messageId is NEW (and remembers it); false if it is a replay. */
  checkAndRemember(messageId) {
    const now = Date.now();
    const expiry = this.seen.get(messageId);
    if (expiry !== undefined) {
      if (expiry > now) return false;    // still inside the window: a replay
      this.seen.delete(messageId);       // expired: it may be used again
    }
    this.seen.set(messageId, now + this.ttl);
    if ((++this.inserts & 0xff) === 0) this.sweep(now);
    while (this.seen.size > this.cap) {
      // Oldest-first eviction. Dropping an entry can only ever make us ACCEPT an old
      // duplicate — never reject a fresh message — so a full table degrades safely.
      const oldest = this.seen.keys().next();
      if (oldest.done) break;
      this.seen.delete(oldest.value);
    }
    return true;
  }

  sweep(now = Date.now()) {
    for (const [k, expiry] of this.seen) {
      if (expiry > now) break;           // insertion order == expiry order (fixed TTL)
      this.seen.delete(k);
    }
  }
}

/** A whole-agent entry sliding-window bound: at most `perMinute` grants in any 60s. Kept
 *  deliberately dumb — it can never hold more than `perMinute` timestamps, so the bound
 *  bounds its own bookkeeping, which is why it is the OUTERMOST guard on the anonymous
 *  lane (it also keeps a flood from growing the replay table). */
class RateBound {
  constructor(perMinute = ANON_RATE_PER_MIN) {
    this.perMinute = Math.max(0, Number(perMinute) || 0);
    this.hits = [];
  }

  /** Consume one token. False when the window is full. */
  allow() {
    const now = Date.now();
    this.hits = this.hits.filter((t) => now - t < 60000);
    if (this.hits.length >= this.perMinute) return false;
    this.hits.push(now);
    return true;
  }
}

/** Per-ACCOUNT sliding windows, in a map that is itself bounded — because the keys are
 *  free to mint, an unbounded map here would be the memory-growth vector the bound exists
 *  to close. Eviction is oldest-first, the ledger's own discipline.
 *
 *  Read the eviction honestly: a caller cycling fresh keys is evicted and re-admitted with
 *  a clean window every time, so this tier alone stops NOTHING it was not already unable to
 *  stop. That is not a flaw to fix here — it is why the whole-entry ceiling is not optional. */
class AccountRateBounds {
  constructor(perMinute, maxKeys) {
    this.perMinute = perMinute;
    this.maxKeys = Math.max(1, Number(maxKeys) || 1);
    this.byAccount = new Map();
  }

  /** Consume one token for `account`. False when that account's window is full. */
  allow(account) {
    let bound = this.byAccount.get(account);
    if (!bound) {
      if (this.byAccount.size >= this.maxKeys) {
        const oldest = this.byAccount.keys().next().value;
        if (oldest !== undefined) this.byAccount.delete(oldest);
      }
      bound = new RateBound(this.perMinute);
      this.byAccount.set(account, bound);
    }
    return bound.allow();
  }
}

/**
 * An unpaired UTF-16 surrogate — a string with no UTF-8 encoding at all.
 *
 * `"\ud800"` is legal JSON and both parsers accept it, but Python's `.encode("utf-8")`
 * RAISES on it while a JavaScript Buffer quietly substitutes U+FFFD. Measured: a one-shot
 * POST carrying `"text": "\ud800"` from a stranger with no key killed the Python reference
 * entry's request with no HTTP response, and was answered -32001 here — same bytes, two
 * verdicts, one of them a dead socket. It is not text; the shape gate refuses it on both.
 *
 * Written without the `u` flag on purpose: in a Unicode-mode pattern these ranges are not
 * matchable as isolated code units, which is exactly what has to be matched here.
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * The STRICT type check on the fields that end up inside the signed payload. Returns a
 * reason string, or null when the shape is acceptable.
 *
 * WHY (measured divergence, not theory). The contract is "one agent entry, two
 * implementations": the same bytes must get the same verdict. They did not. A NUMERIC text
 * part was coerced to '' HERE and an account row was minted, while the Python reference
 * raised and answered -32600 — the same POST created a customer on one deployment and was
 * refused on the other, which is the double-book class for the booking flow this tier
 * sells. Likewise a non-string `contextId` (the reproduced case was the float `1.0`):
 * JavaScript renders it `1` and Python renders it `1.0`, so exactly one of them can verify
 * the signature — and we would then ECHO it into our own signed reply.
 *
 * Also here, and for the same reason, are the ENVELOPE fields — `metadata` and the
 * `from`/`to`/`sig` inside it. Step 4 below can only ask "is it there", and a wrongly-typed
 * one answered that question WRONG on both twins in opposite directions: `metadata: "x"`
 * read as an EMPTY envelope here (so -32001, or — with the anonymous lane on — a SIGNED
 * ANONYMOUS REPLY, a malformed envelope silently downgraded to a walk-in) while the Python
 * reference answered -32600; and `metadata.to = 1` survived Python's presence test and
 * reached `to_did[:24]`, a TypeError that closed the socket with no HTTP response at all.
 * A partial or malformed envelope is never an absent one — that rule is already written
 * down for a stripped `sig` in docs/AGENT_ENTRY.md, and it holds for the type too.
 *
 * -32600 (Invalid Request) for all of them: a wrongly-typed field is a malformed request,
 * not a failed signature. `examples/agent_entry_reference.py::_wire_shape_error` answers the
 * same code for the same input, case for case.
 */
function wireShapeError(msg) {
  const parts = msg.parts;
  if (parts !== undefined && parts !== null && !Array.isArray(parts)) {
    return 'parts must be an array';
  }
  for (const part of (Array.isArray(parts) ? parts : [])) {
    if (!part || typeof part !== 'object' || part.kind !== 'text') continue;
    // ABSENT reads as '' (Python's `.get("text", "")`); PRESENT-but-not-a-string is a
    // refusal, never a coercion — coercing means signing a reply to text nobody wrote.
    if ('text' in part && typeof part.text !== 'string') {
      return 'a text part\'s `text` must be a string';
    }
    if (typeof part.text === 'string' && LONE_SURROGATE.test(part.text)) {
      return 'a text part\'s `text` is not encodable UTF-8 (a lone surrogate)';
    }
  }
  if (typeof msg.messageId !== 'string' || !msg.messageId) {
    return 'messageId must be a non-empty string';
  }
  if (LONE_SURROGATE.test(msg.messageId)) {
    return 'messageId is not encodable UTF-8 (a lone surrogate)';
  }
  if (msg.contextId !== undefined && msg.contextId !== null
      && typeof msg.contextId !== 'string') {
    return 'contextId must be a string or null';
  }
  if (typeof msg.contextId === 'string' && LONE_SURROGATE.test(msg.contextId)) {
    return 'contextId is not encodable UTF-8 (a lone surrogate)';
  }
  // The ENVELOPE fields. `null` reads as ABSENT (the stripped-sig case the ladder answers
  // -32001 for, and the shape of a walk-in on the anonymous lane); PRESENT-but-not-a-string
  // is a malformed request and is never an absent envelope. `typeof null === 'object'` and
  // an Array is an object too, so both are excluded explicitly.
  const meta = msg.metadata;
  if (meta !== undefined && meta !== null
      && (typeof meta !== 'object' || Array.isArray(meta))) {
    return 'metadata must be an object';
  }
  for (const field of ['from', 'to', 'sig']) {
    const v = (meta ?? {})[field];
    if (v === undefined || v === null) continue;
    if (typeof v !== 'string') return `metadata.${field} must be a string`;
    if (LONE_SURROGATE.test(v)) {
      return `metadata.${field} is not encodable UTF-8 (a lone surrogate)`;
    }
  }
  // LAST, because the Python reference reaches the equivalent refusal last: its shape gate
  // runs and THEN `Message.from_a2a` raises. `kind: "message"` is what makes this an A2A
  // Message rather than some other object that happens to carry a `parts` array, and
  // `shared/protocol.py::from_a2a` has always required it — while this file had no check at
  // all. Measured with a valid signature and a fresh timestamp: a message with `kind`
  // removed was ACCEPTED here, BOOKED AN ACCOUNT and got a signed reply, where the reference
  // answered -32600. A muretai NODE refuses the same bytes, so accepting them would also
  // mean the entry tier and the node tier disagree about what an A2A message is.
  if (msg.kind !== 'message') return 'not an A2A message object';
  return null;
}

/** Every response carries these. An agent entry reads NO cookie, header credential or session —
 *  authority comes only from an Ed25519 signature inside the body — so `*` grants a browser
 *  agent exactly what curl already had, and nothing more. Never add Allow-Credentials.
 *  `Access-Control-Allow-Methods` is the ORIGIN-WIDE default and is overridden per resource
 *  on any response that also carries `Allow` (see `allowHeaders`). */
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '600',
};

/** The refusal text for a request-target that is not in origin form. Shared with
 *  `ORIGIN_FORM_ONLY` in examples/agent_entry_reference.py so the two twins return the same
 *  diagnostic for the same request. */
const ORIGIN_FORM_ONLY = 'the request-target must be an origin-form path: this entry answers '
  + 'exactly the address its card names, and that address has no other spelling';

/** Transport bounds. Node bounds the first three by DEFAULT (300 s / 60 s / 5 s) and the
 *  Python reference bounded NONE, which made it the only tier a stranger could wedge with no
 *  key and no request body — 40 trickle connections took it from 2 threads to 42 with 0
 *  responses. These are the numbers BOTH twins now use, spelled here so the two files can be
 *  read against each other: `AgentEntry.HEADER_TIMEOUT` / `BODY_BUDGET` /
 *  `KEEPALIVE_TIMEOUT` / `MAX_CONNECTIONS`. */
const HEADERS_TIMEOUT_MS = 20_000;
const REQUEST_TIMEOUT_MS = 20_000;
const KEEPALIVE_TIMEOUT_MS = 5_000;
const MAX_CONNECTIONS = 64;

/** What the (MAX_CONNECTIONS+1)-th connection is answered with, byte for byte the same
 *  response `_BoundedThreadingHTTPServer` writes in the Python reference. */
const OVERLOADED_BODY = '{"error":"too many concurrent connections"}';
const OVERLOADED_RESPONSE = 'HTTP/1.1 503 Service Unavailable\r\n'
  + 'Content-Type: application/json; charset=utf-8\r\n'
  + `Content-Length: ${OVERLOADED_BODY.length}\r\n`
  + 'Connection: close\r\n\r\n' + OVERLOADED_BODY;

/** The stdlib's STRICT UTF-8 decoder: it THROWS on an invalid byte instead of substituting
 *  U+FFFD, which is what `Buffer.toString('utf8')` does and what let a body neither
 *  implementation could agree about reach the ladder. Node global since v11 — no dependency. */
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });

/**
 * The JSON-RPC `id` we may ECHO, or null.
 *
 * JSON-RPC 2.0 says an id is a String, a Number or Null — never an object or an array — and
 * this enforces exactly that, for a reason larger than pedantry: the id is the ONE field no
 * signature covers and it is written straight back out, so whatever the two runtimes
 * disagree about here becomes a disagreement about the whole response. Two measured cases,
 * both closed by refusing the SHAPE rather than the instance:
 *   - `id = {"x":"\ud800"}`. `JSON.stringify` escapes the lone surrogate happily; Python's
 *     `p.dumps` RAISES, so the reference booked the account and then died in serialisation
 *     (HTTP 500, no reply, customer on the books) while this file answered 200 and signed.
 *   - a number outside ±2^53. `10**400` arrives here as `Infinity` and re-serialises as
 *     `null`, while Python echoes the bigint verbatim.
 * `null` is what JSON-RPC allows for an unusable id, and it keeps the VERDICT — not the
 * echo — as the thing the two implementations have to agree on.
 * Mirrors `AgentEntry._safe_id` in examples/agent_entry_reference.py.
 */
function safeId(id) {
  if (typeof id === 'string') return LONE_SURROGATE.test(id) ? null : id;
  if (typeof id === 'number') {
    return (Number.isFinite(id) && Math.abs(id) <= 2 ** 53) ? id : null;
  }
  return null;
}

function jsonResponse(status, obj, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  return {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': String(body.length),
      ...CORS_HEADERS,
      ...extraHeaders,
    },
    body,
  };
}

function rpcError(id, error, data) {
  const err = { ...error };
  if (data) err.data = data;
  return jsonResponse(200, { jsonrpc: '2.0', id: id ?? null, error: err });
}

function isThenable(v) {
  return v !== null && typeof v === 'object' && typeof v.then === 'function';
}

/**
 * `then1(x, f)` — apply `f` to `x`, awaiting `x` only if it is a promise.
 *
 * This is what lets ONE verification ladder serve both the synchronous in-memory state and
 * an asynchronous external `store` (T105), instead of the ladder being written twice and
 * drifting. Writing it twice was the alternative considered and rejected: the ladder is the
 * security-critical path, its steps are ORDER-DEPENDENT, and two copies of an ordered
 * security argument is how one of them silently stops matching the other.
 *
 * The sync branch is not an optimisation — it is the contract. With no store, every step
 * returns a plain value, the ladder returns a plain value, and `handleRequest` (the
 * synchronous entry point) keeps working exactly as it always has.
 */
function then1(x, f) {
  return isThenable(x) ? x.then(f) : f(x);
}

/**
 * Validate a caller-supplied `store` and return it unchanged.
 *
 * Checked ONCE at construction rather than per call, and it throws rather than filling in a
 * default: a store missing `seenMessage` would otherwise silently disable replay protection,
 * and the failure would appear as "the door works" until somebody replayed a message.
 */
function asStore(store) {
  const REQUIRED = ['seenMessage', 'getAccount', 'putAccount', 'getDeviceOwner',
    'putDeviceOwner'];
  const missing = REQUIRED.filter((m) => typeof store[m] !== 'function');
  if (missing.length) {
    throw new TypeError(
      `createAgentEntry: store is missing ${missing.join(', ')}. A store must implement all `
      + `of ${REQUIRED.join(', ')} — a partial store would disable a security rule silently `
      + 'rather than loudly.');
  }
  return store;
}

// ---------------------------------------------------------------- baseUrl canonicalisation

/** RFC 3986 `pchar` plus '/' — the only characters an accepted path may carry. Everything
 *  outside this set is percent-encoded by `new URL()` and left verbatim by Python's
 *  urlsplit, which is precisely the divergence canonicalBaseUrl exists to prevent. */
const PATH_OK = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/");
const HEX = new Set('0123456789abcdefABCDEF');
/** A host is lowercased before this is applied. '_' is not legal in a hostname but is real
 *  in the wild and both parsers keep it verbatim, so it is not a divergence. */
const HOST_OK = new Set('abcdefghijklmnopqrstuvwxyz0123456789.-_');
const DEFAULT_PORT = { http: 80, https: 443 };

/**
 * `'.'` or `'..'` if this path segment is a dot segment AS THE URL PARSERS SEE IT, else null.
 *
 * Raw `.` and `..` are the obvious spellings; `new URL()` ALSO removes `%2e`, `%2E` and every
 * mixture (`.%2e`, `%2e.`, `%2e%2e`), and Python's `urlsplit` removes none of them. A segment
 * test written against the raw text therefore lets exactly that family through: measured,
 * `https://shop.example/a/%2e%2e/support` started and published on the Python side, and was
 * refused here only by the `new URL()` tripwire at the bottom of canonicalBaseUrl — which
 * announced "a bug in this file, not in your input" for an input problem with a paste-able
 * fix. Decoding just this one escape (never the whole segment — `%41` must stay `%41`, it is
 * a different path) makes both implementations refuse the same family, for the right reason.
 */
function dotSegment(seg) {
  const decoded = seg.replaceAll('%2e', '.').replaceAll('%2E', '.');
  return (decoded === '.' || decoded === '..') ? decoded : null;
}

/** Raise the one refusal shape, in the order an operator can act on at 2am: what they gave
 *  (JSON-quoted, so an invisible tab is VISIBLE), which rule in words, the fix as a string
 *  they can paste, and one clause of why. `<field> is not publishable:` is the greppable
 *  stem the Python twin shares — `base_url` for the address, `domains` for the names this
 *  entry claims to speak for, `base_path` for the mount override. */
function refuseBaseUrl(given, rule, why, fix, field = 'base_url') {
  const lines = [`${field} is not publishable: ${rule}`, `  given: ${JSON.stringify(given)}`];
  if (fix) lines.push(`  use:   ${JSON.stringify(fix)}`);
  lines.push(`  ${why}`);
  throw new TypeError(lines.join('\n'));
}

/**
 * canonicalBaseUrl(baseUrl) -> the exact string this entry may publish as its card `url`.
 *
 * The contract, and the only reason this function exists: **the returned value equals what
 * a VISITOR computes** from the url they dialled (`Outbox.card_scope` in agent/outbox.py)
 * when deciding whether this card is about this site. An entry that publishes anything else
 * fails verification on a stranger's machine, with "signature verification failed" as the
 * only diagnostic and nothing at all on the operator's screen.
 *
 * So every input on which the operator's spelling and the visitor's arithmetic could
 * disagree — or on which this file and its Python twin (examples/agent_entry_reference.py)
 * could disagree — is REFUSED here, loudly, at construction. The two are held byte-identical
 * by an acceptance suite; a value they canonicalise differently is a signed-bytes split for
 * identical operator input, which is the bug this whole function is about.
 *
 * It HAND-PARSES rather than using `new URL()`, which is not a candidate: it keeps a trailing
 * DNS dot (`https://x.`) that the verifier drops, punycodes hosts, percent-encodes non-ASCII,
 * spaces and `|^{}`, removes dot segments, and rewrites `\` to `/` — five spellings Python
 * does not produce. `new URL()` runs at the END instead, as a tripwire: if a future Node
 * changes the parser out from under the hand-parse, that is a loud startup failure here
 * rather than silent byte drift discovered by a customer whose card stopped verifying.
 *
 * The gate (steps 1-7) runs before any folding, which is what makes the folds safe: it
 * removes exactly the inputs the two languages disagree about, so every remaining fold is
 * one they already agree on.
 */
export function canonicalBaseUrl(baseUrl, { warn = true } = {}) {
  if (typeof baseUrl !== 'string' || !baseUrl.trim()) {
    refuseBaseUrl(baseUrl, 'it is empty.', undefined,
      'Set it to the URL visitors actually dial — it is what your signed card claims, and '
      + 'a card naming a different origin proves nothing about yours.');
  }
  const s = baseUrl.trim();

  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (c >= 0x21 && c <= 0x7e) continue;
    if (c > 0x7e) {
      const hostGuess = (s.split('://')[1] ?? s).split('/')[0];
      let fix;
      try {                                     // best-effort A-label, for the message only
        const asciiHost = new URL(`https://${hostGuess}`).hostname;
        if (asciiHost && asciiHost !== hostGuess) fix = s.replace(hostGuess, asciiHost);
      } catch { /* not a host we can suggest a spelling for */ }
      refuseBaseUrl(s, 'it is not ASCII.', fix,
        'Python and JavaScript disagree on how to spell this (Python keeps it as typed, '
        + 'JavaScript percent-encodes or punycodes it), so the two Agent Entry '
        + 'implementations would sign different bytes for the same site. Supply the ASCII '
        + 'form, and publish your links and QR codes in that same form.');
    }
    refuseBaseUrl(s, 'it contains whitespace or a control character.', undefined,
      'Both URL parsers DELETE a tab or newline silently and mid-string, so the value you '
      + 'meant and the value that gets signed are not the same string and nothing tells you.');
  }

  if (s.includes('\\')) {
    refuseBaseUrl(s, 'it contains a backslash.', s.replaceAll('\\', '/'),
      "JavaScript reads '\\' as '/' and Python does not, so the two Agent Entry "
      + 'implementations would disagree about where the host ends.');
  }
  for (const [bad, label] of [['?', 'a query string'], ['#', 'a fragment']]) {
    if (s.includes(bad)) {
      refuseBaseUrl(s, `it carries ${label}.`, s.split(bad)[0] || undefined,
        'This string is signed into your Agent Card, and every visitor compares it to the '
        + 'URL they dialled — which never carries one.');
    }
  }

  const sep = s.indexOf('://');
  const scheme = sep < 0 ? '' : s.slice(0, sep).toLowerCase();
  if (sep < 0 || !(scheme in DEFAULT_PORT)) {
    refuseBaseUrl(s, 'it is not an http(s) URL.',
      sep < 0 && !s.startsWith('/') ? `https://${s}` : undefined,
      'An Agent Card names an origin a visitor can dial over HTTP.');
  }
  const rest = s.slice(sep + 3);
  const cut = rest.indexOf('/');
  const authority = cut < 0 ? rest : rest.slice(0, cut);
  let path = cut < 0 ? '' : rest.slice(cut);

  if (authority.includes('@')) {
    refuseBaseUrl(s, "it carries userinfo (a '@' before the host).",
      `${scheme}://${authority.slice(authority.lastIndexOf('@') + 1)}${path}`,
      "The part before '@' is not the host: a visitor dials the part AFTER it, so a card "
      + 'built from this string would name a different site than the one being served.');
  }
  if (authority.includes('%')) {
    refuseBaseUrl(s, 'the host contains a percent-escape.', undefined,
      'Python lowercases it into the host and JavaScript refuses the URL outright, so the '
      + 'two Agent Entry implementations cannot agree.');
  }

  let host;
  let portS;
  if (authority.startsWith('[')) {              // IPv6 literal — brackets are part of it
    const close = authority.indexOf(']');
    if (close < 0) {
      refuseBaseUrl(s, "the IPv6 host is missing its closing ']'.", undefined,
        'An address literal must be bracketed, e.g. http://[::1]:9000');
    }
    host = authority.slice(0, close + 1).toLowerCase();
    const tail = authority.slice(close + 1);
    if (tail && !tail.startsWith(':')) {
      refuseBaseUrl(s, 'there is text after the IPv6 address.', undefined,
        "Only ':<port>' may follow a bracketed address.");
    }
    portS = tail ? tail.slice(1) : '';
  } else {
    const colon = authority.lastIndexOf(':');
    host = (colon < 0 ? authority : authority.slice(0, colon)).toLowerCase();
    portS = colon < 0 ? '' : authority.slice(colon + 1);
  }

  let port = null;
  if (portS) {
    const n = Number(portS);
    if (!/^[0-9]+$/.test(portS) || !Number.isInteger(n) || n < 1 || n > 65535) {
      refuseBaseUrl(s, `the port ${JSON.stringify(portS)} is not a number in 1-65535.`,
        undefined, 'A visitor dials a real port; anything else cannot be reached.');
    }
    port = n;
  }
  host = host.replace(/\.+$/, '');              // trailing dot: DNS-equal, byte-different
  if (!host || (!host.startsWith('[') && [...host].some((c) => !HOST_OK.has(c)))) {
    refuseBaseUrl(s, 'the host is missing or contains characters that are not a hostname.',
      undefined, 'A card must name a host a visitor can resolve.');
  }

  path = path.replace(/\/+$/, '');              // ALL of them: card_scope uses rstrip too
  if (path) {
    for (let i = 0; i < path.length;) {
      const ch = path[i];
      if (ch === '%') {
        if (path.length - i < 3 || !HEX.has(path[i + 1]) || !HEX.has(path[i + 2])) {
          refuseBaseUrl(s, 'the path has a malformed percent-escape.', undefined,
            "'%' must be followed by exactly two hex digits, or the two URL parsers "
            + 'disagree about what the path is.');
        }
        i += 3;
        continue;
      }
      if (!PATH_OK.has(ch)) {
        refuseBaseUrl(s, `the path contains ${JSON.stringify(ch)}, which is not allowed `
          + 'unencoded.', undefined,
        'JavaScript percent-encodes this character and Python leaves it verbatim, so the '
        + 'two Agent Entry implementations would sign different bytes. Percent-encode it '
        + 'yourself.');
      }
      i += 1;
    }
    const parts = path.split('/');
    if (parts.some((seg) => dotSegment(seg) !== null)) {
      const segs = [];                          // RFC 3986 remove_dot_segments, for the fix
      for (const seg of parts) {
        const dot = dotSegment(seg);
        if (dot === '.') continue;
        if (dot === '..') { if (segs.length > 1) segs.pop(); continue; }
        segs.push(seg);
      }
      refuseBaseUrl(s, "the path contains '.' or '..' segments "
        + "(the percent-encoded spellings '%2e' and '%2E' count).",
      `${scheme}://${authority}${segs.join('/').replace(/\/+$/, '')}`,
      'JavaScript collapses these segments — encoded ones included — and Python does not, '
      + 'so the two Agent Entry implementations would sign different bytes.');
    }
  }

  const originOut = `${scheme}://${host}${port !== null && port !== DEFAULT_PORT[scheme] ? `:${port}` : ''}`;
  const out = originOut + path;

  // The tripwire. Not redundant with the hand-parse: it is what turns a future Node/WHATWG
  // change into a loud startup failure instead of silent byte drift. If this ever fires,
  // the hand-parse and the platform parser have diverged on an input the gate let through.
  //
  // It must NOT claim to know which of the two is at fault. It used to open with "a bug in
  // this file, not in your input" and send the operator to an issue tracker — and the input
  // that actually fired it was `https://shop.example/a/%2e%2e/support`, an encoded dot
  // segment, which is an input problem with a paste-able fix (now refused above, by name).
  // A tripwire sees a disagreement, not a culprit. Name both, input first.
  const probe = new URL(out);
  if (probe.origin !== originOut || probe.pathname !== (path || '/')
      || probe.search || probe.hash) {
    throw new TypeError(
      `base_url is not publishable: canonicalising it produces a value this runtime's URL `
      + `parser reads differently.\n`
      + `  given: ${JSON.stringify(baseUrl)}\n`
      + `  this file canonicalises it to ${JSON.stringify(out)}, which the URL parser reads `
      + `as ${JSON.stringify(probe.origin + probe.pathname)}.\n`
      + `  Check the address first — a spelling this gate does not know how to fold lands `
      + `here. If it is an ordinary http(s) URL with no unusual escaping, this is a bug in `
      + `this file: please report it at https://github.com/muretai/agent-entry/issues`);
  }

  if (warn) {
    if (/[A-Z]/.test(path)) {
      process.stderr.write(`warning: base_url path ${JSON.stringify(path)} contains `
        + `uppercase letters. Paths are case-SENSITIVE and are not folded by the visitor's `
        + `check, so a visitor who dials ${JSON.stringify(path.toLowerCase())} will fail to `
        + `verify your card. Make sure every link, invite and QR code you publish spells it `
        + `exactly ${JSON.stringify(path)}.\n`);
    }
    if (path.includes('%')) {
      process.stderr.write(`warning: base_url path ${JSON.stringify(path)} contains a `
        + `percent-escape. It is compared verbatim, case included, so a visitor who dials `
        + `another spelling of the same path will fail to verify your card.\n`);
    }
    if (scheme === 'http' && !['localhost', '127.0.0.1', '[::1]'].includes(host)) {
      process.stderr.write(`warning: base_url ${JSON.stringify(out)} is plain HTTP on a `
        + `public host. A visiting agent refuses a plain-http open door (the message text `
        + `would cross the wire in the clear), so this entry will be skipped by every `
        + `well-behaved visitor. Use https.\n`);
    }
  }
  return out;
}

// ---------------------------------------------------------------- domains + the mount

/** The outer whitespace BOTH languages strip identically. Python's `str.strip()` also
 *  removes \x1c-\x1f, U+0085 and U+00A0; JavaScript's `trim()` removes a different tail of
 *  Unicode spaces. Folding only this intersection — and refusing every other character
 *  outside 0x21..0x7E — is what stops the twins accepting different strings for the same
 *  operator input. Must match `_OUTER_WS` in examples/agent_entry_reference.py. */
const OUTER_WS = ' \t\n\r\f\v';
/** Characters that betray a URL, an authority or whitespace smuggling where a bare domain
 *  was expected (shared/domainbind._NOT_IN_DOMAIN). */
const NOT_IN_DOMAIN = ['/', '?', '#', '@', '\\', ' ', '\t', '\r', '\n', '%', '[', ']'];
const LDH = new Set('abcdefghijklmnopqrstuvwxyz0123456789-');
/** RFC 1035 total length of a domain name, applied to the HOST only, plus the longest
 *  legal ":<port>" for the raw-input bound (shared/domainbind.MAX_DOMAIN_LEN). */
const MAX_DOMAIN_LEN = 253;

/** Exported because the RUNNER needs the same fold: `examples/agent_entry_server.mjs` decides
 *  whether `AGENT_ENTRY_DOMAINS` is blank at all, and it used `trim()`. That is a different
 *  set from Python's `strip()` in BOTH directions, so one variable got two verdicts — a
 *  `\x1c` started the Python runner with no domains and made this one exit 2, and a BOM
 *  (what a paste out of a spreadsheet or a Windows `.env` carries) did the reverse. */
export function trimOuter(s) {
  let a = 0;
  let b = s.length;
  while (a < b && OUTER_WS.includes(s[a])) a += 1;
  while (b > a && OUTER_WS.includes(s[b - 1])) b -= 1;
  return s.slice(a, b);
}

/**
 * The JS twin of `shared/domainbind.valid_domain` — the ONE definition of "is this a bare
 * domain" in this system, and therefore the one both halves of a domain binding must agree
 * on. Total on untrusted input; never throws.
 *
 * A domain here is not a URL: ASCII LDH labels only (a-z, 0-9, '-'), LOWERCASE (case is
 * folded by the caller, visibly, because `valid_domain` REJECTS an uppercase spelling
 * rather than folding it), 1..63 characters per label, no leading or trailing '-', at
 * least two labels (a single-label name has no owner a verifier could hold responsible),
 * host <= 253 with no trailing dot, and an optional ':<port>' 1..65535 with no leading
 * zero. Ports exist only because a loopback or staging box cannot use 443.
 *
 * Re-implemented rather than imported for the same reason everything else in this file is:
 * a site copies ONE file. `test_agent_entry_contract.py` is what holds the two spellings to
 * the same verdicts.
 */
function validBareDomain(domain) {
  if (typeof domain !== 'string' || !domain || domain.length > MAX_DOMAIN_LEN + 6) {
    return false;
  }
  if (NOT_IN_DOMAIN.some((ch) => domain.includes(ch))) return false;
  for (const ch of domain) if (ch.codePointAt(0) > 0x7f) return false;   // IDN U-labels
  let host = domain;
  const colon = domain.indexOf(':');            // the FIRST one: `str.partition` semantics
  if (colon >= 0) {
    host = domain.slice(0, colon);
    const portS = domain.slice(colon + 1);      // a second ':' leaves a non-numeric tail
    if (!/^[0-9]+$/.test(portS)) return false;
    if (portS.length > 1 && portS.startsWith('0')) return false;
    const port = Number(portS);
    if (port < 1 || port > 65535) return false;
  }
  if (!host || host.length > MAX_DOMAIN_LEN || host.endsWith('.')) return false;
  const labels = host.split('.');
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
    for (const ch of label) if (!LDH.has(ch)) return false;
  }
  return true;
}

/** A pasteable repair for a domain we refused, or undefined when we cannot guess one.
 *  Only ever suggests something `validBareDomain` accepts, so a wrong guess produces no
 *  suggestion rather than a second bad value to paste. */
function domainFix(candidate) {
  try {
    let guess = trimOuter(String(candidate)).toLowerCase();
    guess = guess.includes('://') ? guess.slice(guess.indexOf('://') + 3) : guess;
    for (const cut of ['/', '?', '#']) {
      const at = guess.indexOf(cut);
      if (at >= 0) guess = guess.slice(0, at);
    }
    if (guess.includes('@')) guess = guess.slice(guess.lastIndexOf('@') + 1);
    guess = guess.replace(/\.+$/, '');
    return (guess && guess !== candidate && validBareDomain(guess)) ? guess : undefined;
  } catch {
    return undefined;
  }
}

/**
 * canonicalDomains(domains) -> the exact list this entry may publish as its card `domains`.
 *
 * WHAT IT IS FOR. A domain binding is BILATERAL and neither half is worth anything alone
 * (shared/domainbind.py, agent/domainverify.py): the DOMAIN publishes a credential naming
 * this DID at /.well-known/did-configuration.json, and the AGENT's own live card names the
 * domain back. This list is that second half. Without it a verifier holding the domain's
 * file answers `card-withdrawn` — the domain vouches for an agent that does not claim the
 * domain — so an entry with no `domains` can never be proven to belong to the site it is
 * serving from. Because the halves are written by different parties, EITHER can end the
 * binding alone: the domain owner deletes a line from the file, or the entry drops the name.
 *
 * Absent or empty -> `[]`, and the card then carries NO `domains` key at all, so an entry
 * from before this option existed publishes byte-identical bytes and nobody has to
 * re-publish or re-sign anything.
 *
 * Anything else is REFUSED at construction, loudly, exactly like `canonicalBaseUrl`: a
 * name the credential can never bind is not something to warn about and publish anyway.
 * The rule is `validBareDomain` — deliberately the same predicate core uses, because a
 * second opinion here produces an entry that starts happily and can never verify.
 * `strip().lower()` is the ONLY canonicalization, matching agent/domainverify._norm_domain.
 *
 * Names are de-duplicated (operator order kept), and MORE THAN `MAX_CARD_DOMAINS` distinct
 * names is a REFUSAL, not a truncation — even though `build_agent_card` truncates at the
 * same 5. That function renders a card for many callers at runtime and must not blow up
 * mid-render; this one validates an argument an operator just typed, and it already
 * refuses every other bad value there. Truncating would start the entry with a claim that
 * is USABLE and NOT WHAT THEY SAID.
 */
export function canonicalDomains(domains, { warn = true } = {}) {
  if (domains === undefined || domains === null) return [];
  if (!Array.isArray(domains)) {
    refuseBaseUrl(domains, 'it is not a list of domain names.',
      'Pass an array, e.g. ["example.com"] — a single string is refused rather than '
      + 'wrapped, so this file and its Python twin cannot disagree about what was meant.',
      undefined, 'domains');
  }
  const out = [];
  for (const entry of domains) {
    if (typeof entry !== 'string') {
      refuseBaseUrl(entry, 'it is not a string.', 'A domain is a name, e.g. "example.com".',
        undefined, 'domains');
    }
    const s = trimOuter(entry);
    for (const ch of s) {
      const c = ch.codePointAt(0);
      if (c < 0x21 || c > 0x7e) {
        refuseBaseUrl(entry,
          'it contains whitespace, a control character or a non-ASCII character.',
          'A domain here is compared byte for byte against the origin in the credential '
          + 'the domain itself serves, so an internationalized name must be given in its '
          + 'punycode (xn--…) A-label form and nothing else may travel with it.',
          domainFix(s), 'domains');
      }
    }
    const lowered = s.toLowerCase();
    if (!validBareDomain(lowered)) {
      refuseBaseUrl(entry, 'it is not a bare domain name.',
        "Give the HOST only: ASCII letters, digits and '-', at least two labels (each "
        + "1-63 characters, not starting or ending with '-'), at most 253 characters, "
        + "optionally ':<port>' 1-65535 — no scheme, no path, no query, no '@', no "
        + 'trailing dot. The domain\'s own credential binds https://<this exact string>, '
        + 'so anything else can never match it.',
        domainFix(lowered), 'domains');
    }
    if (!out.includes(lowered)) out.push(lowered);
  }
  if (out.length > MAX_CARD_DOMAINS) {
    refuseBaseUrl(domains,
      `it names ${out.length} distinct domains, more than the ${MAX_CARD_DOMAINS} a card `
      + 'may advertise.',
      'Every name listed is an outbound HTTPS fetch this entry asks strangers to make, so '
      + `a card carries at most ${MAX_CARD_DOMAINS}. Publishing the first `
      + `${MAX_CARD_DOMAINS} and dropping the rest would start this entry with a claim `
      + 'that is usable and NOT what you said: the names that vanished fail for whoever '
      + 'verifies them and nothing anywhere says why. Drop names, or run a second entry '
      + '(its own key) for the rest.',
      undefined, 'domains');
  }
  return out;
}

/**
 * canonicalMount(canonUrl, basePath) -> the path prefix this entry ANSWERS at. `''` for a
 * bare origin; otherwise `'/support'`-shaped, taken from the already-canonicalised url.
 *
 * WHY IT IS DERIVED AND NOT CONFIGURED. A mount the operator spells separately from
 * `baseUrl` is a second place to write the same fact, and the failure it produces is the
 * worst one this system has: the entry answers at one path while its signed card claims
 * another, so every visitor fails `Outbox.card_binds_to` and the only diagnostic anyone
 * gets is "cannot prove that … owns …". Deriving it makes the router's mount and the
 * card's advertised address THE SAME STRING by construction. (Measured before this
 * existed: an entry given `baseUrl: 'http://h:p/support'` printed that address, signed
 * `/support` into its card, and then answered the BARE HOST — three answers to one
 * question.)
 *
 * THE ONE OVERRIDE. A reverse proxy that STRIPS the prefix hands this process `/…` while
 * the public address is still `https://h/support`. That deployment is real, so `basePath:
 * ''` is allowed — but ONLY `''` or exactly the canonical url's own path. Any other value
 * would be a third spelling of the address, which is what this function exists to prevent.
 */
export function canonicalMount(canonUrl, basePath) {
  const path = new URL(canonUrl).pathname.replace(/\/+$/, '');
  if (basePath === undefined || basePath === null) return path;
  if (typeof basePath !== 'string') {
    refuseBaseUrl(basePath, 'it is not a string.',
      'Pass "" (a proxy that strips the prefix) or the same path as baseUrl.',
      undefined, 'base_path');
  }
  const given = trimOuter(basePath).replace(/\/+$/, '');
  if (given !== '' && given !== path) {
    refuseBaseUrl(basePath, 'it is neither empty nor the path baseUrl already names.',
      `This entry publishes ${JSON.stringify(canonUrl)}, so a visitor dials `
      + `${JSON.stringify(path || '/')} and nothing else. Use "" only when a proxy strips `
      + 'the prefix before the request reaches this process.',
      path || '', 'base_path');
  }
  return given;
}

/**
 * createAgentEntry(opts) -> { did, card, ledger, handleRequest, handleRequestAsync, listen }
 *
 *   seedHex        the site's 32-byte identity seed (hex). THE PRIVATE KEY.
 *   name           the public name on the Agent Card.
 *   baseUrl        the base a visitor dials. It goes in the card's `url`, and the visitor
 *                  REQUIRES card.url to name the origin+path it dialled (Outbox.card_binds_to)
 *                  — that binding is what stops an attacker re-serving your signed card at
 *                  their own host. Get it wrong and Path A verification fails, silently.
 *                  It MAY carry a path (`https://example.com/support`): every route then
 *                  hangs off that path and the bare host is 404, so one hostname holds a
 *                  front desk, support and sales as three agents with three keys.
 *   domains        the bare domains this entry claims to speak for, e.g. ['example.com']
 *                  (default none, and then the card carries no `domains` key at all). A
 *                  CLAIM, never evidence: the proof is the credential the DOMAIN serves at
 *                  /.well-known/did-configuration.json, and a verifier requires both halves.
 *   basePath       ONLY for a proxy that strips the prefix: '' or exactly baseUrl's path.
 *                  See canonicalMount for why this is not a general knob.
 *   guest          GUEST MOUNT: the SITE keeps its own front page and this entry claims
 *                  only its card paths and the POST door (default false). It requires a
 *                  baseUrl WITH a path — the door — because a guest entry at a bare origin
 *                  would claim `/`, which is the one thing this mode exists to give back.
 *                  Three differences from the ordinary (site-owning) mount, and no others:
 *                  the GET notice is not served (the entry never shadows a page the site
 *                  owns), the card is ALSO served at the ORIGIN's well-known paths (where a
 *                  stranger's agent looks — RFC 8615), and `Allow` on the door names POST
 *                  only. `GET /` and `POST /` are not this entry's contract in this mode.
 *   responder      (envelope) => string | {text, contextId?, timestamp?} | Promise<…>
 *   openDoor       advertise `muretai.open_door` (default true) — the flag that tells a
 *                  visiting agent it may contact you without an introduction.
 *   anonymousLane  also accept UNSIGNED inquiries (default false). They create no account,
 *                  and the lane as a whole is capped at `anonRatePerMin` signed replies per
 *                  minute — it is unauthenticated, so it must not be an unmetered signing
 *                  oracle.
 *   anonRatePerMin anonymous replies per minute for the WHOLE agent entry (default 30).
 *   signedRatePerMin / signedRatePerMinTotal
 *                  the SIGNED lane's ceilings: replies per minute per ACCOUNT (default 60)
 *                  and for the whole entry (default 600). Both ON by default; pass 0 or a
 *                  non-number to disable a tier. Checked AFTER the signature, so no
 *                  stranger can spend another account's budget, and BEFORE the ledger and
 *                  the responder, so a refused flood grows neither. See
 *                  SIGNED_RATE_PER_MIN for why being attributable is not being bounded.
 *   howToUrl       OPTIONAL page a keyless visitor is pointed at (`howTo` on the card and
 *                  the refusal). DEFAULT EMPTY and the field is then omitted entirely: a
 *                  reference implementation names no host, and the refusal is a complete
 *                  recipe without it. SHIP THE PAGE FIRST — a pointer that 404s
 *                  out-competes every field beside it and reads as terminal.
 *   wbaVerifiers   OPTIONAL inbound Web Bot Auth (T107): a JWKS document {keys:[…]} of
 *                  Ed25519 keys whose holders this entry should RECOGNISE — the body of
 *                  a key directory you verified out of band. Absent (the default) the
 *                  feature is entirely off: no header is read, bytes are unchanged.
 *                  Recognition only ever ADDS identity (env.wba_did, the wbaVisits
 *                  count); it never changes verified, a ledger row, a rate lane or any
 *                  refusal verdict.
 *   observer       OPTIONAL `(env) => void` — a WATCHER, called once per message with the
 *                  same frozen envelope the responder gets. It exists so that OBSERVING a
 *                  visit is not the same edit as ANSWERING one: wanting a counter should
 *                  not mean reaching into the code that decides what to say.
 *
 *                  IT CANNOT AFFECT ANYTHING. It is called AFTER the verdict is settled,
 *                  its return value is discarded, a thrown error is swallowed, and a
 *                  promise is never awaited — so a slow or broken watcher cannot delay,
 *                  fail, or change one byte of the signed reply. That is the whole contract
 *                  and it is not a formality: this door answers in ONE round trip with no
 *                  callback, and a watcher that dialled out on the hot path would make the
 *                  visitor's answer depend on somebody else's uptime.
 *
 *                  WHAT NOT TO PUT IN IT. The envelope carries `peer_did`/`owner_did`,
 *                  which a visitor handed you to transact with YOU. Forwarding a raw DID to
 *                  a third party shares a durable identifier its owner never offered them;
 *                  if you need a metric, send a salted, site-scoped digest and keep the DID
 *                  in your own store. This module ships no sink and names no vendor — the
 *                  slot is here so an adapter can live outside it.
 */
export function createAgentEntry({
  seedHex,
  name = 'Muretai AgentEntry',
  baseUrl,
  description = 'Signed agent-to-agent messaging. Send an A2A message and get a signed reply.',
  version = '1',
  responder = () => 'Thanks — a human will follow up.',
  openDoor = true,
  anonymousLane = false,
  anonRatePerMin = ANON_RATE_PER_MIN,
  signedRatePerMin = SIGNED_RATE_PER_MIN,
  signedRatePerMinTotal = SIGNED_RATE_PER_MIN_TOTAL,
  skills = [],
  domains = null,
  basePath = null,
  guest = false,
  maxAccounts = 50000,
  howToUrl = FIRST_KNOCK_URL,
  observer = null,
  wbaVerifiers = null,
  store = null,
} = {}) {
  if (!seedHex) throw new TypeError('createAgentEntry: seedHex is required');
  if (!baseUrl) throw new TypeError('createAgentEntry: baseUrl is required (it is signed into the card)');
  // The ONE string this entry publishes as its card url. Canonicalised, not echoed: it must
  // equal what a visitor's Outbox.card_scope computes for the url they dialled, or the card
  // fails verification on THEIR machine with nothing on ours.
  const canonUrl = canonicalBaseUrl(baseUrl);
  // The path prefix this entry ANSWERS at, DERIVED from that same string so the router and
  // the signed card cannot disagree. '' for a bare origin — every route below is then the
  // byte-identical string this module always matched.
  const mount = canonicalMount(canonUrl, basePath);
  const guestMount = Boolean(guest);
  // A guest entry with NO path would claim the origin — `isMountPath('/')` is the door and
  // the notice both — which is exactly the front page this mode exists to leave alone.
  // Refuse to start rather than take it: an operator who asked for coexistence and silently
  // got occupation finds out from their own home page.
  if (guestMount && !mount) {
    refuseBaseUrl(canonUrl, 'a guest mount needs a door path, and this url has none.',
      'A guest entry leaves GET / to the site and answers at a path beside it, so the '
      + 'address it publishes must name that path — the mount, the card url and the POST '
      + 'door are then one string by construction. Give the door in baseUrl (the card names '
      + 'it, so a visitor that read the card posts to the right place with no other '
      + 'knowledge), or drop `guest` and let this entry own its origin.',
      `${canonUrl}/agent`);
  }
  // The agent half of a T88 domain binding. Refuses to start on anything that is not a
  // bare domain: a name the domain's credential can never bind is not worth publishing.
  const canonDomains = canonicalDomains(domains);
  const did = didFromSeedHex(seedHex);
  // WHERE A VISITOR POSTS — derived from the PUBLISHED url, never from `mount`. The two
  // are different questions and the answers legitimately differ: `mount` is the path THIS
  // PROCESS matches (a prefix-stripping proxy makes it '' while the public address still
  // carries the path), and this is the address a stranger dials. Appending `mount` to a
  // url that already carries that same path published `https://h/support/support` on every
  // default path mount — a 404 signed into a public card, on the one field that exists to
  // stop a caller guessing. It stayed invisible because the only per-twin assertion ran at
  // a bare origin, where `mount` is '' and the wrong formula is accidentally right.
  const doorUrl = canonUrl + (canonicalMount(canonUrl) ? '' : '/');
  // The terms of this door, built ONCE: the card publishes it (E1, before the knock) and
  // the no-envelope refusal returns the same object (E2, after it).
  const requirement = signedEnvelopeRequirement(did, doorUrl, howToUrl);

  const card = {
    protocolVersion: PROTOCOL_VERSION,
    name,
    description,
    url: canonUrl,
    did,
    version,
    capabilities: { streaming: false, pushNotifications: false },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills,
  };
  // T88, the REVERSE EDGE only, in the same top-level field and the same position
  // shared/protocol.build_agent_card uses, so one verifier rule reads a node's card and an
  // entry's card. Omitted entirely when no domain was named — that is what keeps an
  // already-deployed entry's published bytes unchanged.
  if (canonDomains.length) card.domains = canonDomains;
  // Neutral key first, vendor key beside it for one release. See the securitySchemes block
  // below for why the old spelling stays: a consumer must learn the new name BEFORE
  // producers stop emitting the old one, never after.
  if (openDoor) card.agentEntry = { open_door: true };
  if (openDoor) card.muretai = { open_door: true };
  // Deliberately NO `relay`/`enc_pub` on the card: those advertise a store-and-forward
  // mailbox, and an agent entry has no listener draining one. Advertising a mailbox nobody
  // reads is worse than advertising none — mail would queue at the relay forever.
  //
  // THE DOOR'S TERMS, IN STANDARD A2A SHAPE (E1). `securitySchemes` + `security` are the
  // fields A2A has for exactly this, and until now both were absent — so a card that
  // advertised a skill said nothing at all about HOW to call it, and the only way to learn
  // the requirement was to knock and be refused. That is the discovery step an HTTP-402
  // style protocol structurally cannot have and a card CAN; publishing it is what turns the
  // refusal below into a fallback instead of the only teacher.
  //
  // APPENDED LAST so every field an already-deployed entry publishes keeps its bytes AND
  // its position. `type` is deliberately NOT one of OpenAPI's five: `http` would claim an
  // `Authorization` header this door never reads, and a standard-but-wrong type makes a
  // conformant client do the wrong thing, where an unknown one makes it read the block
  // beside it. The scheme is named three times (key, `type`, `muretai.scheme`) and every
  // spelling is the same string the refusal returns.
  //
  // The description is IMPERATIVE for the same reason the requirement object is: a real
  // agent that started here read the terms, concluded correctly that it could not sign,
  // and stopped — "the card does not offer an alternative communication method". A card
  // that states a requirement and nothing about how to come to meet it is a locked door
  // with the lock documented. The worked-example clause appears only when the page it
  // names is known to resolve (see FIRST_KNOCK_URL); a 404 here would out-compete the
  // block beside it.
  //
  // THE TERMS ARE PUBLISHED UNDER A NEUTRAL KEY, and under the vendor one BESIDE it for a
  // release. A standard whose core machine-readable object is KEYED BY A VENDOR is not a
  // standard; a standard that carries vendor BLOCKS is healthy — so the object moves to
  // `agentEntry` and `muretai` stays as a byte-identical alias until consumers have turned
  // over. Additive on purpose: removing the old spelling first would split doors from
  // visitors, and a reader who learned one name must keep finding the terms where they
  // looked. `muretai` is dropped at the next MAJOR, not at a minor. Settle this BEFORE a
  // second scheme exists: whatever ships next would otherwise land inside the vendor key
  // and entrench it at exactly the moment neutrality is the point.
  card.securitySchemes = {
    [SIGNED_ENVELOPE_SCHEME]: {
      type: SIGNED_ENVELOPE_SCHEME,
      description: 'Generate an Ed25519 keypair if you do not have one - no account, no '
        + 'registration, any crypto library will do - then sign every message/send with '
        + 'the did:key you present as metadata.from. The step-by-step instruction, the '
        + 'signed fields, the canonical bytes and the address to send to are in '
        + '`agentEntry` beside this line'
        + (howToUrl ? `; a worked example is at ${howToUrl}` : ''),
      agentEntry: requirement,
      // The vendor spelling, byte-identical, kept for one release so a consumer that
      // learned this name still finds the terms. Dropped at the next MAJOR.
      muretai: requirement,
    },
  };
  card.security = [{ [SIGNED_ENVELOPE_SCHEME]: [] }];

  const cardBytes = Buffer.from(JSON.stringify(card), 'utf8');   // identical bytes on both paths
  // ACCOUNT DID -> {first_seen, last_seen, messages}. Keyed by the RESOLVED account (T102):
  // the OWNER DID when a valid v2 binding rides along, else the device DID — so an owner's
  // sibling devices are ONE customer row. The entry never reads it back to gate, greet, or
  // rate-limit, so it runs fine unpersisted — but keeping it in the site's own store is
  // RECOMMENDED: it is the customer list (recognise a returning account, contact it again
  // later). An analytics sink records visits too, but can never be read back.
  const ledger = new Map();
  // device DID -> owner DID, the in-process TOFU pin (T102). The first VALID binding pins a
  // device to its owner; a later binding for the same device naming a DIFFERENT owner is
  // refused. Per-process on purpose for v1.5 — persisting it (and the fold) is RECOMMENDED,
  // not required: without it the conflict rule resets to trust-on-first-use every restart.
  // Unlike the ledger it is READ on every message, so only a real store can carry it.
  const deviceOwner = new Map();
  const replay = new ReplayGuard();

  // ---------------------------------------------------------------- the state seam (T105)
  //
  // WHY. The three structures above live in CLOSURE MEMORY, and a serverless instance keeps
  // none of them between requests. The round-trip shape suits those platforms perfectly —
  // one signed POST in, one signed reply out, nothing to keep awake — so what blocks them is
  // not the shape but the STATE. Losing `replay` re-opens every message inside the freshness
  // window to replay; losing `deviceOwner` resets the no-re-ownership rule to
  // trust-on-first-use at every cold start.
  //
  // `store` is an OPTIONAL duck-typed object whose five methods may each return a value or a
  // promise:
  //
  //   seenMessage(messageId, ttlSeconds) -> bool   TRUE when the id was NEW (and is now
  //                                                remembered). The test and the remember
  //                                                MUST be atomic in the backing store.
  //   getAccount(did)          -> row | null
  //   putAccount(did, row)     -> void             row === null DELETES the row.
  //   getDeviceOwner(deviceDid)-> ownerDid | null
  //   putDeviceOwner(dev, own) -> void
  //
  // Rate counters are deliberately NOT in this interface, and that is the approved design,
  // not an omission: a bound that costs a store write per request is its own denial of
  // service, and losing one fails open for a single minute — a bounded loss, unlike a lost
  // replay set or a lost pin.
  //
  // WITH NO STORE the default below is SYNCHRONOUS and wraps exactly the Maps above, so the
  // no-store path stays byte-identical and `handleRequest` (the sync entry point) keeps
  // working. With a store the message path returns a promise, which `route()` already
  // propagates and `handleRequestAsync` already awaits.
  const memoryStore = {
    seenMessage: (messageId) => replay.checkAndRemember(messageId),
    getAccount: (did) => ledger.get(did) ?? null,
    putAccount: (did, row) => {
      if (row === null) { ledger.delete(did); return; }
      ledger.set(did, row);
      while (ledger.size > maxAccounts) {
        const oldest = ledger.keys().next();
        if (oldest.done) break;
        ledger.delete(oldest.value);
      }
    },
    getDeviceOwner: (deviceDid) => deviceOwner.get(deviceDid) ?? null,
    putDeviceOwner: (deviceDid, ownerDid) => { deviceOwner.set(deviceDid, ownerDid); },
  };
  const state = store ? asStore(store) : memoryStore;
  const storeIsExternal = Boolean(store);
  const anonRate = new RateBound(anonRatePerMin);
  // A tier is ON unless its ceiling is a non-positive or non-finite number. Constructed
  // rather than clamped, so "disabled" is one absent object and never a bound of 0 — which
  // RateBound reads as refuse-everything, the opposite of what an operator passing 0 means.
  const perMin = (n) => (Number.isFinite(Number(n)) && Number(n) > 0 ? Number(n) : 0);
  const signedAccountRate = perMin(signedRatePerMin)
    ? new AccountRateBounds(perMin(signedRatePerMin), maxAccounts) : null;
  const signedTotalRate = perMin(signedRatePerMinTotal)
    ? new RateBound(perMin(signedRatePerMinTotal)) : null;
  let sigEnvelope = null;
  let sigMintedAt = 0;

  // T107: inbound Web Bot Auth, verify-only, against keys GIVEN at construction — the
  // entry never fetches a directory on the hot path (network-free while answering).
  // Refuse-to-start posture, house style: a key the entry can never match is config the
  // operator believes protects them and does not.
  let wbaKeys = null;
  let wbaAuthority = null;
  // DID -> count of WBA-verified GET/HEAD fetches. DECISION 1: a signed GET IDENTIFIES
  // but never ENROLS — a crawler fetching 10,000 pages mints zero ledger rows; this
  // count is bounded by the configured key list, never by attacker choice. Exposed on
  // the returned object like `ledger` (in-process sample state, never on the wire).
  const wbaVisits = new Map();
  if (wbaVerifiers !== null && wbaVerifiers !== undefined) {
    const keys = (wbaVerifiers && typeof wbaVerifiers === 'object'
      && !Array.isArray(wbaVerifiers)) ? wbaVerifiers.keys : null;
    if (!Array.isArray(keys) || keys.length === 0) {
      throw new TypeError('createAgentEntry: wbaVerifiers must be a JWKS document '
        + '{keys:[…]} — the key-directory body you verified out of band');
    }
    if (keys.length > 64) {
      throw new TypeError(`createAgentEntry: wbaVerifiers holds ${keys.length} keys — `
        + 'more than 64 is not a verifier list, it is a directory dump');
    }
    keys.forEach((jwk, i) => {
      if (wbaPublicFromJwk(jwk) === null) {
        throw new TypeError(`createAgentEntry: wbaVerifiers.keys[${i}] is not an `
          + 'Ed25519 OKP JWK (kty "OKP", crv "Ed25519", x = unpadded base64url of '
          + '32 bytes)');
      }
    });
    wbaKeys = { keys: keys.map((k) => ({ kty: k.kty, crv: k.crv, x: k.x })) };
    // @authority derives from the CANONICAL baseUrl, NEVER a Host header — a header a
    // client can set is not a fact about where we were reached. canonUrl already
    // lowercased the host and stripped the scheme's default port, so URL.host IS the
    // RFC 9421 authority (shared/webbotauth.authority_of computes the same string).
    wbaAuthority = new URL(canonUrl).host;
  }

  /** The WBA-verified caller DID for this request's headers, or null. Total on hostile
   *  input; costs one keyid comparison per configured key and an Ed25519 verify only on
   *  a keyid match. */
  function wbaIdentify(headers) {
    if (!wbaKeys) return null;
    return wbaVerifyRequest(headers, { authority: wbaAuthority, jwks: wbaKeys });
  }

  function wbaObserve(headers) {
    const did = wbaIdentify(headers);
    if (did) wbaVisits.set(did, (wbaVisits.get(did) || 0) + 1);
  }

  // family -> stage -> count. OBSERVATION ONLY, and out-of-contract sample state like the
  // ledger's row shape: `stats()` is how a site owner sees who is knocking, it is never
  // served on the wire (a stats route would be new unauthenticated surface leaking traffic
  // composition to any stranger). Keyspace bounded by the fixed UA_FAMILIES table times
  // five stage names — an attacker choosing UA strings cannot grow it.
  const uaStats = new Map();

  function tally(family, stage) {
    let row = uaStats.get(family);
    if (!row) { row = new Map(); uaStats.set(family, row); }
    row.set(stage, (row.get(stage) || 0) + 1);
  }

  /** A plain JSON-able copy of the counters: { family: { stage: n } }. */
  function stats() {
    const out = {};
    for (const [family, row] of uaStats) {
      out[family] = {};
      for (const [stage, n] of row) out[family][stage] = n;
    }
    return out;
  }

  /** The `Link` header the notice route carries. TWO relations with different audiences,
   *  in ONE header field (RFC 8288 allows several link-values in one field, and one field
   *  is what keeps the two twins' bytes identical through their single-header plumbing):
   *
   *    - the DOOR pointer, `rel="https://muretai.net/rel/agent-entry"`, for EVERY caller.
   *      This is the coexistence primitive (E4): an agent that fetched a page finds the
   *      machine-readable door in the RESPONSE, with no HTML to parse and no prose to
   *      read, and a browser ignores it — which is what lets a site keep its own front
   *      page and add ONE header instead of migrating. An absolute URI because RFC 8288
   *      §2.1.2 permits a bare token only for an IANA-registered relation.
   *    - `rel="service-desc"` (RFC 8631's registered relation for "service description …
   *      primarily intended for consumption by machines"), FIRST and only for the UA
   *      families that read as an AI agent — the T119 signpost, unchanged in meaning.
   *
   *  HEADER-ONLY on purpose: the notice BODY is byte-identical for every caller, so what
   *  the UA changes is still only this one additive relation and never a verdict. */
  function steerHeaders(family) {
    const door = `<${mount}${AGENT_CARD_PATH}>; rel="${AGENT_ENTRY_REL}"`;
    if (!AI_AGENT_FAMILIES.has(family)) return { Link: door };
    return { Link: `<${mount}${AGENT_CARD_PATH}>; rel="service-desc", ${door}` };
  }

  /** Which stage a finished POST was, from OBSERVABLES only — the request bytes and the
   *  response we are about to return — so the refusal ladder in `handlePost` stays
   *  byte-untouched by observation. A signed reply whose REQUEST carried metadata.sig is
   *  a signed_post; a signed reply for a request without one is the anonymous lane; every
   *  other outcome (413/400/any JSON-RPC error) is refused_post. Must decide identically
   *  to `_post_stage` in examples/agent_entry_reference.py. */
  function postStage(bodyBuffer, out) {
    let signedReplyOut = false;
    try {
      const body = JSON.parse(out.body.toString('utf8'));
      const result = (body && typeof body === 'object') ? body.result : null;
      const meta = (result && typeof result === 'object') ? result.metadata : null;
      signedReplyOut = Boolean(meta && typeof meta === 'object' && typeof meta.sig === 'string');
    } catch { signedReplyOut = false; }
    if (!signedReplyOut) return 'refused_post';
    let hadSig = false;
    try {
      const req = JSON.parse(bodyBuffer.toString('utf8'));
      const params = (req && typeof req === 'object' && !Array.isArray(req)) ? req.params : null;
      const msg = (params && typeof params === 'object' && !Array.isArray(params))
        ? params.message : null;
      const meta = (msg && typeof msg === 'object' && !Array.isArray(msg)) ? msg.metadata : null;
      hadSig = Boolean(meta && typeof meta === 'object'
        && typeof meta.sig === 'string' && meta.sig);
    } catch { hadSig = false; }
    return hadSig ? 'signed_post' : 'anon_post';
  }

  /** The signed card, re-minted at most hourly. A CONSUMER REJECTS AN ENVELOPE OLDER THAN
   *  6h (and one dated in the FUTURE), so this is a freshness window, not a cache tweak:
   *  without it a saved copy would still "prove" ownership to whoever holds the origin next. */
  function cardEnvelopeBytes() {
    const now = nowEpoch();
    if (!sigEnvelope || now - sigMintedAt >= CARD_SIG_REFRESH_S) {
      sigEnvelope = Buffer.from(JSON.stringify(makeCardEnvelope(seedHex, card, now)), 'utf8');
      sigMintedAt = now;
    }
    return sigEnvelope;
  }

  /** Record contact from an account. Returns the row (or a promise of it, with a store). */
  function noteContact(accountDid) {
    const now = nowEpoch();
    return then1(state.getAccount(accountDid), (row) => {
      if (row) {
        // A store hands back a COPY, so the row must be written home again. The in-memory
        // store hands back the live object and the write is a no-op re-set of the same
        // reference — one code path, correct for both.
        const updated = { ...row, messages: (row.messages || 0) + 1, last_seen: now };
        return then1(state.putAccount(accountDid, updated), () => updated);
      }
      // FIRST CONTACT IS ACCOUNT CREATION. There is no signup form: the sender proved
      // control of a device key one line above, which is strictly more than an email link.
      // The row is keyed by the ACCOUNT (the owner when bound), so sibling devices are one
      // customer.
      const fresh = { first_seen: now, last_seen: now, messages: 1 };
      return then1(state.putAccount(accountDid, fresh), () => fresh);
    });
  }

  /** When a device that ALREADY has an unbound ledger row first proves its owner, move that
   *  row's history into the owner row — ONCE. Never the reverse: a later stripped binding
   *  resolves to the device DID and must not merge, or stripping a binding would become a
   *  way to read the owner's history. */
  function foldDeviceIntoOwner(deviceDid, ownerDid) {
    return then1(state.getAccount(deviceDid), (devRow) => {
      if (!devRow) return undefined;
      return then1(state.putAccount(deviceDid, null), () =>
        then1(state.getAccount(ownerDid), (ownerRow) => {
          if (!ownerRow) return state.putAccount(ownerDid, devRow);
          const merged = {
            ...ownerRow,
            messages: (ownerRow.messages || 0) + (devRow.messages || 0),
            first_seen: Math.min(ownerRow.first_seen, devRow.first_seen),
          };
          return state.putAccount(ownerDid, merged);
        }));
    });
  }

  /**
   * The account (owner) DID this message belongs to (T102) — the JS twin of
   * examples/agent_entry_reference.py::_resolve_account and, one tier up,
   * agent/inbox.py::_resolve_account. Returns { ok:true, account } or { ok:false, reason }.
   * Absent binding → the device DID (`from`), byte-identical to today. Present binding → every
   * check must hold or it FAILS CLOSED with the same UNAUTHENTICATED code and a distinct
   * reason; never a silent downgrade to unbound, never a proven owner handed on unverified.
   * The cheap structural pins produce the distinct reasons; the two signatures are left to
   * `verifyDeviceBindingV2`, the one contract the Python reference re-implements.
   */
  function resolveAccount(binding, from) {
    if (binding === undefined || binding === null) return { ok: true, account: from };
    if (typeof binding !== 'object' || Array.isArray(binding)) {
      return { ok: false, reason: 'attached device binding is malformed' };
    }
    if (binding.typ !== BINDING_V2_TYP) {
      return { ok: false, reason: 'attached device binding has an unsupported typ' };
    }
    if (typeof binding.rootDid !== 'string' || !binding.rootDid) {
      return { ok: false, reason: 'attached device binding names no owner' };
    }
    if (binding.deviceDid !== from) {
      return { ok: false, reason: 'device binding does not name the sender' };
    }
    const { ts, validUntil, rootDid } = binding;
    // `Number.isSafeInteger` is the SAME predicate the Python twin now applies after
    // normalising an integer-valued float: both accept `1` and `1.0`, both refuse a true
    // fraction, and both refuse a magnitude that cannot round-trip (Python because such a
    // float is not integer-valued once it loses precision, JS at the safe-integer bound).
    // They disagreed before: Python refused `1.0` outright while this accepted it, so the
    // same POST created a customer here and 401'd there
    // (ISSUE(agent-entry-binding-float-ts-divergence)).
    if (!Number.isSafeInteger(ts) || !Number.isSafeInteger(validUntil)) {
      return { ok: false, reason: 'device binding timestamps must be integers' };
    }
    const now = nowEpoch();
    if (ts > now + CLOCK_WINDOW_S) {
      return { ok: false, reason: 'device binding ts is in the future' };
    }
    if (validUntil !== 0 && now > validUntil) {
      return { ok: false, reason: 'device binding has expired' };
    }
    if (!verifyDeviceBindingV2(binding, { now, expectedDeviceDid: from })) {
      return { ok: false, reason: 'device binding does not verify' };
    }
    return then1(state.getDeviceOwner(from), (pinned) => {
      if (pinned !== null && pinned !== undefined && pinned !== rootDid) {
        return { ok: false, reason:
          'device is already bound to a different owner (a device DID is never re-owned '
          + '— a new owner means a new device key)' };
      }
      if (pinned === null || pinned === undefined) {
        return then1(state.putDeviceOwner(from, rootDid), () =>
          then1(foldDeviceIntoOwner(from, rootDid), () => ({ ok: true, account: rootDid })));
      }
      return { ok: true, account: rootDid };
    });
  }

  /** The FROZEN backend-handoff shape (agent/webhookwake.py::_envelope). The site's own
   *  code consumes this, so the key set must not drift: a webhook push, a drive-API read
   *  and an agent entry callback all parse with ONE schema. */
  function backendEnvelope(msg, { verified, peerDid, ownerDid = null, wbaDid = null }) {
    const meta = msg.metadata || {};
    return {
      to_agent: name,
      to_did: did,
      direction: 'in',
      verified,
      peer_did: peerDid,
      // T102: the resolved ACCOUNT (owner) DID when a valid v2 binding proved this device
      // belongs to an owner, else null. `peer_did` STAYS the device that signed; sibling
      // devices share one owner_did, which is how a merchant reads them as one account.
      owner_did: ownerDid,
      // T107: the DID whose Web Bot Auth signature covered this REQUEST's transport
      // (@authority + signature-agent), or null. TRANSPORT-LEVEL identification only: it
      // does not prove the DID wrote `text` — `verified`/`peer_did` do that — and a WBA
      // header set is replayable until it expires, so it must never be read as
      // authorship. Additive; null whenever no verifier is configured.
      wba_did: wbaDid,
      peer_name: null,
      context_id: msg.contextId ?? null,
      text: messageText(msg),
      msg_id: msg.messageId ?? null,
      reply_to: meta.replyTo ?? null,
      wire_ts: meta.timestamp ?? null,
      auto: Boolean(meta.auto),
      coord: meta.coordination ?? null,
      deal: meta.deal ?? null,
      group: meta.group ?? null,
    };
  }

  function signedReply(reqId, { text, contextId, timestamp, toDid, replyTo }) {
    const messageId = newId();
    const ts = Number.isSafeInteger(timestamp) ? timestamp : nowEpoch();
    const ctx = contextId ?? null;
    const sig = signEnvelope(seedHex, { from: did, to: toDid, messageId, contextId: ctx,
      timestamp: ts, text });
    const message = toA2A({ role: 'agent', text, messageId, contextId: ctx, timestamp: ts,
      from: did, to: toDid, sig, replyTo });
    return jsonResponse(200, { jsonrpc: '2.0', id: reqId ?? null, result: message });
  }

  function finishReply(reqId, answer, { inbound, toDid }) {
    let text = answer;
    let contextId = inbound.contextId ?? null;
    let timestamp = null;
    if (answer && typeof answer === 'object') {
      text = answer.text;
      // The overrides exist so a test can prove a VISITOR refuses a cross-conversation or
      // stale reply. An honest agent entry never sets them.
      if ('contextId' in answer) contextId = answer.contextId;
      else if ('context_id' in answer) contextId = answer.context_id;
      if ('timestamp' in answer) timestamp = answer.timestamp;
    }
    if (typeof text !== 'string') text = String(text ?? '');
    return signedReply(reqId, { text, contextId, timestamp, toDid,
      replyTo: inbound.messageId });
  }

  /**
   * The POST contract, in EXACTLY this order (agent/inbox.py::verify). The order is
   * load-bearing: an oversized message must cost the recipient nothing to refuse, so the
   * size checks come BEFORE any parsing or crypto — a check placed after the signature is
   * a check the attacker simply skips.
   */
  function handlePost(rawBody, reqHeaders) {
    // RAW BYTES, always. A host app that hands us a decoded string has already destroyed
    // the evidence the strict decode below exists to find, so normalise once and measure
    // the SIZE in bytes rather than in UTF-16 code units.
    const bodyBuffer = Buffer.isBuffer(rawBody) ? rawBody
      : (ArrayBuffer.isView(rawBody)
        ? Buffer.from(rawBody.buffer, rawBody.byteOffset, rawBody.byteLength)
        : Buffer.from(String(rawBody ?? ''), 'utf8'));
    // 1. body over 1 MiB — refused WITHOUT parsing.
    if (bodyBuffer.length > MAX_BODY_BYTES) {
      return jsonResponse(413, { error: 'request body too large' });
    }
    // 2. unparseable or non-object JSON — a transport-level refusal, not a JSON-RPC one.
    //
    // STRICT UTF-8, and `Buffer.toString('utf8')` — what this used to be — is why:
    // it SILENTLY SUBSTITUTES U+FFFD for every invalid byte and parses on, where
    // `shared/protocol.loads` does `raw.decode("utf-8")` and raises. Measured with a valid
    // signature over the six frozen fields and a single raw 0xFF byte in the JSON-RPC `id`
    // (a field no signature covers): the Python reference answered HTTP 400 and booked
    // nothing, this file answered 200, CREATED THE ACCOUNT and returned a signed reply.
    // The class is larger than the id — a substituted byte anywhere means the bytes we
    // verified are not the bytes that arrived, which is precisely the thing a signature is
    // supposed to make impossible to be wrong about. `TextDecoder` with `fatal` is the
    // stdlib's strict decoder (global since Node 11); no dependency is added.
    let req;
    try {
      req = JSON.parse(STRICT_UTF8.decode(bodyBuffer));
    } catch {
      return jsonResponse(400, { error: 'malformed JSON' });
    }
    if (!req || typeof req !== 'object' || Array.isArray(req)) {
      return jsonResponse(400, { error: 'JSON-RPC request must be an object' });
    }
    // 3. From here every refusal is HTTP 200 with a JSON-RPC error object.
    const reqId = safeId(req.id);
    // STRICT, and the `typeof` guard this replaces is why: it short-circuited, so a
    // NON-STRING `method` skipped the check entirely and fell into the message ladder.
    // Measured with a valid signature and a fresh timestamp — `"method": null`, `1` and
    // `{}` each returned a SIGNED REPLY and CREATED AN ACCOUNT here, while the Python
    // reference answered -32601 for all three. That is the double-book class this file's
    // `wireShapeError` docstring is about, one field above where it was looking. An
    // absent method lands here too, which is also -32601 on the Python side.
    if (req.method !== 'message/send') {
      return rpcError(reqId, ERRORS.METHOD_NOT_FOUND,
        'an agent entry implements message/send only');
    }
    // A plain OBJECT, never an Array: `typeof [] === 'object'`, so an array `message` used
    // to reach the shape gate and be refused -32600 where Python answered -32602.
    const params = (req.params && typeof req.params === 'object' && !Array.isArray(req.params))
      ? req.params : null;
    const msg = params ? params.message : null;
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
      return rpcError(reqId, ERRORS.INVALID_PARAMS,
        'params.message must be an A2A message object');
    }
    // 3a. wrongly-TYPED wire fields, on the raw object and before anything measures or
    //     hashes it. These are the fields that end up inside a signed payload — theirs and,
    //     for contextId, ours — so a coercion here is a signature over something the sender
    //     did not say. Same check, same code, same order as the Python reference.
    const shape = wireShapeError(msg);
    if (shape !== null) return rpcError(reqId, ERRORS.INVALID_REQUEST, shape);

    // Absent metadata reads as an empty envelope — the walk-in shape. A PRESENT one that
    // is not an object never gets here: the shape gate above refused it (-32600), so this
    // fallback can no longer turn a malformed envelope into an anonymous one.
    const meta = (msg.metadata && typeof msg.metadata === 'object') ? msg.metadata : {};
    const text = messageText(msg);

    // 3b. text over the 64 KiB ceiling — BEFORE any crypto.
    const over = Buffer.byteLength(text, 'utf8') - MAX_TEXT_BYTES;
    if (over > 0) {
      return rpcError(reqId, ERRORS.MESSAGE_TOO_LARGE,
        `text is ${over} bytes over the ${MAX_TEXT_BYTES}-byte limit`);
    }

    const from = typeof meta.from === 'string' ? meta.from : null;
    const to = typeof meta.to === 'string' ? meta.to : null;
    const sig = typeof meta.sig === 'string' ? meta.sig : null;

    // 4. no signing envelope. The anonymous lane accepts an inquiry that carries NO
    //    envelope at all (a walk-in with no DID); a message that carries a PARTIAL one
    //    (from/to present, sig stripped) is a downgrade attempt and is always refused.
    if (!from || !to || !sig) {
      const bare = !from && !to && !sig;
      if (!(anonymousLane && bare)) {
        // THE REFUSAL TEACHES (E2) — but only the keyless walk-in. `data` keeps the human
        // string it always carried, under `detail`, and gains `accepts[]`: the ways in,
        // as an array, each naming its scheme. A visitor that has only this can mint a
        // did:key, sign the six fields and be answered on its next POST — which is the
        // whole point, because refusing an agent for not having a key it was never told
        // how to make is the error, not the key.
        //
        // A PARTIAL envelope (from/to present, sig stripped) gets the old refusal
        // unchanged. It is a DOWNGRADE ATTEMPT, not a walk-in: whoever sent it already
        // holds a key and already knows the shape, so there is nothing to teach and no
        // reason to hand a prober a machine-readable map of what to try next.
        if (bare) {
          return rpcError(reqId, ERRORS.UNAUTHENTICATED, {
            detail: 'missing signing envelope (from/to/sig)',
            accepts: [requirement],
          });
        }
        return rpcError(reqId, ERRORS.UNAUTHENTICATED, 'missing signing envelope (from/to/sig)');
      }
      // Anonymous: answer, signed by us, addressed to nobody. NO ledger row — an
      // unauthenticated stranger must never be able to mint an account.
      //
      // It runs the SAME ladder as the signed lane, minus the checks that need a key: the
      // body cap, the shape gate and the text cap are the shared code above; the rate bound
      // and the dedup are here. Both refusals cost this agent entry no signature, which is the
      // whole point — the lane used to answer every unsigned repeat of ONE messageId with a
      // fresh signature, an unmetered signing oracle. Freshness is deliberately NOT checked:
      // an unsigned timestamp is a number the sender chose, so refusing an old one buys
      // nothing the dedup does not already buy.
      if (!anonRate.allow()) {
        return rpcError(reqId, ERRORS.RATE_LIMITED,
          `the anonymous lane is limited to ${anonRatePerMin} replies per minute — `
          + 'sign your message to lift the bound');
      }
      return then1(state.seenMessage(msg.messageId, REPLAY_TTL_S), (fresh) => {
        if (!fresh) {
          return rpcError(reqId, ERRORS.REPLAY_REJECTED,
            'duplicate messageId (replay) detected');
        }
        // T107: the interesting case — an anonymous inquiry whose TRANSPORT a known key
        // signed. `verified` STAYS false (the WBA signature covers @authority +
        // signature-agent, not the text), no ledger row is minted (the header set is a
        // bearer credential and replayable while it lives), and the anon rate bound
        // above already applied. Identify, don't enrol.
        return respond(backendEnvelope(msg, { verified: false, peerDid: null,
          wbaDid: wbaIdentify(reqHeaders) }), reqId, msg, '');
      });
    }
    // 5. addressed to someone else. Checked BEFORE decoding `from`, so a junk DID in a
    //    misaddressed message never reaches the base58 decoder.
    if (to !== did) {
      return rpcError(reqId, ERRORS.WRONG_RECIPIENT, `not addressed to me: ${to.slice(0, 24)}…`);
    }
    // 6. an INTEGER epoch, inside the clock window (both directions: a future timestamp is
    //    as unusable as a stale one). Integer is the CONTRACT, not a preference: a float
    //    renders through Python's repr and no other language reproduces those bytes, so a
    //    fractional timestamp is a signature only one implementation could check. A STRING
    //    timestamp lands here too — `Number.isSafeInteger('1786580417')` is false — and the
    //    Python reference now answers the same -32002 instead of coercing it with float()
    //    and accepting.
    //
    //    Note what this check CANNOT see: `JSON.parse` destroys the int/float distinction,
    //    so a body that wrote `1786580417.0` is already the Number 1786580417 here. That is
    //    why the contract makes the canonical INTEGER spelling the thing the signature is
    //    verified against (step 8 signs/verifies `timestamp: ts`, an integer Number): the
    //    float-spelled sender then fails on BOTH implementations with -32001 rather than
    //    being accepted by whichever one happened to keep the original bytes.
    const ts = meta.timestamp;
    if (!Number.isSafeInteger(ts) || Math.abs(nowEpoch() - ts) > CLOCK_WINDOW_S) {
      return rpcError(reqId, ERRORS.REPLAY_REJECTED, 'timestamp out of range (clock skew or replay)');
    }
    // 7. the signature itself, under the key DERIVED FROM `from`. (`messageId`'s type was
    //    settled by the shape gate: a non-string never reaches here on either implementation.)
    const messageId = msg.messageId;
    const fields = { from, to, messageId, contextId: msg.contextId ?? null,
      timestamp: ts, text, sig };
    if (!verifyEnvelope(fields, { recipientDid: did })) {
      return rpcError(reqId, ERRORS.UNAUTHENTICATED, 'signature does not match');
    }
    // 8. duplicate messageId inside the replay window — AFTER the verify, and the ORDER is the
    //    property. The table is state an authenticated sender depends on, so a caller who has
    //    proved nothing must not write into it. Ahead of the verify a stranger could BURN an id
    //    its real sender was about to use, and because the table is capped and evicts
    //    oldest-first, flood past the cap to discard genuine entries and re-open real messages
    //    to replay — invalid signatures are not rate-limited, so that flood is free. This is the
    //    rule the signed lane's ceiling already follows one step below, for the same reason; it
    //    was simply never applied here. The cost of the swap is one Ed25519 verify spent on a
    //    replayed VALID message, which an attacker must first have obtained.
    return then1(state.seenMessage(messageId, REPLAY_TTL_S), (fresh) => {
      if (!fresh) {
        return rpcError(reqId, ERRORS.REPLAY_REJECTED, 'duplicate messageId (replay) detected');
      }

      // 9. T102 account layer. An OPTIONAL countersigned v2 binding collapses an owner's
      //    device DIDs to ONE account; a present-but-INVALID binding fails closed with the
      //    SAME UNAUTHENTICATED code (never a silent downgrade to unbound). Absent → the
      //    device DID.
      return then1(resolveAccount(meta.binding, from), (acct) => {
        if (!acct.ok) return rpcError(reqId, ERRORS.UNAUTHENTICATED, acct.reason);
        const account = acct.account;
        const ownerDid = account !== from ? account : null;

        // 10. THE SIGNED LANE'S CEILING. Here and not earlier: before the signature a
        //     stranger could spend somebody else's budget by naming them, and before
        //     `resolveAccount` an owner's devices would each get their own. Here and not
        //     later: a refused flood must grow neither the ledger nor whatever the
        //     responder costs.
        //     PER-ACCOUNT FIRST, deliberately — one loud peer is then stopped by ITS OWN
        //     window without drawing down the shared one, so it cannot starve everybody
        //     else on its way to being refused. Neither refusal names its ceiling: a
        //     published number is a calibration table telling a flood exactly how many keys
        //     to mint.
        //
        //     These two bounds stay IN PROCESS even with an external store, and that is the
        //     approved design rather than an omission: a ceiling that costs a store write
        //     per request is its own denial of service, and losing a counter fails open for
        //     one minute — bounded, unlike a lost replay set or a lost device pin. A
        //     serverless deployment therefore gets its ceiling per instance; put a real one
        //     at the edge if that matters.
        if (signedAccountRate && !signedAccountRate.allow(account)) {
          return rpcError(reqId, ERRORS.RATE_LIMITED,
            'you are sending faster than this door answers — slow down and retry');
        }
        if (signedTotalRate && !signedTotalRate.allow()) {
          return rpcError(reqId, ERRORS.RATE_LIMITED,
            'this entry is at its ceiling right now — retry shortly');
        }

        return then1(noteContact(account), () =>
          // T107: `wba_did` may legitimately differ from `peer_did` (the transport signer
          // vs the message signer) — both facts are honest, and the schema says which is
          // which.
          respond(backendEnvelope(msg, { verified: true, peerDid: from, ownerDid,
            wbaDid: wbaIdentify(reqHeaders) }), reqId, msg, from));
      });
    });
  }

  /** Hand the envelope to the watcher, and make sure it can cost nothing.
   *
   *  Called BEFORE the responder on purpose: observing that a visit HAPPENED must not
   *  depend on the answer succeeding, or the one request worth counting — the one where
   *  the site's own code threw — is the one that goes uncounted.
   *
   *  Everything here is a refusal to let a watcher matter: the return value is discarded,
   *  a synchronous throw is swallowed, and a returned promise is given a rejection handler
   *  and then DROPPED rather than awaited. That last one is not tidiness — an unhandled
   *  rejection can take a Node process down, so the watcher must not be able to end the
   *  door by failing quietly in the background. */
  function observe(env) {
    if (typeof observer !== 'function') return;
    try {
      const r = observer(env);
      if (isThenable(r)) r.then(undefined, () => {});
    } catch { /* a watcher never changes what this door does */ }
  }

  function respond(env, reqId, msg, toDid) {
    observe(env);
    let answer;
    try {
      answer = responder(env);
    } catch (e) {
      return rpcError(reqId, ERRORS.INTERNAL_ERROR, 'the site backend failed to answer');
    }
    const inbound = { contextId: msg.contextId ?? null, messageId: msg.messageId ?? null };
    if (isThenable(answer)) {
      return answer.then(
        (v) => finishReply(reqId, v, { inbound, toDid }),
        (e) => rpcError(reqId, ERRORS.INTERNAL_ERROR, 'the site backend failed to answer'));
    }
    return finishReply(reqId, answer, { inbound, toDid });
  }

  /** Is this the message endpoint — the base the card's `url` names? EXACT, because a
   *  wandering endpoint is not this contract: with a bare origin that is `/` and nothing
   *  else (byte-for-byte what this module always accepted), and with a mount it is
   *  `/support` plus its trailing-slash spelling, since `card_scope` folds the two and a
   *  visitor may legitimately have been handed either. */
  function isMountPath(pathname) {
    if (!mount) return pathname === '/';
    return pathname === mount || pathname === `${mount}/`;
  }

  /** The GET routes this entry owns, built ONCE from the mount so a request path is a
   *  lookup and never string arithmetic. On a GUEST mount the card is served at the
   *  ORIGIN's well-known paths TOO — that is the only address a stranger's agent knows to
   *  try (RFC 8615), and a door nobody can find is not a door. The card's `url` still names
   *  the DOOR, which is ordinary A2A: the well-known location is where a card is
   *  DISCOVERED, not the endpoint it describes. */
  const CARD_ROUTES = new Set([mount + AGENT_CARD_PATH, mount + AGENT_CARD_PATH_LEGACY]);
  const SIG_ROUTES = new Set([mount + AGENT_CARD_SIG_PATH]);
  if (guestMount) {
    CARD_ROUTES.add(AGENT_CARD_PATH).add(AGENT_CARD_PATH_LEGACY);
    SIG_ROUTES.add(AGENT_CARD_SIG_PATH);
  }

  /** What `Allow:` may truthfully say about THIS path, or null when the entry does not own
   *  it at all. RFC 9110 §10.2.1 makes `Allow` a statement about the target RESOURCE, so a
   *  single server-wide list is a wrong answer to a right question — and on a guest mount
   *  it would be worse than wrong: answering for `/` at all, even with a 204 and a header,
   *  is speaking for the site's own front page, which is the one thing a guest mount must
   *  never do. Whatever the GET route does for an address we do not own (404), OPTIONS and
   *  the method table do the same. */
  function allowFor(pathname) {
    if (CARD_ROUTES.has(pathname) || SIG_ROUTES.has(pathname)) return ALLOW_CARD;
    if (isMountPath(pathname)) return guestMount ? ALLOW_DOOR : ALLOW_MOUNT;
    return null;
  }

  /** The headers that state a resource's methods — BOTH spellings, always the same value.
   *  `Allow` and `Access-Control-Allow-Methods` answer the same question for two different
   *  readers, and a response that says `Allow: POST, OPTIONS` beside
   *  `Access-Control-Allow-Methods: GET, POST, OPTIONS` contradicts itself in one message:
   *  a browser-resident agent preflighting the guest door was told GET was on the menu at
   *  the exact address whose GET is 405. `CORS_HEADERS` stays the origin-wide default
   *  everywhere else (a card GET, a signed reply, a 404); it is narrowed only where the
   *  resource's real method list is known, which is exactly where `Allow` is emitted. */
  function allowHeaders(allow) {
    return { Allow: allow, 'Access-Control-Allow-Methods': allow };
  }

  function route(method, path, bodyBuffer, headers) {
    // Classified ONCE per request, used only to count and to signpost. Everything the
    // ladder decides is decided exactly as if this line did not exist.
    const family = uaFamily(uaOf(headers));
    const target = String(path || '/');
    // ORIGIN FORM ONLY, and SAY SO. HTTP/1.1 lets a client write the request-target in
    // absolute form (`POST http://elsewhere.example/support HTTP/1.1`) and RFC 9112 §3.2.2
    // says a server MUST accept it; this contract deliberately does not, because this entry
    // answers exactly the address its card names and that address has no other spelling.
    // A refusal that is legal-per-RFC to make and illegal-per-RFC to make silently is
    // exactly the one that has to carry a diagnostic: `{"error":"not found"}` for a target
    // an integrator believes is correct costs an afternoon and teaches nothing.
    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(target) || target.startsWith('//')) {
      return jsonResponse(404, { error: 'not found', detail: ORIGIN_FORM_ONLY });
    }
    const pathname = target.split('?')[0].split('#')[0];
    // EVERY route hangs off the mount — the path the signed card already claims. A visitor
    // builds the same strings (Outbox's fetcher keeps the base's path prefix when it
    // appends a well-known path), so this is not a new convention; it is the one the
    // fetcher already follows. With mount === '' these are the original constants.
    if (method === 'GET' || method === 'HEAD') {
      if (CARD_ROUTES.has(pathname)) {
        // Byte-identical on every path: the current A2A path, the legacy alias, and (on a
        // guest mount) the origin's well-known copy of both. Which address a client
        // happened to fetch must never change what it believes about this DID.
        tally(family, 'card_get');
        // T107: identify (count), never enrol, never change a byte. Runs only after a
        // route MATCHED, so refused/404 paths never pay for crypto.
        wbaObserve(headers);
        return { status: 200, headers: cardHeaders(cardBytes.length), body: cardBytes };
      }
      if (SIG_ROUTES.has(pathname)) {
        const env = cardEnvelopeBytes();
        tally(family, 'card_get');
        wbaObserve(headers);
        return { status: 200, headers: cardHeaders(env.length), body: env };
      }
      // The human notice — NOT served on a guest mount, where GET belongs to the site (E3).
      // Falling through to 404 is deliberate and is the same non-disclosure the POST route
      // already makes: an entry beside other agents does not confirm what lives at an
      // address it was not given.
      if (!guestMount && isMountPath(pathname)) {
        tally(family, 'notice_get');
        wbaObserve(headers);
        const body = Buffer.from(
          // "This ADDRESS", not "this origin": once an entry can be mounted under a
          // path, the origin may hold several agents and this notice speaks for exactly
          // one of them. A bare-origin entry reads the same either way.
          `${name}\n\nThis address is agent-reachable (Muretai agent entry).\n`
          + `DID:  ${did}\nCard: ${canonUrl}${AGENT_CARD_PATH}\n`
          + `POST a signed A2A message/send request to ${mount || '/'} for a signed reply.\n`,
          'utf8');
        return { status: 200,
          headers: { 'Content-Type': 'text/plain; charset=utf-8',
            'Content-Length': String(body.length),
            // The ONE wire-visible thing observation adds: an AI-agent UA is pointed at
            // the machine-readable door. The body above is byte-identical either way.
            ...steerHeaders(family) },
          body };
      }
      // A GUEST MOUNT'S DOOR ANSWERS GET WITH 405, NOT 404 (proof run 3, 2026-08-18).
      // Run A guessed the door path CORRECTLY, GET it, and was told nothing was there —
      // its one correct guess, refuted. This is NOT the
      // DECISION(non-door-post-answers-404-not-405) non-disclosure case, and the
      // difference is where the address came from: that decision protects a path a caller
      // GUESSED AT RANDOM, where a 405 would confirm a door it has no right to know about.
      // The door's address is PUBLISHED, in the card, signed, at a well-known path — so
      // hiding it from a GET conceals nothing from anyone and costs a visitor the one
      // thing it got right. `allowFor` is non-null here only for the guest door: card and
      // signature routes matched above, and a site-owning mount already returned its
      // notice. A path this entry does not own still falls through to 404, and a guest
      // mount still answers nothing it does not own.
      const getAllow = allowFor(pathname);
      if (getAllow !== null) {
        return jsonResponse(405, { error: 'method not allowed' }, allowHeaders(getAllow));
      }
      return jsonResponse(404, { error: 'not found' });
    }
    if (method === 'POST') {
      // EXACTLY the address the card names. A POST anywhere else is not this contract —
      // and when this entry is mounted under a path, "anywhere else" INCLUDES the bare
      // host, which belongs to the site (or to the neighbour agent) and not to us.
      if (!isMountPath(pathname)) return jsonResponse(404, { error: 'not found' });
      // A QUERY STRING MEANS THE POST IS NOT OURS. The door's address is the signed
      // card's `url`, byte-exact: a base URL carrying a query is refused at startup, and
      // a visitor's walk drops any query it was handed before it POSTs the card's `url` —
      // so no conformant caller can arrive here, while a site's own query-multiplexed
      // traffic (`?wc-api=`, `?wc-ajax=`, `?rest_route=`) always does. Disjoint BY
      // CONSTRUCTION, which is what makes this a rule and not a heuristic. Measured:
      // WooCommerce Stripe delivers its only webhook to `/?wc-api=wc_stripe` (path `/`,
      // application/json); a bare-origin door that claimed it answered HTTP 200/-32601
      // echoing the event id, the sender recorded the event as delivered and never
      // retried — payment events lost SILENTLY. The answer is the unowned-path 404
      // above, same bytes, one meaning — the DECISION(non-door-post-answers-404-not-405)
      // non-disclosure again, because the caller most likely to land here is the site's
      // own webhook, which deserves the most anonymous answer, never a door verdict.
      const hashless = target.split('#')[0];
      const queryAt = hashless.indexOf('?');
      if (queryAt !== -1 && queryAt + 1 < hashless.length) {
        return jsonResponse(404, { error: 'not found' });
      }
      const buf = bodyBuffer || Buffer.alloc(0);
      const out = handlePost(buf, headers);
      // The stage is read off the finished answer, so an async responder tallies when it
      // resolves. Known micro-skew, accepted: in the misconfigured sync-caller-with-async-
      // responder case `handleRequest` replaces the thenable with -32603 AFTER this wrap,
      // so a stage is tallied for a reply that was then replaced. Sample state only.
      if (isThenable(out)) return out.then((o) => { tally(family, postStage(buf, o)); return o; });
      tally(family, postStage(buf, out));
      return out;
    }
    // Everything below answers for a RESOURCE, so an address this entry does not own is a
    // 404 first — the same answer GET and POST give it. Before this, OPTIONS 204'd for
    // EVERY path (a guest mount would have spoken for the site's front page one verb over)
    // and the 405 carried no `Allow` at all, which RFC 9110 §15.5.6 REQUIRES.
    const allow = allowFor(pathname);
    if (allow === null) return jsonResponse(404, { error: 'not found' });
    if (method === 'OPTIONS') {
      // The CORS PREFLIGHT lands here: a browser-resident agent POSTing application/json
      // is not a simple request, so this answer is what decides whether the POST is ever
      // sent. BOTH method statements narrow to the resource: `Allow` and
      // `Access-Control-Allow-Methods` are the same fact for two readers, and this is the
      // one response where the browser reader acts on it.
      return { status: 204,
        headers: { 'Content-Length': '0', ...CORS_HEADERS, ...allowHeaders(allow) },
        body: Buffer.alloc(0) };
    }
    return jsonResponse(405, { error: 'method not allowed' }, allowHeaders(allow));
  }

  function cardHeaders(length) {
    return {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': String(length),
      // The card and its envelope are public by design: a card is a self-assertion anyone
      // may fetch and re-verify, so there is nothing here to keep from a browser agent.
      ...CORS_HEADERS,
    };
  }

  /** SYNCHRONOUS request handling: (method, path, headers, bodyBuffer) -> {status, headers, body}.
   *  If `responder` returned a Promise, this answers -32603 rather than serializing
   *  "[object Promise]" into a signed reply — use `handleRequestAsync` for an async responder. */
  function handleRequest(method, path, headers, bodyBuffer) {
    const out = route(method, path, bodyBuffer, headers);
    if (isThenable(out)) {
      // Two different causes, and an operator can only fix the one they are told about.
      // A `store` makes EVERY message path async by construction, so saying "responder is
      // async" to somebody who passed a synchronous responder and a KV store would send
      // them looking in the wrong place entirely.
      return rpcError(null, ERRORS.INTERNAL_ERROR, storeIsExternal
        ? 'this entry has an external store, so every message is answered asynchronously — '
          + 'serve it through listen()/handleRequestAsync()'
        : 'responder is async — serve this agent entry through listen()/handleRequestAsync()');
    }
    return out;
  }

  /** Same contract, awaiting an async responder. This is what `listen()` uses. */
  async function handleRequestAsync(method, path, headers, bodyBuffer) {
    return route(method, path, bodyBuffer, headers);
  }

  /**
   * Bind an HTTP server. Defaults to 127.0.0.1 ON PURPOSE: a demo agent entry that binds
   * 0.0.0.0 by accident is a private key answering the whole LAN. Pass a host explicitly
   * (behind a TLS terminator) to go public.
   */
  function listen(port = 8788, host = '127.0.0.1', onReady) {
    const server = createServer({
      // Node checks its request/headers timeouts on an interval, not on a per-connection
      // timer, and the DEFAULT interval is 30 s — so a 20 s bound measured on the wire fires
      // somewhere between 20 s and 50 s. Tightening the interval is what makes the number
      // above the number a stranger actually observes; measured against the trickle, this
      // takes the 408 from ~58 s to ~22 s, next to the Python twin's ~20.6 s.
      connectionsCheckingInterval: 2_000,
      headersTimeout: HEADERS_TIMEOUT_MS,
      requestTimeout: REQUEST_TIMEOUT_MS,
      keepAliveTimeout: KEEPALIVE_TIMEOUT_MS,
    }, (req, res) => {
      const chunks = [];
      let total = 0;
      let oversize = false;
      req.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_BODY_BYTES) {
          // Stop BUFFERING immediately, but keep draining: answering mid-upload makes the
          // client see a connection reset instead of the 413 we are trying to tell it.
          oversize = true;
          if (total > 32 * MAX_BODY_BYTES) { req.destroy(); return; }   // absurd: hang up
          return;
        }
        chunks.push(chunk);
      });
      req.on('error', () => { try { res.destroy(); } catch { /* already gone */ } });
      req.on('end', () => {
        // MAX_BODY_BYTES+1 bytes is all `handlePost` needs to make the same 413 decision,
        // so the size rule lives in ONE place instead of two that can drift. The sentinel
        // is allocated at most ONCE per process (and only if someone actually sends an
        // oversize body) — minting a fresh 1 MiB buffer per refusal would hand the
        // attacker the very allocation the 413 exists to refuse.
        const body = oversize ? oversizeSentinel() : Buffer.concat(chunks, total);
        Promise.resolve()
          .then(() => handleRequestAsync(req.method, req.url, req.headers, body))
          .catch(() => rpcError(null, ERRORS.INTERNAL_ERROR, 'the entry failed to answer'))
          .then(({ status, headers, body: out }) => {
            res.writeHead(status, headers);
            res.end(req.method === 'HEAD' ? undefined : out);
          })
          .catch(() => { try { res.destroy(); } catch { /* already gone */ } });
      });
    });
    // Also as properties, for a Node old enough to ignore the options above. Explicit
    // rather than inherited: Node's defaults are generous (300 s / 60 s / 5 s) and unstated,
    // and the Python twin has to spell the same numbers out anyway. Writing them in both
    // files is what makes "the two entries bound a stranger identically" a fact a reader can
    // check instead of a claim.
    server.headersTimeout = HEADERS_TIMEOUT_MS;
    server.requestTimeout = REQUEST_TIMEOUT_MS;
    server.keepAliveTimeout = KEEPALIVE_TIMEOUT_MS;
    // The CONNECTION CEILING. There is no Node default, and the timeouts above do not
    // supply one: they bound how LONG each connection lives, not how MANY exist at once.
    // Written by hand rather than with `server.maxConnections`, which DESTROYS the socket
    // silently — an unauthenticated stranger always gets an HTTP response here (the promise
    // in docs/AGENT_ENTRY.md), an operator behind a proxy gets a 503 in the log instead of
    // "upstream closed the connection", and the Python twin can say the same sentence.
    let live = 0;
    server.on('connection', (socket) => {
      live += 1;
      socket.once('close', () => { live -= 1; });
      if (live > MAX_CONNECTIONS) socket.end(OVERLOADED_RESPONSE);
    });
    server.listen(port, host, () => { if (onReady) onReady(server); });
    return server;
  }

  // `mount` is exported so a host app can route exactly what this entry answers (and log
  // it): it is derived, so reading it here can never disagree with the signed card.
  // `stats` is the owner-facing UA-family counters and `wbaVisits` the DID->count of
  // WBA-verified fetches — both in-process only, like `ledger`.
  return { did, card, ledger, mount, stats, wbaVisits,
    handleRequest, handleRequestAsync, listen,
    cardEnvelope: () => JSON.parse(cardEnvelopeBytes().toString('utf8')) };
}

/** The A2A text of a message: every `text` part, joined by newline (Message.from_a2a). */
function messageText(msg) {
  const parts = Array.isArray(msg.parts) ? msg.parts : [];
  return parts
    .filter((p) => p && typeof p === 'object' && p.kind === 'text')
    .map((p) => (typeof p.text === 'string' ? p.text : ''))
    .join('\n');
}
