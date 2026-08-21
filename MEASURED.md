# What was measured, and what was not

Every claim in this repo's README that a runtime "works" is one of the rows below. Rows
that say *reviewed, not executed* are exactly that, and are not dressed up as anything
else.

Measured 2026-08-21.

## Cloudflare Workers — EXECUTED

Run under **workerd** (`wrangler dev --local`, wrangler 4.50.0), which is the same runtime
engine Cloudflare runs in production, with `compatibility_flags = ["nodejs_compat"]`.
Requested compatibility date `2026-08-01`; the installed runtime capped it at
`2025-11-18` and said so, so that is the date the template pins.

| probe | result |
|---|---|
| `didFromSeedHex` | works |
| `canonicalJSON` (non-ASCII, literal UTF-8) | works — `{"a":"群れたい","b":1}` |
| `signEnvelope` (Ed25519) | works |
| `verifyEnvelope` | works |
| `makeCardEnvelope` | works |
| `createAgentEntry` | works |
| **full signed door round trip** | **works — signed reply produced and verified** |
| `node:crypto.diffieHellman` (X25519; relay/E2E only, not the door) | **present** |

This settles the open question the core backlog recorded (T105): the concern was that
`nodejs_compat` might not carry the raw X25519 agreement. It does, and the door never
needed it anyway.

The **full template** (`workers/`, with real Workers KV via wrangler's local KV) was then
judged over HTTP by `tools/receptor_check.py --handshake` from the muretai core repo:
**39/39, 0 failed** — the same verdict the Node, Python, and PHP implementations get.

Not measured: a deploy to Cloudflare's actual edge. Local workerd is the same engine, but
it is not the same network, and a zone in front of it can still refuse agents — see the
Browser Integrity Check warning in the README.

## Vercel and Netlify — HANDLER EXECUTED, PLATFORM ROUTING REVIEWED

Both platforms hand a function a Web `Request` and take a Web `Response`, so the code that
actually answers a stranger — `shared/handler.mjs` plus a store adapter — is
platform-independent by construction. That code was run over plain Node
(`tests/serve-local.mjs`) against in-memory backends implementing the same surfaces the real
services expose, and judged by the same checker:

| store adapter | verdict |
|---|---|
| `shared/blob-store.mjs` (Netlify Blobs surface) | **39/39, 0 failed** |
| `shared/rest-kv-store.mjs` (Upstash/Vercel KV REST) | **39/39, 0 failed** |

**Not executed:** `vercel.json` rewrites and Netlify's `config.path` export — the routing
layer that decides which requests reach the handler at all — and the real network services
behind either store. Neither CLI is installed here and both need an account. If you deploy
one of these, run the checker against your URL and you will know in thirty seconds:

```bash
python3 receptor_check.py --handshake https://your-deployment.example
```

## The replay rule is not equally strong on all three

`seenMessage` must be an atomic test-and-set, and the three backends do not offer the same
guarantee. This is a real difference, so it is stated here rather than buried:

| backend | atomic? | consequence |
|---|---|---|
| Upstash / Vercel KV (Redis) | **yes** — `SET key val NX EX ttl` | correct under concurrency |
| Workers KV | no conditional put | under a genuine race, one messageId can be admitted twice |
| Netlify Blobs | no conditional put | same, plus expiry is carried in the value and swept by hand |

For the two non-atomic backends the attacker must already hold a captured, still-fresh
signed message, and the window is small — but "small" is not "closed". If that matters for
your door, use the Redis adapter (it works unchanged from any of the three platforms) or,
on Cloudflare, swap Workers KV for Durable Objects, which give a real single-writer
test-and-set. Nothing else in the template changes.
