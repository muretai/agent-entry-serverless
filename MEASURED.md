# What was measured, and what was not

Every claim in this repo's README that a runtime "works" is one of the rows below. Rows
that say *reviewed, not executed* are exactly that, and are not dressed up as anything
else.

Measured 2026-08-21. Re-measured later the same day for the **query-string rule** — see the
section at the end.

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
judged over HTTP by `node tests/check-live.mjs --handshake` (which ships in this repo):
**40/40, 0 failed** — the same verdict the Node, Python, and PHP implementations get. (The
checker had 40 checks at the time; it now has 42 — see the query-string section below for
what was and was not re-run.)

Not measured: a deploy to Cloudflare's actual edge. Local workerd is the same engine, but
it is not the same network, and a zone in front of it can still refuse agents — see the
Browser Integrity Check warning in the README.

## Vercel and Netlify — HANDLER EXECUTED, PLATFORM ROUTING REVIEWED

An earlier version of this file asserted that "both platforms hand a function a Web Request
… platform-independent by construction". **That was wrong, and it caused a bug**, so it is
worth stating plainly rather than quietly deleting.

Vercel does not decide the calling convention by the platform; it decides it by INSPECTING
THE EXPORT. Its launcher looks for `.fetch` or a named HTTP-method export and treats
anything else callable as the classic `(req, res)` Node signature. The first cut here
exported a bare function, so Vercel would have called it as `(req, res)`: `new
URL(request.url)` throws on a bare path, the returned `Response` is discarded, and the
invocation hangs. One of three advertised targets, dead on its first request.

That is now a test, run against @vercel/node's own detection code rather than against the
documentation:

| probe | result |
|---|---|
| Vercel's launcher detects `vercel/api/entry.mjs` as a WEB handler | **yes** |
| invoked the way Vercel invokes it, the card is served | **HTTP 200, valid did:key** |
| the same test against the old bare-function export | **fails** (regression guard) |

Run it with `node tests/check-vercel-shape.mjs`, or `npm test` for that plus the
copy-drift check.

Netlify was always correct: `export default async (req) => Response` IS the Functions v2
signature.

The code that actually answers a stranger — `lib/handler.mjs` plus a store adapter — was
executed over plain Node (`tests/serve-local.mjs`) against in-memory backends implementing
the same surfaces the real services expose, and judged by `tests/check-live.mjs`:

| store adapter | verdict |
|---|---|
| `netlify/lib/blob-store.mjs` (Netlify Blobs surface) | **42/42, 0 failed** |
| `vercel/lib/rest-kv-store.mjs` (Upstash/Vercel KV REST) | **42/42, 0 failed** |

**Still not executed:** `vercel.json` rewrites and Netlify's `config.path` export — the
routing layer that decides which requests reach the handler at all — and the real network
services behind either store. Neither CLI is installed here and both need an account. If you
deploy one of these, run the checker against your URL and you will know in thirty seconds:

```bash
node tests/check-live.mjs --handshake https://your-deployment.example
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

## The query-string rule (re-measured 2026-08-21)

The library now refuses to claim a POST whose request-target carries a query string — the
door's address is the signed card's `url`, byte-exact and query-less, while a site's
query-multiplexed routes (`?wc-api=` payment webhooks above all) always carry one. The
checker gained two probes for it: a webhook-shaped JSON POST with a query, and a correctly
signed message with one, must both earn anything BUT a door protocol verdict.

**The probes immediately found a real bug in all three templates here.** Each adapter handed
the library `url.pathname` — the query already stripped — so the library's refusal could
never fire, and a door built from these templates would have kept eating webhook-shaped
POSTs even though its vendored library was correct. Fixed by handing over the full
request-target (`url.pathname + url.search`) in `vercel/lib/handler.mjs`,
`netlify/lib/handler.mjs`, and `workers/src/worker.mjs`. A library can only refuse what its
adapter shows it; this is the second adapter-boundary bug in this repo (the first was the
Vercel export shape), and both were invisible to every test that exercised the library
alone.

| probe | result |
|---|---|
| blob adapter, full serve-local battery | **42/42, 0 failed** |
| redis/kv adapter, full serve-local battery | **42/42, 0 failed** |
| JSON webhook POST to `/?check=1` | falls through — no door verdict |
| correctly signed message POSTed to `/?x=1` | falls through — no door verdict |

Not re-run: the workerd (`wrangler dev --local`) pass — the change is pure request routing
with no new platform API, and the routing layer it changes (`worker.mjs`) is exercised here
over plain Node. The `vercel.json` rewrites and Netlify `config.path` remain reviewed, not
executed, as above; note that both platforms preserve the query string when routing to a
function, which is exactly why the adapter must not strip it.
