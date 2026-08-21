# Agent Entry on serverless

Three ready-to-deploy templates that make a site **answerable by an AI agent** — Cloudflare
Workers, Vercel, and Netlify.

An agent that has nothing but your URL can prove who it is talking to, send you a signed
message, and get a signed answer back in the same request. No account, no API key, no third
party in the middle.

```
GET  /.well-known/agent-card.json      who this site is (name, DID, how to reach it)
GET  /.well-known/agent.json           the same bytes, at the older path
GET  /.well-known/agent-card.sig.json  proof: this key owns this origin
POST /                                 the door — signed message in, signed reply out
```

| template | store | atomic replay guard |
|---|---|---|
| [`workers/`](workers) | Workers KV | no — see [MEASURED.md](MEASURED.md) |
| [`vercel/`](vercel) | Vercel KV / Upstash Redis (REST, zero deps) | **yes** |
| [`netlify/`](netlify) | Netlify Blobs | no — see [MEASURED.md](MEASURED.md) |

## Why serverless suits this

One signed POST in, one signed reply out, nothing to keep awake — the shape fits a function
exactly. What does *not* fit is the state: three of the door's rules are stateful, and a
function instance keeps nothing between requests.

- the **replay set** — lose it and any message inside the freshness window can be replayed
  after a cold start
- the **device → owner pins** — lose them and the no-re-ownership rule resets to
  trust-on-first-use, so a device pinned to owner A can be re-claimed by owner B
- the **ledger** — lose it and a returning customer looks like a stranger every time

So each template is the same library plus one small store adapter. That adapter is the only
thing these templates add, and it is the only thing worth reading.

## Deploy

### 1. Make a key

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

This is your site's identity. Keep it in the platform's **encrypted secret** store — never
in a committed file. If you lose it your site gets a new identity and every peer that
recorded the old one is talking to a stranger.

### 2. Set two variables

| variable | what it is |
|---|---|
| `AGENT_ENTRY_SEED_HEX` | the key from step 1. A **secret**, not a plain variable. |
| `AGENT_ENTRY_BASE_URL` | the **public address a visitor dials** |

`AGENT_ENTRY_BASE_URL` is the one that catches people. It is signed into the Agent Card, and
a visitor **refuses** a card that names an origin other than the one they dialled. Set it to
your real domain, not the preview URL, or every verification fails on their machine with
nothing visibly wrong on yours.

### 3. Deploy, then check

```bash
# Cloudflare
cd workers
wrangler kv namespace create AGENT_ENTRY_KV     # paste the id into wrangler.toml
wrangler secret put AGENT_ENTRY_SEED_HEX
wrangler deploy

# Vercel: set KV_REST_API_URL and KV_REST_API_TOKEN (its KV product injects both), then
#   vercel deploy
# Netlify: Blobs needs no provisioning, then
#   netlify deploy --prod
```

Then confirm it, with a checker that ships here and needs nothing you do not already have:

```bash
node tests/check-live.mjs --handshake https://your-deployment.example
```

It speaks only HTTP, so it judges your door the way a stranger does: fetches the card,
verifies its signature and freshness, checks that the card names the origin you dialled,
walks the CORS and method rules, and — with `--handshake` — sends a real signed message and
every forged variant a door must refuse. Read-only without the flag. Exit status gates a
deploy.

## Two things that will bite you

**1. A CDN can refuse every agent while serving humans perfectly.** On Cloudflare the
setting is **Browser Integrity Check** — a *zone* setting, on by default on the free plan —
and it 403s clients whose user agent looks automated, which is all of them. Your site looks
fine in a browser the whole time. Add an exception matching on **host, method and path
only**, never on user agent, which is the thing being wrongly judged.

**Do not test with `curl`.** It sends its own user agent and sails through the check that is
blocking everyone else, so a green `curl` proves nothing. Use the checker above.

**2. The signed card expires after six hours.** The library re-mints it hourly, in process.
That is fine on any of these platforms because the mint happens on demand, when the signed
card is requested — but it is also why a purely static file can never be an Agent Entry: the
bytes expire and something holding the key has to replace them.

## What your site says back

The default is an acknowledgement. Replace the `responder` with your own logic — a price, an
availability, a lookup in your own data. `envelope.peer_did` is the **verified** sender; the
signature has already been checked by the time you see it.

Deliberately not a model call. A door that reached for an LLM on every inbound message would
hand a stranger your bill. Call your own model inside the responder, where you set the
budget.

## What this does not do

It makes your site **reachable**, not **findable**. Agents still arrive the way they do
today — a search result, a link, a person telling them where to go. Anyone promising that a
file on your server brings agent traffic is selling something.

## Honesty about testing

[MEASURED.md](MEASURED.md) lists exactly what was executed and what was only reviewed, and
it records the one claim that was wrong the first time round and the bug that followed from
it. Short version: the Workers template runs on real workerd and scored a clean sweep
against the in-repo checker; the Vercel and Netlify **handlers and store adapters** were
executed and score 42/42; Vercel's handler SHAPE is checked against @vercel/node's own
detection code; and the **platform routing config** (`vercel.json` rewrites, Netlify's
`config.path`) was reviewed and not executed, because neither CLI is installed here and
both need an account. MEASURED.md also records the adapter bug the newest probes caught:
all three templates handed the library a query-stripped path, which would have let a door
keep eating `?wc-api=`-shaped webhooks even with a correct library underneath.

## Layout

```
workers/     wrangler.toml + src/{worker,store,muretai-agent-entry}.mjs
vercel/      vercel.json  + api/entry.mjs + lib/{handler,rest-kv-store,muretai-agent-entry}.mjs
netlify/     netlify.toml + netlify/functions/entry.mjs + lib/{handler,blob-store,…}.mjs
tests/       check-live.mjs (judge a deployed door) · check-sync.mjs · check-vercel-shape.mjs
             serve-local.mjs (run a template's handler on plain Node)
```

**Each template directory is self-contained on purpose.** You can copy just the one you want
and deploy it, and — more importantly — a platform told to build from a subdirectory cannot
reach a shared folder above it. An earlier layout put the library in a top-level `shared/`,
which would have failed the moment anyone set a root directory on Vercel or Netlify.

The price is three copies of the library, and the price of copies is drift, so
`npm test` fails if they stop matching.

### About the vendored library

`muretai-agent-entry.mjs` is a copy of muretai's Agent Entry library, MIT-licensed, included
so these templates deploy with no install step. It is **a build that includes the `store`
option** these templates depend on.

Do not replace it with an older published copy of `@muretai/agent-entry` and expect the same
behaviour: versions without the `store` seam accept the option and silently **ignore** it,
which drops the replay set, the device pins and the ledger back into per-instance memory —
the exact three failures this repo exists to prevent — with no error and nothing failing.

## Licence

MIT, matching the library.
