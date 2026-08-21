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

Then confirm it with something that is not this repo:

```bash
python3 receptor_check.py --handshake https://your-deployment.example
```

`receptor_check.py` is in the muretai core repo (`tools/receptor_check.py`). It speaks only
HTTP, so it judges your door the way a stranger does. Read-only by default; `--handshake`
also sends a real signed message and the full refusal battery.

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

[MEASURED.md](MEASURED.md) lists exactly what was executed and what was only reviewed. Short
version: the Workers template was run on real workerd and scores 39/39 against the
independent checker; the Vercel and Netlify **handlers and store adapters** were executed
and also score 39/39, while their **platform routing config** (`vercel.json` rewrites,
Netlify's `config.path`) was reviewed and not executed, because neither CLI is installed
here and both need an account.

## Layout

```
shared/handler.mjs         one Request -> Response handler; Vercel and Netlify both use it
shared/rest-kv-store.mjs   Upstash/Vercel KV over REST, zero dependencies
shared/blob-store.mjs      Netlify Blobs
shared/muretai-agent-entry.mjs   the library (vendored, unmodified)
workers/                   Cloudflare: its own worker + KV adapter
vercel/                    api route + rewrites
netlify/                   function + routing via config.path
tests/serve-local.mjs      runs the shared handler over plain Node so a checker can judge it
```

## Licence

MIT, matching the library.
