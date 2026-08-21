/**
 * tests/serve-local.mjs — run the SHARED handler over plain Node, so it can be judged.
 *
 * Neither Vercel nor Netlify can be run here without their CLIs and an account, but the
 * code that actually answers a stranger is `shared/handler.mjs` plus a store — and that is
 * platform-independent by construction, because both platforms hand a function a Web
 * `Request` and take a Web `Response`. This harness supplies exactly that, so
 * `receptor_check.py` can judge the real handler.
 *
 * WHAT THIS PROVES AND WHAT IT DOES NOT. It proves the handler and the store adapters obey
 * the contract. It does NOT exercise Vercel's `rewrites` or Netlify's `config.path` — the
 * routing layer that decides which requests reach the handler at all. Those are reviewed,
 * not executed, and that limit is stated in the repo README rather than glossed.
 *
 *     STORE=blob  node tests/serve-local.mjs 8093
 *     STORE=redis node tests/serve-local.mjs 8094     (against a fake REST endpoint)
 */

import { createServer } from 'node:http';
import { buildEntry, toWebHandler } from '../shared/handler.mjs';
import { blobStore } from '../shared/blob-store.mjs';
import { restKvStore } from '../shared/rest-kv-store.mjs';

const port = Number(process.argv[2] || 8093);
const which = process.env.STORE || 'blob';

// ------------------------------------------------------------------ fake backends
//
// In-memory stand-ins with the SAME surface the real services expose, so the adapter code
// under test is the real adapter code — only the network is faked.

/** Netlify Blobs' get/setJSON/set/delete/list surface. */
function fakeBlobs() {
  const m = new Map();
  return {
    async get(key, opts) {
      if (!m.has(key)) return null;
      const raw = m.get(key);
      return opts && opts.type === 'json' ? JSON.parse(raw) : raw;
    },
    async set(key, value) { m.set(key, String(value)); },
    async setJSON(key, value) { m.set(key, JSON.stringify(value)); },
    async delete(key) { m.delete(key); },
    async list({ prefix } = {}) {
      return { blobs: [...m.keys()].filter((k) => !prefix || k.startsWith(prefix))
        .map((key) => ({ key })) };
    },
  };
}

/** An Upstash-compatible REST endpoint, implementing only the four commands the adapter
 *  sends — including SET's NX and EX options, which is the behaviour that matters. */
function fakeRedisServer() {
  const m = new Map();                            // key -> { v, exp|null }
  const alive = (e) => e && (e.exp === null || e.exp > Date.now() / 1000);
  const srv = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const args = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const [op, key, ...rest] = args;
      let result = null;
      if (op === 'SET') {
        const value = rest[0];
        const nx = rest.includes('NX');
        const exAt = rest.indexOf('EX');
        const ttl = exAt >= 0 ? Number(rest[exAt + 1]) : null;
        const cur = m.get(key);
        if (nx && alive(cur)) {
          result = null;                          // existed: SET NX declines
        } else {
          m.set(key, { v: value, exp: ttl ? Date.now() / 1000 + ttl : null });
          result = 'OK';
        }
      } else if (op === 'GET') {
        const cur = m.get(key);
        result = alive(cur) ? cur.v : null;
      } else if (op === 'DEL') {
        result = m.delete(key) ? 1 : 0;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result }));
    });
  });
  return srv;
}

// ------------------------------------------------------------------ boot

const env = {
  ...process.env,
  AGENT_ENTRY_BASE_URL: process.env.AGENT_ENTRY_BASE_URL || `http://127.0.0.1:${port}`,
  AGENT_ENTRY_NAME: 'Serverless Desk',
  AGENT_ENTRY_REPLY: 'answered from a serverless function',
};

async function main() {
  let store;
  if (which === 'redis') {
    const fake = fakeRedisServer();
    await new Promise((r) => fake.listen(0, '127.0.0.1', r));
    env.KV_REST_API_URL = `http://127.0.0.1:${fake.address().port}`;
    env.KV_REST_API_TOKEN = 'test-token';
    store = restKvStore(env);
  } else {
    store = blobStore(fakeBlobs());
  }

  let ENTRY = null;
  const handler = toWebHandler(() => {
    if (!ENTRY) ENTRY = buildEntry(env, store);
    return ENTRY;
  });

  createServer(async (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const body = Buffer.concat(chunks);
      const request = new Request(`http://127.0.0.1:${port}${req.url}`, {
        method: req.method,
        headers: req.headers,
        body: ['GET', 'HEAD'].includes(req.method) ? undefined : body,
      });
      const out = await handler(request);
      const headers = {};
      out.headers.forEach((v, k) => { headers[k] = v; });
      res.writeHead(out.status, headers);
      const buf = Buffer.from(await out.arrayBuffer());
      res.end(buf);
    });
  }).listen(port, '127.0.0.1', () => {
    console.log(`ready store=${which} http://127.0.0.1:${port}`);
  });
}

main();
