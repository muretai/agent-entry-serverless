/**
 * rest-kv-store.mjs — Agent Entry state on any Upstash-compatible Redis REST API.
 *
 * WHY REST AND NOT A CLIENT LIBRARY. This is the store Vercel provisions (its KV product is
 * Upstash Redis underneath) and it is reachable with nothing but `fetch`, so this adapter
 * has ZERO dependencies and cannot rot when a vendor renames its SDK. It works unchanged
 * against Upstash directly, so a template user is not locked to one host.
 *
 * THE ONE THING THAT MATTERS HERE IS `seenMessage`, and Redis gives it to us properly:
 * `SET key value NX EX ttl` is an atomic test-and-set. It returns OK only if the key did
 * not exist, which is exactly "was this messageId new?" — no read-then-write race, unlike a
 * plain key-value store with no conditional put. That is worth knowing when comparing this
 * to the Workers KV template, which cannot make the same promise.
 *
 * Environment: `KV_REST_API_URL` and `KV_REST_API_TOKEN` — the names Vercel injects, and
 * the same pair Upstash gives you.
 */

function requireEnv(env) {
  const url = env.KV_REST_API_URL;
  const token = env.KV_REST_API_TOKEN;
  if (!url || !token) {
    throw new Error(
      'KV_REST_API_URL and KV_REST_API_TOKEN are not set. Without a store this door forgets '
      + 'every device pin and every replayed messageId at each cold start, which silently '
      + 'disables two security rules — so it refuses to run rather than pretend.');
  }
  return { url: url.replace(/\/+$/, ''), token };
}

/** One Redis command over the REST API. Commands are sent as a JSON array, Upstash's
 *  documented form, which keeps arguments out of the URL path and therefore out of logs. */
async function cmd(env, args) {
  const { url, token } = requireEnv(env);
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  });
  if (!res.ok) {
    // Fail LOUDLY. A store error that returned a soft default would look, from the door's
    // side, exactly like "this messageId is new" — turning an outage into a replay window.
    throw new Error(`kv command failed: ${res.status} ${await res.text()}`);
  }
  const body = await res.json();
  return body.result;
}

export function restKvStore(env) {
  return {
    async seenMessage(messageId, ttl) {
      // SET NX EX: atomic. `result` is "OK" when the key was created, null when it existed.
      const r = await cmd(env, ['SET', `replay:${messageId}`, '1', 'NX', 'EX',
        String(ttl || 600)]);
      // Redis answers 'OK' when it created the key and null when it already existed. Those
      // are the ONLY two answers this means anything for, so anything else is treated as a
      // failure rather than as "new" — a proxy returning some other 200 body must not be
      // able to turn the replay guard off.
      if (r === 'OK') return true;
      if (r === null) return false;
      throw new Error(`kv SET NX returned an unexpected result: ${JSON.stringify(r)}`);
    },

    async getAccount(did) {
      const raw = await cmd(env, ['GET', `acct:${did}`]);
      if (raw === null || raw === undefined) return null;
      try { return typeof raw === 'string' ? JSON.parse(raw) : raw; }
      catch { return null; }
    },

    async putAccount(did, row) {
      if (row === null) {
        await cmd(env, ['DEL', `acct:${did}`]);
        return;
      }
      // No expiry: the ledger is the customer list, and a row that quietly expired would
      // turn a returning customer back into a stranger.
      await cmd(env, ['SET', `acct:${did}`, JSON.stringify(row)]);
    },

    async getDeviceOwner(deviceDid) {
      const r = await cmd(env, ['GET', `pin:${deviceDid}`]);
      return r === undefined ? null : r;
    },

    async putDeviceOwner(deviceDid, ownerDid) {
      // No expiry, and for a sharper reason than the ledger's: an expiring pin IS
      // re-ownership on a timer, and the rule is that a device DID is never re-owned.
      await cmd(env, ['SET', `pin:${deviceDid}`, ownerDid]);
    },
  };
}
