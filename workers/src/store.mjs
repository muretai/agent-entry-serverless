/**
 * store.mjs — the Agent Entry state, in Workers KV.
 *
 * WHY THIS FILE IS THE WHOLE POINT OF THE TEMPLATE. A serverless instance keeps nothing
 * between requests, and three of the door's rules are stateful:
 *
 *   - the REPLAY set. Lose it and every message inside the freshness window can be
 *     replayed after a cold start.
 *   - the DEVICE -> OWNER pins. Lose them and the no-re-ownership rule resets to
 *     trust-on-first-use, so a device pinned to owner A can be re-claimed by owner B.
 *   - the LEDGER. Lose it and a returning customer looks like a stranger every time.
 *
 * So the shape suits serverless — one signed POST in, one signed reply out, nothing to keep
 * awake — and only the state has to move. That is what this adapter does, and it is the
 * only thing this template adds to the library.
 *
 * ON KV'S CONSISTENCY, honestly. Workers KV is eventually consistent and has no atomic
 * test-and-set, so `seenMessage` here can, under a genuine race between two colo regions,
 * admit the same messageId twice. That is a real weakening of the replay rule and it is
 * stated rather than hidden: KV is the right default because it is free, global and
 * requires no extra service, and the replay window is 600 seconds of a message an attacker
 * must first have captured. If your door is worth attacking that way, swap this adapter for
 * Durable Objects, which give you a real single-writer test-and-set. The rest of the
 * template does not change.
 */

/** Seconds a messageId is remembered. Matches the library's REPLAY_TTL_S. */
const REPLAY_TTL_S = 600;

/** KV's own minimum TTL. A shorter expiry is rejected outright, so the replay entry is
 *  kept for the longer of the two — never the shorter, which would silently shrink the
 *  window the door believes it has. */
const KV_MIN_TTL_S = 60;

export function kvStore(kv) {
  if (!kv) {
    throw new Error(
      'No KV namespace bound. Create one and bind it as AGENT_ENTRY_KV — without it the '
      + 'door forgets every replayed message and every device pin at each cold start.');
  }
  return {
    async seenMessage(messageId, ttl) {
      const key = `replay:${messageId}`;
      const existing = await kv.get(key);
      if (existing !== null) return false;
      await kv.put(key, '1', {
        expirationTtl: Math.max(KV_MIN_TTL_S, ttl || REPLAY_TTL_S),
      });
      return true;
    },

    async getAccount(did) {
      return kv.get(`acct:${did}`, 'json');
    },

    async putAccount(did, row) {
      if (row === null) {
        await kv.delete(`acct:${did}`);
        return;
      }
      // No expirationTtl: the ledger is the customer list. A row that quietly expired
      // would turn a returning customer back into a stranger, which is the one thing the
      // account layer exists to prevent.
      await kv.put(`acct:${did}`, JSON.stringify(row));
    },

    async getDeviceOwner(deviceDid) {
      return kv.get(`pin:${deviceDid}`);
    },

    async putDeviceOwner(deviceDid, ownerDid) {
      // Also never expires, and for a sharper reason: an expiring pin IS re-ownership on a
      // timer. The rule is that a device DID is never re-owned, so the pin outlives
      // everything.
      await kv.put(`pin:${deviceDid}`, ownerDid);
    },
  };
}
