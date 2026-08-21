/**
 * blob-store.mjs — Agent Entry state in Netlify Blobs.
 *
 * Netlify Blobs is the platform-native durable store and needs no extra service to
 * provision, which is why it is the default here.
 *
 * BE CLEAR-EYED ABOUT `seenMessage`. Blobs has no atomic test-and-set and no server-side
 * expiry, so this adapter does read-then-write and carries its own expiry timestamp inside
 * the value. Two consequences, both stated rather than hidden:
 *
 *   1. Under a genuine concurrent race, the same messageId can be admitted twice. The
 *      window is small and the attacker must already hold a captured, still-fresh signed
 *      message — but it is a real weakening of the replay rule compared with the Redis
 *      adapter, whose `SET NX EX` is atomic.
 *   2. Expired entries are not reclaimed by the platform, so `seenMessage` deletes the one
 *      key it looked at when it finds it stale. Keys nobody asks about again accumulate;
 *      run `sweep()` from a scheduled function if your door is busy.
 *
 * If the replay rule is load-bearing for your deployment, point the Vercel/Upstash Redis
 * adapter (`rest-kv-store.mjs`) at it instead — it works from Netlify unchanged, and it is
 * the only one of the two that can promise atomicity.
 */

/** Blob keys may not contain characters that would confuse a path; a DID contains none,
 *  but a messageId comes from a stranger, so it is encoded rather than trusted. */
const safe = (s) => encodeURIComponent(String(s));

export function blobStore(store) {
  return {
    async seenMessage(messageId, ttl) {
      const key = `replay/${safe(messageId)}`;
      const now = Math.floor(Date.now() / 1000);
      const existing = await store.get(key, { type: 'json' }).catch(() => null);
      if (existing && typeof existing.exp === 'number' && existing.exp > now) {
        return false;                            // still inside the window: a replay
      }
      await store.setJSON(key, { exp: now + (ttl || 600) });
      return true;
    },

    async getAccount(did) {
      return store.get(`acct/${safe(did)}`, { type: 'json' }).catch(() => null);
    },

    async putAccount(did, row) {
      const key = `acct/${safe(did)}`;
      if (row === null) {
        await store.delete(key).catch(() => {});
        return;
      }
      // Never expires: the ledger is the customer list, and a row that quietly vanished
      // would turn a returning customer back into a stranger.
      await store.setJSON(key, row);
    },

    async getDeviceOwner(deviceDid) {
      const v = await store.get(`pin/${safe(deviceDid)}`).catch(() => null);
      return v || null;
    },

    async putDeviceOwner(deviceDid, ownerDid) {
      // Never expires, and for a sharper reason than the ledger's: an expiring pin IS
      // re-ownership on a timer, and a device DID is never re-owned.
      await store.set(`pin/${safe(deviceDid)}`, ownerDid);
    },

    /** Delete expired replay entries. Call from a scheduled function; see the note above. */
    async sweep() {
      const now = Math.floor(Date.now() / 1000);
      let removed = 0;
      const { blobs } = await store.list({ prefix: 'replay/' });
      for (const b of blobs || []) {
        const v = await store.get(b.key, { type: 'json' }).catch(() => null);
        if (!v || typeof v.exp !== 'number' || v.exp <= now) {
          await store.delete(b.key).catch(() => {});
          removed++;
        }
      }
      return removed;
    },
  };
}
