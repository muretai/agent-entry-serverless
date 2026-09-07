# patches/

`store-seam.patch` is the difference between the upstream `@muretai/agent-entry` module and
the copy these templates vendor: the `store` option and the `then1` ladder that lets one
verification path serve both in-memory state and an external store (Vercel KV / Upstash,
Netlify Blobs, Workers KV).

It is written down so that an upstream release can be re-applied mechanically instead of by
hand: take the new upstream module, apply this patch, write the result to the three
template copies, and run `npm test` (which insists the three copies are identical). Written
from the 1.9.0 base on 2026-08-29; if a future upstream change lands inside a hunk, rebase
the seam here — never patch one template copy by hand.

```
cp <upstream>/muretai-agent-entry.mjs /tmp/m.mjs
patch --forward -p0 /tmp/m.mjs -i patches/store-seam.patch
for t in workers/src vercel/lib netlify/lib; do cp /tmp/m.mjs $t/muretai-agent-entry.mjs; done
npm test
```
