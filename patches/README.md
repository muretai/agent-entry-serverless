# patches/

`store-seam.patch` is the difference between the upstream `@muretai/agent-entry` module and
the copy these templates vendor: the `store` option and the `then1` ladder that lets one
verification path serve both in-memory state and an external store (Vercel KV / Upstash,
Netlify Blobs, Workers KV).

It is applied by `scripts/vendor.mjs` — never by hand, and never to one template copy:

```
node scripts/vendor.mjs --ref <tag|commit>       # reads ../agent-entry, or $MURETAI_AGENT_ENTRY
node scripts/vendor.mjs --ref main --dry-run     # say what would change, write nothing
```

The script reads the door from the agent-entry checkout at that commit (`git show`, so that
checkout's working tree does not matter), applies this patch with `patch --forward` in a temp
dir, writes the result to the three template copies, records the commit, version, date and
the sha256 of each copy in `VENDOR.json`, and runs `npm test`. If a hunk no longer applies,
it writes nothing and prints patch's own output: rebase this file onto that upstream by hand,
then re-run. `tests/check-vendor.mjs` re-derives the copies from the recorded commit whenever
an agent-entry checkout is beside this repo, so the pin cannot name a base the copies were not
built from.

The upstream is the agent-entry repository — <https://github.com/muretai/agent-entry>, the
door's home. The release tool that used to rebuild these copies from the other side and push
them here is gone; the pull happens from this side, with the script above.

**History.** Written on 2026-08-29 against the door of the 1.10.0 release (agent-entry
`f5d5aca`; the base was identified after the fact by reverse-applying this patch, and the
checker's sibling leg proves it). Since agent-entry 1.11.0 (`551cd2c`, 2026-09-05) the
upstream door carries the seam itself: nine of these ten hunks are in it byte for byte, and
the tenth — the `store` paragraph in `createAgentEntry`'s option docs — is worded
differently, so this patch neither applies to nor reverses out of 1.11.0 cleanly. The next
re-vendor is therefore `--no-patch`, after checking the three adapters against upstream's
store contract, and this file is retired with it.
