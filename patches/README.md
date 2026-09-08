# patches/ — retired

These templates used to vendor a PATCHED door. The patch, `store-seam.patch`, added the
`store` option and the `then1` ladder that let a template keep its ledger, replay set and
device pins in Cloudflare KV, Vercel KV or Netlify Blobs instead of per-instance memory —
the three failures a serverless deployment otherwise walks into with no error.

**The seam is upstream now.** `@muretai/agent-entry` 1.11.0 carries all ten of the patch's
hunks: `store` is an option `createAgentEntry` accepts, and `then1`, `asStore` and
`memoryStore` are the module's own. `patch --forward` against 1.11.1 answers
"10 out of 10 hunks ignored — previously applied". A patch that adds nothing can only fail,
and keeping it would pin these templates to the 1.10.0 door for good. It was removed on
2026-09-08; the history holds it if it is ever wanted again.

## Vendoring now

```sh
node scripts/vendor.mjs --ref v1.11.1        # ../agent-entry, or $MURETAI_AGENT_ENTRY
```

That reads the door out of agent-entry at the tag with `git show`, writes the three copies,
and records the commit, the version and each file's sha256 in `VENDOR.json` at the repo root.
`npm test` holds the copies to those digests with no agent-entry checkout present, and — only
when one is beside this repo — checks that the recorded commit really produces those bytes.

The `--no-patch` flag is now the default path and the flag itself is redundant; it stays for
the day a template again needs a difference from upstream. If that day comes, write the
difference down as a patch here, and `scripts/vendor.mjs` will apply it.

What still belongs to these templates, and is not upstream: each platform's store
(`workers/src/store.mjs`, `vercel/lib/rest-kv-store.mjs`, `netlify/lib/blob-store.mjs`),
which implements the five methods the door calls — `seenMessage`, `getAccount`, `putAccount`,
`getDeviceOwner`, `putDeviceOwner`.
