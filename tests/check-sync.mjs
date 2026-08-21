/**
 * tests/check-sync.mjs — the three copies of the library must be identical.
 *
 * Each template directory is SELF-CONTAINED so that it can be deployed on its own: a
 * platform that is given a root directory cannot reach a shared folder above it, which is
 * how the first cut of this repo would have failed on Vercel. The price of that choice is
 * three copies of the same file, and the price of three copies is drift.
 *
 * So this makes drift a failing test rather than a surprise.
 *
 *     node tests/check-sync.mjs
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const GROUPS = {
  'muretai-agent-entry.mjs': [
    'workers/src/muretai-agent-entry.mjs',
    'vercel/lib/muretai-agent-entry.mjs',
    'netlify/lib/muretai-agent-entry.mjs',
  ],
  'handler.mjs': ['vercel/lib/handler.mjs', 'netlify/lib/handler.mjs'],
};

let failed = false;
for (const [name, paths] of Object.entries(GROUPS)) {
  const hashes = paths.map((p) => [p,
    createHash('sha256').update(readFileSync(new URL(`../${p}`, import.meta.url))).digest('hex')]);
  const distinct = new Set(hashes.map(([, h]) => h));
  if (distinct.size === 1) {
    console.log(`ok: ${paths.length} copies of ${name} are identical (${[...distinct][0].slice(0, 12)}…)`);
  } else {
    failed = true;
    console.log(`FAIL: copies of ${name} have DRIFTED`);
    for (const [p, h] of hashes) console.log(`   ${h.slice(0, 12)}…  ${p}`);
  }
}
process.exit(failed ? 1 : 0);
