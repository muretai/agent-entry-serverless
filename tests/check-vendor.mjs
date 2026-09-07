/**
 * tests/check-vendor.mjs — the three copies are what VENDOR.json says they are.
 *
 * check-sync.mjs proves the copies are identical to EACH OTHER. This proves they are identical
 * to what scripts/vendor.mjs wrote: the door from agent-entry at one recorded commit, plus the
 * transform it records (patches/store-seam.patch). Two legs:
 *
 *   pin       ALWAYS: VENDOR.json is well-formed, names all three copies, and every file it
 *             lists is on disk at the sha256 it records. Needs nothing outside this repository.
 *   sibling   ONLY when an agent-entry checkout is beside this one (../agent-entry, or
 *             $MURETAI_AGENT_ENTRY) and has the recorded commit: `git show <commit>:<source>`
 *             plus the recorded transform must reproduce every copy byte for byte — so the pin
 *             cannot name a commit the copies were not built from — and it prints how many
 *             commits behind that checkout's HEAD the pin is. A missing checkout is one `skip:`
 *             line and exit 0: never a failure, never silence.
 *
 * A count nobody asserts is a count that can quietly fall, so there is a floor on the checks.
 *
 *     node tests/check-vendor.mjs                                 (part of `npm test`)
 *     MURETAI_AGENT_ENTRY=/path/to/agent-entry npm test          (sibling rows against that checkout)
 */
import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import process from 'node:process';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const PIN = join(ROOT, 'VENDOR.json');
/** Pinned HERE, not read from VENDOR.json: a pin that lists fewer copies must not pass. */
const COPIES = [
  'workers/src/muretai-agent-entry.mjs',
  'vercel/lib/muretai-agent-entry.mjs',
  'netlify/lib/muretai-agent-entry.mjs',
];

let pass = 0;
const failures = [];
function check(ok, label, detail) {
  if (ok) { pass += 1; return true; }
  failures.push(detail ? `${label}\n      ${detail}` : label);
  return false;
}
const sha = (b) => createHash('sha256').update(b).digest('hex');

// ---------------------------------------------------------------- the pin
let pin = null;
try { pin = JSON.parse(readFileSync(PIN, 'utf8')); } catch (e) {
  check(false, 'pin/VENDOR.json-readable', `${e.message} — run: node scripts/vendor.mjs --ref <tag|commit>`);
}
if (pin) {
  check(pin.from === 'agent-entry' && (pin.commit === null || /^[0-9a-f]{40}$/.test(pin.commit || ''))
        && typeof pin.version === 'string' && pin.files && typeof pin.files === 'object',
        'pin/VENDOR.json-shape', 'VENDOR.json must carry from=agent-entry, a 40-hex commit (or null), a version and a files map');
  for (const p of COPIES) check(p in (pin.files || {}), `pin/${p}-listed`, `VENDOR.json does not list ${p}`);
  for (const [p, v] of Object.entries(pin.files || {})) {
    const local = join(ROOT, p);
    if (!check(existsSync(local), `pin/${p}-present`, `${p} is named by VENDOR.json but is not on disk`)) continue;
    const got = sha(readFileSync(local));
    if (check(got === v.sha256, `pin/${p}-sha256`,
              `on disk ${got.slice(0, 12)}, VENDOR.json says ${String(v.sha256).slice(0, 12)} — edited in place? re-vendor instead`)) {
      console.log(`ok: ${p} is VENDOR.json's ${got.slice(0, 12)}…`);
    }
  }
}
if (failures.length) report();

// ---------------------------------------------------------------- the sibling, when it is there
let derivedRan = false;
const siblingRoot = resolve(ROOT, process.env.MURETAI_AGENT_ENTRY || '../agent-entry');
if (pin.commit === null) {
  console.log(`  note: VENDOR.json carries no commit (ref ${JSON.stringify(pin.ref)}) — the pin is by digest only; run scripts/vendor.mjs to pin a commit`);
} else if (!existsSync(join(siblingRoot, '.git'))) {
  console.log(`  skip: no agent-entry checkout at ${siblingRoot} — the pin was verified by digest only (set MURETAI_AGENT_ENTRY to check the recorded commit too)`);
} else {
  const git = (...a) => execFileSync('git', ['-C', siblingRoot, ...a], { stdio: ['ignore', 'pipe', 'pipe'] });
  let known = true;
  try { git('cat-file', '-e', `${pin.commit}^{commit}`); } catch { known = false; }
  if (!known) {
    console.log(`  skip: ${siblingRoot} does not have commit ${pin.commit.slice(0, 12)} — a checkout behind the pin, or a pin that lies; fetch it, or point MURETAI_AGENT_ENTRY elsewhere`);
  } else {
    const derived = new Map();   // one derivation per distinct (source, transform)
    for (const [p, v] of Object.entries(pin.files)) {
      const key = `${v.source}\0${v.transform || ''}`;
      if (!derived.has(key)) derived.set(key, derive(git, pin.commit, v.source, v.transform));
      const theirs = derived.get(key);
      if (theirs.unavailable) { console.log(`  note: ${theirs.unavailable} — the copies were not re-derived`); continue; }
      derivedRan = true;
      const mine = readFileSync(join(ROOT, p));
      check(theirs.bytes !== null && theirs.bytes.equals(mine), `sibling/${p}-is-what-${pin.commit.slice(0, 7)}-produces`,
            theirs.bytes === null ? theirs.why
              : `the pin lies: ${v.source} at ${pin.commit.slice(0, 7)}${v.transform ? ` + ${v.transform}` : ''} is ${sha(theirs.bytes).slice(0, 12)}, the copy here is ${sha(mine).slice(0, 12)}`);
    }
    const behind = git('rev-list', '--count', `${pin.commit}..HEAD`).toString().trim();
    const head = git('rev-parse', '--short', 'HEAD').toString().trim();
    console.log(`  sibling: ${siblingRoot} — pin ${pin.ref} (${pin.commit.slice(0, 7)}, ${pin.version}) is ${behind} commit(s) behind its HEAD ${head}${derivedRan ? '; every copy re-derived from that commit' : ''}`);
  }
}

report();

/** `git show <commit>:<source>`, then the transform (a unified diff applied with `patch --forward -p0`), if any. */
function derive(git, commit, source, transform) {
  let bytes;
  try { bytes = git('show', `${commit}:${source}`); } catch { return { bytes: null, why: `${commit.slice(0, 7)} has no ${source}` }; }
  if (!transform) return { bytes };
  const patchPath = join(ROOT, transform);
  if (!existsSync(patchPath)) return { bytes: null, why: `${transform} is named by VENDOR.json but is not on disk` };
  const tmp = mkdtempSync(join(tmpdir(), 'agent-entry-vendor-check-'));
  try {
    const work = join(tmp, 'door.mjs');
    writeFileSync(work, bytes);
    const r = spawnSync('patch', ['--forward', '-p0', work, '-i', patchPath], { cwd: tmp, encoding: 'utf8' });
    if (r.error) return { unavailable: `patch(1) is not available here (${r.error.message})` };
    if (r.status !== 0) return { bytes: null, why: `${transform} does not apply to ${source} at ${commit.slice(0, 7)}:\n      ${(r.stdout + r.stderr).trim().split('\n').join('\n      ')}` };
    return { bytes: readFileSync(work) };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function report() {
  if (failures.length) {
    console.log(`\nFAILED — ${failures.length} of ${pass + failures.length} checks:\n`);
    for (const f of failures) console.log(`  ✗ ${f}`);
    console.log('\nThe copies are edited upstream (agent-entry) or in patches/, and re-pulled by');
    console.log('scripts/vendor.mjs — never edited in place.\n');
    process.exit(1);
  }
  // 1 shape + (listed, present, sha256) per copy, plus one re-derivation per copy when the sibling leg ran.
  const FLOOR = 1 + COPIES.length * 3 + (derivedRan ? COPIES.length : 0);
  if (pass < FLOOR) {
    console.log(`\nFAILED — only ${pass} checks ran, and at least ${FLOOR} were expected. Read the rows above.\n`);
    process.exit(1);
  }
  const transform = pin.files[COPIES[0]] && pin.files[COPIES[0]].transform;
  console.log(`OK — ${pass} checks: the ${COPIES.length} copies are @muretai/agent-entry ${pin.version} at ${pin.ref} (${pin.commit ? pin.commit.slice(0, 7) : 'no commit'})${transform ? ` + ${transform}` : ''}.`);
}
