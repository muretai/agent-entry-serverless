#!/usr/bin/env node
/**
 * scripts/vendor.mjs — take the door from agent-entry at one commit, seam it, and pin it.
 *
 * The three template copies of muretai-agent-entry.mjs are not this repository's code: they
 * are @muretai/agent-entry's door, whose home is the agent-entry repository, plus ONE
 * transform of ours — patches/store-seam.patch, the `store` option and the `then1` ladder the
 * three store adapters depend on. This script is the only way the copies change:
 *
 *   1. read agent-entry at --ref (a tag or commit) with `git show`, so what is on disk in that
 *      checkout does not matter, only what is committed;
 *   2. apply patches/store-seam.patch to that door in a temp dir with `patch --forward`. If a
 *      hunk does not apply, write NOTHING and print patch's own output: the seam is rebased by
 *      hand, in the patch — never in one template copy;
 *   3. write the result to the three template copies (tests/check-sync.mjs insists they stay
 *      identical);
 *   4. write VENDOR.json at the repo root — the commit, the version, the date of that commit,
 *      and the sha256 of every copy as written;
 *   5. run `npm test`.
 *
 * Nothing here writes outside this repository, and nothing here runs at test time:
 * tests/check-vendor.mjs holds the copies to VENDOR.json's digests with no agent-entry
 * checkout present, and re-derives them from the recorded commit only when one is beside
 * this repo. The upstream is agent-entry, pulled from THIS side by this script; the release
 * tool that used to rebuild these copies from the other side and push them here is gone.
 *
 *   node scripts/vendor.mjs --ref v1.12.0              # ../agent-entry, or $MURETAI_AGENT_ENTRY
 *   node scripts/vendor.mjs --ref <sha> --from /path
 *   node scripts/vendor.mjs --ref main --dry-run       # say what would change, write nothing
 *   node scripts/vendor.mjs --ref main --no-patch      # the door as-is, once the seam is upstream
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
const SOURCE = 'muretai-agent-entry.mjs';
const PATCH = 'patches/store-seam.patch';
const COPIES = [
  'workers/src/muretai-agent-entry.mjs',
  'vercel/lib/muretai-agent-entry.mjs',
  'netlify/lib/muretai-agent-entry.mjs',
];
const REPOSITORY = 'https://github.com/muretai/agent-entry';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); const v = args[i + 1]; return i >= 0 && v && !v.startsWith('--') ? v : null; };
const ref = opt('--ref');
const from = resolve(ROOT, opt('--from') || process.env.MURETAI_AGENT_ENTRY || '../agent-entry');
const dry = args.includes('--dry-run');
const noPatch = args.includes('--no-patch');

const die = (msg, code = 2) => { console.error(`error: ${msg}`); process.exit(code); };
const indent = (s) => `${s.trim().split('\n').map((l) => `    ${l}`).join('\n')}\n`;
if (!ref) die('usage: node scripts/vendor.mjs --ref <tag|commit> [--from PATH] [--dry-run] [--no-patch]');
if (!existsSync(join(from, '.git'))) die(`no agent-entry checkout at ${from} (pass --from, or set MURETAI_AGENT_ENTRY)`);
const git = (...a) => execFileSync('git', ['-C', from, ...a], { stdio: ['ignore', 'pipe', 'pipe'] });
let commit;
try { commit = git('rev-parse', '--verify', `${ref}^{commit}`).toString().trim(); } catch { die(`${ref} is not a commit in ${from}`); }
const show = (path) => { try { return git('show', `${commit}:${path}`); } catch { return die(`${ref} (${commit.slice(0, 7)}) has no ${path}`); } };
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const date = git('show', '-s', '--format=%cs', commit).toString().trim();
const pkg = JSON.parse(show('package.json').toString('utf8'));
if (pkg.name !== '@muretai/agent-entry') die(`${from} at ${ref} is ${pkg.name}, not @muretai/agent-entry`);
const version = pkg.version;
const upstream = show(SOURCE);
const dirty = git('status', '--porcelain').toString().trim();
if (dirty) console.log(`note: ${from} has uncommitted changes; they are NOT what is vendored — only ${commit.slice(0, 7)} is.`);

// ---- 2. the seam
let door = upstream;
let transform = null;
let patchReport = 'no transform: the door as-is';
if (!noPatch) {
  const patchPath = join(ROOT, PATCH);
  if (!existsSync(patchPath)) die(`${PATCH} is missing — pass --no-patch to vendor the door as-is`);
  const tmp = mkdtempSync(join(tmpdir(), 'agent-entry-vendor-'));
  const work = join(tmp, SOURCE);
  const run = (a) => spawnSync('patch', a, { cwd: tmp, encoding: 'utf8' });
  try {
    writeFileSync(work, upstream);
    const fwd = run(['--forward', '-p0', work, '-i', patchPath]);
    if (fwd.error) die(`could not run patch(1): ${fwd.error.message}`);
    if (fwd.status !== 0) {
      console.log(`${PATCH} does not apply cleanly to ${SOURCE} at ${ref} (${commit.slice(0, 7)}, ${version}, ${date}):\n`);
      process.stdout.write(indent(fwd.stdout + fwd.stderr));
      // Is the seam already in that door? A reverse dry-run says how many hunks it carries.
      writeFileSync(work, upstream);
      const rev = run(['--reverse', '--dry-run', '-p0', work, '-i', patchPath]);
      console.log(`\nreverse dry-run — how much of the seam ${ref}'s door already carries:\n`);
      process.stdout.write(indent(rev.stdout + rev.stderr));
      console.log(`\nnothing written. rebase ${PATCH} onto ${ref} by hand, then re-run.`);
      console.log('(if the reverse dry-run applied every hunk, the seam is upstream now: re-run with --no-patch and retire the patch.)');
      process.exit(1);
    }
    door = readFileSync(work);
    transform = PATCH;
    patchReport = `${PATCH}: applied — ${fwd.stdout.trim().split('\n').filter((l) => /^Hunk|hunks/.test(l)).join('; ') || 'every hunk at its recorded line'}`;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

// ---- 4. the pin
const digest = sha256(door);
const files = {};
for (const p of COPIES) files[p] = { source: SOURCE, sha256: digest, ...(transform ? { transform } : {}) };
const vendor = {
  _: 'Written by scripts/vendor.mjs; do not edit by hand. tests/check-vendor.mjs holds the three copies to these digests without any agent-entry checkout present, and re-derives them from this commit when one is beside this repository.',
  from: 'agent-entry', repository: REPOSITORY, ref, commit, version, date, files,
};

// ---- report, then write
console.log(`agent-entry ${ref} = ${commit.slice(0, 12)} (${version}, ${date}) from ${from}`);
console.log(`  ${SOURCE} at that commit: ${sha256(upstream).slice(0, 12)} (${upstream.toString('utf8').split('\n').length} lines)`);
console.log(`  ${patchReport}`);
for (const p of COPIES) {
  const local = join(ROOT, p);
  const before = existsSync(local) ? sha256(readFileSync(local)) : null;
  console.log(`  ${p}  ${before === digest ? `unchanged (${digest.slice(0, 12)})` : `${before ? before.slice(0, 12) : '(new)'} -> ${digest.slice(0, 12)}`}`);
}
if (dry) { console.log('dry run: nothing written'); process.exit(0); }
for (const p of COPIES) writeFileSync(join(ROOT, p), door);
writeFileSync(join(ROOT, 'VENDOR.json'), `${JSON.stringify(vendor, null, 2)}\n`);
console.log(`  wrote VENDOR.json and ${COPIES.length} copies`);

// ---- 5. the tests
const test = spawnSync('npm', ['test'], { cwd: ROOT, stdio: 'inherit' });
if (test.status !== 0) {
  console.log('\nnpm test FAILED with the new copies in place — fix the cause, or `git checkout` the copies and VENDOR.json');
  process.exit(test.status || 1);
}
console.log('next: commit VENDOR.json and the three copies together');
