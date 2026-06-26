#!/usr/bin/env node
// Keeps the exported `VERSION` const in each package's src/index.ts in sync
// with that package's package.json "version".
//
// Why: the build is plain `tsc` with no version injection, and
// `changeset version` only bumps package.json — leaving the source const
// stale (e.g. '0.0.0'), which then ships in dist. This re-syncs it.
//
// Usage:
//   node scripts/sync-version.mjs          # rewrite consts to match package.json
//   node scripts/sync-version.mjs --check  # exit 1 if any const is out of sync

import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const packagesDir = join(__dirname, '..', 'packages');

// Matches: export const VERSION = '...';  (single or double quoted)
const VERSION_RE = /export const VERSION = (['"])[^'"]*\1;/;

const check = process.argv.includes('--check');

const drift = [];
let changed = 0;

for (const pkg of readdirSync(packagesDir)) {
  const indexPath = join(packagesDir, pkg, 'src', 'index.ts');
  const pkgJsonPath = join(packagesDir, pkg, 'package.json');
  if (!existsSync(indexPath) || !existsSync(pkgJsonPath)) continue;

  const source = readFileSync(indexPath, 'utf8');
  if (!VERSION_RE.test(source)) continue; // package doesn't export VERSION

  const { version } = JSON.parse(readFileSync(pkgJsonPath, 'utf8'));
  const desired = `export const VERSION = '${version}';`;
  const current = source.match(VERSION_RE)[0];

  if (current === desired) continue;

  if (check) {
    drift.push(`  packages/${pkg}: const is \`${current}\` but package.json is ${version}`);
    continue;
  }

  writeFileSync(indexPath, source.replace(VERSION_RE, desired));
  console.log(`synced packages/${pkg}/src/index.ts -> VERSION '${version}'`);
  changed++;
}

if (check && drift.length > 0) {
  console.error('VERSION const out of sync with package.json:');
  console.error(drift.join('\n'));
  console.error('\nRun `node scripts/sync-version.mjs` to fix.');
  process.exit(1);
}

if (!check && changed === 0) {
  console.log('VERSION consts already in sync.');
}
