#!/usr/bin/env node
// `prepare` lifecycle script.
//
// A dev checkout (`npm ci` / `npm install`) has the TypeScript toolchain and
// rebuilds dist/ here. A global install straight from git
// (`npm install -g github:cresec-ai/audit#main`) does NOT: npm runs the
// clone's prepare step without its devDependencies (the global flag leaks
// into the inner install), so tsc is absent — and dist/ is committed to the
// repository precisely so that path works without a build. Never fail a
// consumer install over a missing dev toolchain; fail only when there is
// nothing to ship at all.
'use strict';
const { existsSync } = require('node:fs');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');

const root = join(__dirname, '..');
const tsc = join(root, 'node_modules', 'typescript', 'bin', 'tsc');

if (!existsSync(tsc)) {
  if (!existsSync(join(root, 'dist', 'cli.js'))) {
    console.error('prepare: typescript is not installed and dist/ is missing — run `npm ci && npm run build`');
    process.exit(1);
  }
  console.error('prepare: typescript is not installed here; using the committed dist/');
  process.exit(0);
}

const result = spawnSync(process.execPath, [tsc, '-p', join(root, 'tsconfig.json')], { stdio: 'inherit' });
process.exit(result.status ?? 1);
