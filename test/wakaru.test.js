import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { unpackWithWakaru } from '../src/wakaru.js';

function makeDir() {
  return mkdtempSync(path.join(tmpdir(), 'crxray-wakaru-'));
}

function bigEnough(content) {
  return content.padEnd(100, '/* pad */');
}

test('unpackWithWakaru counts a file wakaru successfully unpacks', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){/* webpack bundle */})();'));

  const exec = () =>
    JSON.stringify({ detected_formats: ['webpack'], modules: ['a.js', 'b.js'], total: 2, failed: 0, warnings: [] });
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.processed, 1);
  assert.equal(results.unpacked, 1);
  assert.equal(results.errors.length, 0);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru records a subprocess failure without throwing', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));

  const exec = () => {
    throw new Error('spawn npx ENOENT');
  };
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.unpacked, 0);
  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /wakaru failed/);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru records malformed JSON output without throwing', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));

  const exec = () => 'not json';
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /could not parse wakaru output/);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru parses JSON even with progress lines ahead of it', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));

  const exec = () =>
    'Resolving modules...\nDone.\n' +
    JSON.stringify({ detected_formats: ['esbuild'], modules: ['a.js'], total: 1, failed: 0, warnings: [] });
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.unpacked, 1);
  assert.equal(results.errors.length, 0);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru treats a zero-module result as skipped, not an error', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'plain.js'), bigEnough('console.log("not a bundle");'));

  const exec = () => JSON.stringify({ detected_formats: [], modules: [], total: 0, failed: 0, warnings: [] });
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.unpacked, 0);
  assert.equal(results.skipped, 1);
  assert.equal(results.errors.length, 0);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru skips tiny files without calling wakaru', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'tiny.js'), 'x');
  let called = false;
  const exec = () => {
    called = true;
    return '{}';
  };

  const results = await unpackWithWakaru(dir, { quiet: true, exec });
  assert.equal(called, false);
  assert.equal(results.skipped, 1);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru does not re-process its own or webcrack output', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));
  mkdirSync(path.join(dir, 'bundle.unpacked'));
  writeFileSync(path.join(dir, 'bundle.unpacked', 'module-0.js'), bigEnough('export const a = 1;'));
  writeFileSync(path.join(dir, 'other.js'), bigEnough('(function(){})();'));
  mkdirSync(path.join(dir, 'other.wakaru'));
  writeFileSync(path.join(dir, 'other.wakaru', 'module-0.js'), bigEnough('export const b = 2;'));

  let callCount = 0;
  const exec = () => {
    callCount++;
    return JSON.stringify({ detected_formats: [], modules: [], total: 0, failed: 0, warnings: [] });
  };

  await unpackWithWakaru(dir, { quiet: true, exec });
  assert.equal(callCount, 2); // bundle.js and other.js — not the .unpacked or .wakaru contents
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru passes a timeout to the subprocess call', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));

  let capturedOpts;
  const exec = (cmd, args, opts) => {
    capturedOpts = opts;
    return JSON.stringify({ detected_formats: [], modules: [], total: 0, failed: 0, warnings: [] });
  };
  await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(typeof capturedOpts.timeout, 'number');
  assert.ok(capturedOpts.timeout > 0);
  rmSync(dir, { recursive: true });
});
