import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { walkFiles, isSupersededByUnpack, isWakaruOutput } from '../src/walk.js';

test('walkFiles finds files recursively, filtered by extension', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  mkdirSync(path.join(dir, 'sub'));
  writeFileSync(path.join(dir, 'a.js'), '');
  writeFileSync(path.join(dir, 'a.css'), '');
  writeFileSync(path.join(dir, 'sub', 'b.js'), '');

  const files = walkFiles(dir, { extensions: ['.js'] }).map((f) => path.relative(dir, f)).sort();
  assert.deepEqual(files, ['a.js', path.join('sub', 'b.js')].sort());
  rmSync(dir, { recursive: true });
});

test('walkFiles refuses directory nesting beyond the depth cap', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  let current = dir;
  for (let i = 0; i < 10; i++) {
    current = path.join(current, `d${i}`);
    mkdirSync(current);
  }
  writeFileSync(path.join(current, 'deep.js'), '');

  assert.throws(
    () => walkFiles(dir, { extensions: ['.js'], maxDepth: 5 }),
    /nesting exceeds 5 levels/
  );
  rmSync(dir, { recursive: true });
});

test('walkFiles refuses more files than the limit', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  for (let i = 0; i < 5; i++) {
    writeFileSync(path.join(dir, `f${i}.js`), '');
  }
  assert.throws(
    () => walkFiles(dir, { extensions: ['.js'], maxFiles: 3 }),
    /more than 3 files/
  );
  rmSync(dir, { recursive: true });
});

test('isSupersededByUnpack is true when a sibling .unpacked directory exists', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  writeFileSync(path.join(dir, 'bundle.js'), 'minified');
  mkdirSync(path.join(dir, 'bundle.unpacked'));
  writeFileSync(path.join(dir, 'bundle.unpacked', 'index.js'), 'readable');

  assert.equal(isSupersededByUnpack(path.join(dir, 'bundle.js')), true);
  assert.equal(isSupersededByUnpack(path.join(dir, 'other.js')), false);
  rmSync(dir, { recursive: true });
});

test('isWakaruOutput is true for a file inside a <name>.wakaru directory', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  writeFileSync(path.join(dir, 'bundle.js'), 'minified');
  mkdirSync(path.join(dir, 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'bundle.wakaru', 'module-0.js'), 'readable');

  assert.equal(isWakaruOutput(path.join(dir, 'bundle.wakaru', 'module-0.js')), true);
  assert.equal(isWakaruOutput(path.join(dir, 'bundle.js')), false);
  rmSync(dir, { recursive: true });
});
