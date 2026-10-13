import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { buildHandlerCallGraph, collectMessagePassing } from '../src/audit.js';

function makeFiles(dir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
}

function listenerIndex(source) {
  const m = /\b(?:chrome|browser)\.runtime\.(?:onMessage|onConnect)\.addListener\s*\(/.exec(source);
  if (!m) throw new Error('fixture has no addListener call -- test fixture bug, not a real failure');
  return m.index;
}

test('buildHandlerCallGraph finds a direct chrome.* API call inside the listener', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  chrome.storage.local.set({ seen: true });
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});

test('buildHandlerCallGraph returns an empty array for a handler with no calls at all', () => {
  const source = `chrome.runtime.onMessage.addListener(() => {});\n`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, []);
});

test('buildHandlerCallGraph degrades to unparseable on a malformed file, without throwing', () => {
  const source = `chrome.runtime.onMessage.addListener((msg) => { this is not valid JS at all (((`;
  assert.doesNotThrow(() => buildHandlerCallGraph(source, listenerIndex(source)));
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ kind: 'unparseable' }]);
});

test('collectMessagePassing attaches calls to a listener entry end-to-end', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-callgraph-'));
  makeFiles(dir, {
    'sw.js': `
chrome.runtime.onMessage.addListener((msg) => {
  chrome.storage.local.get('x');
});
`,
  });
  const map = collectMessagePassing(dir);
  const entry = map.find((c) => c.listener);
  assert.ok(entry, 'the listener-only candidate exists');
  assert.deepEqual(entry.listener.calls, [
    { name: 'chrome.storage.local.get', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.get'] },
  ]);
});

test('collectMessagePassing degrades gracefully on an unparseable file without affecting other files', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-callgraph-'));
  makeFiles(dir, {
    'broken.js': `chrome.runtime.onMessage.addListener((msg) => { ((( not valid`,
    'fine.js': `
chrome.runtime.onMessage.addListener((msg) => {
  chrome.storage.local.set({ ok: true });
});
`,
  });
  const map = collectMessagePassing(dir);
  const broken = map.find((c) => c.listener?.file === 'broken.js');
  const fine = map.find((c) => c.listener?.file === 'fine.js');
  assert.deepEqual(broken.listener.calls, [{ kind: 'unparseable' }]);
  assert.deepEqual(fine.listener.calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});
