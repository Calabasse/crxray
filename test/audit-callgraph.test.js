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

test('buildHandlerCallGraph classifies a bare fetch() call as network', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg) => {
  fetch('https://api.example.com/sync', { method: 'POST' });
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ name: 'fetch', kind: 'network', path: ['(anonymous)', 'fetch'] }]);
});

test('buildHandlerCallGraph classifies new XMLHttpRequest()/new WebSocket() as network', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg) => {
  new XMLHttpRequest();
  new WebSocket('wss://example.com');
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'XMLHttpRequest', kind: 'network', path: ['(anonymous)', 'XMLHttpRequest'] },
    { name: 'WebSocket', kind: 'network', path: ['(anonymous)', 'WebSocket'] },
  ]);
});

test('buildHandlerCallGraph reports an arbitrary member-expression call as unresolved, not recursed into', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg) => {
  someLocalObject.doSomething(msg);
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'someLocalObject.doSomething', kind: 'unresolved', path: ['(anonymous)', 'someLocalObject.doSomething'] },
  ]);
});

test('buildHandlerCallGraph does not report an uninteresting constructor call at all (not even as unresolved)', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg) => {
  const m = new Map();
  chrome.storage.local.set({ size: m.size });
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});

test('buildHandlerCallGraph follows a call into a local top-level function (multi-hop)', () => {
  const source = `
function processRequest(msg) {
  fetch('https://api.example.com/x');
}
chrome.runtime.onMessage.addListener((msg) => {
  processRequest(msg);
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'fetch', kind: 'network', path: ['(anonymous)', 'processRequest', 'fetch'] },
  ]);
});

test('buildHandlerCallGraph follows a call into a const-assigned arrow function', () => {
  const source = `
const processRequest = (msg) => {
  chrome.storage.local.set({ last: msg });
};
chrome.runtime.onMessage.addListener((msg) => {
  processRequest(msg);
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'processRequest', 'chrome.storage.local.set'] },
  ]);
});

test('buildHandlerCallGraph reports a call to an unresolvable bare identifier as unresolved', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg) => {
  doSomethingUndefined(msg);
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'doSomethingUndefined', kind: 'unresolved', path: ['(anonymous)', 'doSomethingUndefined'] },
  ]);
});

test('buildHandlerCallGraph detects direct self-recursion as a cycle, not an infinite loop', () => {
  const source = `
function a() { a(); }
chrome.runtime.onMessage.addListener((msg) => {
  a();
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ name: 'a', kind: 'cycle', path: ['(anonymous)', 'a', 'a'] }]);
});

test('buildHandlerCallGraph detects mutual recursion (A calls B calls A) as a cycle', () => {
  const source = `
function a() { b(); }
function b() { a(); }
chrome.runtime.onMessage.addListener((msg) => {
  a();
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ name: 'a', kind: 'cycle', path: ['(anonymous)', 'a', 'b', 'a'] }]);
});

test('buildHandlerCallGraph stops at the 4-hop depth cap, naming it, rather than silently truncating', () => {
  const source = `
function f1() { f2(); }
function f2() { f3(); }
function f3() { f4(); }
function f4() { f5(); }
function f5() { fetch('https://x'); }
chrome.runtime.onMessage.addListener((msg) => {
  f1();
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].kind, 'depth-limit');
  assert.ok(!calls.some((c) => c.name === 'fetch'), 'f5/fetch is never reached -- the cap actually stopped recursion');
});

test('buildHandlerCallGraph resolves a listener registered by named function reference', () => {
  const source = `
function myHandler(msg) {
  chrome.storage.local.get('x');
}
chrome.runtime.onMessage.addListener(myHandler);
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'chrome.storage.local.get', kind: 'chrome-api', path: ['myHandler', 'chrome.storage.local.get'] },
  ]);
});

test('buildHandlerCallGraph reports unresolved when the listener reference has no matching declaration', () => {
  const source = `chrome.runtime.onMessage.addListener(someImportedHandler);\n`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ kind: 'unresolved', name: 'someImportedHandler', path: ['someImportedHandler'] }]);
});
