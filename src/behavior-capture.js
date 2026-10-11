import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { redactEvent } from './redact.js';
import { auditExtension } from './audit.js';
import { summarizeManifest } from './manifest.js';
import { buildMechanismReport } from './mechanism.js';

export const DISCLAIMER =
  'crxray capture-behavior is a verification aid for extensions you have the right to ' +
  'inspect or test. It is not a license to copy a third party\'s copyrighted code, branding, ' +
  'or paid service. A capture reflects only the scenario actually exercised, under one ' +
  'environment and one run -- it is scenario-specific evidence, not a complete record of ' +
  'everything the extension does.';

const SCHEMA_VERSION = 1;
const DEFAULT_TIMEOUT_MS = 60_000;
const RESPONSE_BODY_BYTE_CAP = 100_000;
const CAPTURABLE_MIME_RE = /^(text\/|application\/json)/i;
const CAPTURE_MARKER = '\u0000__CRXRAY_CAPTURE__\u0000';

function findChrome() {
  if (process.env.CRXRAY_CHROME_PATH && existsSync(process.env.CRXRAY_CHROME_PATH)) {
    return process.env.CRXRAY_CHROME_PATH;
  }
  const candidates =
    process.platform === 'darwin'
      ? [
          '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
          '/Applications/Chromium.app/Contents/MacOS/Chromium',
        ]
      : process.platform === 'win32'
        ? [
            'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
          ]
        : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  const found = candidates.find((p) => existsSync(p));
  if (!found) {
    throw new Error(
      'No Chrome/Chromium binary found. Set CRXRAY_CHROME_PATH to its full path.'
    );
  }
  return found;
}

/**
 * Minimal CDP client over the pipe transport (NUL-delimited JSON on fd 3/4), not the
 * WebSocket/`/json` port transport crxray's static pipeline would use elsewhere -- pipe
 * transport is required for `Extensions.loadUnpacked` (confirmed: Chrome 126+, requires
 * --remote-debugging-pipe plus --enable-unsafe-extension-debugging; the port transport
 * returns "Method not available" for that one command).
 */
class CdpPipeClient {
  constructor(chromePath, args) {
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map(); // method -> Set<fn>
    this.buf = '';
    this.child = spawn(chromePath, args, { stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe'] });
    this.cmdOut = this.child.stdio[3];
    this.evtIn = this.child.stdio[4];
    this.evtIn.on('data', (chunk) => this._onData(chunk));
  }

  _onData(chunk) {
    this.buf += chunk.toString('utf8');
    let idx;
    while ((idx = this.buf.indexOf('\0')) >= 0) {
      const msg = this.buf.slice(0, idx);
      this.buf = this.buf.slice(idx + 1);
      if (!msg) continue;
      let obj;
      try {
        obj = JSON.parse(msg);
      } catch {
        continue;
      }
      if (obj.id !== undefined && this.pending.has(obj.id)) {
        const { resolve } = this.pending.get(obj.id);
        this.pending.delete(obj.id);
        resolve(obj);
      } else if (obj.method) {
        for (const fn of this.listeners.get(obj.method) ?? []) fn(obj);
      }
    }
  }

  on(method, fn) {
    if (!this.listeners.has(method)) this.listeners.set(method, new Set());
    this.listeners.get(method).add(fn);
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve) => {
      this.pending.set(id, { resolve });
      this.cmdOut.write(JSON.stringify(payload) + '\0');
    });
  }

  kill() {
    try {
      this.child.kill('SIGKILL');
    } catch {
      // already exited
    }
  }
}

function addLimitation(limitations, entry) {
  limitations.push(entry);
}

/**
 * Kills Chrome and removes the temp profile, waiting for the process to actually exit first.
 * A bare kill()-then-rmSync raced Chrome's own subprocesses (confirmed by a failing test:
 * ENOTEMPTY -- the profile dir wasn't actually free yet), especially under --headless=new,
 * which can leave child/zygote processes briefly holding files open after the main process
 * is signaled. Retries the removal a few times rather than failing outright on that race.
 */
async function killAndCleanup(client, profileDir) {
  await new Promise((resolve) => {
    if (client.child.exitCode !== null || client.child.killed) {
      resolve();
      return;
    }
    client.child.once('exit', resolve);
    client.kill();
    setTimeout(resolve, 3000);
  });

  let lastErr;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      rmSync(profileDir, { recursive: true, force: true });
      return;
    } catch (err) {
      lastErr = err;
      await new Promise((r) => setTimeout(r, 300));
    }
  }
  throw lastErr;
}

/**
 * Installs pre-execution instrumentation on a newly-attached, paused target and resumes it.
 *
 * The honest, fully-understood boundary of what this can and cannot catch (found by direct
 * testing, not assumed):
 *
 * - `chrome.storage`/`chrome.runtime` do not exist on a service worker's global scope at the
 *   instant it is paused pre-resume (confirmed: a bare reference throws ReferenceError there).
 *   They become available at some point during/after resume, not before -- so a one-shot
 *   pre-resume patch attempt has nothing to wrap yet.
 * - A retry timer *scheduled from inside the worker's own injected code* never fires at all in
 *   this environment (confirmed: a 100ms setInterval heartbeat never ticked once over several
 *   seconds) -- MV3 service workers appear to only service their task queue in response to a
 *   genuine browser-dispatched event, not an arbitrary JS timer they scheduled for themselves.
 *   The retry below is therefore driven by Node's own timer instead, re-invoking an idempotent
 *   patch function already installed on the target -- confirmed working.
 * - A `Object.defineProperty` trap on `globalThis.chrome` (installed before `chrome` exists)
 *   catches the moment the real `chrome` object is assigned, and was confirmed to catch a
 *   storage write made in response to a later event (the popup's message round-trip).
 * - What neither mechanism can catch: a call made synchronously as part of the target's own
 *   top-level script execution, before Node's first follow-up round-trip completes --
 *   confirmed by direct test (the extension's very first, one-time `chrome.storage.local.set`
 *   and its one-time `chrome.runtime.onMessage.addListener` registration are both missed; a
 *   *later*, repeated `chrome.storage.local.set` call -- made after the patch has had time to
 *   land -- is reliably captured, with correct redaction). A one-shot registration's result
 *   (the listener that got bound) stays whatever it was at registration time regardless of
 *   patching later, so this is a structural boundary, not a timing bug to keep chasing.
 * - page-type targets (popup/options): `Page.addScriptToEvaluateOnNewDocument` registers
 *   successfully (confirmed, no error), but the registered script was not observed to run for
 *   a `Target.createTarget`-created popup in this environment -- storage/message capture for
 *   page-type targets should be treated as unconfirmed, not assumed equivalent to the service
 *   worker's partial coverage above. Network and console capture are unaffected (CDP-level,
 *   not dependent on this injection at all) and work for every target type.
 */
async function instrumentAndResume(client, sessionId, targetInfo, limitations) {
  const defineInjectSource = `
    (function() {
      const marker = ${JSON.stringify(CAPTURE_MARKER)};
      function report(entry) { try { console.log(marker + JSON.stringify(entry)); } catch (e) {} }

      function patchStorage() {
        if (!(globalThis.chrome && chrome.storage)) return false;
        for (const area of ['local', 'sync']) {
          const store = chrome.storage[area];
          if (!store || store.__crxrayPatched) continue;
          for (const method of ['get', 'set', 'remove']) {
            const original = store[method];
            if (typeof original !== 'function') continue;
            store[method] = function (...args) {
              report({ kind: 'storage', area, method, value: args[0] });
              return original.apply(store, args);
            };
          }
          store.__crxrayPatched = true;
        }
        return !!(chrome.storage.local && chrome.storage.local.__crxrayPatched);
      }

      function patchRuntime() {
        if (!(globalThis.chrome && chrome.runtime)) return false;
        if (chrome.runtime.sendMessage && !chrome.runtime.sendMessage.__crxrayPatched) {
          const originalSend = chrome.runtime.sendMessage;
          const wrappedSend = function (...args) {
            report({ kind: 'message', direction: 'sent', message: args.find((a) => typeof a !== 'function') });
            return originalSend.apply(chrome.runtime, args);
          };
          wrappedSend.__crxrayPatched = true;
          chrome.runtime.sendMessage = wrappedSend;
        }
        if (chrome.runtime.onMessage && chrome.runtime.onMessage.addListener && !chrome.runtime.onMessage.addListener.__crxrayPatched) {
          const originalAdd = chrome.runtime.onMessage.addListener;
          const wrappedAdd = function (handler) {
            const wrapped = function (message, sender, sendResponse) {
              report({ kind: 'message', direction: 'received', message });
              return handler(message, sender, sendResponse);
            };
            return originalAdd.call(chrome.runtime.onMessage, wrapped);
          };
          wrappedAdd.__crxrayPatched = true;
          chrome.runtime.onMessage.addListener = wrappedAdd;
        }
        return true;
      }

      globalThis.__crxrayTryPatch = function () {
        const storageOk = patchStorage();
        const runtimeOk = patchRuntime();
        globalThis.__crxrayNamespaceCheck = { chromeStorage: storageOk, chromeRuntime: runtimeOk };
        return storageOk && runtimeOk;
      };
      if (!globalThis.__crxrayTryPatch() && typeof chrome === 'undefined') {
        try {
          let realChrome;
          Object.defineProperty(globalThis, 'chrome', {
            configurable: true,
            enumerable: true,
            get() { return realChrome; },
            set(v) {
              realChrome = v;
              globalThis.__crxrayTryPatch();
            },
          });
          globalThis.__crxrayTrapInstalled = true;
        } catch (e) {
          globalThis.__crxrayTrapInstalled = false;
        }
      }
    })();
  `;

  if (targetInfo.type === 'service_worker') {
    await client.send('Runtime.evaluate', { expression: defineInjectSource }, sessionId);
  } else {
    await client.send('Page.enable', {}, sessionId);
    await client.send('Page.addScriptToEvaluateOnNewDocument', { source: defineInjectSource }, sessionId);
  }
  await client.send('Network.enable', {}, sessionId);
  await client.send('Runtime.enable', {}, sessionId);
  await client.send('Log.enable', {}, sessionId);
  await client.send('Runtime.runIfWaitingForDebugger', {}, sessionId);

  // Node-driven follow-up attempts (see function comment for why this has to be Node's timer,
  // not the worker's own).
  let patched = false;
  for (const delayMs of [0, 15, 40, 100, 300]) {
    await new Promise((r) => setTimeout(r, delayMs));
    const res = await client.send(
      'Runtime.evaluate',
      { expression: 'globalThis.__crxrayTryPatch && globalThis.__crxrayTryPatch()' },
      sessionId
    );
    if (res.result?.result?.value === true) {
      patched = true;
      break;
    }
  }
  // Always added, regardless of `patched`: even a confirmed-patched target only has
  // after-the-patch coverage. A one-shot call made at the target's own top level, before the
  // first Node round-trip above completes, is a structural miss this capability cannot close
  // (see the function comment) -- so this capability is never claimed complete, only attempted.
  addLimitation(limitations, {
    capability: 'storageMessageLiveCapture',
    target: targetInfo.type,
    reason: patched
      ? 'chrome.storage/chrome.runtime were patched, but only after the target\'s own top-level script may have already run -- a one-time call made at startup (e.g. an initial storage write or a message-listener registration) can still be missed; a later, repeated call made after patching is reliably captured'
      : 'could not confirm chrome.storage/chrome.runtime were ever successfully patched for this target; treat any storage/message events as best-effort, not complete',
    severity: 'known-gap',
  });
}

function parseScenario(scenarioPath) {
  const raw = JSON.parse(readFileSync(scenarioPath, 'utf8'));
  if (!Array.isArray(raw.steps)) throw new Error('Scenario file must have a "steps" array.');
  return raw.steps;
}

async function runStep(client, state, step) {
  switch (step.action) {
    case 'openPopup': {
      const popupPath = state.manifest?.action?.default_popup ?? state.manifest?.browser_action?.default_popup;
      if (!popupPath) throw new Error('Scenario step "openPopup" but manifest has no action.default_popup.');
      const url = `chrome-extension://${state.extensionId}/${popupPath}`;
      const res = await client.send('Target.createTarget', { url });
      state.namedTargets.popup = { targetId: res.result?.targetId };
      break;
    }
    case 'navigate': {
      const url = step.url.startsWith('chrome-extension://') ? step.url : `chrome-extension://${state.extensionId}/${step.url}`;
      const res = await client.send('Target.createTarget', { url });
      state.namedTargets[step.target ?? 'page'] = { targetId: res.result?.targetId };
      break;
    }
    case 'click': {
      const session = state.sessionFor(step.target ?? 'popup');
      if (session) {
        await client.send(
          'Runtime.evaluate',
          { expression: `document.querySelector(${JSON.stringify(step.selector)})?.click()` },
          session
        );
      }
      break;
    }
    case 'wait':
      await new Promise((r) => setTimeout(r, step.ms ?? 500));
      break;
    case 'evaluate': {
      const session = state.sessionFor(step.target ?? 'serviceWorker');
      if (session) await client.send('Runtime.evaluate', { expression: step.expression }, session);
      break;
    }
    default:
      throw new Error(`Unknown scenario step action: ${step.action}`);
  }
}

/**
 * Captures one extension's real runtime behavior into a structured, redacted file. Opt-in
 * only -- never invoked by the default crxray <url> download path (R10). See the plan this
 * implements: EP+ PLAN "crxray behavior-capture capability".
 *
 * @param {string} extensionDir - unpacked extension directory to load.
 * @param {string} scenarioPath - path to a scenario JSON file ({"steps": [...]})
 * @param {object} opts
 * @param {string} opts.outFile - where to write the capture file.
 * @param {boolean} opts.yesIReviewedPermissions - required confirmation gate (R11).
 * @param {number} [opts.timeoutMs] - hard wall-clock cap for the scenario run (R11).
 * @param {boolean} [opts.quiet]
 */
export async function captureBehavior(extensionDir, scenarioPath, opts = {}) {
  if (!opts.yesIReviewedPermissions) {
    throw new Error(
      'capture-behavior loads and runs third-party extension code. Pass --yes-i-reviewed-permissions ' +
        'after reviewing the extension\'s requested permissions (see `crxray audit`).'
    );
  }

  const manifestPath = path.join(extensionDir, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  // Static, no browser involved -- gives the message-passing/endpoint maps this capture's
  // events get cross-referenced against below (see mechanism.js). Run before anything else
  // touches extensionDir, same assumptions `crxray audit` already makes about that directory.
  const staticAudit = auditExtension(extensionDir, manifest, summarizeManifest(manifest));
  const steps = parseScenario(scenarioPath);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const chromePath = findChrome();
  const profileDir = mkdtempSync(path.join(tmpdir(), 'crxray-capture-'));

  const events = [];
  const limitations = [];
  let seq = 0;
  let extensionId = null;

  const namedTargets = {};
  const state = {
    manifest,
    get extensionId() {
      return extensionId;
    },
    namedTargets,
    sessionFor(name) {
      return namedTargets[name]?.sessionId;
    },
  };

  const client = new CdpPipeClient(chromePath, [
    '--remote-debugging-pipe',
    '--enable-unsafe-extension-debugging',
    `--user-data-dir=${profileDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--headless=new',
    '--disable-gpu',
    'about:blank',
  ]);

  const pendingResponseBodies = new Map(); // requestId -> {sessionId, url}

  function pushEvent(raw) {
    events.push({ seq: seq++, ts: Date.now(), ...redactEvent(raw) });
  }

  client.on('Target.attachedToTarget', (msg) => {
    const { sessionId, targetInfo, waitingForDebugger } = msg.params;
    const belongsToUs = extensionId && targetInfo.url?.includes(extensionId);

    if (targetInfo.type === 'service_worker' && targetInfo.url?.includes(extensionId ?? '\u0000')) {
      namedTargets.serviceWorker = { targetId: targetInfo.targetId, sessionId };
    }
    for (const [name, ref] of Object.entries(namedTargets)) {
      if (ref.targetId === targetInfo.targetId) ref.sessionId = sessionId;
    }

    if (!waitingForDebugger) {
      if (belongsToUs) {
        addLimitation(limitations, {
          capability: 'preExecutionInstrumentation',
          target: targetInfo.type,
          reason: 'target was already running when the capture session attached; calls made before attachment are not captured',
          severity: 'known-gap',
        });
      }
      return;
    }

    instrumentAndResume(client, sessionId, targetInfo, limitations).catch((err) => {
      addLimitation(limitations, {
        capability: 'preExecutionInstrumentation',
        target: targetInfo.type,
        reason: `instrumentation failed: ${err.message}`,
        severity: 'known-gap',
      });
    });
  });

  client.on('Runtime.consoleAPICalled', (msg) => {
    const arg = msg.params.args?.[0];
    if (arg?.type !== 'string' || !arg.value?.startsWith(CAPTURE_MARKER)) return;
    try {
      const entry = JSON.parse(arg.value.slice(CAPTURE_MARKER.length));
      pushEvent({ targetType: 'instrumented', sessionId: msg.sessionId, ...entry });
    } catch {
      // malformed capture payload; drop rather than crash the run
    }
  });

  client.on('Network.requestWillBeSent', (msg) => {
    const { requestId, request } = msg.params;
    pendingResponseBodies.set(requestId, { sessionId: msg.sessionId });
    pushEvent({
      kind: 'network',
      direction: 'request',
      requestId,
      url: request.url,
      method: request.method,
      headers: request.headers,
      body: request.postData,
    });
  });

  client.on('Network.responseReceived', async (msg) => {
    const { requestId, response } = msg.params;
    const mimeOk = CAPTURABLE_MIME_RE.test(response.mimeType ?? '');
    const base = {
      kind: 'network',
      direction: 'response',
      requestId,
      url: response.url,
      status: response.status,
      headers: response.headers,
    };
    if (!mimeOk) {
      addLimitation(limitations, {
        capability: 'responseBody',
        target: response.url,
        reason: `response body skipped (mimeType=${response.mimeType})`,
        severity: 'known-gap',
      });
      pushEvent(base);
      return;
    }
    try {
      const bodyRes = await client.send('Network.getResponseBody', { requestId }, msg.sessionId);
      const bodyText = bodyRes.result?.body ?? '';
      const truncated = bodyText.length > RESPONSE_BODY_BYTE_CAP;
      pushEvent({
        ...base,
        body: truncated ? bodyText.slice(0, RESPONSE_BODY_BYTE_CAP) : bodyText,
        truncated,
        originalByteLength: truncated ? bodyText.length : undefined,
      });
    } catch (err) {
      pushEvent({ ...base, bodyUnavailable: true, reason: err.message });
    }
  });

  client.on('Log.entryAdded', (msg) => {
    pushEvent({ kind: 'console', level: msg.params.entry.level, text: msg.params.entry.text });
  });

  await client.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
  await client.send('Target.setDiscoverTargets', { discover: true });

  const loadRes = await client.send('Extensions.loadUnpacked', { path: path.resolve(extensionDir) });
  if (loadRes.error) {
    await killAndCleanup(client, profileDir);
    throw new Error(`Extensions.loadUnpacked failed: ${loadRes.error.message}`);
  }
  extensionId = loadRes.result.id;

  let timedOut = false;
  try {
    await Promise.race([
      (async () => {
        for (const step of steps) await runStep(client, state, step);
      })(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs)),
    ]);
  } catch (err) {
    if (err.message === 'timeout') {
      timedOut = true;
      addLimitation(limitations, {
        capability: 'scenario',
        target: 'all',
        reason: `scenario exceeded ${timeoutMs}ms timeout and was aborted`,
        severity: 'blocking',
      });
    } else {
      throw err;
    }
  }

  // Let in-flight response bodies settle briefly before closing.
  await new Promise((r) => setTimeout(r, 500));

  await killAndCleanup(client, profileDir);

  addLimitation(limitations, {
    capability: 'scope',
    target: 'all',
    reason: 'this capture reflects only the scenario actually exercised, under one run, one environment -- not a complete record of the extension\'s behavior',
    severity: 'always-on',
  });

  const capture = {
    schemaVersion: SCHEMA_VERSION,
    scenarioId: path.basename(scenarioPath),
    extensionId,
    version: manifest.version ?? null,
    chromeVersion: null,
    timestamp: new Date().toISOString(),
    events,
    mechanism: buildMechanismReport(staticAudit, events),
    limitations,
    disclaimer: DISCLAIMER,
  };

  const outFile = opts.outFile ?? `${path.basename(extensionDir)}-capture.json`;
  writeFileSync(outFile, JSON.stringify(capture, null, 2));

  return { outFile, capture, timedOut };
}
