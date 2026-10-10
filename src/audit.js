import { readFileSync } from 'node:fs';
import path from 'node:path';
import { buildEntryPointMap } from './map.js';
import { walkFiles, relPath, isSupersededByUnpack, isWakaruOutput } from './walk.js';

const HIGH_RISK_PERMISSIONS = new Set([
  'webRequest',
  'webRequestBlocking',
  'cookies',
  'nativeMessaging',
  'debugger',
  'proxy',
  'management',
  'desktopCapture',
  'declarativeNetRequestWithHostAccess',
  'browsingData',
  'history',
  'clipboardRead',
  'geolocation',
  'downloads',
  'tabs',
]);

const MEDIUM_RISK_PERMISSIONS = new Set([
  'scripting',
  'activeTab',
  'notifications',
  'identity',
  'privacy',
  'sessions',
  'bookmarks',
]);

const SUSPICIOUS_PATTERNS = [
  { id: 'eval', label: 'eval()', re: /\beval\s*\(/g, severity: 'high' },
  { id: 'function-constructor', label: 'new Function()', re: /\bnew\s+Function\s*\(/g, severity: 'high' },
  { id: 'atob', label: 'atob() decoding', re: /\batob\s*\(/g, severity: 'medium' },
  { id: 'document-write', label: 'document.write()', re: /\bdocument\.write\s*\(/g, severity: 'medium' },
  { id: 'chrome-cookies', label: 'chrome.cookies access', re: /\b(?:chrome|browser)\.cookies\b/g, severity: 'high' },
  { id: 'chrome-webRequest', label: 'chrome.webRequest access', re: /\b(?:chrome|browser)\.webRequest\b/g, severity: 'high' },
  { id: 'send-beacon', label: 'navigator.sendBeacon()', re: /\bnavigator\.sendBeacon\s*\(/g, severity: 'medium' },
  { id: 'xhr', label: 'XMLHttpRequest', re: /\bnew\s+XMLHttpRequest\s*\(/g, severity: 'low' },
  { id: 'dynamic-import', label: 'dynamic import()', re: /\bimport\s*\(/g, severity: 'low' },
  { id: 'fetch', label: 'fetch()', re: /\bfetch\s*\(/g, severity: 'low' },
  { id: 'websocket', label: 'new WebSocket()', re: /\bnew\s+WebSocket\s*\(/g, severity: 'medium' },
  {
    id: 'runtime-send-message',
    label: 'chrome.runtime.sendMessage/connect',
    re: /\b(?:chrome|browser)\.runtime\.(sendMessage|connect)\s*\(/g,
    severity: 'low',
  },
  {
    id: 'scripting-execute-script',
    label: 'chrome.scripting.executeScript',
    re: /\b(?:chrome|browser)\.scripting\.executeScript\s*\(/g,
    severity: 'high',
  },
  {
    id: 'tabs-execute-script',
    label: 'chrome.tabs.executeScript',
    re: /\b(?:chrome|browser)\.tabs\.executeScript\s*\(/g,
    severity: 'high',
  },
  {
    id: 'external-script-tag',
    label: 'dynamically-created <script> tag',
    re: /createElement\s*\(\s*['"]script['"]\s*\)/g,
    severity: 'medium',
  },
  {
    id: 'chrome-debugger',
    label: 'chrome.debugger access',
    re: /\b(?:chrome|browser)\.debugger\.(attach|sendCommand)\s*\(/g,
    severity: 'high',
  },
  {
    id: 'cdp-dangerous-command',
    label: 'CDP dangerous command',
    re: /["'](Runtime\.evaluate|Network\.enable|Input\.dispatch|Fetch\.enable|Page\.captureScreenshot)["']/g,
    severity: 'high',
  },
  // Secret patterns match a real credential SHAPE (prefix + charset + length),
  // never a variable name -- "a variable named password/apikey" is not a
  // secret, it is a password manager's own domain vocabulary. Confirmed as a
  // real false-positive class in a competing tool's secrets detector before
  // these were written.
  {
    id: 'secret-aws-key',
    label: 'AWS access key',
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'high',
  },
  {
    id: 'secret-github-token',
    label: 'GitHub token',
    re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    severity: 'high',
  },
  {
    id: 'secret-stripe-key',
    label: 'Stripe key',
    re: /\b[sp]k_(live|test)_[A-Za-z0-9]{24,}\b/g,
    severity: 'high',
  },
  {
    id: 'secret-slack-token',
    label: 'Slack token',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    severity: 'high',
  },
  {
    id: 'secret-rsa-private-key',
    label: 'RSA/SSH private key block',
    re: /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/g,
    severity: 'high',
  },
  // Dark patterns: user-hostile, not necessarily malicious. Kept to two
  // well-defined, low-noise checks -- notification-spam and fingerprinting
  // both need multi-signal/control-flow analysis to avoid flooding on
  // ordinary, benign single API calls (e.g. canvas.toDataURL() alone is a
  // completely normal screenshot feature), so they're left for later rather
  // than shipped as a noisy single-call regex.
  {
    id: 'affiliate-link-injection',
    label: 'Affiliate link injection',
    re: /href\s*[+=][^;]{0,80}?[?&](?:ref|aff|affiliate|utm_source)=/gi,
    severity: 'medium',
  },
  {
    id: 'review-nagging-url',
    label: 'Review-nagging store URL',
    re: /(?:chromewebstore\.google\.com\/detail|chrome\.google\.com\/webstore\/detail|addons\.mozilla\.org\/[a-z-]+\/addon)\/[^"'\s]*review/gi,
    severity: 'low',
  },
];

const ENTROPY_MIN_FILE_SIZE = 500;
const ENTROPY_THRESHOLD = 6.0;

// A high-entropy file only gets reported when the SAME file also contains a
// decode/execute call -- eval, new Function, atob, a dynamically-created
// <script> tag. A bare embedded blob with no decode step next to it is
// almost always a legitimate asset (a font, an image, a protobuf schema):
// base64-encoded binary data is inherently high-entropy no matter what it
// encodes, and real obfuscated payloads pair the blob with exactly this
// kind of decode-and-run step in the same file -- that pairing is the
// actual signal, not entropy alone. Confirmed against three real false
// positives this session, none of which had a decode call anywhere nearby:
// a Bitwarden-adjacent wasm hex blob, 45 embedded fonts in Scrnli
// (`module.exports = "data:font/woff2;base64,...";`), and 8 embedded
// protobuf schemas in Grammarly passed as plain function-call arguments --
// a different enough shape from the font case that chasing the syntax
// pattern-by-pattern would never fully close; requiring the companion
// decode signal does, in one general mechanism.
const ENTROPY_COMPANION_PATTERN_IDS = new Set(['eval', 'function-constructor', 'atob', 'external-script-tag']);

function shannonEntropy(str) {
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Permission <-> API-call pairs worth correlating: a permission *declared*
// in the manifest AND a matching call actually found in the source is a
// much stronger signal than either alone. Kept deliberately small --
// each pair here has a real, documented capability link; e.g.
// `webRequestBlocking` and `tabs` were considered and dropped: neither
// actually gates the pattern it would have been paired with
// (`webRequestBlocking` only matters for *blocking* listeners, which the
// bare `chrome.webRequest` regex can't distinguish from an observing one;
// `tabs` gates reading tab properties, not script injection).
const PERMISSION_PATTERN_PAIRS = [
  { permission: 'cookies', patternId: 'chrome-cookies' },
  { permission: 'webRequest', patternId: 'chrome-webRequest' },
  { permission: 'scripting', patternId: 'scripting-execute-script' },
  { permission: 'debugger', patternId: 'chrome-debugger' },
];

const URL_RE = /https?:\/\/[^\s"'`)]+/g;

const EXCLUDED_HOST_SUFFIXES = ['mozilla.org', 'w3.org'];

export function collectEndpointsFromContent(content) {
  const endpoints = [];
  for (const url of content.match(URL_RE) ?? []) {
    const cleaned = url.replace(/[),.;]+$/, '');
    let host;
    try {
      host = new URL(cleaned).hostname;
    } catch {
      continue; // not a well-formed URL (e.g. trailing garbage survived cleanup)
    }
    const excluded = EXCLUDED_HOST_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
    if (!excluded) endpoints.push(cleaned);
  }
  return endpoints;
}

/**
 * Run a security-oriented audit on an unpacked extension directory.
 */
export function auditExtension(dir, manifest, summary) {
  const map = buildEntryPointMap(dir, manifest);
  const permissions = classifyPermissions(summary);
  const findings = scanSource(dir);
  const endpoints = collectEndpoints(dir);
  const flags = manifestFlags(summary);
  const correlations = correlatePermissionsAndFindings(permissions, findings);
  const risk = computeRisk(permissions, findings, summary, flags, correlations);

  return {
    risk,
    permissions,
    findings,
    endpoints,
    flags,
    correlations,
    entryPoints: map.entryPoints,
    readability: map.readability,
    startHere: map.startHere,
    version: summary?.version ?? null,
    name: summary?.name ?? null,
  };
}

const OFFICIAL_UPDATE_URL_HOSTS = new Set([
  'clients2.google.com',
  'edge.microsoft.com',
]);

function manifestFlags(summary) {
  const flags = [];
  if (!summary) return flags;

  if (summary.updateUrl) {
    let host = null;
    try {
      host = new URL(summary.updateUrl).hostname;
    } catch {
      // not a parseable URL; treat as non-official below
    }
    if (!host || !OFFICIAL_UPDATE_URL_HOSTS.has(host)) {
      flags.push({
        severity: 'high',
        label: 'custom update_url (bypasses store-managed updates)',
        detail: summary.updateUrl,
      });
    }
  }
  if (summary.contentSecurityPolicy) {
    const csp = JSON.stringify(summary.contentSecurityPolicy);
    if (/unsafe-eval|wasm-unsafe-eval/.test(csp)) {
      flags.push({ severity: 'high', label: 'CSP allows unsafe-eval', detail: csp });
    }
  }
  if (summary.externallyConnectable) {
    flags.push({
      severity: 'medium',
      label: 'externally_connectable: other extensions/sites can message this one',
      detail: JSON.stringify(summary.externallyConnectable),
    });
  }
  if (summary.oauth2) {
    flags.push({ severity: 'low', label: 'requests OAuth2 scopes', detail: (summary.oauth2.scopes ?? []).join(', ') });
  }
  return flags;
}

function classifyPermissions(summary) {
  if (!summary) return { high: [], medium: [], low: [], hostAccess: [] };

  const all = [
    ...(summary.permissions ?? []),
    ...(summary.optionalPermissions ?? []),
    ...(summary.hostPermissions ?? []),
    ...(summary.optionalHostPermissions ?? []),
  ];

  const high = [];
  const medium = [];
  const low = [];
  const hostAccess = [];

  for (const perm of all) {
    if (perm.includes('://') || perm === '<all_urls>' || perm.startsWith('*://')) {
      hostAccess.push(perm);
      if (perm === '<all_urls>' || perm === '*://*/*') high.push(perm);
      continue;
    }
    if (HIGH_RISK_PERMISSIONS.has(perm)) high.push(perm);
    else if (MEDIUM_RISK_PERMISSIONS.has(perm)) medium.push(perm);
    else low.push(perm);
  }

  return { high, medium, low, hostAccess };
}

function scanSource(dir) {
  const findings = [];
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });

  for (const file of jsFiles) {
    if (isSupersededByUnpack(file) || isWakaruOutput(file)) continue;
    const rel = relPath(dir, file);
    const content = readFileSync(file, 'utf8');
    const lines = content.split('\n');

    let entropyValue = null;
    if (content.length >= ENTROPY_MIN_FILE_SIZE) {
      const entropy = shannonEntropy(content);
      if (entropy >= ENTROPY_THRESHOLD) entropyValue = entropy;
    }
    let hasDecodeSignal = false;

    for (const pattern of SUSPICIOUS_PATTERNS) {
      pattern.re.lastIndex = 0;
      let match;
      while ((match = pattern.re.exec(content)) !== null) {
        if (ENTROPY_COMPANION_PATTERN_IDS.has(pattern.id)) hasDecodeSignal = true;
        const lineStart = content.lastIndexOf('\n', match.index - 1) + 1;
        const line = content.slice(0, match.index).split('\n').length;
        const lineText = lines[line - 1] ?? '';
        const col = match.index - lineStart;
        // Window centered on the match, not just the line's first 120 chars
        // -- a match far past column 120 on a long (often minified) line
        // was previously invisible in the preview even though the finding
        // itself (file/line/pattern) was already correct.
        const windowStart = Math.max(0, col - 40);
        const windowEnd = Math.min(lineText.length, col + match[0].length + 80);
        const snippet = lineText.slice(windowStart, windowEnd).trim();
        findings.push({
          severity: pattern.severity,
          pattern: pattern.label,
          file: rel,
          line,
          snippet,
        });
        if (findings.length >= 200) return findings;
      }
    }

    if (entropyValue !== null && hasDecodeSignal) {
      findings.push({
        severity: 'medium',
        pattern: 'High entropy (possible obfuscation)',
        file: rel,
        line: 1,
        snippet: `entropy=${entropyValue.toFixed(2)}`,
      });
    }
  }

  return findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function collectEndpoints(dir) {
  const endpoints = new Set();
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });

  for (const file of jsFiles) {
    if (isSupersededByUnpack(file) || isWakaruOutput(file)) continue;
    const content = readFileSync(file, 'utf8');
    for (const url of collectEndpointsFromContent(content)) endpoints.add(url);
  }

  return [...endpoints].sort().slice(0, 100);
}

/**
 * Correlate declared permissions with matching API-call findings. A
 * permission alone, or a pattern hit alone, is weaker evidence than both
 * together -- this says "and found a matching call", not "granted": these
 * permission arrays include optional permissions the user may never
 * actually grant at runtime, which static analysis of the manifest alone
 * can't resolve.
 */
function correlatePermissionsAndFindings(permissions, findings) {
  const declared = new Set([...permissions.high, ...permissions.medium, ...permissions.low]);
  const patternLabelById = new Map(SUSPICIOUS_PATTERNS.map((p) => [p.id, p.label]));
  const correlations = [];

  for (const { permission, patternId } of PERMISSION_PATTERN_PAIRS) {
    if (!declared.has(permission)) continue;
    const label = patternLabelById.get(patternId);
    const matchingFiles = [...new Set(findings.filter((f) => f.pattern === label).map((f) => f.file))].sort();
    if (matchingFiles.length === 0) continue;
    correlations.push({ permission, pattern: label, files: matchingFiles });
  }

  return correlations;
}

function computeRisk(permissions, findings, summary, flags = [], correlations = []) {
  const distinctHighHits = new Set(
    findings.filter((f) => f.severity === 'high').map((f) => `${f.file}:${f.pattern}`)
  ).size;
  const distinctMediumHits = new Set(
    findings.filter((f) => f.severity === 'medium').map((f) => `${f.file}:${f.pattern}`)
  ).size;

  let score = 0;
  score += permissions.high.length * 3;
  score += permissions.medium.length * 1;
  score += distinctHighHits * 2;
  score += distinctMediumHits;
  score += flags.filter((f) => f.severity === 'high').length * 3;
  score += flags.filter((f) => f.severity === 'medium').length * 1;
  score += correlations.length * 2;

  const hasBroadHost =
    permissions.hostAccess.includes('<all_urls>') ||
    permissions.hostAccess.includes('*://*/*') ||
    summary?.permissions?.includes('<all_urls>');

  if (hasBroadHost) score += 5;

  let level = 'low';
  if (score >= 12) level = 'critical';
  else if (score >= 7) level = 'high';
  else if (score >= 3) level = 'medium';

  return { level, score, hasBroadHost };
}

function severityRank(severity) {
  return { high: 3, medium: 2, low: 1 }[severity] ?? 0;
}

export function formatAuditReport(audit) {
  const lines = [];
  const riskLabel = audit.risk.level.toUpperCase();

  lines.push(`${riskEmoji(audit.risk.level)}  ${riskLabel} RISK (score ${audit.risk.score})`);
  lines.push('');

  if (audit.signature) {
    lines.push(
      `Signature: ${audit.signature.verified ? '✅ verified store-signed CRX3' : `⚠️ unverifiable (${audit.signature.reason})`}`
    );
    lines.push('');
  }

  if (audit.name) {
    lines.push(`  ${audit.name}${audit.version ? ` v${audit.version}` : ''}`);
    lines.push('');
  }

  if (audit.flags?.length) {
    lines.push('Manifest flags');
    for (const f of audit.flags) lines.push(`  [${f.severity}] ${f.label}${f.detail ? ` — ${f.detail}` : ''}`);
    lines.push('');
  }

  if (audit.correlations?.length) {
    lines.push('Declared permission + matching API call');
    for (const c of audit.correlations) {
      lines.push(`  ${c.permission} -> ${c.pattern} (${c.files.join(', ')})`);
    }
    lines.push('');
  }

  if (audit.permissions.high.length || audit.permissions.hostAccess.length) {
    lines.push('Permissions & access');
    if (audit.permissions.high.length) lines.push(`  High: ${audit.permissions.high.join(', ')}`);
    if (audit.permissions.medium.length) lines.push(`  Medium: ${audit.permissions.medium.join(', ')}`);
    if (audit.permissions.hostAccess.length) lines.push(`  Host: ${audit.permissions.hostAccess.join(', ')}`);
    lines.push('');
  }

  if (audit.findings.length) {
    lines.push('Suspicious patterns');
    for (const f of audit.findings.slice(0, 15)) {
      lines.push(`  ${f.file}:${f.line}  ${f.pattern}`);
      if (f.snippet) lines.push(`    ${f.snippet}`);
    }
    if (audit.findings.length > 15) {
      lines.push(`  ... and ${audit.findings.length - 15} more`);
    }
    lines.push('');
  }

  if (audit.endpoints.length) {
    lines.push(`Network endpoints (${audit.endpoints.length})`);
    for (const ep of audit.endpoints.slice(0, 10)) lines.push(`  ${ep}`);
    if (audit.endpoints.length > 10) lines.push(`  ... and ${audit.endpoints.length - 10} more`);
    lines.push('');
  }

  lines.push('Start here');
  for (const p of audit.startHere) lines.push(`  ${p}`);

  lines.push('');
  lines.push(
    `Readability: ${audit.readability.readable} readable, ${audit.readability.minified} minified JS files`
  );

  return lines.join('\n');
}

function riskEmoji(level) {
  return { critical: '🔴', high: '⚠️', medium: '🟡', low: '🟢' }[level] ?? '⚪';
}
