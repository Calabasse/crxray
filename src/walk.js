import { readdirSync, statSync } from 'node:fs';
import path from 'node:path';

// Chrome/Edge extensions are shallow, small trees. These caps catch a
// pathological input (deep nesting, huge file count) before it can
// stack-overflow or run away during audit/map/diff.
const MAX_FILES = 50_000;
const MAX_DEPTH = 64;

/**
 * Recursively list files under dir, optionally filtered by extension.
 */
export function walkFiles(dir, { extensions = null, maxFiles = MAX_FILES, maxDepth = MAX_DEPTH } = {}) {
  const results = [];
  walk(dir, extensions, 0, results, maxFiles, maxDepth);
  return results;
}

function walk(dir, extensions, depth, results, maxFiles, maxDepth) {
  if (depth > maxDepth) {
    throw new Error(`walkFiles: directory nesting exceeds ${maxDepth} levels under ${dir} — refusing to recurse further.`);
  }
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, extensions, depth + 1, results, maxFiles, maxDepth);
    } else if (!extensions || extensions.some((ext) => entry.name.endsWith(ext))) {
      if (results.length >= maxFiles) {
        throw new Error(`walkFiles: more than ${maxFiles} files under ${dir} — refusing to continue.`);
      }
      results.push(full);
    }
  }
}

export function isDirectory(p) {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

export function relPath(root, file) {
  return path.relative(root, file).replaceAll('\\', '/');
}

/**
 * True when `file` (a .js file) was split into readable modules by
 * deobfuscateDirectory's bundle-unpack step — its sibling `<name>.unpacked/`
 * directory exists. Callers that aggregate findings/stats across .js files
 * should skip a superseded original so its minified content isn't counted
 * twice alongside the readable modules that replaced it.
 */
export function isSupersededByUnpack(file) {
  const unpackedDir = path.join(path.dirname(file), `${path.basename(file, '.js')}.unpacked`);
  return isDirectory(unpackedDir);
}
