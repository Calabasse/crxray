import { readFileSync } from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { walkFiles, relPath, isWakaruOutput } from './walk.js';

const MIN_SIZE = 80;
const MAX_SIZE = 5 * 1024 * 1024;
const WAKARU_TIMEOUT_MS = 30_000;

/**
 * Structurally unpack/unminify every .js file using wakaru — a separate npm
 * package, invoked via `npx wakaru` and never added as a crxray dependency.
 * Runs independently of deobfuscateDirectory/webcrack: same candidate files,
 * no shared state, no data handoff. Output lands in a `<file>.wakaru/`
 * sibling that audit/map never scan (see isWakaruOutput in walk.js).
 */
export async function unpackWithWakaru(dir, { quiet = false, exec = defaultExec } = {}) {
  const jsFiles = walkFiles(dir, { extensions: ['.js'] }).filter(
    (file) => !isWakaruOutput(file) && !isInsideUnpackedDir(file)
  );
  const results = { processed: 0, unpacked: 0, skipped: 0, errors: [] };

  for (const file of jsFiles) {
    results.processed++;
    const rel = relPath(dir, file);
    const size = readFileSync(file).length;

    if (size < MIN_SIZE) {
      results.skipped++;
      continue;
    }
    if (size > MAX_SIZE) {
      results.skipped++;
      results.errors.push({ file: rel, error: 'file too large (>5MB)' });
      continue;
    }

    const outDir = path.join(path.dirname(file), `${path.basename(file, '.js')}.wakaru`);

    let stdout;
    try {
      stdout = exec('npx', ['wakaru', file, '--unpack', '-o', outDir, '--json'], {
        timeout: WAKARU_TIMEOUT_MS,
        encoding: 'utf8',
      });
    } catch (err) {
      results.skipped++;
      results.errors.push({ file: rel, error: `wakaru failed: ${err.message}` });
      continue;
    }

    let report;
    try {
      report = parseWakaruJson(stdout);
    } catch (err) {
      results.skipped++;
      results.errors.push({ file: rel, error: `could not parse wakaru output: ${err.message}` });
      continue;
    }

    if (!report.total) {
      results.skipped++;
      if (!quiet) console.error(`no recognized bundle format in ${rel}`);
      continue;
    }

    results.unpacked++;
    if (!quiet) {
      console.error(`unpacked ${rel} with wakaru → ${relPath(dir, outDir)}/ (${report.total} modules)`);
    }
  }

  return results;
}

function isInsideUnpackedDir(file) {
  return file.split(path.sep).some((seg) => seg.endsWith('.unpacked'));
}

function defaultExec(cmd, args, opts) {
  return execFileSync(cmd, args, opts);
}

// wakaru's --json output is a JSON object, but CLIs commonly interleave
// progress lines on stdout ahead of their final result — parse only the
// last non-empty line so a stray log line doesn't look like malformed JSON.
function parseWakaruJson(stdout) {
  const lines = stdout.trim().split('\n');
  return JSON.parse(lines[lines.length - 1]);
}
