/**
 * OmniOS Deterministic Sample Build Pipeline (`F-060`)
 * Zero external npm dependencies (Node.js 24 built-ins + OmniOS SDK builders).
 *
 * Exports:
 * - `ALL_PLATFORMS`: `['android', 'windows', 'ios', 'macos', 'universal']`
 * - `buildAllSamples({ outputDir, platforms, quiet } = {})`:
 *     Deterministically assembles and packages sample binaries for all requested platforms,
 *     verifying output byte lengths and SHA-256 digests on disk.
 *     M4 builders (`ios`, `macos`, `universal`) are invoked directly; M3 builders
 *     (`android`, `windows`) are discovered dynamically via `fs.existsSync` + dynamic `import()`
 *     so M3 and M4 remain cleanly decoupled while producing all 7 packages in `packages/`
 *     once both milestones are present.
 *
 * CLI Usage:
 *   node sdk/build-samples.mjs [--output-dir <dir>] [--platforms ios,macos,universal|all] [--json] [--quiet]
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildWeatherIslandSample } from './ios-builder.mjs';
import { buildMacStudioSample } from './macos-builder.mjs';
import { buildUniversalCanvasSample } from './universal-builder.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_OUTPUT_DIR = path.join(REPO_ROOT, 'packages');

export const ALL_PLATFORMS = Object.freeze(['android', 'windows', 'ios', 'macos', 'universal']);
const PLATFORM_SET = new Set(ALL_PLATFORMS);

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function normalizePlatforms(platforms) {
  if (platforms === undefined || platforms === null || platforms === 'all') {
    return [...ALL_PLATFORMS];
  }
  const rawList = Array.isArray(platforms)
    ? platforms.flatMap((p) => String(p).split(','))
    : String(platforms).split(',');

  const selected = new Set();
  for (const item of rawList) {
    const clean = item.trim().toLowerCase();
    if (!clean) continue;
    if (clean === 'all') {
      return [...ALL_PLATFORMS];
    }
    if (!PLATFORM_SET.has(clean)) {
      throw new RangeError(
        `Unknown platform "${clean}". Expected one of: ${ALL_PLATFORMS.join(', ')}, all`
      );
    }
    selected.add(clean);
  }
  if (selected.size === 0) {
    throw new RangeError(
      `No valid platforms specified. Expected one of: ${ALL_PLATFORMS.join(', ')}, all`
    );
  }
  return ALL_PLATFORMS.filter((p) => selected.has(p));
}

function extractBytesFromResult(result) {
  if (!result) return null;
  if (result instanceof Uint8Array) return result;
  if (ArrayBuffer.isView(result)) {
    return new Uint8Array(result.buffer, result.byteOffset, result.byteLength);
  }
  if (result instanceof ArrayBuffer) return new Uint8Array(result);
  if (typeof result === 'object') {
    for (const key of ['bytes', 'apkBytes', 'exeBytes', 'peBytes', 'ipaBytes', 'zipBytes', 'uappBytes', 'buffer', 'data']) {
      const val = result[key];
      if (val instanceof Uint8Array) return val;
      if (ArrayBuffer.isView(val)) return new Uint8Array(val.buffer, val.byteOffset, val.byteLength);
      if (val instanceof ArrayBuffer) return new Uint8Array(val);
    }
  }
  return null;
}

function expectsObjectFirstArg(fn) {
  try {
    const src = Function.prototype.toString.call(fn);
    const open = src.indexOf('(');
    if (open === -1) return false;
    const afterParen = src.slice(open + 1).trimStart();
    return afterParen.startsWith('{');
  } catch {
    return false;
  }
}

function verifyBuiltFile(platform, filePath) {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Expected ${platform} sample output file does not exist: ${resolved}`);
  }
  const diskBytes = fs.readFileSync(resolved);
  if (diskBytes.byteLength === 0) {
    throw new Error(`Built ${platform} sample output file is empty (0 bytes): ${resolved}`);
  }
  return {
    platform,
    filename: path.basename(resolved),
    path: resolved,
    bytes: diskBytes.byteLength,
    sha256: sha256Hex(diskBytes),
  };
}

function collectResultPaths(result, outputDir, prefix, ext) {
  const found = new Set();
  const addIfPath = (p) => {
    if (typeof p === 'string' && p.length > 0) {
      const resolved = path.resolve(p);
      if (fs.existsSync(resolved)) {
        found.add(resolved);
      }
    }
  };

  const visit = (node) => {
    if (!node) return;
    if (typeof node === 'string') {
      addIfPath(node);
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) visit(item);
      return;
    }
    if (typeof node === 'object') {
      addIfPath(node.outputPath);
      addIfPath(node.path);
      addIfPath(node.output);
      addIfPath(node.filePath);
      if (typeof node.filename === 'string') {
        addIfPath(path.join(outputDir, node.filename));
      }
      if (Array.isArray(node.packages)) visit(node.packages);
      if (Array.isArray(node.files)) visit(node.files);
      if (Array.isArray(node.samples)) visit(node.samples);
      for (const [k, v] of Object.entries(node)) {
        if (k === 'bytes' || k === 'buffer' || k === 'data') continue;
        if (v && typeof v === 'object' && !(v instanceof Uint8Array) && !ArrayBuffer.isView(v)) {
          visit(v);
        }
      }
    }
  };
  visit(result);

  if (found.size === 0 && fs.existsSync(outputDir)) {
    for (const entry of fs.readdirSync(outputDir)) {
      if (entry.startsWith(prefix) && entry.endsWith(ext)) {
        found.add(path.join(outputDir, entry));
      }
    }
  }

  return Array.from(found).sort();
}

async function buildDynamicPlatformSamples({
  platform,
  builderFilename,
  batchExportNames,
  individualSpecs,
  filePrefix,
  fileExt,
  outputDir,
}) {
  const builderPath = path.join(__dirname, builderFilename);
  if (!fs.existsSync(builderPath)) {
    return {
      packages: [],
      skipped: {
        platform,
        reason: 'builder_not_found',
        builderPath,
      },
    };
  }

  const mod = await import(pathToFileURL(builderPath).href);
  fs.mkdirSync(outputDir, { recursive: true });

  // 1. Prefer batch builder exports when available
  for (const name of batchExportNames) {
    if (typeof mod[name] === 'function') {
      const fn = mod[name];
      const res = expectsObjectFirstArg(fn)
        ? await fn({ outputDir, outDir: outputDir, dir: outputDir })
        : await fn(outputDir);
      const paths = collectResultPaths(res, outputDir, filePrefix, fileExt);
      if (paths.length > 0) {
        return {
          packages: paths.map((p) => verifyBuiltFile(platform, p)),
          skipped: null,
        };
      }
    }
  }

  // 2. Fallback to individual sample builders if exported
  const built = [];
  for (const spec of individualSpecs) {
    const fnName = spec.exportNames.find((n) => typeof mod[n] === 'function');
    if (!fnName) continue;
    const targetPath = path.join(outputDir, spec.filename);
    const fn = mod[fnName];
    const res = expectsObjectFirstArg(fn)
      ? await fn({ outputPath: targetPath, outputDir, filename: spec.filename })
      : await fn(targetPath);

    if (!fs.existsSync(targetPath)) {
      const bytes = extractBytesFromResult(res);
      if (bytes && bytes.byteLength > 0) {
        fs.writeFileSync(targetPath, bytes);
      }
    }
    if (fs.existsSync(targetPath)) {
      built.push(verifyBuiltFile(platform, targetPath));
    }
  }

  if (built.length > 0) {
    return { packages: built, skipped: null };
  }

  return {
    packages: [],
    skipped: {
      platform,
      reason: 'no_compatible_sample_builder_export',
      builderPath,
      availableExports: Object.keys(mod).sort(),
    },
  };
}

/**
 * Deterministically builds OmniOS sample packages for all requested platforms.
 *
 * @param {object} [options]
 * @param {string} [options.outputDir] Target directory (defaults to `<repo>/packages`)
 * @param {string|string[]} [options.platforms='all'] Platforms to build (`android`, `windows`, `ios`, `macos`, `universal`, or `all`)
 * @param {boolean} [options.quiet=true] Suppress progress logs when called programmatically
 * @returns {Promise<{ ok: boolean, outputDir: string, platforms: string[], packages: Array<{ platform: string, filename: string, path: string, bytes: number, sha256: string }>, skipped: Array<object> }>}
 */
export async function buildAllSamples({
  outputDir = DEFAULT_OUTPUT_DIR,
  platforms = 'all',
  quiet = true,
} = {}) {
  const resolvedOutDir = path.resolve(outputDir);
  const selectedPlatforms = normalizePlatforms(platforms);
  fs.mkdirSync(resolvedOutDir, { recursive: true });

  const packages = [];
  const skipped = [];

  for (const platform of selectedPlatforms) {
    if (platform === 'android') {
      const res = await buildDynamicPlatformSamples({
        platform: 'android',
        builderFilename: 'android-builder.mjs',
        batchExportNames: [
          'buildAndroidSamples',
          'buildAllAndroidSamples',
          'buildSampleApks',
          'buildAndroidSamplePackages',
          'buildDefaultSamples',
          'buildSamples',
          'buildAll',
        ],
        individualSpecs: [
          {
            filename: 'android-calc.apk',
            exportNames: [
              'buildAndroidCalcSample',
              'buildCalcSample',
              'buildCalculatorSample',
              'buildAndroidCalcApk',
              'buildCalcApk',
            ],
          },
          {
            filename: 'android-notes-sharer.apk',
            exportNames: [
              'buildAndroidNotesSharerSample',
              'buildNotesSharerSample',
              'buildAndroidNotesSample',
              'buildNotesSample',
              'buildAndroidNotesApk',
              'buildNotesSharerApk',
            ],
          },
        ],
        filePrefix: 'android-',
        fileExt: '.apk',
        outputDir: resolvedOutDir,
      });
      packages.push(...res.packages);
      if (res.skipped) skipped.push(res.skipped);
    } else if (platform === 'windows') {
      const res = await buildDynamicPlatformSamples({
        platform: 'windows',
        builderFilename: 'windows-builder.mjs',
        batchExportNames: [
          'buildWindowsSamples',
          'buildAllWindowsSamples',
          'buildSampleExes',
          'buildWindowsSamplePackages',
          'buildDefaultSamples',
          'buildSamples',
          'buildAll',
        ],
        individualSpecs: [
          {
            filename: 'win-sysinfo.exe',
            exportNames: [
              'buildWinSysinfoSample',
              'buildSysinfoSample',
              'buildSysInfoSample',
              'buildWindowsSysinfoSample',
              'buildWinSysinfoExe',
            ],
          },
          {
            filename: 'win-notepad.exe',
            exportNames: [
              'buildWinNotepadSample',
              'buildNotepadSample',
              'buildWindowsNotepadSample',
              'buildWinNotepadExe',
            ],
          },
        ],
        filePrefix: 'win-',
        fileExt: '.exe',
        outputDir: resolvedOutDir,
      });
      packages.push(...res.packages);
      if (res.skipped) skipped.push(res.skipped);
    } else if (platform === 'ios') {
      const targetPath = path.join(resolvedOutDir, 'ios-weather-island.ipa');
      const built = buildWeatherIslandSample(targetPath);
      const entry = verifyBuiltFile('ios', targetPath);
      if (built?.ipaBytes && entry.bytes !== built.ipaBytes.byteLength) {
        throw new Error(
          `iOS sample byte-length mismatch: expected ${built.ipaBytes.byteLength}, got ${entry.bytes}`
        );
      }
      packages.push(entry);
    } else if (platform === 'macos') {
      const targetPath = path.join(resolvedOutDir, 'macos-studio.app.zip');
      const built = buildMacStudioSample(targetPath);
      const entry = verifyBuiltFile('macos', targetPath);
      if (built?.sha256 && entry.sha256 !== built.sha256) {
        throw new Error(
          `macOS sample SHA-256 mismatch: expected ${built.sha256}, got ${entry.sha256}`
        );
      }
      packages.push(entry);
    } else if (platform === 'universal') {
      const targetPath = path.join(resolvedOutDir, 'universal-canvas.uapp');
      const built = buildUniversalCanvasSample(targetPath);
      const entry = verifyBuiltFile('universal', targetPath);
      if (built?.bytes && entry.bytes !== built.bytes.byteLength) {
        throw new Error(
          `Universal sample byte-length mismatch: expected ${built.bytes.byteLength}, got ${entry.bytes}`
        );
      }
      packages.push(entry);
    }
  }

  if (!quiet) {
    for (const pkg of packages) {
      console.log(
        `[sdk:build] ${pkg.platform.padEnd(9)} ${pkg.filename.padEnd(28)} ${String(pkg.bytes).padStart(7)} bytes  sha256=${pkg.sha256}`
      );
    }
    for (const sk of skipped) {
      console.log(`[sdk:build] ${sk.platform.padEnd(9)} skipped (${sk.reason})`);
    }
  }

  return {
    ok: true,
    outputDir: resolvedOutDir,
    platforms: selectedPlatforms,
    packages,
    skipped,
  };
}

function parseCliArgs(argv) {
  const opts = {
    outputDir: DEFAULT_OUTPUT_DIR,
    platforms: 'all',
    json: false,
    quiet: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      opts.help = true;
    } else if (arg === '--json') {
      opts.json = true;
    } else if (arg === '--quiet' || arg === '-q') {
      opts.quiet = true;
    } else if (arg === '--output-dir' || arg === '-o') {
      if (i + 1 >= argv.length) throw new Error(`${arg} requires a directory path`);
      opts.outputDir = argv[++i];
    } else if (arg.startsWith('--output-dir=')) {
      opts.outputDir = arg.slice('--output-dir='.length);
    } else if (arg === '--platforms' || arg === '-p') {
      if (i + 1 >= argv.length) throw new Error(`${arg} requires a platform list`);
      opts.platforms = argv[++i];
    } else if (arg.startsWith('--platforms=')) {
      opts.platforms = arg.slice('--platforms='.length);
    } else {
      throw new Error(`Unknown CLI argument: ${arg}`);
    }
  }
  return opts;
}

// CLI entrypoint
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  try {
    const cli = parseCliArgs(process.argv.slice(2));
    if (cli.help) {
      console.log(
        'Usage: node sdk/build-samples.mjs [--output-dir <dir>] [--platforms ios,macos,universal|all] [--json] [--quiet]'
      );
      process.exit(0);
    }
    const manifest = await buildAllSamples({
      outputDir: cli.outputDir,
      platforms: cli.platforms,
      quiet: cli.quiet || cli.json,
    });
    if (cli.json) {
      console.log(JSON.stringify(manifest, null, 2));
    }
  } catch (err) {
    console.error(`[sdk:build] ERROR: ${err?.message ?? err}`);
    process.exit(1);
  }
}
