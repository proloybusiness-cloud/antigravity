/**
 * OmniOS Android `.apk` Package Loader & Verifier (F-036)
 * - Reuses M2 `listZipEntries` / `readZip` (EOCD centralDirOffset authority, ZIP-slip, ZIP-bomb, CRC-32)
 * - Parses APK Signing Block v2/v3 (`"APK Sig Block 42"` before Central Directory) & detects JAR v1 signatures
 * - Parses `resources.arsc`, `AndroidManifest.xml` (AXML or plain XML fallback), and multidex `classes*.dex`
 * - Flattens `<intent-filter>` elements into flat `IntentRouter` descriptors (`SCOPE.md` Landmine #1)
 * - Zero external dependencies; pure in-memory parser without host filesystem access.
 */

import { listZipEntries, readZip } from '../../pkg/zip.mjs';
import { FormatError, ERROR_CODES } from '../../common/errors.mjs';
import { parseXmlOrAxml } from './axml-parser.mjs';
import { parseResourcesArsc } from './resources-arsc.mjs';
import { parseDexContainer, createDexParseBudget, MAX_CONTAINER_DEX_FILES } from './dex-parser.mjs';

const TEXT_ENCODER = new TextEncoder();
export const APK_SIG_BLOCK_MAGIC = 'APK Sig Block 42';
const APK_SIG_MAGIC_BYTES = TEXT_ENCODER.encode(APK_SIG_BLOCK_MAGIC);

export const MAX_APK_SIG_BLOCK_PAIRS = 4096;
const MAX_INTENT_FILTERS = 256;
const MAX_INTENT_FILTER_ITEMS = 4096;
const MAX_FLATTENED_INTENTS = 1024;
const EMPTY_FROZEN_ARRAY = Object.freeze([]);

export const APK_SIG_SCHEME_IDS = Object.freeze({
  V2: 0x7109871a,
  V3: 0xf05368c0,
  V3_1: 0x1b93ad61,
  VERITY_PADDING: 0x42726577,
});

function toBytes(input) {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new FormatError('APK input must be a Uint8Array, ArrayBuffer, or ArrayBufferView', {
    code: ERROR_CODES.E_MALFORMED_ZIP,
    format: 'apk',
    offset: 0,
  });
}

/**
 * Parses the APK Signing Block v2/v3 located immediately before the ZIP Central Directory.
 * Layout:
 *   [uint64 sizeOfBlock]
 *   [pairs: uint64 len, uint32 id, bytes(len - 4)]...
 *   [uint64 sizeOfBlock]
 *   ["APK Sig Block 42" (16 bytes)]
 */
export function parseApkSigningBlock(bytes, cdOffset) {
  const empty = {
    present: false,
    offset: null,
    size: 0,
    hasV2: false,
    hasV3: false,
    schemes: [],
    pairs: [],
  };

  const buf = toBytes(bytes);
  if (!Number.isSafeInteger(cdOffset) || cdOffset < 32 || cdOffset > buf.byteLength) {
    return empty;
  }

  const magicStart = cdOffset - 16;
  for (let i = 0; i < 16; i++) {
    if (buf[magicStart + i] !== APK_SIG_MAGIC_BYTES[i]) {
      return empty;
    }
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const footerSizeBig = view.getBigUint64(cdOffset - 24, true);
  if (footerSizeBig < 24n || footerSizeBig > BigInt(cdOffset - 8)) {
    return empty;
  }

  const footerSize = Number(footerSizeBig);
  const totalBlockSize = footerSize + 8;
  const blockStart = cdOffset - totalBlockSize;
  if (blockStart < 0) {
    return empty;
  }

  const headerSizeBig = view.getBigUint64(blockStart, true);
  if (headerSizeBig !== footerSizeBig) {
    return empty;
  }

  const pairsEnd = cdOffset - 24;
  let pos = blockStart + 8;
  const pairs = [];
  let hasV2 = false;
  let hasV3 = false;

  while (pos < pairsEnd) {
    if (pairs.length >= MAX_APK_SIG_BLOCK_PAIRS) {
      throw new FormatError(
        `APK Signing Block pair count exceeds maximum (${MAX_APK_SIG_BLOCK_PAIRS})`,
        { code: ERROR_CODES.E_MALFORMED_ZIP, format: 'apk', offset: pos }
      );
    }
    if (pos + 12 > pairsEnd) {
      return empty;
    }
    const pairLenBig = view.getBigUint64(pos, true);
    if (pairLenBig < 4n || BigInt(pos) + 8n + pairLenBig > BigInt(pairsEnd)) {
      return empty;
    }
    pos += 8;
    const pairLen = Number(pairLenBig);
    const id = view.getUint32(pos, true);
    const valueSize = pairLen - 4;
    pos += pairLen;

    pairs.push({ id, valueSize });
    if (id === APK_SIG_SCHEME_IDS.V2) hasV2 = true;
    if (id === APK_SIG_SCHEME_IDS.V3 || id === APK_SIG_SCHEME_IDS.V3_1) hasV3 = true;
  }

  if (pos !== pairsEnd) {
    return empty;
  }

  const schemes = [];
  if (hasV2) schemes.push('v2');
  if (hasV3) schemes.push('v3');

  return {
    present: true,
    offset: blockStart,
    size: totalBlockSize,
    hasV2,
    hasV3,
    schemes,
    pairs,
  };
}

function getAttr(node, localName, resources = null) {
  if (!node || !node.attrs) return null;
  let raw =
    node.attrs[`android:${localName}`] !== undefined
      ? node.attrs[`android:${localName}`]
      : node.attrs[localName];

  if (raw === undefined || raw === null) return null;
  if (typeof raw === 'string' && raw.startsWith('@') && resources) {
    const resolved = resources.getString(raw);
    if (resolved !== null) return resolved;
  }
  return raw;
}

function resolveComponentClass(packageName, rawName) {
  if (!rawName || typeof rawName !== 'string') return '';
  const trimmed = rawName.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('.')) {
    return `${packageName}${trimmed}`;
  }
  if (!trimmed.includes('.')) {
    return `${packageName}.${trimmed}`;
  }
  return trimmed;
}

function extractIntentFilters(
  componentNode,
  { packageName, appLabel, resources, intentBudget = null, collectFlattened = true }
) {
  const budget = intentBudget ?? { filters: 0, items: 0, flattened: 0 };
  const filters = [];
  const flattened = [];

  for (const child of componentNode.children ?? []) {
    if (child.tag !== 'intent-filter') continue;
    budget.filters += 1;
    if (budget.filters > MAX_INTENT_FILTERS) {
      throw new FormatError(
        `AndroidManifest.xml intent-filter count (${budget.filters}) exceeds maximum (${MAX_INTENT_FILTERS})`,
        { code: ERROR_CODES.E_MALFORMED_AXML, format: 'apk' }
      );
    }

    const priorityRaw = getAttr(child, 'priority', resources);
    const priority =
      typeof priorityRaw === 'number' ? priorityRaw : Number.parseInt(String(priorityRaw ?? '0'), 10) || 0;

    const actionSet = new Set();
    const categorySet = new Set();
    const dataItems = [];

    for (const item of child.children ?? []) {
      if (item.tag === 'action' || item.tag === 'category' || item.tag === 'data') {
        budget.items += 1;
        if (budget.items > MAX_INTENT_FILTER_ITEMS) {
          throw new FormatError(
            `AndroidManifest.xml intent-filter item count (${budget.items}) exceeds maximum (${MAX_INTENT_FILTER_ITEMS})`,
            { code: ERROR_CODES.E_MALFORMED_AXML, format: 'apk' }
          );
        }
      }
      if (item.tag === 'action') {
        const name = getAttr(item, 'name', resources);
        if (typeof name === 'string' && name.length > 0) actionSet.add(name);
      } else if (item.tag === 'category') {
        const name = getAttr(item, 'name', resources);
        if (typeof name === 'string' && name.length > 0) categorySet.add(name);
      } else if (item.tag === 'data') {
        const scheme = getAttr(item, 'scheme', resources);
        const host = getAttr(item, 'host', resources);
        const mimeType = getAttr(item, 'mimeType', resources);
        const pathPattern = getAttr(item, 'pathPattern', resources);
        const pathExtension = getAttr(item, 'pathExtension', resources);
        let extensions = EMPTY_FROZEN_ARRAY;
        if (typeof pathExtension === 'string' && pathExtension.length > 0) {
          extensions = Object.freeze([pathExtension.startsWith('.') ? pathExtension : `.${pathExtension}`]);
        } else if (typeof pathPattern === 'string') {
          const lastDot = pathPattern.lastIndexOf('.');
          if (lastDot !== -1 && lastDot < pathPattern.length - 1) {
            const ext = pathPattern.slice(lastDot + 1);
            if (/^[A-Za-z0-9]+$/.test(ext)) {
              extensions = Object.freeze([`.${ext}`]);
            }
          }
        }
        dataItems.push({
          scheme: typeof scheme === 'string' ? scheme : null,
          host: typeof host === 'string' ? host : null,
          mimeType: typeof mimeType === 'string' ? mimeType : null,
          extensions,
        });
      }
    }

    const actions = actionSet.size > 0 ? Object.freeze(Array.from(actionSet)) : EMPTY_FROZEN_ARRAY;
    const categories = categorySet.size > 0 ? Object.freeze(Array.from(categorySet)) : EMPTY_FROZEN_ARRAY;

    filters.push({ actions, categories, data: dataItems, priority });

    if (!collectFlattened) continue;

    // Determine if this is purely the MAIN/LAUNCHER entry filter (keep actionable intents in IntentRouter)
    const isOnlyMainLauncher =
      actions.length === 1 &&
      actions[0] === 'android.intent.action.MAIN' &&
      categorySet.has('android.intent.category.LAUNCHER') &&
      dataItems.length === 0;

    if (!isOnlyMainLauncher && (actions.length > 0 || dataItems.length > 0)) {
      const label = appLabel || packageName;
      if (dataItems.length === 0) {
        budget.flattened += 1;
        if (budget.flattened > MAX_FLATTENED_INTENTS) {
          throw new FormatError(
            `AndroidManifest.xml flattened intent descriptor count (${budget.flattened}) exceeds maximum (${MAX_FLATTENED_INTENTS})`,
            { code: ERROR_CODES.E_MALFORMED_AXML, format: 'apk' }
          );
        }
        flattened.push({
          actions,
          categories,
          schemes: EMPTY_FROZEN_ARRAY,
          hosts: EMPTY_FROZEN_ARRAY,
          mimeTypes: EMPTY_FROZEN_ARRAY,
          extensions: EMPTY_FROZEN_ARRAY,
          priority,
          platform: 'android',
          label,
        });
      } else {
        if (budget.flattened + dataItems.length > MAX_FLATTENED_INTENTS) {
          throw new FormatError(
            `AndroidManifest.xml flattened intent descriptor count (${budget.flattened + dataItems.length}) exceeds maximum (${MAX_FLATTENED_INTENTS})`,
            { code: ERROR_CODES.E_MALFORMED_AXML, format: 'apk' }
          );
        }
        budget.flattened += dataItems.length;
        for (const d of dataItems) {
          flattened.push({
            actions,
            categories,
            schemes: d.scheme ? [d.scheme] : EMPTY_FROZEN_ARRAY,
            hosts: d.host ? [d.host] : EMPTY_FROZEN_ARRAY,
            mimeTypes: d.mimeType ? [d.mimeType] : EMPTY_FROZEN_ARRAY,
            extensions: d.extensions,
            priority,
            platform: 'android',
            label,
          });
        }
      }
    }
  }

  return { filters, flattened };
}

/**
 * Extracts structured Android manifest metadata and flat `IntentRouter` descriptors.
 */
export function extractManifestInfo(manifestDoc, resources = null) {
  const root = manifestDoc?.root;
  if (!root || root.tag !== 'manifest') {
    throw new FormatError('AndroidManifest.xml root element must be <manifest>', {
      code: ERROR_CODES.E_MALFORMED_AXML,
      format: 'apk',
    });
  }

  const packageName = getAttr(root, 'package', resources);
  if (typeof packageName !== 'string' || packageName.trim().length === 0) {
    throw new FormatError('AndroidManifest.xml missing required package attribute', {
      code: ERROR_CODES.E_MALFORMED_AXML,
      format: 'apk',
    });
  }

  const versionCodeRaw = getAttr(root, 'versionCode', resources);
  const versionCode =
    typeof versionCodeRaw === 'number'
      ? versionCodeRaw
      : Number.parseInt(String(versionCodeRaw ?? '1'), 10) || 1;
  const versionNameRaw = getAttr(root, 'versionName', resources);
  const versionName =
    versionNameRaw !== null && versionNameRaw !== undefined
      ? String(versionNameRaw)
      : `${versionCode}.0.0`;

  let minSdkVersion = 21;
  let targetSdkVersion = 34;
  const permissions = [];
  const permSet = new Set();

  let appLabel = packageName;
  let appIcon = null;
  const activities = [];
  const services = [];
  const receivers = [];
  const providers = [];
  const allFlattenedIntents = [];
  const intentBudget = { filters: 0, items: 0, flattened: 0 };
  let launcherActivity = null;

  for (const child of root.children ?? []) {
    if (child.tag === 'uses-sdk') {
      const minRaw = getAttr(child, 'minSdkVersion', resources);
      const tgtRaw = getAttr(child, 'targetSdkVersion', resources);
      if (minRaw !== null) minSdkVersion = Number.parseInt(String(minRaw), 10) || minSdkVersion;
      if (tgtRaw !== null) targetSdkVersion = Number.parseInt(String(tgtRaw), 10) || targetSdkVersion;
    } else if (child.tag === 'uses-permission' || child.tag === 'uses-permission-sdk-23') {
      const permName = getAttr(child, 'name', resources);
      if (typeof permName === 'string' && permName.length > 0 && !permSet.has(permName)) {
        permSet.add(permName);
        permissions.push(permName);
      }
    } else if (child.tag === 'application') {
      const lbl = getAttr(child, 'label', resources);
      if (typeof lbl === 'string' && lbl.length > 0) appLabel = lbl;
      const icn = getAttr(child, 'icon', resources);
      if (icn !== null) appIcon = String(icn);

      for (const comp of child.children ?? []) {
        const compRawName = getAttr(comp, 'name', resources);
        const compClass = resolveComponentClass(packageName, compRawName);
        const compLabel = getAttr(comp, 'label', resources) ?? appLabel;
        const exported = getAttr(comp, 'exported', resources);

        if (comp.tag === 'activity' || comp.tag === 'activity-alias') {
          const { filters, flattened } = extractIntentFilters(comp, {
            packageName,
            appLabel: String(compLabel),
            resources,
            intentBudget,
            collectFlattened: true,
          });
          const isLauncher = filters.some(
            (f) =>
              f.actions.includes('android.intent.action.MAIN') &&
              f.categories.includes('android.intent.category.LAUNCHER')
          );
          const actInfo = {
            name: compClass,
            rawName: compRawName ?? '',
            label: String(compLabel),
            exported: exported !== null ? Boolean(exported) : filters.length > 0,
            isLauncher,
            intentFilters: filters,
          };
          activities.push(actInfo);
          if (isLauncher && !launcherActivity) {
            launcherActivity = compClass;
          }
          for (const flat of flattened) {
            allFlattenedIntents.push(flat);
          }
        } else if (comp.tag === 'service') {
          const { filters } = extractIntentFilters(comp, {
            packageName,
            appLabel: String(compLabel),
            resources,
            intentBudget,
            collectFlattened: false,
          });
          services.push({ name: compClass, rawName: compRawName ?? '', intentFilters: filters });
        } else if (comp.tag === 'receiver') {
          const { filters, flattened } = extractIntentFilters(comp, {
            packageName,
            appLabel: String(compLabel),
            resources,
            intentBudget,
            collectFlattened: true,
          });
          receivers.push({ name: compClass, rawName: compRawName ?? '', intentFilters: filters });
          for (const flat of flattened) allFlattenedIntents.push(flat);
        } else if (comp.tag === 'provider') {
          const authorities = getAttr(comp, 'authorities', resources) ?? '';
          providers.push({
            name: compClass,
            rawName: compRawName ?? '',
            authorities: String(authorities),
          });
        }
      }
    }
  }

  if (!launcherActivity && activities.length > 0) {
    launcherActivity = activities[0].name;
  }

  return {
    packageName: packageName.trim(),
    label: appLabel,
    icon: appIcon,
    versionCode,
    versionName,
    minSdkVersion,
    targetSdkVersion,
    permissions,
    launcherActivity: launcherActivity ?? '',
    activities,
    services,
    receivers,
    providers,
    intents: allFlattenedIntents,
  };
}

function dexEntryOrder(name) {
  if (name === 'classes.dex') return 1;
  const match = /^classes(\d+)\.dex$/.exec(name);
  return match ? Number.parseInt(match[1], 10) : Number.MAX_SAFE_INTEGER;
}

/**
 * Unpacks, validates, and parses an Android `.apk` package buffer.
 */
export function parseApk(buffer, { verifyDexChecksums = true, zipLimits = undefined } = {}) {
  const bytes = toBytes(buffer);
  const zipIndex = listZipEntries(bytes, zipLimits);
  const signingBlock = parseApkSigningBlock(bytes, zipIndex.centralDirOffset);
  const archive = readZip(bytes, zipLimits);

  const entryNames = archive.entryList.map((e) => e.name);

  // Detect JAR v1 signature artifacts in META-INF/
  const metaInfEntries = entryNames.filter((n) => n.startsWith('META-INF/'));
  const hasManifestMf = metaInfEntries.includes('META-INF/MANIFEST.MF');
  const hasSf = metaInfEntries.some((n) => /^META-INF\/[^/]+\.SF$/i.test(n));
  const hasCert = metaInfEntries.some((n) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(n));
  const hasV1 = hasManifestMf && hasSf && hasCert;

  const signingSchemes = [];
  if (hasV1) signingSchemes.push('v1');
  if (signingBlock.hasV2) signingSchemes.push('v2');
  if (signingBlock.hasV3) signingSchemes.push('v3');

  // Parse resources.arsc if present
  let resources = null;
  if (archive.entries.has('resources.arsc')) {
    resources = parseResourcesArsc(archive.readBytes('resources.arsc'));
  }

  // Parse AndroidManifest.xml (required)
  if (!archive.entries.has('AndroidManifest.xml')) {
    throw new FormatError('APK is missing required AndroidManifest.xml', {
      code: ERROR_CODES.E_MALFORMED_AXML,
      format: 'apk',
      offset: 0,
    });
  }
  const manifestBytes = archive.readBytes('AndroidManifest.xml');
  const manifestDoc = parseXmlOrAxml(manifestBytes, { resources });
  const manifestInfo = extractManifestInfo(manifestDoc, resources);

  // Parse all multidex classes*.dex files in canonical order
  const dexNames = entryNames
    .filter((n) => /^classes\d*\.dex$/.test(n))
    .sort((a, b) => dexEntryOrder(a) - dexEntryOrder(b));

  if (dexNames.length === 0) {
    throw new FormatError('APK is missing required classes.dex', {
      code: ERROR_CODES.E_MALFORMED_DEX,
      format: 'apk',
      offset: 0,
    });
  }
  if (dexNames.length > MAX_CONTAINER_DEX_FILES) {
    throw new FormatError(
      `APK DEX entry count (${dexNames.length}) exceeds maximum (${MAX_CONTAINER_DEX_FILES})`,
      { code: ERROR_CODES.E_MALFORMED_DEX, format: 'apk', offset: 0 }
    );
  }

  let totalDexBytes = 0;
  for (const dexName of dexNames) {
    const rec = archive.entries.get(dexName);
    if (rec?.data) {
      totalDexBytes += rec.data.byteLength;
    }
  }
  const sharedDexBudget = createDexParseBudget(totalDexBytes);

  const dexFiles = [];
  const allClasses = [];
  const allMethods = [];
  for (const dexName of dexNames) {
    const dexBytes = archive.readBytes(dexName);
    const remainingDexSlots = MAX_CONTAINER_DEX_FILES - dexFiles.length;
    if (remainingDexSlots <= 0) {
      throw new FormatError(
        `APK total DEX count exceeds maximum (${MAX_CONTAINER_DEX_FILES})`,
        { code: ERROR_CODES.E_MALFORMED_DEX, format: 'apk', offset: 0 }
      );
    }
    const parsedContainer = parseDexContainer(dexBytes, {
      verifyChecksum: verifyDexChecksums,
      verifySignature: verifyDexChecksums,
      sharedBudget: sharedDexBudget,
      maxContainerDexFiles: remainingDexSlots,
    });
    for (const parsedDex of parsedContainer) {
      parsedDex.entryName = dexName;
      dexFiles.push(parsedDex);
      for (const cls of parsedDex.classDefs) {
        allClasses.push(cls.classType);
      }
      for (const m of parsedDex.methods) {
        allMethods.push(m.key);
      }
    }
  }

  // Collect res/, assets/, and lib/<abi>/*.so
  const res = new Map();
  const assets = new Map();
  const nativeLibs = [];

  for (const meta of archive.entryList) {
    if (meta.isDirectory) continue;
    if (meta.name.startsWith('res/')) {
      res.set(meta.name, archive.readBytes(meta.name));
    } else if (meta.name.startsWith('assets/')) {
      assets.set(meta.name, archive.readBytes(meta.name));
    } else if (/^lib\/[^/]+\/[^/]+\.so$/.test(meta.name)) {
      nativeLibs.push(meta.name);
    }
  }

  return {
    ...manifestInfo,
    manifestFormat: manifestDoc.format,
    manifest: manifestDoc,
    resources,
    dexFiles,
    classes: allClasses,
    methods: allMethods,
    res,
    assets,
    nativeLibs,
    entries: entryNames,
    signing: {
      signed: signingSchemes.length > 0,
      v1: hasV1,
      v2: signingBlock.hasV2,
      v3: signingBlock.hasV3,
      schemes: signingSchemes,
      hasApkSigningBlock: signingBlock.present,
      signingBlock,
    },
  };
}
