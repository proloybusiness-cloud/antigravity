/**
 * OmniOS iOS `.ipa` Package Parser (`F-053`)
 * Zero external dependencies, zero `node:fs` imports.
 *
 * Unpacks `.ipa` archives through `os/pkg/zip.mjs` (enforcing ZIP-slip/bomb/CRC-32),
 * parses `Payload/<BundleName>.app/Info.plist` (`bplist00` or XML 1.0),
 * parses the ARM64 Mach-O executable via `os/runtimes/apple/macho-parser.mjs`
 * (propagating `FormatError(..., { code: ERROR_CODES.E_ENCRYPTED_BINARY })` on FairPlay DRM),
 * extracts optional `embedded.mobileprovision` & `LC_CODE_SIGNATURE` entitlements,
 * and maps iOS TCC usage keys & URL/Document types into flat `PackageManager` / `IntentRouter` descriptors.
 */

import { FormatError, ERROR_CODES } from '../../common/errors.mjs';
import { readZip } from '../../pkg/zip.mjs';
import { IOS_TCC_PERMISSION_MAP } from '../../security/permissions.mjs';
import { UTI_TYPE_MAP } from '../../ipc/router.mjs';
import { parsePlist, parseXmlPlist } from '../apple/plist-parser.mjs';
import { parseMachO } from '../apple/macho-parser.mjs';

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const LATIN1_DECODER = new TextDecoder('latin1', { fatal: false });

const ENTITLEMENT_TO_IOS_TCC = Object.freeze({
  'aps-environment': ['UNUserNotificationCenter'],
  'com.apple.developer.usernotifications': ['UNUserNotificationCenter'],
  'com.apple.developer.usernotifications.time-sensitive': ['UNUserNotificationCenter'],
  'com.apple.security.files.user-selected.read-only': ['NSDocumentsFolderUsageDescription'],
  'com.apple.security.files.user-selected.read-write': [
    'NSDocumentsFolderUsageDescription',
    'kTCCServiceSystemPolicyDocumentsFolderWrite',
  ],
  'com.apple.security.files.downloads.read-only': ['NSDownloadsFolderUsageDescription'],
  'com.apple.security.files.downloads.read-write': [
    'NSDownloadsFolderUsageDescription',
    'kTCCServiceSystemPolicyDocumentsFolderWrite',
  ],
  'com.apple.security.assets.pictures.read-only': ['NSPhotoLibraryUsageDescription'],
  'com.apple.security.assets.pictures.read-write': [
    'NSPhotoLibraryUsageDescription',
    'NSPhotoLibraryAddUsageDescription',
  ],
  'com.apple.security.network.client': ['kTCCServiceNetwork'],
  'com.apple.security.network.server': ['kTCCServiceNetwork'],
  'com.apple.security.device.camera': ['NSCameraUsageDescription'],
  'com.apple.security.personal-information.location': ['NSLocationWhenInUseUsageDescription'],
  'com.apple.security.clipboard.read': ['UIPasteboard'],
  'com.apple.security.clipboard.write': ['kTCCServicePasteboardWrite'],
  'com.apple.security.automation.apple-events': ['kTCCServiceAppleEvents'],
  'com.apple.security.ui.window': ['UIWindow'],
});

function toUint8Array(input) {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new FormatError('IPA parser expects Uint8Array, ArrayBuffer, or ArrayBufferView', {
    code: ERROR_CODES.E_MALFORMED_ZIP,
    format: 'ios-ipa',
  });
}

function isPlainObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val);
}

function addRecognizedIosPerm(set, key) {
  if (typeof key !== 'string') return;
  const trimmed = key.trim();
  if (trimmed.length === 0) return;
  if (Object.prototype.hasOwnProperty.call(IOS_TCC_PERMISSION_MAP, trimmed)) {
    set.add(trimmed);
  }
}

/**
 * Convert Info.plist (`NS*UsageDescription`, `NSSupportsLiveActivities`, `UIWindow`,
 * `UIPasteboard`, `UIBackgroundModes`, document flags) and entitlements into a flat
 * deduplicated `Array<string>` of recognized `IOS_TCC_PERMISSION_MAP` keys.
 */
export function extractIosPermissions(infoPlist, entitlements = null) {
  const perms = new Set();
  // Every iOS UIKit application presents a UIWindow
  addRecognizedIosPerm(perms, 'UIWindow');

  if (isPlainObject(infoPlist)) {
    for (const [key, value] of Object.entries(infoPlist)) {
      if (!value) continue;
      if (Object.prototype.hasOwnProperty.call(IOS_TCC_PERMISSION_MAP, key)) {
        addRecognizedIosPerm(perms, key);
      }
    }

    if (infoPlist.NSSupportsLiveActivities) {
      addRecognizedIosPerm(perms, 'UNUserNotificationCenter');
    }

    if (
      infoPlist.UISupportsDocumentBrowser ||
      infoPlist.UIFileSharingEnabled ||
      infoPlist.LSSupportsOpeningDocumentsInPlace
    ) {
      addRecognizedIosPerm(perms, 'NSDocumentsFolderUsageDescription');
      addRecognizedIosPerm(perms, 'kTCCServiceSystemPolicyDocumentsFolderWrite');
    }

    if (infoPlist.UIRequiresPersistentWiFi || infoPlist.NSAppTransportSecurity) {
      addRecognizedIosPerm(perms, 'kTCCServiceNetwork');
    }

    if (infoPlist.UIPasteboard || infoPlist.OmniOSClipboardAccess) {
      addRecognizedIosPerm(perms, 'UIPasteboard');
      addRecognizedIosPerm(perms, 'kTCCServicePasteboardWrite');
    }

    if (Array.isArray(infoPlist.UIBackgroundModes)) {
      for (const rawMode of infoPlist.UIBackgroundModes) {
        if (typeof rawMode !== 'string') continue;
        const mode = rawMode.trim().toLowerCase();
        if (mode === 'remote-notification' || mode === 'push-to-talk') {
          addRecognizedIosPerm(perms, 'UNUserNotificationCenter');
        } else if (mode === 'location') {
          addRecognizedIosPerm(perms, 'NSLocationAlwaysUsageDescription');
        } else if (mode === 'fetch' || mode === 'processing' || mode === 'voip') {
          addRecognizedIosPerm(perms, 'kTCCServiceNetwork');
        }
      }
    }
  }

  if (isPlainObject(entitlements)) {
    for (const [key, value] of Object.entries(entitlements)) {
      if (!value) continue;
      if (Object.prototype.hasOwnProperty.call(IOS_TCC_PERMISSION_MAP, key)) {
        addRecognizedIosPerm(perms, key);
      }
      if (Object.prototype.hasOwnProperty.call(ENTITLEMENT_TO_IOS_TCC, key)) {
        for (const mapped of ENTITLEMENT_TO_IOS_TCC[key]) {
          addRecognizedIosPerm(perms, mapped);
        }
      }
    }
  }

  return Array.from(perms);
}

/**
 * Convert `CFBundleURLTypes` (`CFBundleURLSchemes`) and `CFBundleDocumentTypes`
 * (extensions, MIME types, and UTIs via `UTI_TYPE_MAP`) into a flat `Array<FlatIntentDescriptor>`
 * directly consumable by `PackageManager` and `IntentRouter`.
 */
export function extractIosIntents(infoPlist) {
  if (!isPlainObject(infoPlist)) return [];

  const intents = [];
  const defaultLabel =
    (typeof infoPlist.CFBundleDisplayName === 'string' && infoPlist.CFBundleDisplayName.trim()) ||
    (typeof infoPlist.CFBundleName === 'string' && infoPlist.CFBundleName.trim()) ||
    (typeof infoPlist.CFBundleIdentifier === 'string' && infoPlist.CFBundleIdentifier.trim()) ||
    'iOS App';

  // 1. CFBundleURLTypes -> URL scheme handlers
  if (Array.isArray(infoPlist.CFBundleURLTypes)) {
    for (const urlType of infoPlist.CFBundleURLTypes) {
      if (!isPlainObject(urlType)) continue;
      const rawSchemes = Array.isArray(urlType.CFBundleURLSchemes)
        ? urlType.CFBundleURLSchemes
        : typeof urlType.CFBundleURLSchemes === 'string'
          ? [urlType.CFBundleURLSchemes]
          : [];

      const schemes = [];
      const seen = new Set();
      for (const s of rawSchemes) {
        if (typeof s !== 'string') continue;
        const cleaned = s.trim().toLowerCase().replace(/:+$/, '');
        if (!cleaned || seen.has(cleaned)) continue;
        seen.add(cleaned);
        schemes.push(cleaned);
      }

      if (schemes.length > 0) {
        const role = typeof urlType.CFBundleTypeRole === 'string' ? urlType.CFBundleTypeRole.toLowerCase() : '';
        const label =
          (typeof urlType.CFBundleURLName === 'string' && urlType.CFBundleURLName.trim()) || defaultLabel;
        intents.push({
          actions: role === 'editor' ? ['view', 'edit'] : ['view'],
          schemes,
          platform: 'ios',
          label,
          priority: 10,
        });
      }
    }
  }

  // 2. CFBundleDocumentTypes -> file extension / MIME / UTI handlers
  if (Array.isArray(infoPlist.CFBundleDocumentTypes)) {
    for (const docType of infoPlist.CFBundleDocumentTypes) {
      if (!isPlainObject(docType)) continue;

      const extSet = new Set();
      const mimeSet = new Set();

      if (Array.isArray(docType.CFBundleTypeExtensions)) {
        for (const ext of docType.CFBundleTypeExtensions) {
          if (typeof ext !== 'string') continue;
          const clean = ext.trim().toLowerCase().replace(/^\*?\./, '');
          if (clean && !clean.includes('/') && !clean.includes('\\')) {
            extSet.add(`.${clean}`);
          }
        }
      }

      if (Array.isArray(docType.CFBundleTypeMIMETypes)) {
        for (const mt of docType.CFBundleTypeMIMETypes) {
          if (typeof mt !== 'string') continue;
          const clean = mt.trim().toLowerCase();
          if (clean.includes('/')) {
            mimeSet.add(clean);
          }
        }
      }

      if (Array.isArray(docType.LSItemContentTypes)) {
        for (const uti of docType.LSItemContentTypes) {
          if (typeof uti !== 'string') continue;
          const cleanUti = uti.trim().toLowerCase();
          const mapped = Object.prototype.hasOwnProperty.call(UTI_TYPE_MAP, cleanUti)
            ? UTI_TYPE_MAP[cleanUti]
            : null;
          if (mapped) {
            for (const ext of mapped.extensions) extSet.add(ext);
            for (const mt of mapped.mimeTypes) mimeSet.add(mt);
          }
        }
      }

      if (extSet.size > 0 || mimeSet.size > 0) {
        const role = typeof docType.CFBundleTypeRole === 'string' ? docType.CFBundleTypeRole.toLowerCase() : '';
        const label =
          (typeof docType.CFBundleTypeName === 'string' && docType.CFBundleTypeName.trim()) || defaultLabel;
        const desc = {
          actions: role === 'editor' ? ['view', 'edit'] : ['view'],
          platform: 'ios',
          label,
          priority: role === 'editor' ? 10 : 5,
        };
        if (extSet.size > 0) desc.extensions = Array.from(extSet);
        if (mimeSet.size > 0) desc.mimeTypes = Array.from(mimeSet);
        intents.push(desc);
      }
    }
  }

  return intents;
}

/**
 * Extract embedded XML plist from a CMS/PKCS#7 signed `embedded.mobileprovision` file.
 */
function parseMobileProvision(bytes) {
  if (!bytes || bytes.byteLength === 0) return null;
  // Decode as Latin-1 first so binary CMS wrapper bytes never corrupt ASCII XML offsets
  const rawLatin1 = LATIN1_DECODER.decode(bytes);
  const startIdx = rawLatin1.indexOf('<plist');
  if (startIdx < 0) return null;
  const endTag = '</plist>';
  const endIdx = rawLatin1.indexOf(endTag, startIdx);
  if (endIdx < 0) return null;

  // Include optional <?xml ...?> header if immediately preceding <plist
  let sliceStart = startIdx;
  const xmlDeclIdx = rawLatin1.lastIndexOf('<?xml', startIdx);
  if (xmlDeclIdx >= 0 && startIdx - xmlDeclIdx < 256) {
    sliceStart = xmlDeclIdx;
  }
  const xmlSlice = bytes.subarray(sliceStart, endIdx + endTag.length);
  const xmlText = UTF8_DECODER.decode(xmlSlice);
  try {
    const parsed = parseXmlPlist(xmlText);
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function collectMachOIntrospection(macho) {
  const sectionsOrClasses = [];
  const importsSet = new Set();

  if (Array.isArray(macho.sections)) {
    for (const s of macho.sections) {
      sectionsOrClasses.push(`${s.segname}.${s.sectname}`);
    }
  }

  for (const list of [macho.binds, macho.weakBinds, macho.lazyBinds]) {
    if (!Array.isArray(list)) continue;
    for (const b of list) {
      if (b && typeof b.symbol === 'string' && b.symbol.length > 0) {
        importsSet.add(b.symbol);
      }
    }
  }

  if (macho.chainedFixups && Array.isArray(macho.chainedFixups.imports)) {
    for (const imp of macho.chainedFixups.imports) {
      if (imp && typeof imp.name === 'string' && imp.name.length > 0) {
        importsSet.add(imp.name);
      }
    }
  }

  if (Array.isArray(macho.symbols)) {
    for (const sym of macho.symbols) {
      if (sym && sym.isUndefined && typeof sym.name === 'string' && sym.name.length > 0) {
        importsSet.add(sym.name);
      }
    }
  }

  if (Array.isArray(macho.objcClasses)) {
    for (const cls of macho.objcClasses) {
      if (typeof cls === 'string' && cls.length > 0) {
        sectionsOrClasses.push(cls);
      }
    }
  }

  if (Array.isArray(macho.objcSelectors)) {
    for (const sel of macho.objcSelectors) {
      if (typeof sel === 'string' && sel.length > 0) {
        importsSet.add(sel);
      }
    }
  }

  return {
    sectionsOrClasses,
    importsOrMethods: Array.from(importsSet),
  };
}

/**
 * Unpack and validate an iOS `.ipa` archive into structured package, Info.plist,
 * provisioning, entitlements, Mach-O, permissions, and flat intent descriptors.
 */
export function parseIpa(buffer, opts = {}) {
  const bytes = toUint8Array(buffer);
  const archive = readZip(bytes, opts.zipLimits);

  // Locate Payload/<BundleName>.app/Info.plist (exact case preferred, case-insensitive fallback)
  let infoPlistEntry =
    archive.entryList.find((e) => !e.isDirectory && /^Payload\/[^/]+\.app\/Info\.plist$/.test(e.name)) ??
    archive.entryList.find((e) => !e.isDirectory && /^Payload\/[^/]+\.app\/Info\.plist$/i.test(e.name)) ??
    null;

  if (!infoPlistEntry) {
    throw new FormatError('IPA archive is missing Payload/<BundleName>.app/Info.plist', {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format: 'ios-ipa',
    });
  }

  const bundleMatch = /^Payload\/([^/]+)\.app\/Info\.plist$/i.exec(infoPlistEntry.name);
  if (!bundleMatch) {
    throw new FormatError(`Invalid IPA Info.plist path: ${infoPlistEntry.name}`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format: 'ios-ipa',
    });
  }

  const bundleName = bundleMatch[1];
  const bundleDir = infoPlistEntry.name.slice(0, infoPlistEntry.name.lastIndexOf('/'));
  const infoPlistBytes = archive.readBytes(infoPlistEntry.name);
  const infoPlist = parsePlist(infoPlistBytes);

  if (!isPlainObject(infoPlist)) {
    throw new FormatError('IPA Info.plist root must be a dictionary', {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'ios-ipa',
    });
  }

  const bundleId = typeof infoPlist.CFBundleIdentifier === 'string' ? infoPlist.CFBundleIdentifier.trim() : '';
  if (!bundleId) {
    throw new FormatError('IPA Info.plist is missing required CFBundleIdentifier', {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'ios-ipa',
    });
  }

  const executableName =
    typeof infoPlist.CFBundleExecutable === 'string' ? infoPlist.CFBundleExecutable.trim() : '';
  if (
    !executableName ||
    executableName.includes('/') ||
    executableName.includes('\\') ||
    executableName.includes('..') ||
    executableName.includes('\0')
  ) {
    throw new FormatError('IPA Info.plist is missing a valid CFBundleExecutable', {
      code: ERROR_CODES.E_MALFORMED_PLIST,
      format: 'ios-ipa',
    });
  }

  const expectedExecPath = `${bundleDir}/${executableName}`;
  const execEntry =
    archive.entryList.find((e) => !e.isDirectory && e.name === expectedExecPath) ??
    archive.entryList.find((e) => !e.isDirectory && e.name.toLowerCase() === expectedExecPath.toLowerCase()) ??
    null;

  if (!execEntry) {
    throw new FormatError(`IPA executable not found in archive: ${expectedExecPath}`, {
      code: ERROR_CODES.E_MALFORMED_BINARY,
      format: 'ios-ipa',
      details: { executablePath: expectedExecPath },
    });
  }

  const executableBytes = archive.readBytes(execEntry.name);
  // Propagates FormatError(..., { code: ERROR_CODES.E_ENCRYPTED_BINARY }) when FairPlay cryptid !== 0!
  const macho = parseMachO(executableBytes, {
    preferredArch: opts.preferredArch ?? 'arm64',
    allowEncrypted: Boolean(opts.allowEncrypted),
  });

  // Optional embedded.mobileprovision
  const provisionPath = `${bundleDir}/embedded.mobileprovision`;
  const provisionEntry =
    archive.entryList.find((e) => !e.isDirectory && e.name === provisionPath) ??
    archive.entryList.find((e) => !e.isDirectory && e.name.toLowerCase() === provisionPath.toLowerCase()) ??
    null;
  const mobileprovision = provisionEntry ? parseMobileProvision(archive.readBytes(provisionEntry.name)) : null;

  // Merge entitlements from embedded.mobileprovision and Mach-O LC_CODE_SIGNATURE
  const mergedEntitlements = {};
  if (isPlainObject(mobileprovision?.Entitlements)) {
    Object.assign(mergedEntitlements, mobileprovision.Entitlements);
  }
  if (isPlainObject(macho.entitlements)) {
    Object.assign(mergedEntitlements, macho.entitlements);
  }

  const permissions = extractIosPermissions(infoPlist, mergedEntitlements);
  const intents = extractIosIntents(infoPlist);
  const { sectionsOrClasses, importsOrMethods } = collectMachOIntrospection(macho);

  const urlSchemes = [];
  const schemeSet = new Set();
  for (const intent of intents) {
    if (Array.isArray(intent.schemes)) {
      for (const s of intent.schemes) {
        if (!schemeSet.has(s)) {
          schemeSet.add(s);
          urlSchemes.push(s);
        }
      }
    }
  }

  const documentTypes = Array.isArray(infoPlist.CFBundleDocumentTypes)
    ? infoPlist.CFBundleDocumentTypes.filter(isPlainObject)
    : [];

  const displayName =
    (typeof infoPlist.CFBundleDisplayName === 'string' && infoPlist.CFBundleDisplayName.trim()) ||
    (typeof infoPlist.CFBundleName === 'string' && infoPlist.CFBundleName.trim()) ||
    bundleName;
  const version =
    (typeof infoPlist.CFBundleShortVersionString === 'string' && infoPlist.CFBundleShortVersionString.trim()) ||
    (typeof infoPlist.CFBundleVersion === 'string' && infoPlist.CFBundleVersion.trim()) ||
    '1.0.0';
  const buildVersion =
    (typeof infoPlist.CFBundleVersion === 'string' && infoPlist.CFBundleVersion.trim()) || '1';

  return {
    bundleId,
    name: displayName,
    displayName,
    bundleName,
    bundleDir,
    version,
    buildVersion,
    executableName,
    executablePath: execEntry.name,
    infoPlistPath: infoPlistEntry.name,
    infoPlist,
    mobileprovision,
    entitlements: mergedEntitlements,
    macho,
    executableBytes,
    arch: macho.arch || 'arm64',
    permissions,
    intents,
    urlSchemes,
    documentTypes,
    supportsLiveActivities: Boolean(infoPlist.NSSupportsLiveActivities),
    sectionsOrClasses,
    importsOrMethods,
    entries: archive.entryList.map((e) => e.name),
  };
}
