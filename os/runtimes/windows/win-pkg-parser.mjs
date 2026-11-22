/**
 * OmniOS Windows Package Parsers: `.msix` / `.appx` & `.msi` OLE CFBF (`os/runtimes/windows/win-pkg-parser.mjs`)
 * - `.msix`/`.appx`: M2 `readZip` + `AppxManifest.xml` (Identity, DisplayName, Executable, Capabilities,
 *   flat IntentRouter descriptors for FileTypeAssociation/Protocol) + `AppxBlockMap.xml` SHA-256 block verification
 * - `.msi`: OLE Compound File Binary Format (CFBF v3 512B & v4 4096B), cycle-guarded DIFAT/FAT/MiniFAT,
 *   128-byte Directory Entries, `\x05SummaryInformation` property set metadata, and `readStream(name)`
 */

import crypto from 'node:crypto';
import { readZip } from '../../pkg/zip.mjs';
import { FormatError, ERROR_CODES } from '../../common/errors.mjs';

export const OLE_CFBF_MAGIC = new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false });
const UTF16LE_DECODER = new TextDecoder('utf-16le', { fatal: false });

const CFBF_FREESECT = 0xffffffff;
const CFBF_ENDOFCHAIN = 0xfffffffe;
const CFBF_FATSECT = 0xfffffffd;
const CFBF_DIFSECT = 0xfffffffc;
const CFBF_MAXREGSECT = 0xfffffffa;

const MSIX_BLOCK_SIZE = 65536; // 64 KiB uncompressed block per MSIX AppxBlockMap spec
const MAX_MSIX_XML_BYTES = 2 * 1024 * 1024; // 2 MiB hard cap on AppxManifest.xml & AppxBlockMap.xml
const MAX_MSIX_TAGS = 65536; // Hard cap on extracted XML tags per scan
const MAX_MSIX_ATTRS = 4096; // Hard cap on attributes per XML element

function toBytes(input, code, format) {
  if (input instanceof Uint8Array) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new FormatError(`${format} input must be a Uint8Array, Buffer, or ArrayBuffer`, {
    code,
    format,
  });
}

function decodeXmlEntities(str) {
  if (!str || !str.includes('&')) return str;
  return str.replace(/&(#[^<>&;]*|amp|lt|gt|quot|apos);/g, (match, ent) => {
    if (ent === 'amp') return '&';
    if (ent === 'lt') return '<';
    if (ent === 'gt') return '>';
    if (ent === 'quot') return '"';
    if (ent === 'apos') return "'";
    if (ent.startsWith('#x')) {
      const hex = ent.slice(2);
      if (!/^[0-9a-fA-F]{1,8}$/.test(hex)) {
        throw new FormatError(`Invalid hexadecimal XML character reference: &${ent};`, {
          code: ERROR_CODES.E_INVALID_MSIX,
          format: 'windows-msix',
        });
      }
      const cp = parseInt(hex, 16);
      if (!Number.isSafeInteger(cp) || cp < 1 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
        throw new FormatError(`Invalid XML character reference code point: &${ent};`, {
          code: ERROR_CODES.E_INVALID_MSIX,
          format: 'windows-msix',
        });
      }
      return String.fromCodePoint(cp);
    }
    if (ent.startsWith('#')) {
      const dec = ent.slice(1);
      if (!/^[0-9]{1,8}$/.test(dec)) {
        throw new FormatError(`Invalid decimal XML character reference: &${ent};`, {
          code: ERROR_CODES.E_INVALID_MSIX,
          format: 'windows-msix',
        });
      }
      const cp = parseInt(dec, 10);
      if (!Number.isSafeInteger(cp) || cp < 1 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
        throw new FormatError(`Invalid XML character reference code point: &${ent};`, {
          code: ERROR_CODES.E_INVALID_MSIX,
          format: 'windows-msix',
        });
      }
      return String.fromCodePoint(cp);
    }
    return match;
  });
}

function isXmlWs(code) {
  return code === 32 || code === 9 || code === 10 || code === 13 || code === 12;
}

function isXmlNameStart(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95;
}

function isXmlNameChar(code) {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 95 || // _
    code === 58 || // :
    code === 46 || // .
    code === 45    // -
  );
}

function isTagPrefixChar(code) {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 95 || // _
    code === 46 || // .
    code === 45    // -
  );
}

function isTagNameBoundary(code) {
  return code === 62 || code === 47 || isXmlWs(code); // '>', '/', whitespace
}

function matchesAsciiLower(str, start, end, lowerTarget) {
  const tLen = lowerTarget.length;
  if (end - start !== tLen) return false;
  for (let k = 0; k < tLen; k++) {
    let c = str.charCodeAt(start + k);
    if (c >= 65 && c <= 90) c += 32;
    if (c !== lowerTarget.charCodeAt(k)) return false;
  }
  return true;
}

function stripXmlComments(xml) {
  if (!xml || !xml.includes('<!--')) return xml;
  const parts = [];
  let pos = 0;
  while (pos < xml.length) {
    const start = xml.indexOf('<!--', pos);
    if (start === -1) {
      parts.push(xml.slice(pos));
      break;
    }
    if (start > pos) {
      parts.push(xml.slice(pos, start));
    }
    const closeIdx = xml.indexOf('-->', start + 4);
    if (closeIdx === -1) {
      throw new FormatError('Unclosed XML comment in MSIX manifest', {
        code: ERROR_CODES.E_INVALID_MSIX,
        format: 'windows-msix',
      });
    }
    pos = closeIdx + 3;
  }
  return parts.join('');
}

function parseXmlAttrs(attrStr) {
  const attrs = Object.create(null);
  if (!attrStr) return attrs;
  const len = attrStr.length;
  let i = 0;
  let attrCount = 0;
  while (i < len) {
    while (i < len && !isXmlNameStart(attrStr.charCodeAt(i))) i += 1;
    if (i >= len) break;
    const nameStart = i;
    i += 1;
    while (i < len && isXmlNameChar(attrStr.charCodeAt(i))) i += 1;
    const fullName = attrStr.slice(nameStart, i);
    while (i < len && isXmlWs(attrStr.charCodeAt(i))) i += 1;
    if (i >= len || attrStr.charCodeAt(i) !== 61) { // '='
      continue;
    }
    i += 1;
    while (i < len && isXmlWs(attrStr.charCodeAt(i))) i += 1;
    if (i >= len) break;
    const quote = attrStr.charCodeAt(i);
    if (quote !== 34 && quote !== 39) { // '"' or "'"
      continue;
    }
    const qChar = quote === 34 ? '"' : "'";
    const valStart = i + 1;
    const valEnd = attrStr.indexOf(qChar, valStart);
    if (valEnd === -1) break;
    const val = decodeXmlEntities(attrStr.slice(valStart, valEnd));
    attrs[fullName] = val;
    const colonIdx = fullName.indexOf(':');
    if (colonIdx !== -1) {
      const localName = fullName.slice(colonIdx + 1);
      if (!(localName in attrs)) {
        attrs[localName] = val;
      }
    }
    attrCount += 1;
    if (attrCount > MAX_MSIX_ATTRS) {
      throw new FormatError(`MSIX XML element exceeds maximum attribute count (${MAX_MSIX_ATTRS})`, {
        code: ERROR_CODES.E_INVALID_MSIX,
        format: 'windows-msix',
      });
    }
    i = valEnd + 1;
  }
  return attrs;
}

function makeLowerIndex(xml) {
  if (!xml) return '';
  const lowered = xml.toLowerCase();
  // In Unicode toLowerCase(), UTF-16 length never shrinks; equal length guarantees 1:1 index alignment.
  return lowered.length === xml.length ? lowered : null;
}

function findNextOpeningTag(xml, xmlLower, localLower, pos) {
  const len = xml.length;
  if (xmlLower !== null) {
    let searchPos = pos;
    let fromBound = pos;
    const tLen = localLower.length;
    while (searchPos < len) {
      const idx = xmlLower.indexOf(localLower, searchPos);
      if (idx === -1) return null;
      const nameEnd = idx + tLen;
      if (nameEnd < len && isTagNameBoundary(xml.charCodeAt(nameEnd))) {
        let p = idx - 1;
        let matched = false;
        if (p >= fromBound && xml.charCodeAt(p) === 60) { // '<'
          matched = true;
        } else if (p >= fromBound + 2 && xml.charCodeAt(p) === 58) { // ':'
          p -= 1;
          const prefixEnd = p;
          while (p >= fromBound && isTagPrefixChar(xml.charCodeAt(p))) p -= 1;
          if (p >= fromBound && p < prefixEnd && xml.charCodeAt(p) === 60) {
            matched = true;
          }
        }
        if (matched) {
          return { lt: p, nameEnd };
        }
      }
      fromBound = nameEnd;
      searchPos = nameEnd;
    }
    return null;
  }

  // Fallback when xml contains length-changing Unicode uppercase chars (e.g. U+0130 'İ')
  let cur = pos;
  while (cur < len) {
    const lt = xml.indexOf('<', cur);
    if (lt === -1) return null;
    let q = lt + 1;
    if (q >= len) return null;
    const first = xml.charCodeAt(q);
    if (first === 47 || first === 33 || first === 63) { // '/', '!', '?'
      cur = q + 1;
      continue;
    }
    let localStart = q;
    let seenColon = false;
    while (q < len) {
      const ch = xml.charCodeAt(q);
      if (isTagPrefixChar(ch)) {
        q += 1;
      } else if (ch === 58 && !seenColon && q > lt + 1) {
        seenColon = true;
        q += 1;
        localStart = q;
      } else {
        break;
      }
    }
    const nameEnd = q;
    if (
      nameEnd < len &&
      matchesAsciiLower(xml, localStart, nameEnd, localLower) &&
      isTagNameBoundary(xml.charCodeAt(nameEnd))
    ) {
      return { lt, nameEnd };
    }
    cur = Math.max(lt + 1, nameEnd);
  }
  return null;
}

function findClosingTag(xml, xmlLower, localLower, fromIdx) {
  const len = xml.length;
  const firstClose = xml.indexOf('</', fromIdx);
  if (firstClose === -1) return null;

  if (xmlLower !== null) {
    const tLen = localLower.length;
    let searchPos = firstClose + 2;
    let fromBound = firstClose;
    while (searchPos < len) {
      const idx = xmlLower.indexOf(localLower, searchPos);
      if (idx === -1) return null;
      const nameEnd = idx + tLen;
      let q = nameEnd;
      while (q < len && isXmlWs(xml.charCodeAt(q))) q += 1;
      if (q < len && xml.charCodeAt(q) === 62) { // '>'
        let p = idx - 1;
        let closeStart = -1;
        if (p >= fromBound + 1 && xml.charCodeAt(p) === 47 && xml.charCodeAt(p - 1) === 60) { // '</'
          closeStart = p - 1;
        } else if (p >= fromBound + 3 && xml.charCodeAt(p) === 58) { // ':'
          p -= 1;
          const prefixEnd = p;
          while (p >= fromBound + 1 && isTagPrefixChar(xml.charCodeAt(p))) p -= 1;
          if (
            p >= fromBound + 1 &&
            p < prefixEnd &&
            xml.charCodeAt(p) === 47 &&
            xml.charCodeAt(p - 1) === 60
          ) {
            closeStart = p - 1;
          }
        }
        if (closeStart !== -1) {
          return { closeStart, closeEnd: q + 1 };
        }
      }
      fromBound = nameEnd;
      searchPos = nameEnd;
    }
    return null;
  }

  let p = firstClose;
  while (p < len) {
    const lt = xml.indexOf('</', p);
    if (lt === -1) return null;
    let q = lt + 2;
    let localStart = q;
    let seenColon = false;
    while (q < len) {
      const ch = xml.charCodeAt(q);
      if (isTagPrefixChar(ch)) {
        q += 1;
      } else if (ch === 58 && !seenColon && q > lt + 2) { // ':'
        seenColon = true;
        q += 1;
        localStart = q;
      } else {
        break;
      }
    }
    const nameEnd = q;
    while (q < len && isXmlWs(xml.charCodeAt(q))) q += 1;
    if (
      q < len &&
      xml.charCodeAt(q) === 62 && // '>'
      matchesAsciiLower(xml, localStart, nameEnd, localLower)
    ) {
      return { closeStart: lt, closeEnd: q + 1 };
    }
    p = Math.max(lt + 2, q);
  }
  return null;
}

function hasOpeningTag(xml, localTagName, preLower = undefined) {
  const xmlLower = preLower !== undefined ? preLower : makeLowerIndex(xml);
  return findNextOpeningTag(xml, xmlLower, localTagName.toLowerCase(), 0) !== null;
}

function findTagText(xml, localTagName, preLower = undefined) {
  const localLower = localTagName.toLowerCase();
  const xmlLower = preLower !== undefined ? preLower : makeLowerIndex(xml);
  let pos = 0;
  while (pos < xml.length) {
    const hit = findNextOpeningTag(xml, xmlLower, localLower, pos);
    if (!hit) return null;
    const openClose = xml.indexOf('>', hit.nameEnd);
    if (openClose === -1) return null;
    if (openClose > hit.nameEnd && xml.charCodeAt(openClose - 1) === 47) { // self-closing '/>'
      pos = openClose + 1;
      continue;
    }
    const closing = findClosingTag(xml, xmlLower, localLower, openClose + 1);
    if (!closing) return null;
    return decodeXmlEntities(xml.slice(openClose + 1, closing.closeStart).trim());
  }
  return null;
}

function findAllTags(xml, localTagName, preLower = undefined) {
  const results = [];
  const localLower = localTagName.toLowerCase();
  const xmlLower = preLower !== undefined ? preLower : makeLowerIndex(xml);
  let pos = 0;
  while (pos < xml.length) {
    const hit = findNextOpeningTag(xml, xmlLower, localLower, pos);
    if (!hit) break;
    const openClose = xml.indexOf('>', hit.nameEnd);
    if (openClose === -1) break;
    const isSelfClosing = openClose > hit.nameEnd && xml.charCodeAt(openClose - 1) === 47;
    if (isSelfClosing) {
      if (results.length >= MAX_MSIX_TAGS) {
        throw new FormatError(
          `MSIX XML exceeds maximum <${localTagName}> element count (${MAX_MSIX_TAGS})`,
          { code: ERROR_CODES.E_INVALID_MSIX, format: 'windows-msix' }
        );
      }
      results.push({
        attrs: parseXmlAttrs(xml.slice(hit.nameEnd, openClose - 1)),
        inner: '',
      });
      pos = openClose + 1;
      continue;
    }
    const closing = findClosingTag(xml, xmlLower, localLower, openClose + 1);
    // Strictly O(N): if no matching closing tag exists anywhere after openClose, break immediately
    if (!closing) break;
    if (results.length >= MAX_MSIX_TAGS) {
      throw new FormatError(
        `MSIX XML exceeds maximum <${localTagName}> element count (${MAX_MSIX_TAGS})`,
        { code: ERROR_CODES.E_INVALID_MSIX, format: 'windows-msix' }
      );
    }
    results.push({
      attrs: parseXmlAttrs(xml.slice(hit.nameEnd, openClose)),
      inner: xml.slice(openClose + 1, closing.closeStart),
    });
    pos = closing.closeEnd;
  }
  return results;
}

function normalizeArch(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (s === 'x64' || s === 'amd64' || s === 'x86_64') return 'x86_64';
  if (s === 'x86' || s === 'i386' || s === 'win32') return 'x86';
  if (s === 'arm64') return 'arm64';
  return 'x86_64';
}

function normalizeZipPath(p) {
  return String(p || '').replace(/\\/g, '/').replace(/^\/+/, '');
}

// ============================================================================
// MSIX / APPX Parser (ZIP + AppxManifest.xml + AppxBlockMap.xml SHA-256)
// ============================================================================

export function parseMsix(buffer) {
  const bytes = toBytes(buffer, ERROR_CODES.E_INVALID_MSIX, 'windows-msix');

  let zip;
  try {
    zip = readZip(bytes);
  } catch (err) {
    if (err?.code === ERROR_CODES.E_PATH_TRAVERSAL || err?.code === ERROR_CODES.E_ARCHIVE_BOMB) {
      throw err;
    }
    throw new FormatError(`Failed to read MSIX/APPX ZIP archive: ${err.message}`, {
      code: ERROR_CODES.E_INVALID_MSIX,
      format: 'windows-msix',
      cause: err,
    });
  }

  // Case-insensitive lookup map over extracted ZIP entries
  const files = new Map();
  const filesLower = new Map();
  for (const [name, entry] of zip.entries.entries()) {
    if (entry.isDirectory) continue;
    const norm = normalizeZipPath(name);
    files.set(norm, entry.data);
    filesLower.set(norm.toLowerCase(), { name: norm, data: entry.data });
  }

  const manifestEntry = filesLower.get('appxmanifest.xml');
  if (!manifestEntry) {
    throw new FormatError('MSIX/APPX package is missing required AppxManifest.xml', {
      code: ERROR_CODES.E_INVALID_MSIX,
      format: 'windows-msix',
    });
  }

  if (manifestEntry.data.byteLength > MAX_MSIX_XML_BYTES) {
    throw new FormatError(
      `MSIX AppxManifest.xml exceeds maximum size (${manifestEntry.data.byteLength} > ${MAX_MSIX_XML_BYTES} bytes)`,
      { code: ERROR_CODES.E_INVALID_MSIX, format: 'windows-msix' }
    );
  }

  const manifestXml = UTF8_DECODER.decode(manifestEntry.data);
  const cleanManifest = stripXmlComments(manifestXml);
  const cleanManifestLower = makeLowerIndex(cleanManifest);

  if (!hasOpeningTag(cleanManifest, 'Package', cleanManifestLower)) {
    throw new FormatError('Invalid AppxManifest.xml: missing <Package> root element', {
      code: ERROR_CODES.E_INVALID_MSIX,
      format: 'windows-msix',
    });
  }

  const identityTags = findAllTags(cleanManifest, 'Identity', cleanManifestLower);
  if (identityTags.length === 0 || !identityTags[0].attrs.Name) {
    throw new FormatError('Invalid AppxManifest.xml: missing <Identity Name="..."/>', {
      code: ERROR_CODES.E_INVALID_MSIX,
      format: 'windows-msix',
    });
  }
  const idAttrs = identityTags[0].attrs;
  const identity = {
    name: idAttrs.Name,
    publisher: idAttrs.Publisher ?? '',
    version: idAttrs.Version ?? '1.0.0.0',
    processorArchitecture: idAttrs.ProcessorArchitecture ?? 'x64',
  };

  const displayName =
    findTagText(cleanManifest, 'DisplayName', cleanManifestLower) ??
    identity.name;
  const publisherDisplayName =
    findTagText(cleanManifest, 'PublisherDisplayName', cleanManifestLower) ??
    identity.publisher;
  const description = findTagText(cleanManifest, 'Description', cleanManifestLower) ?? '';
  const logo = findTagText(cleanManifest, 'Logo', cleanManifestLower) ?? null;

  // Applications
  const appTags = findAllTags(cleanManifest, 'Application', cleanManifestLower);
  const applications = appTags.map((tag) => {
    const veTags = findAllTags(tag.inner, 'VisualElements');
    const ve = veTags[0]?.attrs ?? {};
    return {
      id: tag.attrs.Id ?? 'App',
      executable: tag.attrs.Executable ? normalizeZipPath(tag.attrs.Executable) : '',
      entryPoint: tag.attrs.EntryPoint ?? '',
      displayName: ve.DisplayName ?? displayName,
      description: ve.Description ?? description,
    };
  });

  const primaryApp = applications[0] ?? {
    id: 'App',
    executable: '',
    entryPoint: '',
    displayName,
    description,
  };

  // Capabilities (Capability + DeviceCapability across namespaces)
  const capSet = new Set();
  for (const tag of findAllTags(cleanManifest, 'Capability', cleanManifestLower)) {
    if (tag.attrs.Name) capSet.add(tag.attrs.Name);
  }
  for (const tag of findAllTags(cleanManifest, 'DeviceCapability', cleanManifestLower)) {
    if (tag.attrs.Name) capSet.add(tag.attrs.Name);
  }
  const capabilities = Array.from(capSet);

  // Extensions -> FLAT IntentRouter descriptors (CRITICAL Landmine #1!)
  const intents = [];
  const extTags = findAllTags(cleanManifest, 'Extension', cleanManifestLower);
  for (const ext of extTags) {
    const category = String(ext.attrs.Category || '').toLowerCase();
    if (category === 'windows.filetypeassociation') {
      const fileTypeTags = findAllTags(ext.inner, 'FileType');
      const extensions = [];
      for (const ft of fileTypeTags) {
        const rawExt = decodeXmlEntities(ft.inner.trim());
        if (rawExt) {
          extensions.push(rawExt.startsWith('.') ? rawExt.toLowerCase() : `.${rawExt.toLowerCase()}`);
        }
      }
      if (extensions.length > 0) {
        intents.push({
          actions: ['view'],
          extensions,
          platform: 'windows',
          label: primaryApp.displayName || displayName,
        });
      }
    } else if (category === 'windows.protocol') {
      const protoTags = findAllTags(ext.inner, 'Protocol');
      const schemes = [];
      for (const pt of protoTags) {
        if (pt.attrs.Name) {
          schemes.push(pt.attrs.Name.trim().toLowerCase());
        }
      }
      if (schemes.length > 0) {
        intents.push({
          actions: ['view'],
          schemes,
          platform: 'windows',
          label: primaryApp.displayName || displayName,
        });
      }
    }
  }

  // Verify AppxBlockMap.xml SHA-256 block hashes if present
  let blockMapVerified = false;
  let blockMapFileCount = 0;
  const blockMapEntry = filesLower.get('appxblockmap.xml');
  if (blockMapEntry) {
    if (blockMapEntry.data.byteLength > MAX_MSIX_XML_BYTES) {
      throw new FormatError(
        `MSIX AppxBlockMap.xml exceeds maximum size (${blockMapEntry.data.byteLength} > ${MAX_MSIX_XML_BYTES} bytes)`,
        { code: ERROR_CODES.E_INVALID_MSIX, format: 'windows-msix' }
      );
    }
    const bmXml = stripXmlComments(UTF8_DECODER.decode(blockMapEntry.data));
    const bmXmlLower = makeLowerIndex(bmXml);
    const bmTag = findAllTags(bmXml, 'BlockMap', bmXmlLower)[0];
    const hashMethod = bmTag?.attrs?.HashMethod ?? '';
    if (hashMethod && !/sha256/i.test(hashMethod)) {
      throw new FormatError(`Unsupported AppxBlockMap.xml HashMethod: ${hashMethod}`, {
        code: ERROR_CODES.E_INVALID_MSIX,
        format: 'windows-msix',
      });
    }

    const fileTags = findAllTags(bmXml, 'File', bmXmlLower);
    const seenBlockMapFiles = new Set();
    for (const fTag of fileTags) {
      const rawName = fTag.attrs.Name;
      if (!rawName) continue;
      const normName = normalizeZipPath(rawName);
      const lowerNorm = normName.toLowerCase();
      // AppxBlockMap does not hash itself or AppxSignature.p7x
      if (lowerNorm === 'appxblockmap.xml') continue;
      if (seenBlockMapFiles.has(lowerNorm)) {
        throw new FormatError(`AppxBlockMap.xml contains duplicate entry for "${normName}"`, {
          code: ERROR_CODES.E_INVALID_MSIX,
          format: 'windows-msix',
        });
      }
      seenBlockMapFiles.add(lowerNorm);

      const actual = filesLower.get(lowerNorm);
      if (!actual) {
        throw new FormatError(`AppxBlockMap.xml references missing archive file "${normName}"`, {
          code: ERROR_CODES.E_INVALID_MSIX,
          format: 'windows-msix',
        });
      }
      const fileData = actual.data;
      if (fTag.attrs.Size !== undefined) {
        const declaredSize = Number(fTag.attrs.Size);
        if (!Number.isFinite(declaredSize) || declaredSize < 0 || declaredSize !== fileData.byteLength) {
          throw new FormatError(
            `AppxBlockMap.xml size mismatch for "${normName}": declared ${fTag.attrs.Size}, actual ${fileData.byteLength}`,
            { code: ERROR_CODES.E_INVALID_MSIX, format: 'windows-msix' }
          );
        }
      }

      const blockTags = findAllTags(fTag.inner, 'Block');
      if (fileData.byteLength > 0 && blockTags.length === 0) {
        throw new FormatError(
          `AppxBlockMap.xml entry for non-empty file "${normName}" (${fileData.byteLength} bytes) contains zero <Block> elements`,
          { code: ERROR_CODES.E_INVALID_MSIX, format: 'windows-msix' }
        );
      }

      let offset = 0;
      for (let bIdx = 0; bIdx < blockTags.length; bIdx++) {
        const bAttrs = blockTags[bIdx].attrs;
        const expectedHash = (bAttrs.Hash || '').trim();
        if (!expectedHash) {
          throw new FormatError(`AppxBlockMap.xml block #${bIdx} for "${normName}" is missing Hash`, {
            code: ERROR_CODES.E_INVALID_MSIX,
            format: 'windows-msix',
          });
        }
        const remaining = fileData.byteLength - offset;
        if ((fileData.byteLength > 0 && remaining <= 0) || (fileData.byteLength === 0 && bIdx > 0)) {
          throw new FormatError(`AppxBlockMap.xml has extra blocks beyond EOF for "${normName}"`, {
            code: ERROR_CODES.E_INVALID_MSIX,
            format: 'windows-msix',
          });
        }
        const chunkLen = Math.min(MSIX_BLOCK_SIZE, remaining);
        const chunk = fileData.subarray(offset, offset + chunkLen);
        const actualHash = crypto.createHash('sha256').update(chunk).digest('base64');
        if (actualHash !== expectedHash) {
          throw new FormatError(
            `AppxBlockMap.xml SHA-256 hash mismatch for "${normName}" block #${bIdx}`,
            {
              code: ERROR_CODES.E_INVALID_MSIX,
              format: 'windows-msix',
              details: { file: normName, blockIndex: bIdx, expectedHash, actualHash },
            }
          );
        }
        offset += chunkLen;
      }

      if (offset < fileData.byteLength) {
        throw new FormatError(
          `AppxBlockMap.xml blocks cover only ${offset}/${fileData.byteLength} bytes of "${normName}"`,
          { code: ERROR_CODES.E_INVALID_MSIX, format: 'windows-msix' }
        );
      }

      blockMapFileCount += 1;
    }
    blockMapVerified = true;
  }

  return {
    format: 'windows-msix',
    identity,
    displayName,
    publisher: publisherDisplayName,
    description,
    logo,
    version: identity.version,
    arch: normalizeArch(identity.processorArchitecture),
    executable: primaryApp.executable,
    entryPoint: primaryApp.entryPoint,
    applications,
    capabilities,
    intents,
    blockMapVerified,
    blockMapFileCount,
    files,
    fileNames: Array.from(files.keys()),
    manifestXml,
  };
}

// ============================================================================
// MSI OLE Compound File Binary Format (CFBF v3 & v4) Parser
// ============================================================================

function msiErr(message, offset = null, details = null) {
  return new FormatError(message, {
    code: ERROR_CODES.E_INVALID_MSI,
    format: 'windows-msi',
    offset,
    details,
  });
}

function parseSummaryInfoStream(streamBytes) {
  if (!streamBytes || streamBytes.byteLength < 48) return {};
  const dv = new DataView(streamBytes.buffer, streamBytes.byteOffset, streamBytes.byteLength);
  const byteOrder = dv.getUint16(0, true);
  if (byteOrder !== 0xfffe) return {};
  const numSections = dv.getUint32(24, true);
  if (numSections < 1 || 48 > streamBytes.byteLength) return {};

  // First section offset sits at byte 44 (after 28B header + 16B FMTID)
  const sectionOff = dv.getUint32(44, true);
  if (sectionOff + 8 > streamBytes.byteLength) return {};

  const propCount = dv.getUint32(sectionOff + 4, true);
  if (propCount > 256) return {};

  const PID_MAP = {
    2: 'title',
    3: 'subject',
    4: 'author',
    5: 'keywords',
    6: 'comments',
    7: 'template',
    9: 'revisionNumber',
    18: 'creatingApp',
  };

  const info = {};
  for (let i = 0; i < propCount; i++) {
    const entryOff = sectionOff + 8 + i * 8;
    if (entryOff + 8 > streamBytes.byteLength) break;
    const propId = dv.getUint32(entryOff, true);
    const relOff = dv.getUint32(entryOff + 4, true);
    const key = PID_MAP[propId];
    if (!key) continue;

    const valOff = sectionOff + relOff;
    if (valOff + 8 > streamBytes.byteLength) continue;
    const vt = dv.getUint32(valOff, true);
    if (vt === 30) { // VT_LPSTR
      const len = dv.getUint32(valOff + 4, true);
      if (valOff + 8 + len <= streamBytes.byteLength && len > 0) {
        const raw = streamBytes.subarray(valOff + 8, valOff + 8 + len);
        let end = raw.byteLength;
        while (end > 0 && raw[end - 1] === 0) end -= 1;
        info[key] = UTF8_DECODER.decode(raw.subarray(0, end));
      }
    } else if (vt === 31) { // VT_LPWSTR
      const charCount = dv.getUint32(valOff + 4, true);
      const byteLen = charCount * 2;
      if (valOff + 8 + byteLen <= streamBytes.byteLength && byteLen > 0) {
        const raw = streamBytes.subarray(valOff + 8, valOff + 8 + byteLen);
        const decoded = UTF16LE_DECODER.decode(raw);
        let end = decoded.length;
        while (end > 0 && decoded.charCodeAt(end - 1) === 0) end -= 1;
        info[key] = end === decoded.length ? decoded : decoded.slice(0, end);
      }
    } else if (vt === 3) { // VT_I4
      info[key] = dv.getInt32(valOff + 4, true);
    }
  }
  return info;
}

export function parseMsi(buffer) {
  const bytes = toBytes(buffer, ERROR_CODES.E_INVALID_MSI, 'windows-msi');
  if (bytes.byteLength < 512) {
    throw msiErr(`MSI CFBF file too small (${bytes.byteLength} bytes, minimum 512)`, 0);
  }

  for (let i = 0; i < 8; i++) {
    if (bytes[i] !== OLE_CFBF_MAGIC[i]) {
      throw msiErr('Invalid OLE CFBF signature (expected D0 CF 11 E0 A1 B1 1A E1)', 0);
    }
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const minorVersion = view.getUint16(0x18, true);
  const majorVersion = view.getUint16(0x1a, true);
  const byteOrder = view.getUint16(0x1c, true);
  const sectorShift = view.getUint16(0x1e, true);
  const miniSectorShift = view.getUint16(0x20, true);

  if (byteOrder !== 0xfffe) {
    throw msiErr(`Invalid CFBF byte order marker 0x${byteOrder.toString(16)} (expected 0xFFFE)`, 0x1c);
  }
  if (majorVersion !== 3 && majorVersion !== 4) {
    throw msiErr(`Unsupported CFBF major version: ${majorVersion} (expected 3 or 4)`, 0x1a);
  }
  const expectedShift = majorVersion === 4 ? 12 : 9;
  if (sectorShift !== expectedShift) {
    throw msiErr(
      `CFBF v${majorVersion} sectorShift mismatch: got ${sectorShift}, expected ${expectedShift}`,
      0x1e
    );
  }
  if (miniSectorShift !== 6) {
    throw msiErr(`Invalid CFBF miniSectorShift: ${miniSectorShift} (expected 6)`, 0x20);
  }

  const sectorSize = 1 << sectorShift; // 512 (v3) or 4096 (v4)
  const miniSectorSize = 1 << miniSectorShift; // 64
  if (bytes.byteLength < sectorSize) {
    throw msiErr(`CFBF file smaller than one header sector (${sectorSize} bytes)`, 0);
  }

  const numDirSectors = view.getUint32(0x28, true);
  const numFatSectors = view.getUint32(0x2c, true);
  const firstDirSector = view.getUint32(0x30, true);
  const miniStreamCutoff = view.getUint32(0x38, true);
  const firstMiniFatSector = view.getUint32(0x3c, true);
  const numMiniFatSectors = view.getUint32(0x40, true);
  const firstDifatSector = view.getUint32(0x44, true);
  const numDifatSectors = view.getUint32(0x48, true);

  if (miniStreamCutoff > 0x10000) {
    throw msiErr(
      `Invalid CFBF miniStreamCutoff 0x${miniStreamCutoff.toString(16)} (exceeds maximum 0x10000)`,
      0x38
    );
  }

  const maxSectorIdx = Math.floor((bytes.byteLength - sectorSize) / sectorSize);
  if (numFatSectors > maxSectorIdx) {
    throw msiErr(`CFBF numFatSectors (${numFatSectors}) exceeds total sectors (${maxSectorIdx})`, 0x2c);
  }
  if (numDifatSectors > maxSectorIdx) {
    throw msiErr(`CFBF numDifatSectors (${numDifatSectors}) exceeds total sectors (${maxSectorIdx})`, 0x48);
  }
  if (numDirSectors > maxSectorIdx) {
    throw msiErr(`CFBF numDirSectors (${numDirSectors}) exceeds total sectors (${maxSectorIdx})`, 0x28);
  }
  if (numMiniFatSectors > maxSectorIdx) {
    throw msiErr(`CFBF numMiniFatSectors (${numMiniFatSectors}) exceeds total sectors (${maxSectorIdx})`, 0x40);
  }

  const sectorOffset = (sid) => sectorSize + sid * sectorSize;

  const readSectorSlice = (sid) => {
    if (sid < 0 || sid >= maxSectorIdx) {
      throw msiErr(`CFBF sector ${sid} out of bounds (max ${maxSectorIdx})`, 0);
    }
    const off = sectorOffset(sid);
    return bytes.subarray(off, off + sectorSize);
  };

  // 1. Build DIFAT list (109 inline entries at 0x4C + cycle-guarded DIFAT sector chain)
  // Deduplicate FAT sector IDs across header + external DIFAT sectors so fat.byteLength <= file size (zero amplification).
  const fatSectorIds = [];
  const seenFat = new Set();
  const seenDifat = new Set();

  const recordFatSector = (sid, contextLabel, offset = null) => {
    if (sid > CFBF_MAXREGSECT || sid >= maxSectorIdx) {
      throw msiErr(`Invalid FAT sector ID ${sid} in ${contextLabel}`, offset);
    }
    if (seenFat.has(sid) || seenDifat.has(sid)) {
      throw msiErr(`Duplicate FAT sector ID ${sid} in CFBF DIFAT (${contextLabel})`, offset);
    }
    seenFat.add(sid);
    fatSectorIds.push(sid);
    if (fatSectorIds.length > maxSectorIdx) {
      throw msiErr(
        `CFBF FAT sector count (${fatSectorIds.length}) exceeds total sectors (${maxSectorIdx})`,
        offset
      );
    }
  };

  for (let i = 0; i < 109; i++) {
    const sid = view.getUint32(0x4c + i * 4, true);
    if (sid === CFBF_FREESECT || sid === CFBF_ENDOFCHAIN) continue;
    recordFatSector(sid, 'DIFAT header', 0x4c + i * 4);
  }

  if (numDifatSectors > 0 && firstDifatSector !== CFBF_ENDOFCHAIN && firstDifatSector !== CFBF_FREESECT) {
    let difatSid = firstDifatSector;
    let steps = 0;
    const entriesPerDifat = (sectorSize / 4) - 1;
    while (difatSid !== CFBF_ENDOFCHAIN && difatSid !== CFBF_FREESECT) {
      if (
        difatSid > CFBF_MAXREGSECT ||
        difatSid >= maxSectorIdx ||
        seenDifat.has(difatSid) ||
        seenFat.has(difatSid) ||
        steps >= numDifatSectors ||
        steps >= maxSectorIdx
      ) {
        throw msiErr(`Cyclic or runaway DIFAT sector chain at sector ${difatSid}`);
      }
      seenDifat.add(difatSid);
      steps += 1;
      const sec = readSectorSlice(difatSid);
      const sdv = new DataView(sec.buffer, sec.byteOffset, sec.byteLength);
      for (let i = 0; i < entriesPerDifat; i++) {
        const sid = sdv.getUint32(i * 4, true);
        if (sid === CFBF_FREESECT || sid === CFBF_ENDOFCHAIN) continue;
        recordFatSector(sid, `DIFAT sector ${difatSid}`);
      }
      difatSid = sdv.getUint32(entriesPerDifat * 4, true);
    }
  }

  if (fatSectorIds.length === 0) {
    throw msiErr('CFBF contains no valid FAT sectors');
  }

  // 2. Build FAT table
  const entriesPerFat = sectorSize / 4;
  const fat = new Uint32Array(fatSectorIds.length * entriesPerFat);
  for (let i = 0; i < fatSectorIds.length; i++) {
    const sec = readSectorSlice(fatSectorIds[i]);
    const sdv = new DataView(sec.buffer, sec.byteOffset, sec.byteLength);
    const base = i * entriesPerFat;
    for (let j = 0; j < entriesPerFat; j++) {
      fat[base + j] = sdv.getUint32(j * 4, true);
    }
  }

  const readFatChain = (startSid, maxLenBytes = Infinity) => {
    if (startSid === CFBF_ENDOFCHAIN || startSid === CFBF_FREESECT) {
      return new Uint8Array(0);
    }
    const visited = new Set();
    const chunks = [];
    let sid = startSid;
    let total = 0;
    while (sid !== CFBF_ENDOFCHAIN) {
      if (sid === CFBF_FREESECT || sid === CFBF_FATSECT || sid === CFBF_DIFSECT || sid > CFBF_MAXREGSECT) {
        throw msiErr(`Invalid sector entry 0x${sid.toString(16)} in FAT chain`);
      }
      if (visited.has(sid)) {
        throw msiErr(`Cyclic FAT sector chain detected at sector ${sid}`);
      }
      if (sid >= fat.length || sid >= maxSectorIdx) {
        throw msiErr(`FAT sector chain out of bounds at sector ${sid}`);
      }
      visited.add(sid);
      if (total < maxLenBytes) {
        chunks.push(readSectorSlice(sid));
        total += sectorSize;
      }
      sid = fat[sid];
    }
    const out = new Uint8Array(Math.min(total, maxLenBytes));
    let pos = 0;
    for (const c of chunks) {
      const n = Math.min(c.byteLength, out.byteLength - pos);
      out.set(c.subarray(0, n), pos);
      pos += n;
      if (pos >= out.byteLength) break;
    }
    return out;
  };

  // 3. Read Directory Stream & parse 128-byte Directory Entries
  const dirBytes = readFatChain(firstDirSector);
  if (dirBytes.byteLength < 128) {
    throw msiErr('CFBF directory stream is empty or truncated');
  }
  const dirView = new DataView(dirBytes.buffer, dirBytes.byteOffset, dirBytes.byteLength);
  const entryCount = Math.floor(dirBytes.byteLength / 128);
  const entries = [];

  for (let i = 0; i < entryCount; i++) {
    const base = i * 128;
    const objType = dirBytes[base + 66];
    if (objType === 0) continue; // unallocated
    const nameLenBytes = dirView.getUint16(base + 64, true);
    const clampedLen = Math.min(Math.max(nameLenBytes, 0), 64);
    const rawName = clampedLen >= 2
      ? dirBytes.subarray(base, base + clampedLen - 2)
      : new Uint8Array(0);
    const name = UTF16LE_DECODER.decode(rawName);
    const leftSiblingId = dirView.getUint32(base + 68, true);
    const rightSiblingId = dirView.getUint32(base + 72, true);
    const childId = dirView.getUint32(base + 76, true);
    const startSector = dirView.getUint32(base + 116, true);
    const streamSize = majorVersion === 4
      ? Number(dirView.getBigUint64(base + 120, true))
      : dirView.getUint32(base + 120, true);

    entries.push({
      id: i,
      name,
      objectType: objType,
      typeName: objType === 5 ? 'root' : (objType === 1 ? 'storage' : (objType === 2 ? 'stream' : 'unknown')),
      leftSiblingId,
      rightSiblingId,
      childId,
      startSector,
      streamSize,
    });
  }

  const rootEntry = entries.find((e) => e.objectType === 5);
  if (!rootEntry) {
    throw msiErr('CFBF directory is missing Root Entry');
  }

  // 4. Build MiniFAT & Root MiniStream (cycle-guarded)
  let miniFat = new Uint32Array(0);
  if (numMiniFatSectors > 0 && firstMiniFatSector !== CFBF_ENDOFCHAIN && firstMiniFatSector !== CFBF_FREESECT) {
    const miniFatBytes = readFatChain(firstMiniFatSector, numMiniFatSectors * sectorSize);
    const mfv = new DataView(miniFatBytes.buffer, miniFatBytes.byteOffset, miniFatBytes.byteLength);
    miniFat = new Uint32Array(Math.floor(miniFatBytes.byteLength / 4));
    for (let i = 0; i < miniFat.length; i++) {
      miniFat[i] = mfv.getUint32(i * 4, true);
    }
  }

  const miniStreamBytes =
    rootEntry.streamSize > 0 && rootEntry.startSector !== CFBF_ENDOFCHAIN && rootEntry.startSector !== CFBF_FREESECT
      ? readFatChain(rootEntry.startSector, rootEntry.streamSize)
      : new Uint8Array(0);

  const readMiniChain = (startSid, size) => {
    if (size === 0 || startSid === CFBF_ENDOFCHAIN || startSid === CFBF_FREESECT) {
      return new Uint8Array(0);
    }
    if (!Number.isSafeInteger(size) || size < 0 || size > miniStreamBytes.byteLength) {
      throw msiErr(
        `CFBF MiniStream entry size (${size}) exceeds root MiniStream length (${miniStreamBytes.byteLength})`
      );
    }
    const visited = new Set();
    const chunks = [];
    let sid = startSid;
    let total = 0;
    const maxMiniSectors = Math.floor(miniStreamBytes.byteLength / miniSectorSize);
    while (sid !== CFBF_ENDOFCHAIN) {
      if (sid > CFBF_MAXREGSECT || sid >= miniFat.length || sid >= maxMiniSectors) {
        throw msiErr(`MiniFAT sector ${sid} out of bounds`);
      }
      if (visited.has(sid)) {
        throw msiErr(`Cyclic MiniFAT chain detected at mini-sector ${sid}`);
      }
      visited.add(sid);
      if (total < size) {
        const off = sid * miniSectorSize;
        const n = Math.min(miniSectorSize, size - total);
        chunks.push(miniStreamBytes.subarray(off, off + n));
        total += n;
      }
      sid = miniFat[sid];
    }
    const out = new Uint8Array(total);
    let pos = 0;
    for (const c of chunks) {
      out.set(c, pos);
      pos += c.byteLength;
    }
    return out;
  };

  const readStreamEntry = (entry) => {
    if (!entry || entry.objectType !== 2) return null;
    if (entry.streamSize === 0) return new Uint8Array(0);
    if (entry.streamSize < miniStreamCutoff && miniStreamBytes.byteLength > 0) {
      return readMiniChain(entry.startSector, entry.streamSize);
    }
    return readFatChain(entry.startSector, entry.streamSize);
  };

  const readStream = (name) => {
    if (typeof name !== 'string') return null;
    const exact = entries.find((e) => e.objectType === 2 && e.name === name);
    if (exact) return readStreamEntry(exact);
    const lower = name.toLowerCase();
    const ci = entries.find(
      (e) =>
        e.objectType === 2 &&
        (e.name.toLowerCase() === lower || e.name.replace(/^\x05/, '').toLowerCase() === lower)
    );
    return ci ? readStreamEntry(ci) : null;
  };

  // 5. Extract \x05SummaryInformation metadata if present
  const summaryBytes = readStream('\x05SummaryInformation');
  const summaryInfo = summaryBytes ? parseSummaryInfoStream(summaryBytes) : {};

  return {
    format: 'windows-msi',
    version: majorVersion,
    minorVersion,
    sectorSize,
    miniSectorSize,
    numFatSectors,
    numDirSectors,
    entries,
    streamNames: entries.filter((e) => e.objectType === 2).map((e) => e.name),
    summaryInfo,
    readStream,
  };
}
