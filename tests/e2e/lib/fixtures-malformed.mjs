/**
 * Deterministic Adversarial & Edge-Case Binary Fixture Corpus covering ALL 29
 * authoritative binary, CPU, VMM, VFS, plist, and WASI edge cases from PROJECT.md
 * (plus malformed .dmg / .pkg containers).
 *
 * Acyclic Dependency: imports ONLY Node 24 built-ins + `./binary-utils.mjs`
 * + `./fixtures-android-win.mjs` + `./fixtures-apple-wasm.mjs`.
 */

import zlib from 'node:zlib';
import {
  BinaryWriter,
  alignUp,
  concatBytes,
  crc32,
  adler32,
  sha1,
  buildZip,
  buildAxmlManifest,
  buildResourcesArsc as buildBaseResourcesArsc,
  buildBinaryPlist,
} from './binary-utils.mjs';
import {
  DALVIK,
  X64,
  buildDex,
  buildCustomApk,
  buildCustomPe64Exe,
  buildErrorlevelSemanticsScript,
} from './fixtures-android-win.mjs';
import {
  ARM64_SVC_80,
  ARM64_NOP,
  arm64Movz,
  arm64AddImm,
  arm64SubImm,
  arm64SubsImm,
  arm64SubReg,
  arm64AddReg,
  arm64Adr,
  arm64Adrp,
  arm64Ldr64,
  arm64Str64,
  arm64Blr,
  arm64Cbz,
  arm64Cbnz,
  arm64BCond,
  packArm64Insns,
  buildMachO64,
  buildMachO64WithLayout,
  buildCustomIpa,
  buildCustomDmg,
  buildCustomPkg,
  buildCustomWasm,
  buildCustomUapp,
} from './fixtures-apple-wasm.mjs';

const textEncoder = new TextEncoder();

// ============================================================================
// #1: ZIP-slip (../../, C:\, leading /, NUL byte)
// ============================================================================

export function buildZipSlipArchive(variant = 'dotdot', { wrapAsApk = false } = {}) {
  const slipPaths = {
    dotdot: '../../etc/passwd',
    'win-drive': 'C:\\Windows\\evil.dll',
    'leading-slash': '/etc/shadow',
    'nul-byte': 'Payload/App.app/Info.plist\0../../evil.txt',
  };
  const evilName = slipPaths[variant];
  if (!evilName) {
    throw new Error(`Unknown ZIP-slip variant "${variant}". Expected: ${Object.keys(slipPaths).join(', ')}`);
  }

  const entries = [];
  if (wrapAsApk) {
    entries.push({ name: 'AndroidManifest.xml', data: buildAxmlManifest({ packageName: 'com.omnios.zipslip' }), method: 0 });
    entries.push({ name: 'classes.dex', data: buildDex({ extraStrings: ['zipslip'] }), method: 0 });
  }
  entries.push({
    name: evilName,
    data: textEncoder.encode(`OMNIOS_ZIP_SLIP_${variant}\n`),
    method: 0,
  });
  return buildZip(entries);
}

// ============================================================================
// #2: ZIP Bomb (>100 MiB uncompressed, >1000x ratio, lazy memoized)
// ============================================================================

const zipBombCache = new Map();

function getCompressedZeros(uncompBytes) {
  if (zipBombCache.has(uncompBytes)) return zipBombCache.get(uncompBytes);
  const zeros = Buffer.alloc(uncompBytes);
  const compBuf = zlib.deflateRawSync(zeros, { level: 9 });
  const compBytes = new Uint8Array(compBuf.buffer, compBuf.byteOffset, compBuf.byteLength);
  const crc = typeof zlib.crc32 === 'function' ? (zlib.crc32(zeros) >>> 0) : crc32(zeros);
  const cached = { compBytes, crc, uncompBytes };
  zipBombCache.set(uncompBytes, cached);
  return cached;
}

export function buildZipBomb({ uncompBytes = 110 * 1024 * 1024, fakeSmallUncompSize = false } = {}) {
  const { compBytes, crc } = getCompressedZeros(uncompBytes);
  return buildZip([
    {
      name: 'bomb.bin',
      method: 8,
      rawCompData: compBytes,
      overrideCrc32: crc,
      overrideUncompSize: fakeSmallUncompSize ? 1024 : uncompBytes,
      overrideCompSize: compBytes.length,
    },
  ]);
}

// ============================================================================
// #3: APK Signing Block v2/v3 before Central Directory (positive)
// ============================================================================

export function buildApkWithV2SigningBlock(baseApkBytes = null, { schemeId = 0x7109871a } = {}) {
  const base = baseApkBytes instanceof Uint8Array
    ? baseApkBytes
    : buildCustomApk({
        packageName: 'com.omnios.v2sig',
        appLabel: 'V2SigApp',
        includeV2SigBlock: false,
      });

  // Locate EOCD signature (PK\x05\x06) scanning backwards from EOF
  const view = new DataView(base.buffer, base.byteOffset, base.byteLength);
  let eocdOff = -1;
  for (let i = base.length - 22; i >= Math.max(0, base.length - 65557); i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOff = i;
      break;
    }
  }
  if (eocdOff < 0) throw new Error('Invalid base APK ZIP: EOCD not found');

  const cdOffset = view.getUint32(eocdOff + 16, true);
  const payload = textEncoder.encode('OMNIOS_APK_SIG_SCHEME_V2_PAYLOAD');
  const pairLen = BigInt(4 + payload.length);
  const blockSize = BigInt(8 + 4 + payload.length + 8 + 16);

  const sb = new BinaryWriter(Number(blockSize) + 8);
  sb.u64le(blockSize)
    .u64le(pairLen)
    .u32le(schemeId >>> 0)
    .bytes(payload)
    .u64le(blockSize)
    .ascii('APK Sig Block 42');
  const sigBlock = sb.toUint8Array();

  const beforeCd = base.subarray(0, cdOffset);
  const cdAndEocd = base.slice(cdOffset); // copy so we can patch EOCD cdOffset
  const cdView = new DataView(cdAndEocd.buffer, cdAndEocd.byteOffset, cdAndEocd.byteLength);
  cdView.setUint32((eocdOff - cdOffset) + 16, cdOffset + sigBlock.length, true);

  return concatBytes(beforeCd, sigBlock, cdAndEocd);
}

// ============================================================================
// #4: ZIP Data Descriptor Flag Bit 3 (0x0008) (positive)
// ============================================================================

export function buildZipWithDataDescriptor(entries = null) {
  const finalEntries = entries ?? [
    { name: 'payload.txt', data: 'OmniOS ZIP Data Descriptor Bit 3 Valid Payload\n', method: 8 },
    { name: 'meta.json', data: JSON.stringify({ flagBit3: true, codec: 'deflate' }), method: 8 },
  ];
  return buildZip(finalEntries, { useDataDescriptor: true });
}

// ============================================================================
// #5: Malformed AXML (chunk.size == 0, subchunk size == 0, size < headerSize, OOB)
// ============================================================================

export function buildMalformedAxml(variant = 'zero-size') {
  const w = new BinaryWriter(32);
  switch (variant) {
    case 'zero-size':
      w.u16le(0x0003).u16le(8).u32le(0).zeros(16);
      break;
    case 'subchunk-zero-size':
      w.u16le(0x0003).u16le(8).u32le(24) // valid outer chunk
        .u16le(0x0001).u16le(28).u32le(0).zeros(8); // zero-size inner string pool
      break;
    case 'size-lt-header':
      w.u16le(0x0003).u16le(8).u32le(4).zeros(16);
      break;
    case 'oob-size':
      w.u16le(0x0003).u16le(8).u32le(0x00010000).zeros(24);
      break;
    default:
      throw new Error(`Unknown malformed AXML variant "${variant}"`);
  }
  return w.toUint8Array();
}

export function buildMalformedAxmlApk(variant = 'zero-size') {
  return buildZip([
    { name: 'AndroidManifest.xml', data: buildMalformedAxml(variant), method: 0 },
    { name: 'classes.dex', data: buildDex({ extraStrings: ['malformed_axml'] }), method: 8 },
  ]);
}

// ============================================================================
// #6: resources.arsc FLAG_OFFSET16 (0x02) & FLAG_SPARSE (0x01) (positive)
// ============================================================================

export function buildResourcesArsc({
  mode = 'offset16', // 'offset16' | 'sparse'
  packageId = 0x7f,
  packageName = 'com.omnios.arsc.edge',
  strings = [
    { id: 0, name: 'app_name', value: 'OmniArscEdge' },
    { id: 5, name: 'sparse_label', value: 'SparseHit_0x7F010005' },
  ],
} = {}) {
  return buildBaseResourcesArsc({
    packageId,
    packageName,
    strings,
    mode,
  });
}

// ============================================================================
// #7: Malformed DEX (isolated checksum/header/endian/type_ids/truncated)
// ============================================================================

function repatchDexHashes(bytes, { skipSha1 = false, skipAdler = false } = {}) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (!skipSha1) {
    bytes.set(sha1(bytes.subarray(0x20)), 0x0c);
  }
  if (!skipAdler) {
    view.setUint32(0x08, adler32(bytes.subarray(0x0c)), true);
  }
  return bytes;
}

export function buildMalformedDex(variant = 'bad-adler32', baseDex = null) {
  const src = baseDex instanceof Uint8Array
    ? new Uint8Array(baseDex)
    : buildDex({ extraStrings: ['OmniMalformedDexBase'] });

  const view = new DataView(src.buffer, src.byteOffset, src.byteLength);

  switch (variant) {
    case 'bad-adler32':
      src[0x08] ^= 0xff;
      return src;
    case 'bad-sha1':
      // Flip SHA-1 byte AND recompute Adler-32 so parser MUST check SHA-1 independently!
      src[0x0c] ^= 0xff;
      return repatchDexHashes(src, { skipSha1: true, skipAdler: false });
    case 'bad-header-size':
      view.setUint32(0x24, 0x60, true);
      return repatchDexHashes(src);
    case 'bad-endian':
      view.setUint32(0x28, 0x78563412, true);
      return repatchDexHashes(src);
    case 'type-ids-overflow':
      view.setUint32(0x40, 65536, true);
      return repatchDexHashes(src);
    case 'truncated':
      return src.slice(0, 64);
    default:
      throw new Error(`Unknown malformed DEX variant "${variant}"`);
  }
}

export function buildMalformedDexApk(variant = 'bad-adler32') {
  return buildZip([
    { name: 'AndroidManifest.xml', data: buildAxmlManifest({ packageName: `com.omnios.baddex.${variant.replace(/-/g, '')}` }), method: 8 },
    { name: 'classes.dex', data: buildMalformedDex(variant), method: 8 },
  ]);
}

// ============================================================================
// #8: DEX MUTF-8 0xC0 0x80 + Surrogates (positive) & Overlong 6-Byte LEB128 (negative)
// ============================================================================

export function buildDexMutf8Valid() {
  return buildDex({
    extraStrings: ['A\u0000B', '😀', 'Omni\u0000MUTF8\uD83D\uDE00'],
  });
}

export function buildDexOverlongLeb128() {
  const base = buildDex({ extraStrings: ['OverlongTarget'] });
  const overlongEntry = Uint8Array.from([0x81, 0x80, 0x80, 0x80, 0x80, 0x00, 0x41, 0x00]); // 6-byte LEB128 (>5B max!)
  const combined = concatBytes(base, overlongEntry);
  const view = new DataView(combined.buffer, combined.byteOffset, combined.byteLength);

  const strIdsOff = view.getUint32(0x3c, true);
  const dataOff = view.getUint32(0x6c, true);
  // Point string_ids[0] to our appended 6-byte overlong LEB128 entry
  view.setUint32(strIdsOff, base.length, true);
  view.setUint32(0x20, combined.length, true); // file_size
  view.setUint32(0x68, combined.length - dataOff, true); // data_size
  return repatchDexHashes(combined);
}

// ============================================================================
// #9: Dalvik code_item with tries_size > 0 & ODD insns_size (2-byte padding)
// ============================================================================

export function buildDexOddInsnsTryCatchApk({ token = 'CATCH_PAD_OK' } = {}) {
  return buildCustomApk({
    packageName: 'com.omnios.oddpad',
    appLabel: 'OddPadTryCatch',
    rawDexInsns: (ctx) => {
      const codeUnits = [
        ...DALVIK.const4(0, 1), // [0] (1 cu)
        ...DALVIK.const4(1, 0), // [1] (1 cu)
        ...DALVIK.binop(DALVIK.OP_DIV_INT, 0, 0, 1), // [2..3] (2 cu) -> throws ArithmeticException
        ...DALVIK.returnVoid(), // [4] (1 cu)
        // Catch handler target at [5]:
        ...DALVIK.moveException(0), // [5] (1 cu)
        ...DALVIK.constString(1, ctx.str('OddPadCatch')), // [6..7] (2 cu)
        ...DALVIK.constString(2, ctx.str(token)), // [8..9] (2 cu)
        ...DALVIK.invoke35c(
          DALVIK.OP_INVOKE_STATIC,
          [1, 2],
          ctx.method('Landroid/util/Log;', 'i', 'I', ['Ljava/lang/String;', 'Ljava/lang/String;'])
        ), // [10..12] (3 cu)
        ...DALVIK.returnVoid(), // [13] (1 cu)
        ...DALVIK.nop(), // [14] (1 cu) -> total = 15 code units (ODD!)
      ];
      return {
        codeUnits,
        tries: [
          {
            startAddr: 0,
            insnCount: 4,
            handlers: [{ type: 'Ljava/lang/ArithmeticException;', addr: 5 }],
            catchAllAddr: 5,
          },
        ],
      };
    },
  });
}

// ============================================================================
// #10: Dalvik div-int by 0 & INT32_MIN / -1 wrap
// ============================================================================

export function buildDexDivByZeroApk() {
  return buildCustomApk({
    packageName: 'com.omnios.divzero',
    appLabel: 'DivByZero',
    rawDexInsns: () => [
      ...DALVIK.const4(0, 5),
      ...DALVIK.const4(1, 0),
      ...DALVIK.binop(DALVIK.OP_DIV_INT, 0, 0, 1),
      ...DALVIK.returnVoid(),
    ],
  });
}

export function buildDexInt32MinDivNeg1Apk() {
  return buildCustomApk({
    packageName: 'com.omnios.int32mindiv',
    appLabel: 'Int32MinDiv',
    rawDexInsns: (ctx) => [
      ...DALVIK.constHigh16(0, 0x8000), // v0 = -2147483648 (INT32_MIN)
      ...DALVIK.const4(1, -1), // v1 = -1
      ...DALVIK.binop(DALVIK.OP_DIV_INT, 2, 0, 1), // v2 = -2147483648 (wraps, must NOT throw)
      ...DALVIK.binop(DALVIK.OP_REM_INT, 3, 0, 1), // v3 = 0
      ...DALVIK.invoke35c(
        DALVIK.OP_INVOKE_STATIC,
        [2],
        ctx.method('Ljava/lang/Integer;', 'toString', 'Ljava/lang/String;', ['I'])
      ),
      ...DALVIK.moveResultObj(4),
      ...DALVIK.constString(5, ctx.str('Int32MinDiv')),
      ...DALVIK.invoke35c(
        DALVIK.OP_INVOKE_STATIC,
        [5, 4],
        ctx.method('Landroid/util/Log;', 'i', 'I', ['Ljava/lang/String;', 'Ljava/lang/String;'])
      ),
      ...DALVIK.returnVoid(),
    ],
  });
}

// ============================================================================
// #11: Dalvik Infinite Loop (`goto 0`) & Deep Recursion
// ============================================================================

export function buildDexInfiniteLoopApk() {
  return buildCustomApk({
    packageName: 'com.omnios.infloop',
    appLabel: 'InfiniteLoop',
    rawDexInsns: () => [...DALVIK.goto8(0)], // [0x0028] goto +0
  });
}

export function buildDexDeepRecursionApk() {
  return buildCustomApk({
    packageName: 'com.omnios.deeprec',
    appLabel: 'DeepRecursion',
    rawDexInsns: (ctx, classDesc) => [
      ...DALVIK.invoke35c(
        DALVIK.OP_INVOKE_VIRTUAL,
        [6, 7],
        ctx.method(classDesc, 'onCreate', 'V', ['Landroid/os/Bundle;'])
      ),
      ...DALVIK.returnVoid(),
    ],
  });
}

// ============================================================================
// #12: Malformed PE (bad e_lfanew, NumberOfSections=97, NumberOfRvaAndSizes=99, bad PE magic)
// ============================================================================

export function buildMalformedPe(variant = 'lfanew-lt-64', basePe = null) {
  const buf = basePe instanceof Uint8Array
    ? new Uint8Array(basePe)
    : buildCustomPe64Exe({ message: 'BasePE\n', exitCode: 0 });
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const eLfanew = view.getUint32(0x3c, true);

  switch (variant) {
    case 'lfanew-lt-64':
      view.setUint32(0x3c, 32, true);
      return buf;
    case 'lfanew-past-eof':
      view.setUint32(0x3c, 0x7ffffff0, true);
      return buf;
    case 'too-many-sections':
      view.setUint16(eLfanew + 6, 97, true);
      return buf;
    case 'bad-rva-count':
      // PE32+ Optional Header NumberOfRvaAndSizes is at e_lfanew + 24 + 108
      view.setUint32(eLfanew + 24 + 108, 99, true);
      return buf;
    case 'bad-pe-magic':
      buf.set(textEncoder.encode('BAD!'), eLfanew);
      return buf;
    default:
      throw new Error(`Unknown malformed PE variant "${variant}"`);
  }
}

// ============================================================================
// #13: PE .bss (VirtualSize > SizeOfRawData) & Padded Section (RawSize > VirtualSize)
// ============================================================================

export function buildPeSectionSizingEdgeExe() {
  return buildCustomPe64Exe({
    textVirtualSize: 0x100, // RawSize = 0x200 > VirtualSize = 0x100
    addBssSection: true,
    bssVirtualSize: 0x2000, // VirtualSize = 0x2000 > RawSize = 0
    customCodeBytes: ({ textRva, bssRva, iat, code, curRva, emit }) => {
      const targetRva = bssRva + 0x1500;
      const exitIat = iat.get('ExitProcess');

      const movzxEaxRip = (rva) => {
        const disp = rva - (curRva() + 7);
        return [0x0f, 0xb6, 0x05, disp & 0xff, (disp >>> 8) & 0xff, (disp >>> 16) & 0xff, (disp >>> 24) & 0xff];
      };
      const movByteRipImm8 = (rva, imm8) => {
        const disp = rva - (curRva() + 7);
        return [0xc6, 0x05, disp & 0xff, (disp >>> 8) & 0xff, (disp >>> 16) & 0xff, (disp >>> 24) & 0xff, imm8 & 0xff];
      };

      emit(X64.subRspImm8(0x28));

      // Verify .bss+0x1500 is zero-initialized
      emit(movzxEaxRip(targetRva));
      emit([0x85, 0xc0]); // test eax, eax
      const jneFail1Off = code.pos;
      emit([0x75, 0x00]); // jne fail1 (patched)

      // Write 0x5A into .bss+0x1500 and read back
      emit(movByteRipImm8(targetRva, 0x5a));
      emit(movzxEaxRip(targetRva));
      emit([0x83, 0xf8, 0x5a]); // cmp eax, 0x5A
      const jneFail2Off = code.pos;
      emit([0x75, 0x00]); // jne fail2 (patched)

      // Success: exit(0)
      emit(X64.xorEcxEcx());
      const jmpExit0Off = code.pos;
      emit([0xeb, 0x00]); // jmp do_exit

      // fail1: exit(1)
      const fail1Pos = code.pos;
      emit(X64.movEcxImm32(1));
      const jmpExit1Off = code.pos;
      emit([0xeb, 0x00]); // jmp do_exit

      // fail2: exit(2)
      const fail2Pos = code.pos;
      emit(X64.movEcxImm32(2));

      // do_exit:
      const doExitPos = code.pos;
      emit(X64.callRipIat(curRva(), exitIat));
      emit(X64.addRspImm8(0x28));
      emit(X64.ret());

      code.patchU8(jneFail1Off + 1, (fail1Pos - (jneFail1Off + 2)) & 0xff);
      code.patchU8(jneFail2Off + 1, (fail2Pos - (jneFail2Off + 2)) & 0xff);
      code.patchU8(jmpExit0Off + 1, (doExitPos - (jmpExit0Off + 2)) & 0xff);
      code.patchU8(jmpExit1Off + 1, (doExitPos - (jmpExit1Off + 2)) & 0xff);

      // Ensure textRva referenced cleanly
      void textRva;
    },
  });
}

// ============================================================================
// #14: PE OriginalFirstThunk == 0 IAT Fallback (positive)
// ============================================================================

export function buildPeZeroOftExe({ message = 'OFT_ZERO_OK\n', exitCode = 0 } = {}) {
  return buildCustomPe64Exe({
    message,
    exitCode,
    useOriginalFirstThunkZero: true,
  });
}

// ============================================================================
// #15: PE CERTIFICATE_TABLE Raw File Offset Rule (positive)
// ============================================================================

export function buildPeWithCertificateTableExe({ message = 'CERT_RAW_OFF_OK\n', exitCode = 0 } = {}) {
  return buildCustomPe64Exe({
    message,
    exitCode,
    addCertTableRawOffset: true,
  });
}

// ============================================================================
// #16: x86-64 32-Bit Zero-Extension vs 16/8-Bit Preservation (positive)
// ============================================================================

export function buildPeX64RegisterWidthTestExe() {
  const movabsRdx = (imm64) => {
    const bi = BigInt.asUintN(64, BigInt(imm64));
    const bytes = [0x48, 0xba];
    for (let i = 0; i < 8; i++) bytes.push(Number((bi >> BigInt(i * 8)) & 0xffn));
    return bytes;
  };

  return buildCustomPe64Exe({
    customCodeBytes: ({ iat, code, curRva, emit }) => {
      const exitIat = iat.get('ExitProcess');

      emit(X64.subRspImm8(0x28));

      // 1. 8-bit write (mov al, 0x99) MUST preserve upper 56 bits
      emit(X64.movabsRaxImm64(0x1122334455667788n));
      emit(X64.movAlImm8(0x99));
      emit(movabsRdx(0x1122334455667799n));
      emit([0x48, 0x39, 0xd0]); // cmp rax, rdx
      const jne1 = code.pos;
      emit([0x75, 0x00]); // jne fail1

      // 2. 16-bit write (mov ax, 0xAABB) MUST preserve upper 48 bits
      emit(X64.movAxImm16(0xaabb));
      emit(movabsRdx(0x112233445566aabbn));
      emit([0x48, 0x39, 0xd0]); // cmp rax, rdx
      const jne2 = code.pos;
      emit([0x75, 0x00]); // jne fail2

      // 3. 32-bit write (mov eax, 0x12345678) MUST zero upper 32 bits!
      emit(X64.movEaxImm32(0x12345678));
      emit(movabsRdx(0x0000000012345678n));
      emit([0x48, 0x39, 0xd0]); // cmp rax, rdx
      const jne3 = code.pos;
      emit([0x75, 0x00]); // jne fail3

      // All passed -> exit(0)
      emit(X64.xorEcxEcx());
      const jmp0 = code.pos;
      emit([0xeb, 0x00]);

      const fail1Pos = code.pos;
      emit(X64.movEcxImm32(1));
      const jmp1 = code.pos;
      emit([0xeb, 0x00]);

      const fail2Pos = code.pos;
      emit(X64.movEcxImm32(2));
      const jmp2 = code.pos;
      emit([0xeb, 0x00]);

      const fail3Pos = code.pos;
      emit(X64.movEcxImm32(3));

      const doExitPos = code.pos;
      emit(X64.callRipIat(curRva(), exitIat));
      emit(X64.addRspImm8(0x28));
      emit(X64.ret());

      code.patchU8(jne1 + 1, (fail1Pos - (jne1 + 2)) & 0xff);
      code.patchU8(jne2 + 1, (fail2Pos - (jne2 + 2)) & 0xff);
      code.patchU8(jne3 + 1, (fail3Pos - (jne3 + 2)) & 0xff);
      code.patchU8(jmp0 + 1, (doExitPos - (jmp0 + 2)) & 0xff);
      code.patchU8(jmp1 + 1, (doExitPos - (jmp1 + 2)) & 0xff);
      code.patchU8(jmp2 + 1, (doExitPos - (jmp2 + 2)) & 0xff);
    },
  });
}

// ============================================================================
// #17: x86-64 RIP-Relative Addressing (next-RIP calculation) (positive)
// ============================================================================

export function buildPeRipRelativeTestExe({ message = 'RIP_REL_NEXT_IP_OK\n', exitCode = 0 } = {}) {
  return buildCustomPe64Exe({ message, exitCode });
}

// ============================================================================
// #18: .bat vs .cmd ERRORLEVEL Semantics (positive)
// ============================================================================

export function buildBatVsCmdErrorlevelScripts({ failCode = 7 } = {}) {
  const script = buildErrorlevelSemanticsScript({ failCode });
  return {
    script,
    batFilename: 'errorlevel-check.bat',
    cmdFilename: 'errorlevel-check.cmd',
    expectedBatExitCode: failCode,
    expectedCmdExitCode: 0,
  };
}

// ============================================================================
// #19: Java .class (0xCAFEBABE 00000034) — Must NOT be misidentified as Mach-O Fat
// ============================================================================

export function buildJavaClassBytes() {
  return Uint8Array.from([
    0xca, 0xfe, 0xba, 0xbe, // Java class magic (NOT Mach-O Fat: nfat_arch = 52 > 32)
    0x00, 0x00, 0x00, 0x34, // minor=0, major=52 (Java 8)
    0x00, 0x03, // constant_pool_count = 3
    0x01, 0x00, 0x04, 0x54, 0x65, 0x73, 0x74, // UTF8 "Test"
    0x07, 0x00, 0x01, // Class #1
    0x00, 0x21, // access_flags
    0x00, 0x02, // this_class
    0x00, 0x00, // super_class
    0x00, 0x00, // interfaces_count
    0x00, 0x00, // fields_count
    0x00, 0x00, // methods_count
    0x00, 0x00, // attributes_count
  ]);
}

// ============================================================================
// #20: FairPlay Encrypted Mach-O / IPA (LC_ENCRYPTION_INFO_64.cryptid == 1)
// ============================================================================

export function buildFairPlayEncryptedMachO() {
  return buildMachO64({
    arch: 'arm64',
    platform: 2,
    cryptid: 1,
    message: 'FairPlayEncrypted\n',
  });
}

export function buildFairPlayEncryptedIpa() {
  return buildCustomIpa({
    bundleId: 'com.omnios.ios.fairplay',
    displayName: 'FairPlayLocked',
    executableName: 'FairPlayLocked',
    cryptid: 1,
  });
}

// ============================================================================
// #21: ARM64 __PAGEZERO Dereference (movz x1, #0x100; ldr x0, [x1] — NEVER [x31]!)
// ============================================================================

export function buildPageZeroDerefMachO({ addr = 0x100 } = {}) {
  const codeBytes = packArm64Insns([
    arm64Movz(1, addr & 0xffff), // movz x1, #0x100 (NEVER use x31, which is SP!)
    arm64Ldr64(0, 1, 0), // ldr x0, [x1] -> MUST fault SIGSEGV in __PAGEZERO!
    arm64Movz(0, 0),
    arm64Movz(16, 1), // SYS_exit (unreachable)
    ARM64_SVC_80,
  ]);
  return buildMachO64({
    arch: 'arm64',
    platform: 2,
    includePageZero: true,
    codeBytes,
  });
}

// ============================================================================
// #22: Mach-O LC_MAIN Non-Zero entryoff (__TEXT.vmaddr + slide + entryoff)
// ============================================================================

export function buildNonZeroEntryOffMachO({
  entryOffset = 0x1200,
  message = 'ENTRYOFF_OK\n',
  exitCode = 0,
} = {}) {
  const textOffset = 0x1000;
  if (entryOffset < textOffset + 12 || (entryOffset % 4) !== 0) {
    throw new RangeError(`entryOffset must be 4-byte aligned and >= 0x100C, got ${entryOffset}`);
  }
  const msgBytes = textEncoder.encode(String(message));
  const cstringBytes = concatBytes(msgBytes, [0]);
  const realCodeLen = 8 * 4; // 32 bytes
  const totalCodeLen = (entryOffset - textOffset) + realCodeLen;
  const cstringOff = alignUp(textOffset + totalCodeLen, 16);

  const insns = [];
  // Fail trap at __text start (0x1000): exits 99 if loader ignores LC_MAIN.entryoff!
  insns.push(arm64Movz(0, 99), arm64Movz(16, 1), ARM64_SVC_80);
  const padCount = ((entryOffset - textOffset) / 4) - insns.length;
  for (let i = 0; i < padCount; i++) insns.push(ARM64_NOP);

  // Real entrypoint at entryOffset:
  insns.push(
    arm64Adr(1, cstringOff - entryOffset),
    arm64Movz(0, 1),
    arm64Movz(2, msgBytes.length & 0xffff),
    arm64Movz(16, 4), // SYS_write
    ARM64_SVC_80,
    arm64Movz(0, exitCode & 0xffff),
    arm64Movz(16, 1), // SYS_exit
    ARM64_SVC_80
  );

  return buildMachO64({
    arch: 'arm64',
    platform: 1,
    textOffset,
    entryOffset,
    codeBytes: packArm64Insns(insns),
    cstringBytes,
  });
}

// ============================================================================
// #23: ARM64 Register 31 SP vs XZR Semantics (positive)
// ============================================================================

export function buildArm64Reg31TestMachO() {
  const insns = [
    arm64SubImm(31, 31, 16), // [0] sub sp, sp, #16
    arm64AddImm(1, 31, 0), // [1] add x1, sp, #0  (Rn=31 is SP -> non-zero)
    arm64Cbz(1, (14 - 2) * 4), // [2] cbz x1, fail11
    arm64Movz(31, 0x1234), // [3] movz xzr, #0x1234 (writes discarded)
    arm64AddReg(2, 31, 31), // [4] add x2, xzr, xzr  (Rn=Rm=31 are XZR -> 0)
    arm64Cbnz(2, (17 - 5) * 4), // [5] cbnz x2, fail12
    arm64SubsImm(31, 31, 0), // [6] subs xzr, sp, #0 (Rd=XZR, Rn=SP; SP unchanged!)
    arm64AddImm(3, 31, 0), // [7] add x3, sp, #0
    arm64SubReg(3, 3, 1), // [8] sub x3, x3, x1
    arm64Cbnz(3, (20 - 9) * 4), // [9] cbnz x3, fail13
    arm64AddImm(31, 31, 16), // [10] add sp, sp, #16
    arm64Movz(0, 0), // [11] exit(0)
    arm64Movz(16, 1), // [12]
    ARM64_SVC_80, // [13]
    // fail11 [14]:
    arm64Movz(0, 11),
    arm64Movz(16, 1),
    ARM64_SVC_80,
    // fail12 [17]:
    arm64Movz(0, 12),
    arm64Movz(16, 1),
    ARM64_SVC_80,
    // fail13 [20]:
    arm64Movz(0, 13),
    arm64Movz(16, 1),
    ARM64_SVC_80,
  ];
  return buildMachO64({
    arch: 'arm64',
    platform: 2,
    codeBytes: packArm64Insns(insns),
  });
}

// ============================================================================
// #24: Apple ARM64 Variadic Arguments on 8-Byte Stack Slots (positive)
// ============================================================================

export function buildArm64VariadicStackArgsMachO({ value1 = 42, value2 = 99 } = {}) {
  const cstringBytes = textEncoder.encode('V=%d,%d\n\0');
  const dummyCode = new Uint8Array(16 * 4);
  const commonOpts = {
    arch: 'arm64',
    platform: 1,
    dylibs: ['/usr/lib/libSystem.B.dylib'],
    gotSymbols: [{ name: '_printf', dylibOrdinal: 1 }],
    cstringBytes,
  };

  // Pass 1: discover exact cstringOff and gotVmAddr
  const { layout } = buildMachO64WithLayout({ ...commonOpts, codeBytes: dummyCode });

  const textBase = layout.textBase;
  const textOff = layout.textOff;
  const adrPcOff = textOff + 7 * 4;
  const adrpPcVa = textBase + BigInt(textOff + 8 * 4);
  const gotPageOff = Number(layout.gotVmAddr & 0xfffn);

  // Pass 2: assemble exact 16 instructions using 4 KiB ADRP page mask + poisoned X1/X2
  const insns = [
    arm64SubImm(31, 31, 16), // [0] sub sp, sp, #16
    arm64Movz(9, value1 & 0xffff), // [1] movz x9, #value1
    arm64Str64(9, 31, 0), // [2] str x9, [sp, #0]
    arm64Movz(10, value2 & 0xffff), // [3] movz x10, #value2
    arm64Str64(10, 31, 8), // [4] str x10, [sp, #8]
    arm64Movz(1, 777), // [5] poison X1 (must NOT be read by Apple variadic ABI!)
    arm64Movz(2, 888), // [6] poison X2
    arm64Adr(0, layout.cstringOff - adrPcOff), // [7] adr x0, "V=%d,%d\n"
    arm64Adrp(16, adrpPcVa, layout.gotVmAddr), // [8] adrp x16, __got@PAGE
    arm64Ldr64(16, 16, gotPageOff), // [9] ldr x16, [x16, __got@PAGEOFF]
    arm64Blr(16), // [10] blr x16 (_printf)
    arm64AddImm(31, 31, 16), // [11] add sp, sp, #16
    arm64Movz(0, 0), // [12] exit(0)
    arm64Movz(16, 1), // [13]
    ARM64_SVC_80, // [14]
    ARM64_NOP, // [15]
  ];

  return buildMachO64({ ...commonOpts, codeBytes: packArm64Insns(insns) });
}

// ============================================================================
// #25: Darwin XNU Carry Flag Error Signaling + Positive errno (positive)
// ============================================================================

export function buildDarwinErrnoCarryMachO({ missingPath = '/nonexistent/omnios_e2e_missing_404' } = {}) {
  const textOff = 0x1000;
  const cstringBytes = concatBytes(textEncoder.encode(missingPath), [0]);
  const cstringOff = alignUp(textOff + 12 * 4, 16);

  const insns = [
    arm64Adr(0, cstringOff - textOff), // [0] path
    arm64Movz(1, 0), // [1] O_RDONLY
    arm64Movz(2, 0), // [2] mode
    arm64Movz(16, 5), // [3] SYS_open
    ARM64_SVC_80, // [4] -> MUST set PSTATE.C=1 and X0=ENOENT(2)
    arm64BCond(0x3, (9 - 5) * 4), // [5] b.cc fail_99 (branch if Carry Clear!)
    arm64Movz(16, 1), // [6] SYS_exit(X0) -> exits with positive 2!
    ARM64_SVC_80, // [7]
    ARM64_NOP, // [8]
    // fail_99 [9]:
    arm64Movz(0, 99),
    arm64Movz(16, 1),
    ARM64_SVC_80,
  ];

  return buildMachO64({
    arch: 'arm64',
    platform: 1,
    textOffset: textOff,
    codeBytes: packArm64Insns(insns),
    cstringBytes,
  });
}

// ============================================================================
// #26: Objective-C objc_msgSend(nil, sel) Returns 0 Without Faulting (positive)
// ============================================================================

export function buildObjcNilMsgSendMachO() {
  const dummyCode = new Uint8Array(9 * 4);
  const commonOpts = {
    arch: 'arm64',
    platform: 2,
    dylibs: ['/usr/lib/libSystem.B.dylib', '/usr/lib/libobjc.A.dylib'],
    gotSymbols: [{ name: '_objc_msgSend', dylibOrdinal: 2 }],
    objcSelectors: ['length'],
  };

  // Pass 1: get exact GOT VA and selector string VA
  const { layout } = buildMachO64WithLayout({ ...commonOpts, codeBytes: dummyCode });
  const textBase = layout.textBase;
  const textOff = layout.textOff;
  const selVa = layout.objcMethNameVa.get('length');
  const selAdrPcVa = textBase + BigInt(textOff + 1 * 4);
  const adrpPcVa = textBase + BigInt(textOff + 2 * 4);
  const gotPageOff = Number(layout.gotVmAddr & 0xfffn);

  // Pass 2: call _objc_msgSend(0, "length") and exit(X0)
  const insns = [
    arm64Movz(0, 0), // [0] nil receiver
    arm64Adr(1, Number(selVa - selAdrPcVa)), // [1] sel = "length"
    arm64Adrp(16, adrpPcVa, layout.gotVmAddr), // [2] adrp x16, __got@PAGE
    arm64Ldr64(16, 16, gotPageOff), // [3] ldr x16, [x16, __got@PAGEOFF]
    arm64Blr(16), // [4] blr _objc_msgSend -> returns 0 in X0
    arm64Movz(16, 1), // [5] SYS_exit(X0)
    ARM64_SVC_80, // [6]
    ARM64_NOP, // [7]
    ARM64_NOP, // [8]
  ];

  return buildMachO64({ ...commonOpts, codeBytes: packArm64Insns(insns) });
}

// ============================================================================
// #27: bplist00 Cyclic References, Signed 8B Negative Int (0x13), 2001 CF Epoch (0x33)
// ============================================================================

export function buildCyclicBplist(variant = 'self-dict') {
  const w = new BinaryWriter(64);
  w.ascii('bplist00');

  let offsets;
  if (variant === 'self-dict') {
    // Obj 0 (off 8): dict { "self"(ref 1): ref 0 }
    // Obj 1 (off 11): ASCII "self"
    offsets = [8, 11];
    w.bytes([0xd1, 0x01, 0x00]);
    w.bytes([0x54, 0x73, 0x65, 0x6c, 0x66]);
  } else if (variant === 'ab-dict') {
    // Obj 0 (off 8): dict { "b"(ref 2): ref 1 }
    // Obj 1 (off 11): dict { "a"(ref 3): ref 0 }
    // Obj 2 (off 14): "b"
    // Obj 3 (off 16): "a"
    offsets = [8, 11, 14, 16];
    w.bytes([0xd1, 0x02, 0x01]);
    w.bytes([0xd1, 0x03, 0x00]);
    w.bytes([0x51, 0x62]);
    w.bytes([0x51, 0x61]);
  } else if (variant === 'self-array') {
    // Obj 0 (off 8): array [ref 0]
    offsets = [8];
    w.bytes([0xa1, 0x00]);
  } else {
    throw new Error(`Unknown cyclic bplist variant "${variant}"`);
  }

  const offsetTableOffset = w.pos;
  for (const off of offsets) w.u8(off);

  // 32-byte BE trailer
  w.zeros(5)
    .u8(0) // sortVersion
    .u8(1) // offsetIntSize
    .u8(1) // objectRefSize
    .u64be(BigInt(offsets.length))
    .u64be(0n) // topObject
    .u64be(BigInt(offsetTableOffset));

  return w.toUint8Array();
}

export function buildCyclicBplistIpa(variant = 'self-dict') {
  const execBytes = buildMachO64({ arch: 'arm64', platform: 2, message: 'CyclicPlist\n' });
  return buildZip([
    { name: 'Payload/CyclicApp.app/Info.plist', data: buildCyclicBplist(variant), method: 8 },
    { name: 'Payload/CyclicApp.app/CyclicApp', data: execBytes, method: 8, externalAttr: 0x81ed0000 },
  ]);
}

export function buildBplistEdgeValues({ negInt64 = -1234567890123n, cfSeconds = 86400.0 } = {}) {
  const cfEpochMs = Date.UTC(2001, 0, 1, 0, 0, 0, 0);
  return buildBinaryPlist({
    negInt: BigInt(negInt64),
    cfDate: new Date(cfEpochMs + cfSeconds * 1000),
    unicode: 'OmniOS ★🚀',
  });
}

// ============================================================================
// #28: Windows Mixed-Case Lookup & Traversal / Symlink Cycle Vectors
// ============================================================================

export function getVfsEdgeCasePayloads() {
  return {
    windowsMixedCase: {
      createPath: 'C:\\Users\\user\\Documents\\CaseTest_AbC.txt',
      canonicalExpected: '/home/user/Documents/CaseTest_AbC.txt',
      preservedBasename: 'CaseTest_AbC.txt',
      lookupVariants: [
        'C:\\Users\\user\\Documents\\casetest_abc.txt',
        'c:\\users\\USER\\DOCUMENTS\\CASETEST_ABC.TXT',
        'C:/Users/user/Documents/CaSeTeSt_aBc.TxT',
      ],
    },
    traversalEscapes: [
      '../../../../etc/passwd',
      'C:\\Users\\user\\..\\..\\..\\..\\etc\\passwd',
      '/sdcard/../../../../etc/shadow',
      '/home/user/Documents/safe.txt\0../../evil.txt',
    ],
    symlinkCycles: {
      twoNode: [
        { linkPath: '/tmp/eloop_a', target: '/tmp/eloop_b' },
        { linkPath: '/tmp/eloop_b', target: '/tmp/eloop_a' },
      ],
      deepChain18: Array.from({ length: 18 }, (_, i) => ({
        linkPath: `/tmp/eloop_chain_${i}`,
        target: `/tmp/eloop_chain_${(i + 1) % 18}`,
      })),
    },
  };
}

// ============================================================================
// #29: WASI fd_write Bounds (iovs_len > 1024, OOB Pointer, Ungranted FD)
// ============================================================================

export function buildWasiInvalidIovsLenWasm() {
  return buildCustomWasm({ invalidIovsLen: 2048, returnFdWriteErrno: true });
}

export function buildWasiOobPointerWasm() {
  return buildCustomWasm({ oobPointer: 0x100000, returnFdWriteErrno: true });
}

export function buildWasiUngrantedFdWasm() {
  return buildCustomWasm({ ungrantedFd: 99, returnFdWriteErrno: true });
}

export function buildWasiEdgeUapp(variant = 'invalid-iovs-len') {
  const builders = {
    'invalid-iovs-len': buildWasiInvalidIovsLenWasm,
    'oob-pointer': buildWasiOobPointerWasm,
    'ungranted-fd': buildWasiUngrantedFdWasm,
  };
  const fn = builders[variant];
  if (!fn) {
    throw new Error(`Unknown WASI edge variant "${variant}". Expected: ${Object.keys(builders).join(', ')}`);
  }
  return buildCustomUapp({
    appId: `com.omnios.wasi.edge.${variant.replace(/-/g, '')}`,
    name: `WasiEdge_${variant}`,
    wasmBytes: fn(),
  });
}

// ============================================================================
// Bonus FA-13 Malformed Apple Containers (.dmg koly & .pkg xar!)
// ============================================================================

export function buildMalformedDmg() {
  return buildCustomDmg({ corruptKoly: true });
}

export function buildMalformedPkg() {
  return buildCustomPkg({ corruptXar: true });
}

// ============================================================================
// Master 29-Entry Edge-Case Corpus Index (1:1 with PROJECT.md)
// ============================================================================

export const MALFORMED_CORPUS_INDEX = Object.freeze({
  1: { id: 1, area: 'FA-09', title: 'ZIP-slip traversal & NUL entry names', positive: false, expected: 'E_PATH_TRAVERSAL', build: () => buildZipSlipArchive('dotdot') },
  2: { id: 2, area: 'FA-09', title: 'ZIP bomb (>100 MiB & >1000x ratio)', positive: false, expected: 'E_ARCHIVE_BOMB', build: () => buildZipBomb() },
  3: { id: 3, area: 'FA-10', title: 'APK v2/v3 Signing Block before Central Directory', positive: true, expected: 'parses cleanly via EOCD cdOffset', build: () => buildApkWithV2SigningBlock() },
  4: { id: 4, area: 'FA-09', title: 'ZIP Data Descriptor flag bit 3 (0x0008)', positive: true, expected: 'extracts via authoritative CDFH', build: () => buildZipWithDataDescriptor() },
  5: { id: 5, area: 'FA-10', title: 'AXML chunk.size==0 / <headerSize / OOB', positive: false, expected: 'E_MALFORMED_AXML', build: () => buildMalformedAxmlApk('zero-size') },
  6: { id: 6, area: 'FA-10', title: 'resources.arsc FLAG_OFFSET16 & FLAG_SPARSE', positive: true, expected: 'resolves present IDs & null on NO_ENTRY', build: () => buildResourcesArsc({ mode: 'offset16' }) },
  7: { id: 7, area: 'FA-10', title: 'DEX bad Adler-32/SHA-1/header_size/endian/type_ids>65535', positive: false, expected: 'E_INVALID_DEX_*', build: () => buildMalformedDexApk('bad-sha1') },
  8: { id: 8, area: 'FA-10', title: 'DEX MUTF-8 0xC0 0x80 & overlong >5B LEB128', positive: false, expected: 'MUTF-8 valid; >5B LEB128 rejected', build: () => buildDexOverlongLeb128() },
  9: { id: 9, area: 'FA-10', title: 'Dalvik code_item tries_size>0 & odd insns_size 2B pad', positive: true, expected: 'skips 2B pad & catches ArithmeticException', build: () => buildDexOddInsnsTryCatchApk() },
  10: { id: 10, area: 'FA-10', title: 'Dalvik div-int by 0 & INT32_MIN/-1 wrap', positive: false, expected: 'ArithmeticException on 0; wrap on INT32_MIN/-1', build: () => buildDexDivByZeroApk() },
  11: { id: 11, area: 'FA-10', title: 'Dalvik infinite loop goto 0 & deep recursion', positive: false, expected: 'E_CPU_QUOTA / StackOverflowError', build: () => buildDexInfiniteLoopApk() },
  12: { id: 12, area: 'FA-11', title: 'PE bad e_lfanew / NumberOfSections>96 / RvaCount>16', positive: false, expected: 'E_INVALID_PE', build: () => buildMalformedPe('too-many-sections') },
  13: { id: 13, area: 'FA-11', title: 'PE .bss (VSize>Raw) & padded (Raw>VSize)', positive: true, expected: 'zero-fills .bss & exits 0', build: () => buildPeSectionSizingEdgeExe() },
  14: { id: 14, area: 'FA-11', title: 'PE OriginalFirstThunk == 0 IAT fallback', positive: true, expected: 'falls back to FirstThunk & exits 0', build: () => buildPeZeroOftExe() },
  15: { id: 15, area: 'FA-11', title: 'PE CERTIFICATE_TABLE raw file offset rule', positive: true, expected: 'treats Dir[4] as raw offset & exits 0', build: () => buildPeWithCertificateTableExe() },
  16: { id: 16, area: 'FA-11', title: 'x86-64 32-bit zero-ext vs 16/8-bit preserve', positive: true, expected: 'exits 0 on exact register width semantics', build: () => buildPeX64RegisterWidthTestExe() },
  17: { id: 17, area: 'FA-11', title: 'x86-64 RIP-relative next-RIP addressing', positive: true, expected: 'prints exact string & exits 0', build: () => buildPeRipRelativeTestExe() },
  18: { id: 18, area: 'FA-11', title: '.bat vs .cmd ERRORLEVEL after successful SET', positive: true, expected: '.bat preserves 7; .cmd resets to 0', build: () => buildBatVsCmdErrorlevelScripts() },
  19: { id: 19, area: 'FA-09', title: 'Java .class 0xCAFEBABE not Mach-O Fat', positive: false, expected: 'not detected as macos-macho', build: () => buildJavaClassBytes() },
  20: { id: 20, area: 'FA-12', title: 'FairPlay DRM LC_ENCRYPTION_INFO_64 cryptid=1', positive: false, expected: 'E_ENCRYPTED_BINARY', build: () => buildFairPlayEncryptedIpa() },
  21: { id: 21, area: 'FA-12', title: 'ARM64 __PAGEZERO dereference fault', positive: false, expected: 'SIGSEGV without 4GiB RAM alloc', build: () => buildPageZeroDerefMachO() },
  22: { id: 22, area: 'FA-12', title: 'Mach-O LC_MAIN non-zero entryoff', positive: true, expected: 'enters at __TEXT.vmaddr+slide+entryoff', build: () => buildNonZeroEntryOffMachO() },
  23: { id: 23, area: 'FA-12', title: 'ARM64 reg-31 SP vs XZR semantics', positive: true, expected: 'exits 0 on exact SP/XZR decoding', build: () => buildArm64Reg31TestMachO() },
  24: { id: 24, area: 'FA-12', title: 'Apple ARM64 variadic 8B stack slots', positive: true, expected: 'prints V=42,99 (ignoring poisoned X1/X2)', build: () => buildArm64VariadicStackArgsMachO() },
  25: { id: 25, area: 'FA-12', title: 'Darwin XNU Carry flag + positive errno', positive: true, expected: 'exits with positive 2 (ENOENT)', build: () => buildDarwinErrnoCarryMachO() },
  26: { id: 26, area: 'FA-12', title: 'Objective-C objc_msgSend(nil, sel) returns 0', positive: true, expected: 'returns 0 without faulting', build: () => buildObjcNilMsgSendMachO() },
  27: { id: 27, area: 'FA-12', title: 'bplist00 cyclic / 0x13 signed neg / 0x33 CF epoch', positive: false, expected: 'E_CYCLIC_PLIST & exact 0x13/0x33 decoding', build: () => buildCyclicBplistIpa() },
  28: { id: 28, area: 'FA-04', title: 'Windows VFS mixed-case preservation & traversal/ELOOP', positive: true, expected: 'preserves creation case & blocks escape/ELOOP', build: () => getVfsEdgeCasePayloads() },
  29: { id: 29, area: 'FA-13', title: 'WASI fd_write iovs_len>1024 / OOB / ungranted fd', positive: false, expected: 'WASI_EINVAL / WASI_EFAULT / WASI_ENOTCAPABLE', build: () => buildWasiEdgeUapp('invalid-iovs-len') },
});
