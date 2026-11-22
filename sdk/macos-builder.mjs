/**
 * OmniOS Pure-JS macOS SDK Builder & Sample App Packager (`F-058`)
 * Zero external dependencies — emits genuine externally verifiable:
 *  - ARM64 Mach-O 64 (`buildMachOArm64Mac`)
 *  - x86-64 Mach-O 64 (`buildMachOX86_64Mac`)
 *  - Universal Fat Mach-O (`0xCAFEBABE`, `nfat_arch = 2`: ARM64 + x86-64) (`buildUniversalFatMachO`)
 *  - macOS `.app.zip` bundles (`buildMacAppZip`) with XML or `bplist00` `Info.plist`
 *  - Synthetic UDIF `.dmg` (`koly` + XML `blkx`/`mish`) images (`buildTestDmg`)
 *  - Synthetic Flat Installer `.pkg` (XAR `xar!` + zlib TOC + gzipped CPIO Payload) (`buildTestPkg`)
 *  - Default sample package `packages/macos-studio.app.zip` (`buildMacStudioSample`)
 *
 * Every emitted binary is 100% spec-driven (zero hardcoded app names or test results) and
 * externally verifiable via `llvm-objdump --macho --universal-headers --private-headers`
 * and Python 3 `zipfile` + `plistlib`.
 */

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createZip } from '../os/pkg/zip.mjs';
import { writeXmlPlist, writeBinaryPlist } from '../os/runtimes/apple/plist-parser.mjs';
import { MACHO_CONSTANTS } from '../os/runtimes/apple/macho-parser.mjs';

const TEXT_ENCODER = new TextEncoder();
const PAGE_ALIGN = 0x4000; // 16 KiB Apple Silicon / Universal page alignment
const TEXT_VMADDR_BASE = 0x100000000n;
const DETERMINISTIC_MTIME = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));

function alignUp(val, align) {
  const rem = val % align;
  return rem === 0 ? val : val + (align - rem);
}

function encodeUleb128(value) {
  let v = typeof value === 'bigint' ? value : BigInt(value);
  const out = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) byte |= 0x80;
    out.push(byte);
  } while (v !== 0n);
  return out;
}

function writeFixedStr(buf, offset, str, maxLen) {
  const enc = TEXT_ENCODER.encode(str);
  const len = Math.min(enc.byteLength, maxLen);
  buf.set(enc.subarray(0, len), offset);
}

// ============================================================================
// Spec Normalization (100% Dynamic — Supports Arbitrary Runtime Nonces & Menus)
// ============================================================================

function normalizeMacSpec(spec = {}) {
  if (spec && spec._normalized === true) return spec;
  const appName = String(spec.appName ?? 'OmniStudio');
  const executableName = String(
    spec.executableName ?? (appName.replace(/[^A-Za-z0-9._-]+/g, '') || 'OmniStudio')
  );
  const bundleId = String(spec.bundleId ?? 'com.omnios.macos.studio');
  const version = String(spec.version ?? '1.0.0');
  const buildNumber = String(spec.buildNumber ?? '100');
  const nonce = spec.nonce !== undefined && spec.nonce !== null ? String(spec.nonce) : '';
  const delegateClassName = String(spec.delegateClassName ?? 'StudioAppDelegate');
  const title = String(spec.title ?? (nonce ? `${appName} [${nonce}]` : `${appName} — macOS Studio`));
  const initialText = String(
    spec.initialText ?? (nonce ? `${appName} Ready (${nonce})` : `${appName} Ready — Universal macOS Workspace`)
  );
  const buttonTitle = String(spec.buttonTitle ?? 'Copy & Sync');
  const documentFile = String(spec.documentFile ?? '/Users/user/Documents/omnistudio-note.txt');
  const documentContent = String(
    spec.documentContent ?? (nonce ? `OmniOS Studio Note [${nonce}]` : `Hello from ${appName} on OmniOS macOS!`)
  );
  const defaultsKey = spec.defaultsKey !== undefined ? String(spec.defaultsKey) : 'studio.lastLaunch';
  const defaultsValue =
    spec.defaultsValue !== undefined
      ? String(spec.defaultsValue)
      : (nonce ? `launched-${nonce}` : `${appName}-${version}`);
  const pasteboardText =
    spec.pasteboardText !== undefined && spec.pasteboardText !== null
      ? String(spec.pasteboardText)
      : null;
  const writeDocumentOnLaunch = Boolean(spec.writeDocumentOnLaunch);
  const category = String(spec.category ?? 'public.app-category.developer-tools');
  const description = String(
    spec.description ?? `${appName} — Native Universal macOS AppKit Workspace`
  );
  const urlSchemes = Array.isArray(spec.urlSchemes) ? spec.urlSchemes.map(String) : ['omnistudio'];
  const documentTypes = Array.isArray(spec.documentTypes)
    ? spec.documentTypes
    : [
        {
          name: 'Plain Text Document',
          role: 'Editor',
          extensions: ['txt', 'md'],
          mimeTypes: ['text/plain', 'text/markdown'],
          contentTypes: ['public.plain-text', 'net.daringfireball.markdown'],
        },
      ];

  const entitlements =
    spec.entitlements !== undefined
      ? spec.entitlements
      : {
          'com.apple.security.app-sandbox': true,
          'com.apple.security.files.user-selected.read-write': true,
          'com.apple.security.clipboard.read': true,
          'com.apple.security.clipboard.write': true,
          'com.apple.security.network.client': true,
        };

  // Build menu bar groups (standard macOS App + File + Edit + any custom spec.menuItems)
  const appMenu = {
    label: appName,
    items: [
      { label: `About ${appName}`, selector: 'onAbout:', keyEquivalent: '' },
      { separator: true },
      { label: `Quit ${appName}`, selector: 'terminate:', keyEquivalent: 'q' },
    ],
  };
  const fileMenu = {
    label: 'File',
    items: [
      { label: 'New Document', selector: 'onNewDocument:', keyEquivalent: 'n' },
      { label: 'Save to Documents', selector: 'onSaveDocument:', keyEquivalent: 's' },
    ],
  };
  const editMenu = {
    label: 'Edit',
    items: [
      { label: 'Copy', selector: 'onCopy:', keyEquivalent: 'c' },
      { label: 'Paste', selector: 'onPaste:', keyEquivalent: 'v' },
    ],
  };

  const menus = [appMenu, fileMenu, editMenu];
  const customActions = [];

  if (Array.isArray(spec.menuItems)) {
    for (let i = 0; i < spec.menuItems.length; i++) {
      const mi = spec.menuItems[i];
      if (!mi || typeof mi !== 'object') continue;
      const targetMenuLabel = String(mi.menu ?? 'File');
      let grp = menus.find((m) => m.label.toLowerCase() === targetMenuLabel.toLowerCase());
      if (!grp) {
        grp = { label: targetMenuLabel, items: [] };
        menus.push(grp);
      }
      if (mi.separator) {
        grp.items.push({ separator: true });
        continue;
      }
      const rawSel = String(mi.selector ?? mi.action ?? `onCustomAction${i}:`);
      const sel = rawSel.endsWith(':') ? rawSel : `${rawSel}:`;
      const label = String(mi.label ?? `Action ${i + 1}`);
      const keyEquivalent = String(mi.keyEquivalent ?? mi.shortcut ?? '');
      grp.items.push({ label, selector: sel, keyEquivalent });

      const builtInSels = new Set([
        'onAbout:',
        'terminate:',
        'onNewDocument:',
        'onSaveDocument:',
        'onCopy:',
        'onPaste:',
        'onActionClick:',
      ]);
      if (!builtInSels.has(sel)) {
        customActions.push({
          selector: sel,
          statusText: String(mi.statusText ?? `${label}${nonce ? ` [${nonce}]` : ''}`),
          windowTitle: mi.windowTitle ? String(mi.windowTitle) : null,
          copyText: mi.copyText ? String(mi.copyText) : null,
        });
      }
    }
  }

  return {
    appName,
    executableName,
    bundleId,
    version,
    buildNumber,
    nonce,
    delegateClassName,
    title,
    initialText,
    buttonTitle,
    documentFile,
    documentContent,
    defaultsKey,
    defaultsValue,
    pasteboardText,
    writeDocumentOnLaunch,
    category,
    description,
    urlSchemes,
    documentTypes,
    entitlements,
    menus,
    customActions,
    universal: spec.universal !== false,
    arch: spec.arch ?? 'arm64',
    plistFormat: spec.plistFormat ?? 'xml',
    _normalized: true,
  };
}

// ============================================================================
// Portable ARM64 & x86-64 Code Emitter Abstraction (2-Pass PIC)
// ============================================================================

class Arm64CodeGen {
  constructor() {
    this.insns = [];
    this.relocs = []; // { insnIdx, kind: 'adrp_add'|'adrp_ldr'|'adrp_str', targetName }
  }

  get byteOffset() {
    return this.insns.length * 4;
  }

  emit(u32) {
    this.insns.push(u32 >>> 0);
  }

  movReg(rd, rm) {
    this.emit(0xaa0003e0 | ((rm & 31) << 16) | (rd & 31));
  }

  movImm16(rd, imm16) {
    this.emit(0xd2800000 | ((imm16 & 0xffff) << 5) | (rd & 31));
  }

  // Standard Apple ARM64 frame: [SP+0..31] outgoing variadic args, [SP+32..95] X19..X26, [SP+96..111] X29/X30
  prologue() {
    this.emit(0xd101c3ff); // SUB SP, SP, #112
    this.emit(0xa9000000 | ((4 << 15) | (20 << 10) | (31 << 5) | 19)); // STP X19, X20, [SP, #32]
    this.emit(0xa9000000 | ((6 << 15) | (22 << 10) | (31 << 5) | 21)); // STP X21, X22, [SP, #48]
    this.emit(0xa9000000 | ((8 << 15) | (24 << 10) | (31 << 5) | 23)); // STP X23, X24, [SP, #64]
    this.emit(0xa9000000 | ((10 << 15) | (26 << 10) | (31 << 5) | 25)); // STP X25, X26, [SP, #80]
    this.emit(0xa9000000 | ((12 << 15) | (30 << 10) | (31 << 5) | 29)); // STP X29, X30, [SP, #96]
    this.emit(0x910183fd); // ADD X29, SP, #96
  }

  epilogue() {
    this.emit(0xa9400000 | ((12 << 15) | (30 << 10) | (31 << 5) | 29)); // LDP X29, X30, [SP, #96]
    this.emit(0xa9400000 | ((10 << 15) | (26 << 10) | (31 << 5) | 25)); // LDP X25, X26, [SP, #80]
    this.emit(0xa9400000 | ((8 << 15) | (24 << 10) | (31 << 5) | 23)); // LDP X23, X24, [SP, #64]
    this.emit(0xa9400000 | ((6 << 15) | (22 << 10) | (31 << 5) | 21)); // LDP X21, X22, [SP, #48]
    this.emit(0xa9400000 | ((4 << 15) | (20 << 10) | (31 << 5) | 19)); // LDP X19, X20, [SP, #32]
    this.emit(0x9101c3ff); // ADD SP, SP, #112
    this.emit(0xd65f03c0); // RET
  }

  loadAddr(rd, targetName) {
    const idx = this.insns.length;
    this.emit(0x90000000 | (rd & 31)); // ADRP placeholder
    this.emit(0x91000000 | ((rd & 31) << 5) | (rd & 31)); // ADD placeholder
    this.relocs.push({ insnIdx: idx, kind: 'adrp_add', rd, targetName });
  }

  loadPtr(rd, targetName) {
    const idx = this.insns.length;
    this.emit(0x90000000 | (rd & 31)); // ADRP placeholder
    this.emit(0xf9400000 | ((rd & 31) << 5) | (rd & 31)); // LDR placeholder
    this.relocs.push({ insnIdx: idx, kind: 'adrp_ldr', rd, targetName });
  }

  storePtr(rt, targetName, scratchReg = 17) {
    const idx = this.insns.length;
    this.emit(0x90000000 | (scratchReg & 31)); // ADRP Xscratch, target@PAGE
    this.emit(0xf9000000 | ((scratchReg & 31) << 5) | (rt & 31)); // STR Xt, [Xscratch, target@PAGEOFF]
    this.relocs.push({ insnIdx: idx, kind: 'adrp_str', rd: scratchReg, rt, targetName });
  }

  callGot(gotName) {
    this.loadPtr(16, gotName);
    this.emit(0xd63f0000 | (16 << 5)); // BLR X16
  }

  storeStackArg(rt, slotIndex) {
    const imm12 = slotIndex & 0xfff; // 8-byte scaled
    this.emit(0xf9000000 | (imm12 << 10) | (31 << 5) | (rt & 31)); // STR Xt, [SP, #(slotIndex*8)]
  }

  patch(textBaseVA, symbolVAs) {
    const bytes = new Uint8Array(this.insns.length * 4);
    const dv = new DataView(bytes.buffer);
    for (const rel of this.relocs) {
      const targetVA = symbolVAs.get(rel.targetName);
      if (targetVA === undefined) {
        throw new Error(`Unresolved ARM64 relocation target: ${rel.targetName}`);
      }
      const pcVA = textBaseVA + BigInt(rel.insnIdx * 4);
      const deltaPages = ((targetVA & ~0xfffn) - (pcVA & ~0xfffn)) >> 12n;
      const immlo = Number(deltaPages & 3n);
      const immhi = Number((deltaPages >> 2n) & 0x7ffffn);
      const pageOff = Number(targetVA & 0xfffn);

      this.insns[rel.insnIdx] = (0x90000000 | (immlo << 29) | (immhi << 5) | (rel.rd & 31)) >>> 0;
      if (rel.kind === 'adrp_add') {
        this.insns[rel.insnIdx + 1] = (0x91000000 | ((pageOff & 0xfff) << 10) | ((rel.rd & 31) << 5) | (rel.rd & 31)) >>> 0;
      } else if (rel.kind === 'adrp_ldr') {
        this.insns[rel.insnIdx + 1] =
          (0xf9400000 | (((pageOff >>> 3) & 0xfff) << 10) | ((rel.rd & 31) << 5) | (rel.rd & 31)) >>> 0;
      } else if (rel.kind === 'adrp_str') {
        this.insns[rel.insnIdx + 1] =
          (0xf9000000 | (((pageOff >>> 3) & 0xfff) << 10) | ((rel.rd & 31) << 5) | (rel.rt & 31)) >>> 0;
      }
    }
    for (let i = 0; i < this.insns.length; i++) {
      dv.setUint32(i * 4, this.insns[i], true);
    }
    return bytes;
  }
}

// x86-64 GPR indices: RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7, R8..R15=8..15
const X64_ARG_REGS = [7, 6, 2, 1, 8, 9]; // RDI, RSI, RDX, RCX, R8, R9
const X64_CALLEE_SAVED = [3, 12, 13, 14, 15]; // RBX, R12, R13, R14, R15

class X64CodeGen {
  constructor() {
    this.bytes = [];
    this.relocs = []; // { dispOffset, nextRipOffset, targetName }
  }

  get byteOffset() {
    return this.bytes.length;
  }

  emit(...vals) {
    for (const b of vals) this.bytes.push(b & 0xff);
  }

  emitI32(val) {
    const v = val | 0;
    this.bytes.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
  }

  pushReg(r) {
    if (r >= 8) this.emit(0x41, 0x50 + (r - 8));
    else this.emit(0x50 + r);
  }

  popReg(r) {
    if (r >= 8) this.emit(0x41, 0x58 + (r - 8));
    else this.emit(0x58 + r);
  }

  prologue() {
    // On entry RSP % 16 === 8. Push RBP + 5 callee-saved regs (6 pushes = 48B -> RSP % 16 === 8) + SUB RSP, 40 (5*8 -> RSP % 16 === 0)
    this.pushReg(5); // RBP
    this.emit(0x48, 0x89, 0xe5); // MOV RBP, RSP
    for (const r of X64_CALLEE_SAVED) this.pushReg(r);
    this.emit(0x48, 0x83, 0xec, 40); // SUB RSP, 40 -> 16B aligned
  }

  epilogue() {
    this.emit(0x48, 0x83, 0xc4, 40); // ADD RSP, 40
    for (let i = X64_CALLEE_SAVED.length - 1; i >= 0; i--) this.popReg(X64_CALLEE_SAVED[i]);
    this.popReg(5); // RBP
    this.emit(0xc3); // RET
  }

  movReg(dst, src) {
    const rex = 0x48 | (src >= 8 ? 4 : 0) | (dst >= 8 ? 1 : 0);
    this.emit(rex, 0x89, 0xc0 | ((src & 7) << 3) | (dst & 7));
  }

  movImm32(dst, imm) {
    const rex = 0x48 | (dst >= 8 ? 1 : 0);
    this.emit(rex, 0xc7, 0xc0 | (dst & 7));
    this.emitI32(imm);
  }

  leaRip(dst, targetName) {
    const rex = 0x48 | (dst >= 8 ? 4 : 0);
    this.emit(rex, 0x8d, ((dst & 7) << 3) | 0x05);
    const dispOffset = this.bytes.length;
    this.emitI32(0);
    this.relocs.push({ dispOffset, nextRipOffset: this.bytes.length, targetName });
  }

  loadPtr(dst, targetName) {
    const rex = 0x48 | (dst >= 8 ? 4 : 0);
    this.emit(rex, 0x8b, ((dst & 7) << 3) | 0x05);
    const dispOffset = this.bytes.length;
    this.emitI32(0);
    this.relocs.push({ dispOffset, nextRipOffset: this.bytes.length, targetName });
  }

  storePtr(src, targetName) {
    const rex = 0x48 | (src >= 8 ? 4 : 0);
    this.emit(rex, 0x89, ((src & 7) << 3) | 0x05);
    const dispOffset = this.bytes.length;
    this.emitI32(0);
    this.relocs.push({ dispOffset, nextRipOffset: this.bytes.length, targetName });
  }

  callGot(gotName) {
    this.emit(0xff, 0x15);
    const dispOffset = this.bytes.length;
    this.emitI32(0);
    this.relocs.push({ dispOffset, nextRipOffset: this.bytes.length, targetName: gotName });
  }

  patch(textBaseVA, symbolVAs) {
    const out = Uint8Array.from(this.bytes);
    const dv = new DataView(out.buffer);
    for (const rel of this.relocs) {
      const targetVA = symbolVAs.get(rel.targetName);
      if (targetVA === undefined) {
        throw new Error(`Unresolved x86-64 relocation target: ${rel.targetName}`);
      }
      const nextRip = textBaseVA + BigInt(rel.nextRipOffset);
      const disp = Number(targetVA - nextRip);
      dv.setInt32(rel.dispOffset, disp, true);
    }
    return out;
  }
}

// ============================================================================
// High-Level Portable ObjC App Assembler (Emits Real ARM64 OR Real x86-64!)
// ============================================================================

function emitMacAppCode(spec, arch) {
  const isArm64 = arch === 'arm64';
  const cg = isArm64 ? new Arm64CodeGen() : new X64CodeGen();

  // Resource pools collected dynamically from `spec`
  const cfStrings = new Map(); // text -> key
  const selectors = new Map(); // selName -> key
  const gotSymbols = new Set(); // external symbol names
  const globalSlots = [
    'g_delegate',
    'g_app',
    'g_window',
    'g_status_label',
    'g_editor_field',
    'g_main_menu',
  ];

  const internStr = (text) => {
    const s = String(text);
    if (!cfStrings.has(s)) {
      cfStrings.set(s, `cfstr_${cfStrings.size}`);
    }
    return cfStrings.get(s);
  };

  const internSel = (selName) => {
    const s = String(selName);
    if (!selectors.has(s)) {
      selectors.set(s, `sel_${selectors.size}`);
    }
    return selectors.get(s);
  };

  const needGot = (sym) => {
    gotSymbols.add(sym);
    return `got:${sym}`;
  };

  const needClass = (clsName) => needGot(`_OBJC_CLASS_$_${clsName}`);

  // Always need core ObjC runtime & AppKit entry
  needGot('_NSApplicationMain');
  needGot('_objc_msgSend');
  needGot('_NSLog');
  needGot('___CFConstantStringClassReference');
  needClass('NSObject');

  // Portable register slots:
  // ARM64:  saved = [X19, X20, X21, X22, X23, X24, X25, X26], args = [X0..X5], ret = X0
  // x86-64: saved = [RBX, R12, R13, R14, R15],               args = [RDI, RSI, RDX, RCX, R8, R9], ret = RAX
  const R_RET = isArm64 ? 0 : 0;
  const R_ARG = isArm64 ? [0, 1, 2, 3, 4, 5] : X64_ARG_REGS;
  // Saved scratch registers (4 always available across both ARM64 & x86-64!)
  const S0 = isArm64 ? 19 : 3;  // self
  const S1 = isArm64 ? 20 : 12; // temp1 (e.g. window / menu / pasteboard)
  const S2 = isArm64 ? 21 : 13; // temp2 (e.g. contentView / submenu)
  const S3 = isArm64 ? 22 : 14; // temp3 (e.g. topItem / curStr)
  const S4 = isArm64 ? 23 : 15; // temp4 (e.g. mainMenu)

  // Helper: load argument operand into target arg register
  // operand = { reg } | { cls } | { str } | { sel } | { global } | { imm }
  const loadOperand = (dstReg, op) => {
    if (op.reg !== undefined) {
      if (dstReg !== op.reg) cg.movReg(dstReg, op.reg);
    } else if (op.cls !== undefined) {
      cg.loadPtr(dstReg, needClass(op.cls));
    } else if (op.str !== undefined) {
      const k = internStr(op.str);
      if (isArm64) cg.loadAddr(dstReg, k);
      else cg.leaRip(dstReg, k);
    } else if (op.sel !== undefined) {
      cg.loadPtr(dstReg, internSel(op.sel));
    } else if (op.global !== undefined) {
      cg.loadPtr(dstReg, `glob:${op.global}`);
    } else if (op.imm !== undefined) {
      if (isArm64) cg.movImm16(dstReg, op.imm);
      else cg.movImm32(dstReg, op.imm);
    }
  };

  // Emit real CPU `objc_msgSend(receiver, sel, ...extraArgs)`!
  const emitMsgSend = (receiverOp, selName, extraOps = []) => {
    // Load extra args FIRST (so receiverOp using R_RET doesn't get clobbered if extraOps don't depend on R_RET)
    for (let i = extraOps.length - 1; i >= 0; i--) {
      loadOperand(R_ARG[2 + i], extraOps[i]);
    }
    loadOperand(R_ARG[1], { sel: selName });
    loadOperand(R_ARG[0], receiverOp);
    cg.callGot(needGot('_objc_msgSend'));
  };

  // Emit Apple ABI `NSLog(fmt, ...variadicOps)` (Edge Case #24: stack slots on ARM64!)
  const emitNSLog = (fmtStr, variadicOps = []) => {
    if (isArm64) {
      for (let i = 0; i < variadicOps.length; i++) {
        loadOperand(1, variadicOps[i]);
        cg.storeStackArg(1, i);
      }
      loadOperand(0, { str: fmtStr });
      cg.callGot(needGot('_NSLog'));
    } else {
      for (let i = 0; i < variadicOps.length; i++) {
        loadOperand(R_ARG[1 + i], variadicOps[i]);
      }
      loadOperand(R_ARG[0], { str: fmtStr });
      cg.callGot(needGot('_NSLog'));
    }
  };

  const funcOffsets = new Map();
  const markFunc = (name) => {
    while (cg.byteOffset % 16 !== 0) {
      if (isArm64) cg.emit(0xd503201f); // ARM64 NOP
      else cg.emit(0x90); // x86-64 NOP
    }
    funcOffsets.set(name, cg.byteOffset);
  };

  // -------------------------------------------------------------------------
  // 1. `_main(int argc, const char **argv)` -> calls `_NSApplicationMain`
  // -------------------------------------------------------------------------
  markFunc('_main');
  cg.prologue();
  cg.callGot(needGot('_NSApplicationMain'));
  cg.epilogue();

  // -------------------------------------------------------------------------
  // 2. `-[Delegate applicationDidFinishLaunching:]`
  // -------------------------------------------------------------------------
  markFunc('imp_didFinishLaunching');
  cg.prologue();
  cg.movReg(S0, R_ARG[0]); // S0 = self (delegate)
  cg.storePtr(S0, 'glob:g_delegate');

  // g_app = [NSApplication sharedApplication]
  emitMsgSend({ cls: 'NSApplication' }, 'sharedApplication');
  cg.storePtr(R_RET, 'glob:g_app');

  // S1 = [[NSWindow alloc] init]
  emitMsgSend({ cls: 'NSWindow' }, 'alloc');
  cg.movReg(S1, R_RET);
  emitMsgSend({ reg: S1 }, 'init');
  cg.movReg(S1, R_RET);
  cg.storePtr(S1, 'glob:g_window');

  // [window setTitle:spec.title]
  emitMsgSend({ reg: S1 }, 'setTitle:', [{ str: spec.title }]);

  // S2 = [window contentView]
  emitMsgSend({ reg: S1 }, 'contentView');
  cg.movReg(S2, R_RET);

  // Header status label: [NSTextField labelWithString:spec.initialText]
  emitMsgSend({ cls: 'NSTextField' }, 'labelWithString:', [{ str: spec.initialText }]);
  cg.movReg(S3, R_RET);
  cg.storePtr(S3, 'glob:g_status_label');
  emitMsgSend({ reg: S3 }, 'setTag:', [{ imm: 100 }]);
  emitMsgSend({ reg: S2 }, 'addSubview:', [{ reg: S3 }]);

  // Editable editor field: [NSTextField textFieldWithString:spec.documentContent]
  emitMsgSend({ cls: 'NSTextField' }, 'textFieldWithString:', [{ str: spec.documentContent }]);
  cg.movReg(S3, R_RET);
  cg.storePtr(S3, 'glob:g_editor_field');
  emitMsgSend({ reg: S3 }, 'setTag:', [{ imm: 101 }]);
  emitMsgSend({ reg: S3 }, 'setPlaceholderString:', [{ str: 'Enter workspace notes...' }]);
  emitMsgSend({ reg: S2 }, 'addSubview:', [{ reg: S3 }]);

  // Action button: [NSButton buttonWithTitle:spec.buttonTitle target:self action:@selector(onActionClick:)]
  emitMsgSend({ cls: 'NSButton' }, 'buttonWithTitle:target:action:', [
    { str: spec.buttonTitle },
    { reg: S0 },
    { sel: 'onActionClick:' },
  ]);
  cg.movReg(S3, R_RET);
  emitMsgSend({ reg: S3 }, 'setTag:', [{ imm: 102 }]);
  emitMsgSend({ reg: S2 }, 'addSubview:', [{ reg: S3 }]);

  // Live Global Top Menu Bar: S4 = [[NSMenu alloc] initWithTitle:@"MainMenu"]
  emitMsgSend({ cls: 'NSMenu' }, 'alloc');
  cg.movReg(S4, R_RET);
  emitMsgSend({ reg: S4 }, 'initWithTitle:', [{ str: 'MainMenu' }]);
  cg.movReg(S4, R_RET);
  cg.storePtr(S4, 'glob:g_main_menu');

  for (const menuGroup of spec.menus) {
    // S3 = [[NSMenuItem alloc] initWithTitle:group.label action:0 keyEquivalent:@""]
    emitMsgSend({ cls: 'NSMenuItem' }, 'alloc');
    cg.movReg(S3, R_RET);
    emitMsgSend({ reg: S3 }, 'initWithTitle:action:keyEquivalent:', [
      { str: menuGroup.label },
      { imm: 0 },
      { str: '' },
    ]);
    cg.movReg(S3, R_RET);

    // S2 = [[NSMenu alloc] initWithTitle:group.label]
    emitMsgSend({ cls: 'NSMenu' }, 'alloc');
    cg.movReg(S2, R_RET);
    emitMsgSend({ reg: S2 }, 'initWithTitle:', [{ str: menuGroup.label }]);
    cg.movReg(S2, R_RET);

    for (const item of menuGroup.items) {
      if (item.separator) {
        emitMsgSend({ cls: 'NSMenuItem' }, 'separatorItem');
        emitMsgSend({ reg: S2 }, 'addItem:', [{ reg: R_RET }]);
      } else {
        emitMsgSend({ reg: S2 }, 'addItemWithTitle:action:keyEquivalent:', [
          { str: item.label },
          { sel: item.selector },
          { str: item.keyEquivalent || '' },
        ]);
        if (item.selector !== 'terminate:') {
          emitMsgSend({ reg: R_RET }, 'setTarget:', [{ reg: S0 }]);
        }
      }
    }

    // [topItem setSubmenu:submenu]; [mainMenu addItem:topItem]
    emitMsgSend({ reg: S3 }, 'setSubmenu:', [{ reg: S2 }]);
    emitMsgSend({ reg: S4 }, 'addItem:', [{ reg: S3 }]);
  }

  // [[NSApplication sharedApplication] setMainMenu:mainMenu]
  emitMsgSend({ global: 'g_app' }, 'setMainMenu:', [{ reg: S4 }]);

  // [window makeKeyAndOrderFront:nil]
  emitMsgSend({ reg: S1 }, 'makeKeyAndOrderFront:', [{ imm: 0 }]);

  // Write NSUserDefaults key/value on launch
  if (spec.defaultsKey) {
    emitMsgSend({ cls: 'NSUserDefaults' }, 'standardUserDefaults');
    emitMsgSend({ reg: R_RET }, 'setObject:forKey:', [
      { str: spec.defaultsValue },
      { str: spec.defaultsKey },
    ]);
  }

  // Optional initial NSPasteboard write
  if (spec.pasteboardText !== null) {
    emitMsgSend({ cls: 'NSPasteboard' }, 'generalPasteboard');
    emitMsgSend({ reg: R_RET }, 'setString:forType:', [
      { str: spec.pasteboardText },
      { str: 'public.utf8-plain-text' },
    ]);
  }

  // Optional initial shared /Users/user/Documents/ write
  if (spec.writeDocumentOnLaunch && spec.documentFile) {
    emitMsgSend({ str: spec.documentContent }, 'writeToFile:atomically:encoding:error:', [
      { str: spec.documentFile },
      { imm: 1 },
      { imm: 4 },
      { imm: 0 },
    ]);
  }

  // Log startup via variadic NSLog (exercises Edge Case #24 stack-slot variadics on ARM64!)
  emitNSLog('%@ launched [%@]', [
    { str: spec.appName },
    { str: spec.nonce || spec.version },
  ]);

  cg.epilogue();

  // -------------------------------------------------------------------------
  // 3. `-[Delegate onNewDocument:]`
  // -------------------------------------------------------------------------
  markFunc('imp_onNewDocument');
  cg.prologue();
  const newDocStatus = spec.nonce ? `New Document Ready [${spec.nonce}]` : 'New Document Ready';
  const newDocTitle = spec.nonce ? `${spec.appName} — Untitled [${spec.nonce}]` : `${spec.appName} — Untitled`;
  emitMsgSend({ global: 'g_status_label' }, 'setStringValue:', [{ str: newDocStatus }]);
  emitMsgSend({ global: 'g_editor_field' }, 'setStringValue:', [{ str: newDocStatus }]);
  emitMsgSend({ global: 'g_window' }, 'setTitle:', [{ str: newDocTitle }]);
  cg.epilogue();

  // -------------------------------------------------------------------------
  // 4. `-[Delegate onSaveDocument:]`
  // -------------------------------------------------------------------------
  markFunc('imp_onSaveDocument');
  cg.prologue();
  // Read live editor stringValue and write to /Users/user/Documents/... via NSString writeToFile
  emitMsgSend({ global: 'g_editor_field' }, 'stringValue');
  cg.movReg(S1, R_RET);
  emitMsgSend({ reg: S1 }, 'writeToFile:atomically:encoding:error:', [
    { str: spec.documentFile },
    { imm: 1 },
    { imm: 4 },
    { imm: 0 },
  ]);
  const savedMsg = spec.nonce ? `Saved Document [${spec.nonce}]` : `Saved to ${spec.documentFile}`;
  emitMsgSend({ global: 'g_status_label' }, 'setStringValue:', [{ str: savedMsg }]);
  cg.epilogue();

  // -------------------------------------------------------------------------
  // 5. `-[Delegate onCopy:]`
  // -------------------------------------------------------------------------
  markFunc('imp_onCopy');
  cg.prologue();
  emitMsgSend({ global: 'g_editor_field' }, 'stringValue');
  cg.movReg(S1, R_RET);
  emitMsgSend({ cls: 'NSPasteboard' }, 'generalPasteboard');
  cg.movReg(S2, R_RET);
  emitMsgSend({ reg: S2 }, 'clearContents');
  emitMsgSend({ reg: S2 }, 'setString:forType:', [
    { reg: S1 },
    { str: 'public.utf8-plain-text' },
  ]);
  const copiedMsg = spec.nonce ? `Copied to Clipboard [${spec.nonce}]` : 'Copied to Clipboard';
  emitMsgSend({ global: 'g_status_label' }, 'setStringValue:', [{ str: copiedMsg }]);
  cg.epilogue();

  // -------------------------------------------------------------------------
  // 6. `-[Delegate onPaste:]`
  // -------------------------------------------------------------------------
  markFunc('imp_onPaste');
  cg.prologue();
  emitMsgSend({ cls: 'NSPasteboard' }, 'generalPasteboard');
  emitMsgSend({ reg: R_RET }, 'stringForType:', [{ str: 'public.utf8-plain-text' }]);
  cg.movReg(S1, R_RET);
  emitMsgSend({ global: 'g_editor_field' }, 'setStringValue:', [{ reg: S1 }]);
  emitMsgSend({ global: 'g_status_label' }, 'setStringValue:', [{ reg: S1 }]);
  cg.epilogue();

  // -------------------------------------------------------------------------
  // 7. `-[Delegate onAbout:]`
  // -------------------------------------------------------------------------
  markFunc('imp_onAbout');
  cg.prologue();
  emitMsgSend({ cls: 'NSAlert' }, 'alloc');
  cg.movReg(S1, R_RET);
  emitMsgSend({ reg: S1 }, 'init');
  cg.movReg(S1, R_RET);
  const aboutTitle = `About ${spec.appName} ${spec.version}`;
  emitMsgSend({ reg: S1 }, 'setMessageText:', [{ str: aboutTitle }]);
  emitMsgSend({ reg: S1 }, 'setInformativeText:', [{ str: spec.description }]);
  emitMsgSend({ reg: S1 }, 'addButtonWithTitle:', [{ str: 'OK' }]);
  emitMsgSend({ reg: S1 }, 'runModal');
  emitMsgSend({ global: 'g_status_label' }, 'setStringValue:', [{ str: aboutTitle }]);
  cg.epilogue();

  // -------------------------------------------------------------------------
  // 8. `-[Delegate onActionClick:]`
  // -------------------------------------------------------------------------
  markFunc('imp_onActionClick');
  cg.prologue();
  emitMsgSend({ global: 'g_editor_field' }, 'stringValue');
  cg.movReg(S1, R_RET);
  emitMsgSend({ cls: 'NSPasteboard' }, 'generalPasteboard');
  emitMsgSend({ reg: R_RET }, 'setString:forType:', [
    { reg: S1 },
    { str: 'public.utf8-plain-text' },
  ]);
  const syncMsg = spec.nonce ? `Synced Clipboard [${spec.nonce}]` : 'Synced Clipboard';
  emitMsgSend({ global: 'g_status_label' }, 'setStringValue:', [{ str: syncMsg }]);
  cg.epilogue();

  // -------------------------------------------------------------------------
  // 9. `-[Delegate application:openURLs:]`
  // -------------------------------------------------------------------------
  markFunc('imp_openURLs');
  cg.prologue();
  // arg0 = self, arg1 = _cmd, arg2 = app, arg3 = urls NSArray
  emitMsgSend({ reg: R_ARG[3] }, 'description');
  emitMsgSend({ global: 'g_status_label' }, 'setStringValue:', [{ reg: R_RET }]);
  cg.epilogue();

  // -------------------------------------------------------------------------
  // 10. `-[Delegate applicationShouldTerminateAfterLastWindowClosed:]`
  // -------------------------------------------------------------------------
  markFunc('imp_shouldTerminate');
  cg.prologue();
  loadOperand(R_RET, { imm: 1 });
  cg.epilogue();

  // -------------------------------------------------------------------------
  // 11. `-[Delegate applicationWillTerminate:]`
  // -------------------------------------------------------------------------
  markFunc('imp_willTerminate');
  cg.prologue();
  emitNSLog('%@ terminating', [{ str: spec.appName }]);
  cg.epilogue();

  // -------------------------------------------------------------------------
  // 12. Dynamic Custom Menu Item IMPs (spec.customActions)
  // -------------------------------------------------------------------------
  const customImpMethods = [];
  for (let i = 0; i < spec.customActions.length; i++) {
    const act = spec.customActions[i];
    const fnName = `imp_custom_${i}`;
    markFunc(fnName);
    cg.prologue();
    emitMsgSend({ global: 'g_status_label' }, 'setStringValue:', [{ str: act.statusText }]);
    if (act.windowTitle) {
      emitMsgSend({ global: 'g_window' }, 'setTitle:', [{ str: act.windowTitle }]);
    }
    if (act.copyText) {
      emitMsgSend({ cls: 'NSPasteboard' }, 'generalPasteboard');
      emitMsgSend({ reg: R_RET }, 'setString:forType:', [
        { str: act.copyText },
        { str: 'public.utf8-plain-text' },
      ]);
    }
    cg.epilogue();
    customImpMethods.push({ sel: act.selector, fnName, types: 'v24@0:8@16' });
  }

  const delegateMethods = [
    { sel: 'applicationDidFinishLaunching:', fnName: 'imp_didFinishLaunching', types: 'v24@0:8@16' },
    { sel: 'onNewDocument:', fnName: 'imp_onNewDocument', types: 'v24@0:8@16' },
    { sel: 'onSaveDocument:', fnName: 'imp_onSaveDocument', types: 'v24@0:8@16' },
    { sel: 'onCopy:', fnName: 'imp_onCopy', types: 'v24@0:8@16' },
    { sel: 'onPaste:', fnName: 'imp_onPaste', types: 'v24@0:8@16' },
    { sel: 'onAbout:', fnName: 'imp_onAbout', types: 'v24@0:8@16' },
    { sel: 'onActionClick:', fnName: 'imp_onActionClick', types: 'v24@0:8@16' },
    { sel: 'application:openURLs:', fnName: 'imp_openURLs', types: 'v32@0:8@16@24' },
    { sel: 'applicationShouldTerminateAfterLastWindowClosed:', fnName: 'imp_shouldTerminate', types: 'B24@0:8@16' },
    { sel: 'applicationWillTerminate:', fnName: 'imp_willTerminate', types: 'v24@0:8@16' },
    ...customImpMethods,
  ];
  for (const m of delegateMethods) {
    internSel(m.sel);
  }

  return {
    cg,
    funcOffsets,
    cfStrings,
    selectors,
    gotSymbols: Array.from(gotSymbols).sort(),
    globalSlots,
    delegateMethods,
  };
}

// ============================================================================
// Genuine Mach-O 64 Assembler (`LC_SEGMENT_64`, `LC_DYLD_INFO_ONLY`, ObjC ABI2,
// `LC_SYMTAB`/`DYSYMTAB`, `LC_MAIN`, `LC_BUILD_VERSION`, `LC_CODE_SIGNATURE`)
// ============================================================================

function buildCodeSignatureBlob(identifier, entitlements) {
  const entXmlBytes = entitlements
    ? TEXT_ENCODER.encode(writeXmlPlist(entitlements))
    : null;

  // Minimal valid big-endian CS_CodeDirectory (version 0x20400)
  const identBytes = TEXT_ENCODER.encode(`${identifier}\0`);
  const cdHeaderSize = 44;
  const cdSize = cdHeaderSize + identBytes.byteLength;
  const cdBuf = new Uint8Array(cdSize);
  const cdDv = new DataView(cdBuf.buffer);
  cdDv.setUint32(0, MACHO_CONSTANTS.CSMAGIC_CODEDIRECTORY, false);
  cdDv.setUint32(4, cdSize, false);
  cdDv.setUint32(8, 0x00020400, false); // version
  cdDv.setUint32(12, 0x00000002, false); // adhoc flag
  cdDv.setUint32(16, cdSize, false); // hashOffset
  cdDv.setUint32(20, cdHeaderSize, false); // identOffset
  cdDv.setUint32(24, 0, false); // nSpecialSlots
  cdDv.setUint32(28, 0, false); // nCodeSlots
  cdDv.setUint32(32, 0, false); // codeLimit
  cdDv.setUint8(36, 32); // hashSize (SHA-256)
  cdDv.setUint8(37, 2); // hashType (SHA-256)
  cdDv.setUint8(38, 0); // platform
  cdDv.setUint8(39, 12); // pageSize (log2 = 4096)
  cdDv.setUint32(40, 0, false); // spare2
  cdBuf.set(identBytes, cdHeaderSize);

  const blobs = [{ type: 0, data: cdBuf }];
  if (entXmlBytes) {
    const entBuf = new Uint8Array(8 + entXmlBytes.byteLength);
    const entDv = new DataView(entBuf.buffer);
    entDv.setUint32(0, MACHO_CONSTANTS.CSMAGIC_EMBEDDED_ENTITLEMENTS, false);
    entDv.setUint32(4, entBuf.byteLength, false);
    entBuf.set(entXmlBytes, 8);
    blobs.push({ type: 5, data: entBuf });
  }

  const superHeaderSize = 12 + blobs.length * 8;
  let totalLen = superHeaderSize;
  for (const b of blobs) totalLen += b.data.byteLength;

  const out = new Uint8Array(totalLen);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, MACHO_CONSTANTS.CSMAGIC_EMBEDDED_SIGNATURE, false);
  dv.setUint32(4, totalLen, false);
  dv.setUint32(8, blobs.length, false);

  let dataOff = superHeaderSize;
  for (let i = 0; i < blobs.length; i++) {
    dv.setUint32(12 + i * 8, blobs[i].type, false);
    dv.setUint32(12 + i * 8 + 4, dataOff, false);
    out.set(blobs[i].data, dataOff);
    dataOff += blobs[i].data.byteLength;
  }
  return out;
}

function buildMacMachO(rawSpec = {}, arch = 'arm64') {
  const spec = normalizeMacSpec(rawSpec);
  const isArm64 = arch === 'arm64';
  const cputype = isArm64 ? MACHO_CONSTANTS.CPU_TYPE_ARM64 : MACHO_CONSTANTS.CPU_TYPE_X86_64;
  const cpusubtype = isArm64 ? 0 : 3;

  const emitted = emitMacAppCode(spec, arch);
  const { cg, funcOffsets, cfStrings, selectors, gotSymbols, globalSlots, delegateMethods } = emitted;

  // Build read-only string tables for __TEXT sections
  const buildStringPool = (entries) => {
    const offsets = new Map();
    const chunks = [];
    let pos = 0;
    for (const [key, str] of entries) {
      offsets.set(key, pos);
      const b = TEXT_ENCODER.encode(`${str}\0`);
      chunks.push(b);
      pos += b.byteLength;
    }
    const buf = new Uint8Array(Math.max(1, pos));
    let cur = 0;
    for (const c of chunks) {
      buf.set(c, cur);
      cur += c.byteLength;
    }
    return { buf, offsets };
  };

  const cstringEntries = Array.from(cfStrings.entries()).map(([text, key]) => [key, text]);
  const cstringPool = buildStringPool(cstringEntries);

  const methnameEntries = Array.from(selectors.entries()).map(([selName, key]) => [key, selName]);
  const methnamePool = buildStringPool(methnameEntries);

  const classnamePool = buildStringPool([['delegate_cls', spec.delegateClassName]]);
  const methtypeEntries = [];
  const seenTypes = new Set();
  for (const m of delegateMethods) {
    if (!seenTypes.has(m.types)) {
      seenTypes.add(m.types);
      methtypeEntries.push([m.types, m.types]);
    }
  }
  const methtypePool = buildStringPool(methtypeEntries);

  // Dylib list (1-indexed libOrdinal for dyld binds)
  const dylibs = [
    '/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit',
    '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation',
    '/usr/lib/libobjc.A.dylib',
    '/usr/lib/libSystem.B.dylib',
  ];

  // Calculate exact load commands size to place __text cleanly right after header + commands!
  const textSectionCount = 5; // __text, __cstring, __objc_methname, __objc_classname, __objc_methtype
  const dataSectionCount = 6; // __got, __cfstring, __objc_classlist, __objc_selrefs, __objc_const, __objc_data
  const segCmdSize = (nsects) => 72 + nsects * 80;
  const dylibCmdSize = (name) => alignUp(24 + TEXT_ENCODER.encode(name).byteLength + 1, 8);
  const dylinkerCmdSize = alignUp(12 + TEXT_ENCODER.encode('/usr/lib/dyld').byteLength + 1, 8);

  const codeSigBlob = buildCodeSignatureBlob(spec.bundleId, spec.entitlements);

  const loadCmdSpecs = [
    { kind: 'PAGEZERO', size: segCmdSize(0) },
    { kind: 'TEXT', size: segCmdSize(textSectionCount) },
    { kind: 'DATA', size: segCmdSize(dataSectionCount) },
    { kind: 'LINKEDIT', size: segCmdSize(0) },
    { kind: 'DYLD_INFO_ONLY', size: 48 },
    { kind: 'SYMTAB', size: 24 },
    { kind: 'DYSYMTAB', size: 80 },
    { kind: 'LOAD_DYLINKER', size: dylinkerCmdSize },
    { kind: 'UUID', size: 24 },
    { kind: 'BUILD_VERSION', size: 24 },
    { kind: 'MAIN', size: 24 },
    ...dylibs.map((name) => ({ kind: 'LOAD_DYLIB', name, size: dylibCmdSize(name) })),
    { kind: 'CODE_SIGNATURE', size: 16 },
  ];

  const sizeofcmds = loadCmdSpecs.reduce((acc, c) => acc + c.size, 0);
  const headerAndCmdsEnd = 32 + sizeofcmds;

  // ---- Layout __TEXT Segment (fileoff = 0, vmaddr = 0x100000000) ----
  const textCodeOff = alignUp(headerAndCmdsEnd, 16);
  const textCodeSize = cg.byteOffset;

  const cstringOff = alignUp(textCodeOff + textCodeSize, 8);
  const cstringSize = cstringPool.buf.byteLength;

  const methnameOff = alignUp(cstringOff + cstringSize, 8);
  const methnameSize = methnamePool.buf.byteLength;

  const classnameOff = alignUp(methnameOff + methnameSize, 8);
  const classnameSize = classnamePool.buf.byteLength;

  const methtypeOff = alignUp(classnameOff + classnameSize, 8);
  const methtypeSize = methtypePool.buf.byteLength;

  const textSegSize = alignUp(methtypeOff + methtypeSize, PAGE_ALIGN);
  const textBaseVA = TEXT_VMADDR_BASE;

  // ---- Layout __DATA Segment (fileoff = textSegSize, vmaddr = 0x100000000 + textSegSize) ----
  const dataFileOff = textSegSize;
  const dataBaseVA = textBaseVA + BigInt(textSegSize);

  // Within __DATA:
  const gotRelOff = 0;
  const gotSize = gotSymbols.length * 8;

  const cfstringRelOff = alignUp(gotRelOff + gotSize, 8);
  const cfstringSize = cfStrings.size * 32;

  const classlistRelOff = alignUp(cfstringRelOff + cfstringSize, 8);
  const classlistSize = 8; // 1 app class (StudioAppDelegate)

  const selrefsRelOff = alignUp(classlistRelOff + classlistSize, 8);
  const selrefsSize = selectors.size * 8;

  // __objc_const: class_ro_t (72B) + metaclass_ro_t (72B) + method_list_t (8 + N*24)
  const objcConstRelOff = alignUp(selrefsRelOff + selrefsSize, 8);
  const roStructSize = 72;
  const classRoRelOff = objcConstRelOff;
  const metaRoRelOff = classRoRelOff + roStructSize;
  const methodListRelOff = metaRoRelOff + roStructSize;
  const methodListSize = 8 + delegateMethods.length * 24;
  const objcConstSize = (methodListRelOff - objcConstRelOff) + methodListSize;

  // __objc_data: class_t (40B) + metaclass_t (40B) + global pointer slots (globalSlots.length * 8)
  const objcDataRelOff = alignUp(objcConstRelOff + objcConstSize, 8);
  const classTRelOff = objcDataRelOff;
  const metaTRelOff = classTRelOff + 40;
  const globalsRelOff = metaTRelOff + 40;
  const objcDataSize = (globalsRelOff - objcDataRelOff) + globalSlots.length * 8;

  const dataSegSize = alignUp(objcDataRelOff + objcDataSize, PAGE_ALIGN);

  // ---- Build Symbol VA Table for Code Patching ----
  const symbolVAs = new Map();
  for (let i = 0; i < gotSymbols.length; i++) {
    symbolVAs.set(`got:${gotSymbols[i]}`, dataBaseVA + BigInt(gotRelOff + i * 8));
  }
  let cfIdx = 0;
  for (const [, key] of cfStrings.entries()) {
    symbolVAs.set(key, dataBaseVA + BigInt(cfstringRelOff + cfIdx * 32));
    cfIdx++;
  }
  let selIdx = 0;
  for (const [, key] of selectors.entries()) {
    symbolVAs.set(key, dataBaseVA + BigInt(selrefsRelOff + selIdx * 8));
    selIdx++;
  }
  for (let i = 0; i < globalSlots.length; i++) {
    symbolVAs.set(`glob:${globalSlots[i]}`, dataBaseVA + BigInt(globalsRelOff + i * 8));
  }

  // Patch machine code with final VAs!
  const codeBytes = cg.patch(textBaseVA + BigInt(textCodeOff), symbolVAs);

  // ---- Populate __DATA Bytes & Record Rebase/Bind Offsets ----
  const dataBuf = new Uint8Array(dataSegSize);
  const dataDv = new DataView(dataBuf.buffer);
  const rebaseDataOffsets = []; // offsets relative to __DATA segment start
  const bindEntries = []; // { dataOffset, symbol, libOrdinal }

  // 1. __got binds
  for (let i = 0; i < gotSymbols.length; i++) {
    const sym = gotSymbols[i];
    const libOrdinal = sym.startsWith('_OBJC_CLASS_$_NS') ? 1 : sym === '_NSApplicationMain' ? 1 : sym.startsWith('_objc_') ? 3 : 2;
    bindEntries.push({ dataOffset: gotRelOff + i * 8, symbol: sym, libOrdinal });
  }

  // 2. __cfstring entries (32 bytes each: isa_ptr [bind], flags=0x07C8, cstr_ptr [rebase], byte_len)
  cfIdx = 0;
  for (const [text, key] of cfStrings.entries()) {
    const off = cfstringRelOff + cfIdx * 32;
    const cstrVA = textBaseVA + BigInt(cstringOff + cstringPool.offsets.get(key));
    const utf8Len = TEXT_ENCODER.encode(text).byteLength;
    bindEntries.push({ dataOffset: off, symbol: '___CFConstantStringClassReference', libOrdinal: 2 });
    dataDv.setBigUint64(off + 8, 0x07c8n, true);
    dataDv.setBigUint64(off + 16, cstrVA, true);
    dataDv.setBigUint64(off + 24, BigInt(utf8Len), true);
    rebaseDataOffsets.push(off + 16);
    cfIdx++;
  }

  // 3. __objc_classlist -> points to class_t
  const classTVA = dataBaseVA + BigInt(classTRelOff);
  const metaTVA = dataBaseVA + BigInt(metaTRelOff);
  const classRoVA = dataBaseVA + BigInt(classRoRelOff);
  const metaRoVA = dataBaseVA + BigInt(metaRoRelOff);
  const methodListVA = dataBaseVA + BigInt(methodListRelOff);

  dataDv.setBigUint64(classlistRelOff, classTVA, true);
  rebaseDataOffsets.push(classlistRelOff);

  // 4. __objc_selrefs -> pointers into __objc_methname
  selIdx = 0;
  for (const [, key] of selectors.entries()) {
    const off = selrefsRelOff + selIdx * 8;
    const methNameVA = textBaseVA + BigInt(methnameOff + methnamePool.offsets.get(key));
    dataDv.setBigUint64(off, methNameVA, true);
    rebaseDataOffsets.push(off);
    selIdx++;
  }

  // 5. __objc_const: class_ro_t + metaclass_ro_t + method_list_t
  const clsNameVA = textBaseVA + BigInt(classnameOff + classnamePool.offsets.get('delegate_cls'));
  // class_ro_t (72 bytes)
  dataDv.setUint32(classRoRelOff + 0, 0, true); // flags
  dataDv.setUint32(classRoRelOff + 4, 8, true); // instanceStart
  dataDv.setUint32(classRoRelOff + 8, 32, true); // instanceSize
  dataDv.setBigUint64(classRoRelOff + 24, clsNameVA, true);
  dataDv.setBigUint64(classRoRelOff + 32, methodListVA, true);
  rebaseDataOffsets.push(classRoRelOff + 24, classRoRelOff + 32);

  // metaclass_ro_t (72 bytes)
  dataDv.setUint32(metaRoRelOff + 0, 1, true); // RO_META
  dataDv.setUint32(metaRoRelOff + 4, 40, true);
  dataDv.setUint32(metaRoRelOff + 8, 40, true);
  dataDv.setBigUint64(metaRoRelOff + 24, clsNameVA, true);
  rebaseDataOffsets.push(metaRoRelOff + 24);

  // method_list_t (entsize=24, count=N, standard 24-byte method_t entries)
  dataDv.setUint32(methodListRelOff + 0, 24, true);
  dataDv.setUint32(methodListRelOff + 4, delegateMethods.length, true);
  for (let i = 0; i < delegateMethods.length; i++) {
    const m = delegateMethods[i];
    const mOff = methodListRelOff + 8 + i * 24;
    const selKey = selectors.get(m.sel);
    const selStrVA = textBaseVA + BigInt(methnameOff + methnamePool.offsets.get(selKey));
    const typesVA = textBaseVA + BigInt(methtypeOff + methtypePool.offsets.get(m.types));
    const impVA = textBaseVA + BigInt(textCodeOff + funcOffsets.get(m.fnName));
    dataDv.setBigUint64(mOff + 0, selStrVA, true);
    dataDv.setBigUint64(mOff + 8, typesVA, true);
    dataDv.setBigUint64(mOff + 16, impVA, true);
    rebaseDataOffsets.push(mOff + 0, mOff + 8, mOff + 16);
  }

  // 6. __objc_data: class_t (40B) + metaclass_t (40B)
  // class_t: isa=metaTVA, superclass=bind(_OBJC_CLASS_$_NSObject), cache=0, vtable=0, data=classRoVA
  dataDv.setBigUint64(classTRelOff + 0, metaTVA, true);
  bindEntries.push({ dataOffset: classTRelOff + 8, symbol: '_OBJC_CLASS_$_NSObject', libOrdinal: 3 });
  dataDv.setBigUint64(classTRelOff + 32, classRoVA, true);
  rebaseDataOffsets.push(classTRelOff + 0, classTRelOff + 32);

  // metaclass_t: isa=bind(_OBJC_METACLASS_$_NSObject), superclass=bind(_OBJC_METACLASS_$_NSObject), data=metaRoVA
  bindEntries.push({ dataOffset: metaTRelOff + 0, symbol: '_OBJC_METACLASS_$_NSObject', libOrdinal: 3 });
  bindEntries.push({ dataOffset: metaTRelOff + 8, symbol: '_OBJC_METACLASS_$_NSObject', libOrdinal: 3 });
  dataDv.setBigUint64(metaTRelOff + 32, metaRoVA, true);
  rebaseDataOffsets.push(metaTRelOff + 32);

  // ---- Build __LINKEDIT Streams (Rebase + Bind + Symtab + IndirectSymtab + Strtab + CodeSig) ----
  // Segment indices: 0=__PAGEZERO, 1=__TEXT, 2=__DATA, 3=__LINKEDIT
  const DATA_SEG_INDEX = 2;

  const rebaseOps = [0x10 | 1]; // REBASE_OPCODE_SET_TYPE_IMM (POINTER = 1)
  rebaseDataOffsets.sort((a, b) => a - b);
  for (const off of rebaseDataOffsets) {
    rebaseOps.push(0x20 | DATA_SEG_INDEX, ...encodeUleb128(off), 0x50 | 1); // SET_SEG_AND_OFF + DO_REBASE_IMM_TIMES(1)
  }
  rebaseOps.push(0x00); // REBASE_OPCODE_DONE
  const rebaseBytes = Uint8Array.from(rebaseOps);

  const bindOps = [0x50 | 1]; // BIND_OPCODE_SET_TYPE_IMM (POINTER = 1)
  for (const b of bindEntries) {
    bindOps.push(0x10 | (b.libOrdinal & 0x0f));
    bindOps.push(0x40); // SET_SYMBOL_TRAILING_FLAGS_IMM(0)
    const symUtf8 = TEXT_ENCODER.encode(b.symbol);
    for (let i = 0; i < symUtf8.byteLength; i++) bindOps.push(symUtf8[i]);
    bindOps.push(0);
    bindOps.push(0x70 | DATA_SEG_INDEX, ...encodeUleb128(b.dataOffset));
    bindOps.push(0x90); // BIND_OPCODE_DO_BIND
  }
  bindOps.push(0x00); // BIND_OPCODE_DONE
  const bindBytes = Uint8Array.from(bindOps);

  // Symbol Table (`_main` defined in section 1 + undefined symbols for all `__got` entries)
  const strtabChunks = [new Uint8Array([0x20, 0x00])]; // standard Mach-O strtab starts with " \0"
  let strPos = 2;
  const addStr = (s) => {
    const off = strPos;
    const b = TEXT_ENCODER.encode(`${s}\0`);
    strtabChunks.push(b);
    strPos += b.byteLength;
    return off;
  };

  const syms = [];
  // 0: _main (defined external in section 1 __TEXT,__text)
  syms.push({
    strx: addStr('_main'),
    type: 0x0f, // N_SECT | N_EXT
    sect: 1,
    desc: 0,
    value: textBaseVA + BigInt(textCodeOff + funcOffsets.get('_main')),
  });
  // 1..N: undefined external symbols for __got
  const gotSymIndices = [];
  for (let i = 0; i < gotSymbols.length; i++) {
    const symName = gotSymbols[i];
    const libOrd = symName.startsWith('_OBJC_CLASS_$_NS') ? 1 : symName === '_NSApplicationMain' ? 1 : symName.startsWith('_objc_') ? 3 : 2;
    gotSymIndices.push(syms.length);
    syms.push({
      strx: addStr(symName),
      type: 0x01, // N_UNDF | N_EXT
      sect: 0,
      desc: (libOrd & 0xff) << 8,
      value: 0n,
    });
  }

  const symtabBytes = new Uint8Array(syms.length * 16);
  const symDv = new DataView(symtabBytes.buffer);
  for (let i = 0; i < syms.length; i++) {
    const s = syms[i];
    symDv.setUint32(i * 16 + 0, s.strx, true);
    symDv.setUint8(i * 16 + 4, s.type);
    symDv.setUint8(i * 16 + 5, s.sect);
    symDv.setUint16(i * 16 + 6, s.desc, true);
    symDv.setBigUint64(i * 16 + 8, s.value, true);
  }

  const indirectSymBytes = new Uint8Array(gotSymIndices.length * 4);
  const indDv = new DataView(indirectSymBytes.buffer);
  for (let i = 0; i < gotSymIndices.length; i++) {
    indDv.setUint32(i * 4, gotSymIndices[i], true);
  }

  const strtabBytes = new Uint8Array(alignUp(strPos, 8));
  let sp = 0;
  for (const ch of strtabChunks) {
    strtabBytes.set(ch, sp);
    sp += ch.byteLength;
  }

  // Pack __LINKEDIT
  const linkeditFileOff = dataFileOff + dataSegSize;
  const linkeditBaseVA = dataBaseVA + BigInt(dataSegSize);

  const rebaseFileOff = linkeditFileOff;
  const bindFileOff = alignUp(rebaseFileOff + rebaseBytes.byteLength, 8);
  const symtabFileOff = alignUp(bindFileOff + bindBytes.byteLength, 8);
  const indirectFileOff = alignUp(symtabFileOff + symtabBytes.byteLength, 8);
  const strtabFileOff = alignUp(indirectFileOff + indirectSymBytes.byteLength, 8);
  const codeSigFileOff = alignUp(strtabFileOff + strtabBytes.byteLength, 16);
  const totalFileSize = alignUp(codeSigFileOff + codeSigBlob.byteLength, 16);
  const linkeditFileSize = totalFileSize - linkeditFileOff;
  const linkeditVmSize = alignUp(linkeditFileSize, PAGE_ALIGN);

  // ---- Assemble Final Mach-O 64 Image ----
  const out = new Uint8Array(totalFileSize);
  const dv = new DataView(out.buffer);

  // 1. mach_header_64 (32 bytes)
  dv.setUint32(0, MACHO_CONSTANTS.MH_MAGIC_64, true);
  dv.setUint32(4, cputype, true);
  dv.setUint32(8, cpusubtype, true);
  dv.setUint32(12, MACHO_CONSTANTS.MH_EXECUTE, true);
  dv.setUint32(16, loadCmdSpecs.length, true);
  dv.setUint32(20, sizeofcmds, true);
  dv.setUint32(24, 0x00200085, true); // MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE
  dv.setUint32(28, 0, true);

  // 2. Write Load Commands
  let pos = 32;
  const writeSegment = (segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, sections) => {
    const cmdsize = segCmdSize(sections.length);
    dv.setUint32(pos + 0, MACHO_CONSTANTS.LC_SEGMENT_64, true);
    dv.setUint32(pos + 4, cmdsize, true);
    writeFixedStr(out, pos + 8, segname, 16);
    dv.setBigUint64(pos + 24, BigInt(vmaddr), true);
    dv.setBigUint64(pos + 32, BigInt(vmsize), true);
    dv.setBigUint64(pos + 40, BigInt(fileoff), true);
    dv.setBigUint64(pos + 48, BigInt(filesize), true);
    dv.setUint32(pos + 56, maxprot, true);
    dv.setUint32(pos + 60, initprot, true);
    dv.setUint32(pos + 64, sections.length, true);
    dv.setUint32(pos + 68, 0, true);
    let sPos = pos + 72;
    for (const s of sections) {
      writeFixedStr(out, sPos + 0, s.sectname, 16);
      writeFixedStr(out, sPos + 16, segname, 16);
      dv.setBigUint64(sPos + 32, BigInt(s.addr), true);
      dv.setBigUint64(sPos + 40, BigInt(s.size), true);
      dv.setUint32(sPos + 48, s.offset, true);
      dv.setUint32(sPos + 52, s.align ?? 3, true);
      dv.setUint32(sPos + 56, 0, true); // reloff
      dv.setUint32(sPos + 60, 0, true); // nreloc
      dv.setUint32(sPos + 64, s.flags ?? 0, true);
      dv.setUint32(sPos + 68, s.reserved1 ?? 0, true);
      dv.setUint32(sPos + 72, s.reserved2 ?? 0, true);
      dv.setUint32(sPos + 76, 0, true);
      sPos += 80;
    }
    pos += cmdsize;
  };

  // __PAGEZERO (Edge Case #21)
  writeSegment('__PAGEZERO', 0n, 0x100000000n, 0, 0, 0, 0, []);

  // __TEXT
  writeSegment('__TEXT', textBaseVA, BigInt(textSegSize), 0, textSegSize, 5, 5, [
    {
      sectname: '__text',
      addr: textBaseVA + BigInt(textCodeOff),
      size: codeBytes.byteLength,
      offset: textCodeOff,
      align: 4,
      flags: 0x80000400, // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
    },
    {
      sectname: '__cstring',
      addr: textBaseVA + BigInt(cstringOff),
      size: cstringSize,
      offset: cstringOff,
      align: 0,
      flags: MACHO_CONSTANTS.S_CSTRING_LITERALS,
    },
    {
      sectname: '__objc_methname',
      addr: textBaseVA + BigInt(methnameOff),
      size: methnameSize,
      offset: methnameOff,
      align: 0,
      flags: MACHO_CONSTANTS.S_CSTRING_LITERALS,
    },
    {
      sectname: '__objc_classname',
      addr: textBaseVA + BigInt(classnameOff),
      size: classnameSize,
      offset: classnameOff,
      align: 0,
      flags: MACHO_CONSTANTS.S_CSTRING_LITERALS,
    },
    {
      sectname: '__objc_methtype',
      addr: textBaseVA + BigInt(methtypeOff),
      size: methtypeSize,
      offset: methtypeOff,
      align: 0,
      flags: MACHO_CONSTANTS.S_CSTRING_LITERALS,
    },
  ]);

  // __DATA
  writeSegment('__DATA', dataBaseVA, BigInt(dataSegSize), dataFileOff, dataSegSize, 3, 3, [
    {
      sectname: '__got',
      addr: dataBaseVA + BigInt(gotRelOff),
      size: gotSize,
      offset: dataFileOff + gotRelOff,
      align: 3,
      flags: MACHO_CONSTANTS.S_NON_LAZY_SYMBOL_POINTERS,
      reserved1: 0,
    },
    {
      sectname: '__cfstring',
      addr: dataBaseVA + BigInt(cfstringRelOff),
      size: cfstringSize,
      offset: dataFileOff + cfstringRelOff,
      align: 3,
      flags: 0,
    },
    {
      sectname: '__objc_classlist',
      addr: dataBaseVA + BigInt(classlistRelOff),
      size: classlistSize,
      offset: dataFileOff + classlistRelOff,
      align: 3,
      flags: 0,
    },
    {
      sectname: '__objc_selrefs',
      addr: dataBaseVA + BigInt(selrefsRelOff),
      size: selrefsSize,
      offset: dataFileOff + selrefsRelOff,
      align: 3,
      flags: 0,
    },
    {
      sectname: '__objc_const',
      addr: dataBaseVA + BigInt(objcConstRelOff),
      size: objcConstSize,
      offset: dataFileOff + objcConstRelOff,
      align: 3,
      flags: 0,
    },
    {
      sectname: '__objc_data',
      addr: dataBaseVA + BigInt(objcDataRelOff),
      size: objcDataSize,
      offset: dataFileOff + objcDataRelOff,
      align: 3,
      flags: 0,
    },
  ]);

  // __LINKEDIT
  writeSegment('__LINKEDIT', linkeditBaseVA, BigInt(linkeditVmSize), linkeditFileOff, linkeditFileSize, 1, 1, []);

  // LC_DYLD_INFO_ONLY (48 bytes)
  dv.setUint32(pos + 0, MACHO_CONSTANTS.LC_DYLD_INFO_ONLY, true);
  dv.setUint32(pos + 4, 48, true);
  dv.setUint32(pos + 8, rebaseFileOff, true);
  dv.setUint32(pos + 12, rebaseBytes.byteLength, true);
  dv.setUint32(pos + 16, bindFileOff, true);
  dv.setUint32(pos + 20, bindBytes.byteLength, true);
  pos += 48;

  // LC_SYMTAB (24 bytes)
  dv.setUint32(pos + 0, MACHO_CONSTANTS.LC_SYMTAB, true);
  dv.setUint32(pos + 4, 24, true);
  dv.setUint32(pos + 8, symtabFileOff, true);
  dv.setUint32(pos + 12, syms.length, true);
  dv.setUint32(pos + 16, strtabFileOff, true);
  dv.setUint32(pos + 20, strtabBytes.byteLength, true);
  pos += 24;

  // LC_DYSYMTAB (80 bytes)
  dv.setUint32(pos + 0, MACHO_CONSTANTS.LC_DYSYMTAB, true);
  dv.setUint32(pos + 4, 80, true);
  dv.setUint32(pos + 8, 0, true); // ilocalsym
  dv.setUint32(pos + 12, 0, true); // nlocalsym
  dv.setUint32(pos + 16, 0, true); // iextdefsym
  dv.setUint32(pos + 20, 1, true); // nextdefsym (_main)
  dv.setUint32(pos + 24, 1, true); // iundefsym
  dv.setUint32(pos + 28, syms.length - 1, true); // nundefsym
  dv.setUint32(pos + 56, indirectFileOff, true);
  dv.setUint32(pos + 60, gotSymIndices.length, true);
  pos += 80;

  // LC_LOAD_DYLINKER
  dv.setUint32(pos + 0, MACHO_CONSTANTS.LC_LOAD_DYLINKER, true);
  dv.setUint32(pos + 4, dylinkerCmdSize, true);
  dv.setUint32(pos + 8, 12, true);
  writeFixedStr(out, pos + 12, '/usr/lib/dyld', dylinkerCmdSize - 12);
  pos += dylinkerCmdSize;

  // LC_UUID (deterministic SHA-256 derived 16-byte UUID)
  const uuidBytes = crypto
    .createHash('sha256')
    .update(`omnios-macos:${spec.bundleId}:${spec.version}:${spec.nonce}:${arch}`)
    .digest()
    .subarray(0, 16);
  uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40;
  uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80;
  dv.setUint32(pos + 0, MACHO_CONSTANTS.LC_UUID, true);
  dv.setUint32(pos + 4, 24, true);
  out.set(uuidBytes, pos + 8);
  pos += 24;

  // LC_BUILD_VERSION (macOS 14.0.0)
  dv.setUint32(pos + 0, MACHO_CONSTANTS.LC_BUILD_VERSION, true);
  dv.setUint32(pos + 4, 24, true);
  dv.setUint32(pos + 8, MACHO_CONSTANTS.PLATFORM_MACOS, true);
  dv.setUint32(pos + 12, 0x000e0000, true); // minos 14.0.0
  dv.setUint32(pos + 16, 0x000e0000, true); // sdk 14.0.0
  dv.setUint32(pos + 20, 0, true); // ntools
  pos += 24;

  // LC_MAIN (Edge Case #22: entryoff relative to __TEXT.vmaddr)
  dv.setUint32(pos + 0, MACHO_CONSTANTS.LC_MAIN, true);
  dv.setUint32(pos + 4, 24, true);
  dv.setBigUint64(pos + 8, BigInt(textCodeOff + funcOffsets.get('_main')), true);
  dv.setBigUint64(pos + 16, 0n, true);
  pos += 24;

  // LC_LOAD_DYLIB entries
  for (const name of dylibs) {
    const sz = dylibCmdSize(name);
    dv.setUint32(pos + 0, MACHO_CONSTANTS.LC_LOAD_DYLIB, true);
    dv.setUint32(pos + 4, sz, true);
    dv.setUint32(pos + 8, 24, true); // name offset
    dv.setUint32(pos + 12, 2, true); // timestamp
    dv.setUint32(pos + 16, 0x00010000, true); // current_version 1.0.0
    dv.setUint32(pos + 20, 0x00010000, true); // compatibility_version 1.0.0
    writeFixedStr(out, pos + 24, name, sz - 24);
    pos += sz;
  }

  // LC_CODE_SIGNATURE (16 bytes)
  dv.setUint32(pos + 0, MACHO_CONSTANTS.LC_CODE_SIGNATURE, true);
  dv.setUint32(pos + 4, 16, true);
  dv.setUint32(pos + 8, codeSigFileOff, true);
  dv.setUint32(pos + 12, codeSigBlob.byteLength, true);
  pos += 16;

  // 3. Copy Section Payloads
  out.set(codeBytes, textCodeOff);
  out.set(cstringPool.buf, cstringOff);
  out.set(methnamePool.buf, methnameOff);
  out.set(classnamePool.buf, classnameOff);
  out.set(methtypePool.buf, methtypeOff);
  out.set(dataBuf, dataFileOff);
  out.set(rebaseBytes, rebaseFileOff);
  out.set(bindBytes, bindFileOff);
  out.set(symtabBytes, symtabFileOff);
  out.set(indirectSymBytes, indirectFileOff);
  out.set(strtabBytes, strtabFileOff);
  out.set(codeSigBlob, codeSigFileOff);

  return out;
}

/**
 * Builds a genuine 64-bit ARM64 macOS Mach-O executable.
 */
export function buildMachOArm64Mac(spec = {}) {
  return buildMacMachO(spec, 'arm64');
}

/**
 * Builds a genuine 64-bit x86-64 macOS Mach-O executable.
 */
export function buildMachOX86_64Mac(spec = {}) {
  return buildMacMachO(spec, 'x86_64');
}

/**
 * Wraps one or more thin Mach-O 64 slices into a genuine Apple Universal Fat Mach-O (`0xCAFEBABE`).
 */
export function buildUniversalFatMachO(slices) {
  if (!Array.isArray(slices) || slices.length === 0) {
    throw new Error('buildUniversalFatMachO requires a non-empty array of Mach-O slices');
  }

  const parsedSlices = slices.map((raw) => {
    const bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const magic = dv.getUint32(0, true);
    if (magic !== MACHO_CONSTANTS.MH_MAGIC_64 && magic !== MACHO_CONSTANTS.MH_MAGIC) {
      throw new Error(`Invalid thin Mach-O slice magic: 0x${magic.toString(16)}`);
    }
    const cputype = dv.getUint32(4, true);
    const cpusubtype = dv.getUint32(8, true);
    const alignPow = 14; // 16 KiB alignment (compatible with both ARM64 16KB and x86-64 4KB!)
    return { bytes, cputype, cpusubtype, alignPow };
  });

  const headerSize = 8 + parsedSlices.length * 20;
  let cursor = alignUp(headerSize, 1 << 14);
  const layout = [];
  for (const s of parsedSlices) {
    const alignBytes = 1 << s.alignPow;
    cursor = alignUp(cursor, alignBytes);
    layout.push({ ...s, offset: cursor, size: s.bytes.byteLength });
    cursor += s.bytes.byteLength;
  }

  const out = new Uint8Array(cursor);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, MACHO_CONSTANTS.FAT_MAGIC, false); // Big-endian 0xCAFEBABE
  dv.setUint32(4, layout.length, false); // nfat_arch

  for (let i = 0; i < layout.length; i++) {
    const s = layout[i];
    const base = 8 + i * 20;
    dv.setUint32(base + 0, s.cputype, false);
    dv.setUint32(base + 4, s.cpusubtype, false);
    dv.setUint32(base + 8, s.offset, false);
    dv.setUint32(base + 12, s.size, false);
    dv.setUint32(base + 16, s.alignPow, false);
    out.set(s.bytes, s.offset);
  }
  return out;
}

// ============================================================================
// Info.plist & `.app.zip` Bundle Packager
// ============================================================================

function buildInfoPlistDict(spec) {
  const dict = {
    CFBundleDevelopmentRegion: 'en',
    CFBundleDisplayName: spec.appName,
    CFBundleExecutable: spec.executableName,
    CFBundleIdentifier: spec.bundleId,
    CFBundleInfoDictionaryVersion: '6.0',
    CFBundleName: spec.appName,
    CFBundlePackageType: 'APPL',
    CFBundleShortVersionString: spec.version,
    CFBundleVersion: spec.buildNumber,
    LSApplicationCategoryType: spec.category,
    LSMinimumSystemVersion: '14.0',
    NSPrincipalClass: 'NSApplication',
    NSHighResolutionCapable: true,
    NSHumanReadableCopyright: spec.description,
    NSDocumentsFolderUsageDescription: `${spec.appName} reads and saves workspace documents in your Documents folder.`,
    MDItemKeywords: ['macos', 'studio', spec.appName, ...(spec.nonce ? [spec.nonce] : [])],
  };

  if (spec.urlSchemes.length > 0) {
    dict.CFBundleURLTypes = [
      {
        CFBundleURLName: `${spec.bundleId}.url`,
        CFBundleURLSchemes: spec.urlSchemes,
      },
    ];
  }

  if (spec.documentTypes.length > 0) {
    dict.CFBundleDocumentTypes = spec.documentTypes.map((dt) => ({
      CFBundleTypeName: dt.name ?? 'Document',
      CFBundleTypeRole: dt.role ?? 'Editor',
      CFBundleTypeExtensions: dt.extensions ?? [],
      CFBundleTypeMIMETypes: dt.mimeTypes ?? [],
      LSItemContentTypes: dt.contentTypes ?? [],
    }));
  }

  return dict;
}

/**
 * Builds a genuine macOS `.app.zip` package (`<Name>.app/Contents/Info.plist`,
 * `<Name>.app/Contents/MacOS/<Exec>`, `Contents/PkgInfo`, optional `Contents/Resources/`).
 */
export function buildMacAppZip(rawSpec = {}) {
  const spec = normalizeMacSpec(rawSpec);
  const execBytes = spec.universal
    ? buildUniversalFatMachO([buildMachOArm64Mac(spec), buildMachOX86_64Mac(spec)])
    : spec.arch === 'x86_64'
      ? buildMachOX86_64Mac(spec)
      : buildMachOArm64Mac(spec);

  const plistDict = buildInfoPlistDict(spec);
  const plistBytes =
    spec.plistFormat === 'binary'
      ? writeBinaryPlist(plistDict)
      : TEXT_ENCODER.encode(writeXmlPlist(plistDict));

  const bundleDir = `${spec.executableName}.app`;
  const entries = [
    { name: `${bundleDir}/`, data: new Uint8Array(0), isDirectory: true, mtime: DETERMINISTIC_MTIME },
    { name: `${bundleDir}/Contents/`, data: new Uint8Array(0), isDirectory: true, mtime: DETERMINISTIC_MTIME },
    { name: `${bundleDir}/Contents/Info.plist`, data: plistBytes, mtime: DETERMINISTIC_MTIME },
    { name: `${bundleDir}/Contents/PkgInfo`, data: TEXT_ENCODER.encode('APPL????'), mtime: DETERMINISTIC_MTIME },
    { name: `${bundleDir}/Contents/MacOS/`, data: new Uint8Array(0), isDirectory: true, mtime: DETERMINISTIC_MTIME },
    { name: `${bundleDir}/Contents/MacOS/${spec.executableName}`, data: execBytes, mtime: DETERMINISTIC_MTIME },
    { name: `${bundleDir}/Contents/Resources/`, data: new Uint8Array(0), isDirectory: true, mtime: DETERMINISTIC_MTIME },
    {
      name: `${bundleDir}/Contents/Resources/README.txt`,
      data: TEXT_ENCODER.encode(`${spec.appName} ${spec.version}\nBundle: ${spec.bundleId}\n`),
      mtime: DETERMINISTIC_MTIME,
    },
  ];

  return createZip(entries);
}

// ============================================================================
// Synthetic UDIF `.dmg` Builder (Valid 512B BE `koly` + XML `blkx`/`mish`)
// ============================================================================

export function buildTestDmg(spec = {}) {
  const payload =
    spec.payloadBytes instanceof Uint8Array
      ? spec.payloadBytes
      : spec.appZipBytes instanceof Uint8Array
        ? spec.appZipBytes
        : buildMacAppZip(spec);

  const compress = spec.compress !== false;
  const paddedPayloadLen = alignUp(Math.max(512, payload.byteLength), 512);
  const paddedPayload = new Uint8Array(paddedPayloadLen);
  paddedPayload.set(payload, 0);

  const sectorCount = paddedPayloadLen / 512;
  const dataForkBuf = compress
    ? zlib.deflateSync(paddedPayload)
    : paddedPayload;
  const dataForkBytes = new Uint8Array(dataForkBuf.buffer, dataForkBuf.byteOffset, dataForkBuf.byteLength);

  // Build 204-byte big-endian `mish` header + 2 x 40-byte runs (payload run + END run)
  const runCount = 2;
  const mish = new Uint8Array(204 + runCount * 40);
  const mishDv = new DataView(mish.buffer);
  mishDv.setUint32(0, 0x6d697368, false); // 'mish'
  mishDv.setUint32(4, 1, false); // version
  mishDv.setBigUint64(8, 0n, false); // sectorNumber
  mishDv.setBigUint64(16, BigInt(sectorCount), false); // sectorCount
  mishDv.setBigUint64(24, 0n, false); // dataOffset
  mishDv.setUint32(32, 1, false); // buffersNeeded
  mishDv.setUint32(36, 0, false); // blockDescriptors
  mishDv.setUint32(200, runCount, false); // runCount

  // Run 0: ZLIB (0x80000005) or RAW (0x00000001)
  const r0 = 204;
  mishDv.setUint32(r0 + 0, compress ? 0x80000005 : 0x00000001, false);
  mishDv.setUint32(r0 + 4, 0, false);
  mishDv.setBigUint64(r0 + 8, 0n, false);
  mishDv.setBigUint64(r0 + 16, BigInt(sectorCount), false);
  mishDv.setBigUint64(r0 + 24, 0n, false);
  mishDv.setBigUint64(r0 + 32, BigInt(dataForkBytes.byteLength), false);

  // Run 1: END (0xFFFFFFFF)
  const r1 = 244;
  mishDv.setUint32(r1 + 0, 0xffffffff, false);
  mishDv.setUint32(r1 + 4, 0, false);
  mishDv.setBigUint64(r1 + 8, BigInt(sectorCount), false);
  mishDv.setBigUint64(r1 + 16, 0n, false);
  mishDv.setBigUint64(r1 + 24, BigInt(dataForkBytes.byteLength), false);
  mishDv.setBigUint64(r1 + 32, 0n, false);

  const xmlDict = {
    'resource-fork': {
      blkx: [
        {
          Attributes: '0x0050',
          CFName: spec.volumeName ?? `${spec.appName ?? 'OmniStudio'} (Apple_HFS)`,
          Data: mish,
          ID: '0',
          Name: spec.volumeName ?? `${spec.appName ?? 'OmniStudio'} (Apple_HFS : 0)`,
        },
      ],
    },
  };
  const xmlBytes = TEXT_ENCODER.encode(writeXmlPlist(xmlDict));

  const dataForkOffset = 0;
  const dataForkLength = dataForkBytes.byteLength;
  const xmlOffset = dataForkLength;
  const xmlLength = xmlBytes.byteLength;

  // Build 512-byte big-endian `koly` trailer
  const koly = new Uint8Array(512);
  const kolyDv = new DataView(koly.buffer);
  kolyDv.setUint32(0x00, 0x6b6f6c79, false); // 'koly'
  kolyDv.setUint32(0x04, 4, false); // version
  kolyDv.setUint32(0x08, 512, false); // headerSize
  kolyDv.setUint32(0x0c, 1, false); // flags
  kolyDv.setBigUint64(0x10, 0n, false); // runningDataForkOffset
  kolyDv.setBigUint64(0x18, BigInt(dataForkOffset), false);
  kolyDv.setBigUint64(0x20, BigInt(dataForkLength), false);
  kolyDv.setBigUint64(0x28, 0n, false); // rsrcForkOffset
  kolyDv.setBigUint64(0x30, 0n, false); // rsrcForkLength
  kolyDv.setUint32(0x38, 1, false); // segmentNumber
  kolyDv.setUint32(0x3c, 1, false); // segmentCount
  kolyDv.setBigUint64(0xd8, BigInt(xmlOffset), false);
  kolyDv.setBigUint64(0xe0, BigInt(xmlLength), false);
  kolyDv.setUint32(0x1ec, 1, false); // imageVariant
  kolyDv.setBigUint64(0x1f0, BigInt(sectorCount), false);

  const out = new Uint8Array(dataForkLength + xmlLength + 512);
  out.set(dataForkBytes, 0);
  out.set(xmlBytes, xmlOffset);
  out.set(koly, xmlOffset + xmlLength);
  return out;
}

// ============================================================================
// Synthetic Flat Installer `.pkg` Builder (Valid 28B BE XAR + Gzipped CPIO)
// ============================================================================

function buildCpioOdc(files) {
  const chunks = [];
  let ino = 1;
  const pushEntry = (name, data, mode) => {
    const nameBytes = TEXT_ENCODER.encode(`${name}\0`);
    const oct = (n, width) => (n >>> 0).toString(8).padStart(width, '0').slice(-width);
    const hdrStr =
      '070707' +
      oct(0, 6) + // dev
      oct(ino++, 6) + // ino
      oct(mode, 6) + // mode
      oct(0, 6) + // uid
      oct(0, 6) + // gid
      oct(1, 6) + // nlink
      oct(0, 6) + // rdev
      oct(1767225600, 11) + // mtime
      oct(nameBytes.byteLength, 6) + // namesize
      oct(data.byteLength, 11); // filesize
    chunks.push(TEXT_ENCODER.encode(hdrStr), nameBytes, data);
  };

  for (const f of files) {
    const data = f.data instanceof Uint8Array ? f.data : TEXT_ENCODER.encode(String(f.data ?? ''));
    const mode = f.isDirectory ? 0o040755 : (f.mode ?? 0o100644);
    pushEntry(f.name, f.isDirectory ? new Uint8Array(0) : data, mode);
  }
  pushEntry('TRAILER!!!', new Uint8Array(0), 0);

  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.byteLength;
  }
  return out;
}

function escapeXmlAttr(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function buildTestPkg(rawSpec = {}) {
  const spec = normalizeMacSpec(rawSpec);
  const cpioFiles = Array.isArray(rawSpec.cpioFiles) ? rawSpec.cpioFiles : null;

  let filesForCpio;
  if (cpioFiles) {
    filesForCpio = cpioFiles;
  } else {
    const execBytes = spec.universal
      ? buildUniversalFatMachO([buildMachOArm64Mac(spec), buildMachOX86_64Mac(spec)])
      : spec.arch === 'x86_64'
        ? buildMachOX86_64Mac(spec)
        : buildMachOArm64Mac(spec);
    const plistBytes = TEXT_ENCODER.encode(writeXmlPlist(buildInfoPlistDict(spec)));
    const bundleDir = `${spec.executableName}.app`;
    filesForCpio = [
      { name: `./${bundleDir}`, isDirectory: true },
      { name: `./${bundleDir}/Contents`, isDirectory: true },
      { name: `./${bundleDir}/Contents/Info.plist`, data: plistBytes, mode: 0o100644 },
      { name: `./${bundleDir}/Contents/MacOS`, isDirectory: true },
      { name: `./${bundleDir}/Contents/MacOS/${spec.executableName}`, data: execBytes, mode: 0o100755 },
    ];
  }

  const rawCpio = buildCpioOdc(filesForCpio);
  const gzPayload = zlib.gzipSync(rawCpio);
  const payloadBytes = new Uint8Array(gzPayload.buffer, gzPayload.byteOffset, gzPayload.byteLength);

  const pkgInfoXml =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<pkg-info format-version="2" identifier="${escapeXmlAttr(spec.bundleId)}" version="${escapeXmlAttr(spec.version)}" install-location="/Applications" auth="root">\n` +
    `  <payload installKBytes="${Math.ceil(rawCpio.byteLength / 1024)}" numberOfFiles="${filesForCpio.length}"/>\n` +
    `  <bundle path="./${escapeXmlAttr(spec.executableName)}.app" id="${escapeXmlAttr(spec.bundleId)}" CFBundleShortVersionString="${escapeXmlAttr(spec.version)}"/>\n` +
    `</pkg-info>\n`;
  const pkgInfoBytes = TEXT_ENCODER.encode(pkgInfoXml);

  const distXml =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<installer-gui-script minSpecVersion="2">\n` +
    `  <title>${escapeXmlAttr(spec.appName)}</title>\n` +
    `  <pkg-ref id="${escapeXmlAttr(spec.bundleId)}" version="${escapeXmlAttr(spec.version)}">#component.pkg</pkg-ref>\n` +
    `</installer-gui-script>\n`;
  const distBytes = TEXT_ENCODER.encode(distXml);

  // Heap layout: Distribution, PackageInfo, Payload
  const heapFiles = [
    { id: '1', name: 'Distribution', raw: distBytes, encoding: 'application/octet-stream' },
    { id: '2', name: 'PackageInfo', raw: pkgInfoBytes, encoding: 'application/octet-stream' },
    { id: '3', name: 'Payload', raw: payloadBytes, encoding: 'application/octet-stream' },
  ];

  let heapOff = 0;
  const fileEntriesXml = [];
  for (const hf of heapFiles) {
    fileEntriesXml.push(
      `    <file id="${hf.id}">\n` +
        `      <name>${escapeXmlAttr(hf.name)}</name>\n` +
        `      <type>file</type>\n` +
        `      <data>\n` +
        `        <offset>${heapOff}</offset>\n` +
        `        <length>${hf.raw.byteLength}</length>\n` +
        `        <size>${hf.raw.byteLength}</size>\n` +
        `        <encoding style="${hf.encoding}"/>\n` +
        `      </data>\n` +
        `    </file>`
    );
    heapOff += hf.raw.byteLength;
  }

  const tocXml =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<xar>\n` +
    `  <toc>\n` +
    `    <creation-time>2026-01-01T00:00:00Z</creation-time>\n` +
    `${fileEntriesXml.join('\n')}\n` +
    `  </toc>\n` +
    `</xar>\n`;
  const tocUncomp = TEXT_ENCODER.encode(tocXml);
  const tocCompBuf = zlib.deflateSync(tocUncomp);
  const tocComp = new Uint8Array(tocCompBuf.buffer, tocCompBuf.byteOffset, tocCompBuf.byteLength);

  const headerSize = 28;
  const out = new Uint8Array(headerSize + tocComp.byteLength + heapOff);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, 0x78617221, false); // 'xar!'
  dv.setUint16(4, headerSize, false);
  dv.setUint16(6, 1, false); // version
  dv.setBigUint64(8, BigInt(tocComp.byteLength), false);
  dv.setBigUint64(16, BigInt(tocUncomp.byteLength), false);
  dv.setUint32(24, 1, false); // SHA-1 algorithm id

  out.set(tocComp, headerSize);
  let pos = headerSize + tocComp.byteLength;
  for (const hf of heapFiles) {
    out.set(hf.raw, pos);
    pos += hf.raw.byteLength;
  }
  return out;
}

// ============================================================================
// Sample Package Emitter (`packages/macos-studio.app.zip`)
// ============================================================================

export function buildMacStudioSample(outputPath = null) {
  const defaultOut = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../packages/macos-studio.app.zip'
  );
  const targetPath = outputPath ? path.resolve(outputPath) : defaultOut;

  const zipBytes = buildMacAppZip({
    bundleId: 'com.omnios.macos.studio',
    appName: 'OmniStudio',
    executableName: 'OmniStudio',
    version: '1.0.0',
    title: 'OmniStudio — Universal macOS Workspace',
    initialText: 'OmniStudio Ready — Universal ARM64 + x86-64 AppKit App',
    buttonTitle: 'Copy & Sync',
    defaultsKey: 'studio.theme',
    defaultsValue: 'graphite-pro',
    documentFile: '/Users/user/Documents/omnistudio-note.txt',
    documentContent: 'OmniStudio Workspace Document — Cross-Platform macOS Interop',
    urlSchemes: ['omnistudio'],
    documentTypes: [
      {
        name: 'Plain Text Document',
        role: 'Editor',
        extensions: ['txt', 'md'],
        mimeTypes: ['text/plain', 'text/markdown'],
        contentTypes: ['public.plain-text', 'net.daringfireball.markdown'],
      },
    ],
    universal: true,
    plistFormat: 'xml',
  });

  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, zipBytes);

  return {
    outputPath: targetPath,
    sizeBytes: zipBytes.byteLength,
    sha256: crypto.createHash('sha256').update(zipBytes).digest('hex'),
    bytes: zipBytes,
  };
}

// Direct CLI execution: `node sdk/macos-builder.mjs`
const isMainModule =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (isMainModule) {
  const res = buildMacStudioSample();
  console.log(
    `Built ${path.relative(process.cwd(), res.outputPath)} (${res.sizeBytes} bytes, sha256=${res.sha256})`
  );
}
