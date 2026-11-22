/**
 * OmniOS Built-in System App: Binary & Process Inspector (`com.omnios.inspector`, F-072)
 * Deep binary/package inspector (APK/DEX/AXML, PE32/PE32+, IPA/Mach-O/Fat/bplist00, WASM/UAPP)
 * using `pkgManager.inspect()`, `detectFormat()`, and `listZipEntries()` with polymorphic normalization
 * of BOTH string and object items in `sectionsOrClasses` and `importsOrMethods`, PLUS live PID
 * register/VMM/FD/thread debugger via `pcb.executionContext.getDebugState()` & `pcb.addressSpace.getStats()`.
 * Zero host filesystem access.
 */

import { detectFormat } from '../pkg/format-detector.mjs';
import { listZipEntries } from '../pkg/zip.mjs';

export const INSPECTOR_APP_DESCRIPTOR = Object.freeze({
  appId: 'com.omnios.inspector',
  aliases: Object.freeze(['inspector', 'binary-inspector']),
  name: 'Binary Inspector',
  title: 'OmniOS Binary & Process Inspector',
  platform: 'system',
  category: 'Developer',
  icon: 'search-code',
  description: 'Inspect APK/DEX, PE32+, Mach-O/Fat/plist, WASM binaries and live PID registers/VMM pages',
});

const INSPECTOR_MENU_BAR = Object.freeze([
  {
    id: 'inspector',
    label: 'Inspector',
    items: [
      { id: 'inspector.mode_package', label: 'Package / Binary Mode' },
      { id: 'inspector.mode_process', label: 'Live PID Mode' },
      { id: 'inspector.refresh', label: 'Refresh' },
      { id: 'inspector.close', label: 'Close Window' },
    ],
  },
]);

/**
 * Polymorphically normalize section/class items across all 5 platforms:
 * - Android DEX / iOS Mach-O: string items ("Lcom/omnios/calc/MainActivity;", "__TEXT.__text")
 * - Windows PE: { name, virtualAddress, virtualSize, sizeOfRawData, characteristics }
 * - macOS Mach-O: { segment, vmaddr, vmsize, sections }
 * - Universal WASM: { id, name, offset, size }
 */
export function normalizeSectionItem(item) {
  if (typeof item === 'string') {
    return { label: item, kind: 'string', raw: item };
  }
  if (item && typeof item === 'object') {
    if (typeof item.segment === 'string') {
      const subCount = Array.isArray(item.sections) ? item.sections.length : 0;
      return {
        label: `${item.segment} @ ${item.vmaddr ?? '0x0'} (${item.vmsize ?? 0}B, ${subCount} sections)`,
        kind: 'macho-segment',
        name: item.segment,
        vmaddr: item.vmaddr ?? null,
        vmsize: item.vmsize ?? 0,
        sections: Array.isArray(item.sections) ? item.sections : [],
        raw: item,
      };
    }
    if (typeof item.name === 'string' && item.virtualAddress !== undefined) {
      return {
        label: `${item.name} VA=${item.virtualAddress} vsize=${item.virtualSize ?? 0} raw=${item.sizeOfRawData ?? 0}`,
        kind: 'pe-section',
        name: item.name,
        virtualAddress: item.virtualAddress,
        virtualSize: item.virtualSize ?? 0,
        sizeOfRawData: item.sizeOfRawData ?? 0,
        characteristics: item.characteristics ?? null,
        raw: item,
      };
    }
    if (typeof item.name === 'string' && item.id !== undefined) {
      return {
        label: `wasm[${item.id}] ${item.name} (offset=${item.offset ?? 0}, size=${item.size ?? 0}B)`,
        kind: 'wasm-section',
        id: item.id,
        name: item.name,
        offset: item.offset ?? 0,
        size: item.size ?? 0,
        raw: item,
      };
    }
    const fallbackName = item.name ?? item.title ?? JSON.stringify(item);
    return { label: String(fallbackName), kind: 'object', raw: item };
  }
  return { label: String(item), kind: 'unknown', raw: item };
}

/**
 * Polymorphically normalize import/method items across all 5 platforms:
 * - Android DEX / Windows PE / iOS & macOS Mach-O: string items
 * - Universal WASM: { module, name, kind, fullName }
 */
export function normalizeImportItem(item) {
  if (typeof item === 'string') {
    return { label: item, kind: 'string', raw: item };
  }
  if (item && typeof item === 'object') {
    if (typeof item.fullName === 'string') {
      return {
        label: `${item.fullName}${item.kind ? ` (${item.kind})` : ''}`,
        kind: 'wasm-import',
        module: item.module ?? null,
        name: item.name ?? null,
        importKind: item.kind ?? null,
        raw: item,
      };
    }
    if (typeof item.module === 'string' && typeof item.name === 'string') {
      return {
        label: `${item.module}.${item.name}`,
        kind: 'module-import',
        module: item.module,
        name: item.name,
        raw: item,
      };
    }
    return { label: String(item.name ?? item.symbol ?? JSON.stringify(item)), kind: 'object', raw: item };
  }
  return { label: String(item), kind: 'unknown', raw: item };
}

function isZipSignature(bytes) {
  return bytes instanceof Uint8Array && bytes.byteLength >= 4 &&
    bytes[0] === 0x50 && bytes[1] === 0x4b && (bytes[2] === 0x03 || bytes[2] === 0x05) && (bytes[3] === 0x04 || bytes[3] === 0x06);
}

function parseStrictPid(raw) {
  if (typeof raw === 'number') {
    return Number.isSafeInteger(raw) && raw >= 0 ? raw : null;
  }
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!/^\d+$/.test(trimmed)) return null;
    const n = Number(trimmed);
    return Number.isSafeInteger(n) && n >= 0 ? n : null;
  }
  return null;
}

export function createInspectorExecutionContext(os, pcb, launchOpts = {}) {
  const initialPid = launchOpts.pid !== undefined && launchOpts.pid !== null ? parseStrictPid(launchOpts.pid) : null;
  const state = {
    mode: initialPid !== null ? 'process' : 'package',
    targetPath: launchOpts.path ?? null,
    targetPid: initialPid,
    packageReport: null,
    processReport: null,
    statusMessage: 'Select a package path or live PID to inspect',
    errorMessage: null,
  };

  let exited = false;
  let disposed = false;
  let dirty = false;
  let instructionsExecuted = 0;
  let pc = 0x6000;
  let lastSyscall = 'inspector.init';
  let windowId = null;
  let pendingAsync = Promise.resolve();

  const inspectLivePid = (pidNum) => {
    const target = os.processManager.get(pidNum);
    if (!target) {
      state.processReport = null;
      state.errorMessage = `Process PID ${pidNum} not found`;
      return;
    }
    let debugState = null;
    if (target.executionContext && typeof target.executionContext.getDebugState === 'function') {
      try {
        debugState = target.executionContext.getDebugState();
      } catch (err) {
        debugState = { error: err?.message ?? String(err) };
      }
    }
    let vmmStats = null;
    if (target.addressSpace && typeof target.addressSpace.getStats === 'function') {
      try {
        vmmStats = target.addressSpace.getStats();
      } catch (err) {
        vmmStats = { error: err?.message ?? String(err) };
      }
    }
    const summary = os.processManager.toSummary(target);
    const fds = os.processManager.listFds(target.pid);
    const threads = os.processManager.listThreads(target.pid);
    state.mode = 'process';
    state.targetPid = target.pid;
    state.processReport = {
      pid: target.pid,
      ppid: target.ppid,
      name: target.name,
      appId: target.appId,
      platform: target.platform,
      arch: target.arch,
      state: target.state,
      uid: target.uid,
      gid: target.gid,
      cwd: target.cwd,
      debugState,
      vmmStats,
      fds,
      threads,
      summary,
    };
    state.errorMessage = null;
    state.statusMessage = `Inspecting PID ${target.pid} (${target.name}, ${target.arch})`;
    lastSyscall = `inspector.pid:${target.pid}`;
  };

  const inspectBinary = async (source, filenameHint = '') => {
    let bytes;
    let hint = filenameHint;
    if (source instanceof Uint8Array) {
      bytes = source;
    } else if (typeof source === 'string') {
      const pathStr = source.startsWith('file://') ? source.slice('file://'.length) : source;
      hint = hint || pathStr;
      state.targetPath = pathStr;
      bytes = os.vfs.readFile(pathStr, { uid: pcb.uid, gid: pcb.gid });
    } else {
      throw new Error('Binary Inspector requires a VFS path or Uint8Array buffer');
    }

    const detection = detectFormat(bytes, hint, { strictZip: true });
    let inspection = null;
    try {
      inspection = await os.pkgManager.inspect(bytes, hint);
    } catch (inspErr) {
      // Preserve raw format detection even if full package runtime inspection fails
      inspection = {
        format: detection.format,
        platform: detection.platform,
        arch: detection.details?.arch ?? 'unknown',
        appId: null,
        name: hint || 'binary',
        version: null,
        entryPoint: '',
        permissions: [],
        intents: [],
        sectionsOrClasses: [],
        importsOrMethods: [],
        sizeBytes: bytes.byteLength,
        rawMetadata: { inspectionError: inspErr?.message ?? String(inspErr) },
      };
    }

    let zipEntries = [];
    if (isZipSignature(bytes)) {
      try {
        zipEntries = listZipEntries(bytes).slice(0, 200).map((e) => ({
          name: e.name,
          compressedSize: e.compressedSize,
          uncompressedSize: e.uncompressedSize,
          method: e.compressionMethod,
          crc32: `0x${(e.crc32 >>> 0).toString(16).padStart(8, '0')}`,
        }));
      } catch (zipErr) {
        zipEntries = [{ error: zipErr?.message ?? String(zipErr) }];
      }
    }

    const normalizedSections = (inspection.sectionsOrClasses ?? []).map(normalizeSectionItem);
    const normalizedImports = (inspection.importsOrMethods ?? []).map(normalizeImportItem);

    state.mode = 'package';
    state.packageReport = {
      path: state.targetPath,
      filenameHint: hint,
      format: inspection.format,
      platform: inspection.platform,
      arch: inspection.arch,
      architectures: Array.isArray(inspection.rawMetadata?.architectures)
        ? inspection.rawMetadata.architectures
        : [inspection.arch],
      appId: inspection.appId,
      name: inspection.name,
      version: inspection.version,
      entryPoint: inspection.entryPoint,
      sha256: inspection.sha256 ?? null,
      sizeBytes: bytes.byteLength,
      magicHex: detection.magicHex,
      detectionDetails: detection.details ?? {},
      permissions: inspection.permissions ?? [],
      intents: inspection.intents ?? [],
      sectionsOrClasses: normalizedSections,
      importsOrMethods: normalizedImports,
      zipEntries,
      rawMetadata: inspection.rawMetadata ?? {},
    };
    state.errorMessage = null;
    state.statusMessage = `Inspected ${inspection.name} (${inspection.format}, ${inspection.arch}, ${bytes.byteLength}B)`;
    lastSyscall = `inspector.package:${inspection.format}`;
  };

  const buildUiTree = () => {
    const catalog = os.pkgManager?.isReady() ? os.pkgManager.getCatalog() : [];
    const processes = os.processManager.list({ includeTerminated: false });

    return {
      id: 'inspector-root',
      type: 'container',
      role: 'binary-inspector',
      props: {
        appId: INSPECTOR_APP_DESCRIPTOR.appId,
        mode: state.mode,
        targetPath: state.targetPath,
        targetPid: state.targetPid,
        packageReport: state.packageReport,
        processReport: state.processReport,
        statusMessage: state.statusMessage,
        errorMessage: state.errorMessage,
      },
      children: [
        {
          id: 'inspector-toolbar',
          type: 'toolbar',
          props: { mode: state.mode },
          children: [
            {
              id: 'mode-package',
              type: 'button',
              props: { label: 'Package Binary', action: 'set_mode', mode: 'package', active: state.mode === 'package' },
            },
            {
              id: 'mode-process',
              type: 'button',
              props: { label: 'Live PID', action: 'set_mode', mode: 'process', active: state.mode === 'process' },
            },
            { id: 'inspector-refresh', type: 'button', props: { label: 'Refresh', action: 'refresh' } },
          ],
        },
        {
          id: 'inspector-targets',
          type: 'panel',
          props: {
            catalogPackages: catalog.map((c) => ({
              catalogId: c.catalogId,
              appId: c.appId,
              name: c.name,
              platform: c.platform,
              packagePath: c.packagePath,
            })),
            runningProcesses: processes.map((p) => ({
              pid: p.pid,
              name: p.name,
              platform: p.platform,
              arch: p.arch,
              state: p.state,
            })),
          },
        },
        {
          id: 'inspector-report',
          type: 'panel',
          props: {
            mode: state.mode,
            packageReport: state.packageReport,
            processReport: state.processReport,
          },
          children:
            state.mode === 'package' && state.packageReport
              ? [
                  {
                    id: 'inspector-sections',
                    type: 'list',
                    props: { count: state.packageReport.sectionsOrClasses.length },
                    children: state.packageReport.sectionsOrClasses.slice(0, 100).map((sec, idx) => ({
                      id: `sec-${idx}`,
                      type: 'text',
                      props: { text: sec.label, kind: sec.kind },
                    })),
                  },
                  {
                    id: 'inspector-imports',
                    type: 'list',
                    props: { count: state.packageReport.importsOrMethods.length },
                    children: state.packageReport.importsOrMethods.slice(0, 100).map((imp, idx) => ({
                      id: `imp-${idx}`,
                      type: 'text',
                      props: { text: imp.label, kind: imp.kind },
                    })),
                  },
                ]
              : [],
        },
        {
          id: 'inspector-status',
          type: 'statusbar',
          props: {
            text: state.errorMessage ? `Error: ${state.errorMessage}` : state.statusMessage,
            error: state.errorMessage,
          },
        },
      ],
    };
  };

  const renderSurface = () => {
    if (disposed || !windowId || !os.compositor) return;
    if (!os.compositor.getWindow(windowId)) return;
    const suffix =
      state.mode === 'process' && state.targetPid !== null
        ? `PID ${state.targetPid}`
        : state.packageReport?.name ?? 'Ready';
    try {
      os.compositor.updateSurface(windowId, {
        title: `Binary Inspector — ${suffix}`,
        menuBar: INSPECTOR_MENU_BAR,
        uiTree: buildUiTree(),
      });
      dirty = false;
    } catch (err) {
      os.kernel?.log('warn', 'inspector-app', `Failed to update Inspector surface: ${err.message}`);
    }
  };

  const triggerPackageInspect = (source, hint = '') => {
    state.errorMessage = null;
    state.statusMessage = `Inspecting ${hint || 'binary'}...`;
    renderSurface();
    pendingAsync = pendingAsync
      .then(async () => {
        await inspectBinary(source, hint);
        if (!disposed) renderSurface();
      })
      .catch((err) => {
        state.errorMessage = err?.message ?? String(err);
        if (!disposed) renderSurface();
      });
  };

  const dispose = (reason = 'disposed') => {
    if (disposed) return;
    disposed = true;
    exited = true;
    if (windowId && os.compositor?.getWindow(windowId)) {
      try {
        os.compositor.closeWindow(windowId, { notifyProcess: false, reason });
      } catch (err) {
        os.kernel?.log('debug', 'inspector-app', `Window already closed on dispose: ${err.message}`);
      }
    }
  };

  const handleEvent = (event) => {
    if (!event || typeof event !== 'object' || disposed) return;
    pc += 2;
    instructionsExecuted += 5;

    if (event.type === 'window_close' || event.type === 'terminate') {
      lastSyscall = 'window_close';
      dispose(event.type);
      return;
    }

    if (event.type === 'menu_action') {
      const aid = event.actionId ?? event.itemId ?? event.id ?? '';
      if (aid === 'inspector.mode_package') {
        state.mode = 'package';
        renderSurface();
      } else if (aid === 'inspector.mode_process') {
        state.mode = 'process';
        if (state.targetPid !== null) inspectLivePid(state.targetPid);
        renderSurface();
      } else if (aid === 'inspector.refresh') {
        if (state.mode === 'process' && state.targetPid !== null) {
          inspectLivePid(state.targetPid);
          renderSurface();
        } else if (state.targetPath) {
          triggerPackageInspect(state.targetPath, state.targetPath);
        } else {
          renderSurface();
        }
      } else if (aid === 'inspector.close') {
        lastSyscall = 'menu_close';
        dispose('menu_close');
      }
      return;
    }

    if (event.type === 'intent') {
      const intent = event.intent ?? {};
      if (intent.extras?.pid !== undefined) {
        const pidNum = parseStrictPid(intent.extras.pid);
        if (pidNum === null) {
          state.errorMessage = 'Valid targetPid integer required';
        } else {
          inspectLivePid(pidNum);
        }
        renderSurface();
      } else if (intent.uri || intent.extras?.path) {
        const target = intent.extras?.path ?? intent.uri;
        triggerPackageInspect(target, target);
      }
      return;
    }

    const action = event.action ?? '';
    const targetId = event.targetId ?? '';

    if (action === 'set_mode' || targetId === 'mode-package' || targetId === 'mode-process') {
      const mode = event.mode ?? (targetId === 'mode-process' ? 'process' : 'package');
      if (mode === 'package' || mode === 'process') {
        state.mode = mode;
        renderSurface();
      }
      return;
    }

    if (action === 'inspect_pid' || action === 'select_pid') {
      const rawPid =
        event.targetPid ??
        event.data?.pid ??
        event.payload?.pid ??
        (targetId.startsWith('pid-') ? targetId.slice('pid-'.length) : undefined) ??
        event.value ??
        (event.windowId === undefined ? event.pid : undefined);
      const pidNum = parseStrictPid(rawPid);
      if (pidNum === null) {
        state.errorMessage = 'Valid targetPid integer required';
        renderSurface();
        return;
      }
      inspectLivePid(pidNum);
      renderSurface();
      return;
    }

    if (action === 'inspect_package' || action === 'inspect_path' || action === 'inspect_bytes' || action === 'inspect_catalog') {
      if (event.bytes instanceof Uint8Array) {
        triggerPackageInspect(event.bytes, event.filenameHint ?? event.filename ?? 'buffer.bin');
        return;
      }
      if (typeof event.base64 === 'string' && event.base64.length > 0) {
        const bytes = new Uint8Array(Buffer.from(event.base64, 'base64'));
        triggerPackageInspect(bytes, event.filenameHint ?? event.filename ?? 'buffer.bin');
        return;
      }
      if (typeof event.path === 'string' && event.path.length > 0) {
        triggerPackageInspect(event.path, event.filenameHint ?? event.path);
        return;
      }
      const lookup = event.catalogId ?? event.appId;
      if (lookup && os.pkgManager?.isReady()) {
        const cat = os.pkgManager.getCatalog().find((c) => c.catalogId === lookup || c.appId === lookup);
        if (cat?.packagePath) {
          triggerPackageInspect(cat.packagePath, cat.metadata?.filename ?? cat.packagePath);
          return;
        }
      }
      state.errorMessage = 'No valid path, catalogId, or bytes provided for inspection';
      renderSurface();
      return;
    }

    if (action === 'refresh' || targetId === 'inspector-refresh') {
      if (state.mode === 'process' && state.targetPid !== null) {
        inspectLivePid(state.targetPid);
        renderSurface();
      } else if (state.targetPath) {
        triggerPackageInspect(state.targetPath, state.targetPath);
      } else {
        renderSurface();
      }
    }
  };

  if (state.targetPid !== null) {
    inspectLivePid(Number(state.targetPid));
  }

  const win = os.compositor.createWindow(pcb.pid, {
    appId: INSPECTOR_APP_DESCRIPTOR.appId,
    platform: 'system',
    title: 'Binary Inspector — Ready',
    icon: INSPECTOR_APP_DESCRIPTOR.icon,
    width: 840,
    height: 580,
    chromeStyle: 'unified',
    menuBar: INSPECTOR_MENU_BAR,
    uiTree: buildUiTree(),
  });
  windowId = win.windowId;

  const initialPath = launchOpts.path ?? launchOpts.intent?.extras?.path ?? launchOpts.intent?.uri ?? null;
  if (typeof initialPath === 'string' && initialPath.length > 0) {
    triggerPackageInspect(initialPath, initialPath);
  }

  return {
    windowId,
    flushPending: () => pendingAsync,
    step(budget = 100) {
      void budget;
      if (dirty && !disposed) {
        renderSurface();
      }
      if (exited || disposed) {
        return { status: 'EXITED', exitCode: 0, instructionsExecuted: 1 };
      }
      return { status: 'BLOCKED', waitReason: 'ui_event', instructionsExecuted: 1 };
    },
    deliverEvent(event) {
      handleEvent(event);
    },
    getDebugState() {
      return {
        arch: 'native',
        appId: INSPECTOR_APP_DESCRIPTOR.appId,
        pc,
        sp: 0x7ffa0000,
        registers: {
          r0: state.mode === 'package' ? 0 : 1,
          r1: state.targetPid ?? -1,
          r2: state.packageReport?.sectionsOrClasses?.length ?? 0,
        },
        instructionsExecuted,
        lastSyscall,
        stackTop: 0x7ffa0000,
        windowId,
        stateSummary: {
          mode: state.mode,
          targetPath: state.targetPath,
          targetPid: state.targetPid,
          hasPackageReport: Boolean(state.packageReport),
          hasProcessReport: Boolean(state.processReport),
        },
      };
    },
    dispose() {
      dispose('disposed');
    },
  };
}
