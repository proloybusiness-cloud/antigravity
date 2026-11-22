/**
 * OmniOS macOS Cocoa / AppKit Bridge & Live Global Top Menu Bar (`F-055`)
 * Zero external dependencies, zero `node:fs` imports.
 *
 * Registers AppKit Objective-C classes and C entry points onto Stage 1A's `ObjCRuntime`:
 *  - `NSApplication` (`sharedApplication`, `delegate`, `setDelegate:`, `mainMenu`, `setMainMenu:`,
 *    `run`, `terminate:`, `stop:`, `windows`, `keyWindow`, `activateIgnoringOtherApps:`)
 *  - `NSWindow` (`initWithContentRect:styleMask:backing:defer:`, `title`, `setTitle:`, `contentView`,
 *    `setContentView:`, `makeKeyAndOrderFront:`, `orderOut:`, `close`, `frame`)
 *  - `NSView`, `NSTextField`, `NSButton`
 *  - `NSMenu`, `NSMenuItem` -> live Compositor Global Top Menu Bar (`menuBar` + `activeMenuBar`)
 *  - `NSAlert` -> Notification Center + modal surface + returns `1000` (`NSAlertFirstButtonReturn`)
 *  - `NSPasteboard` -> live `services.clipboard` (`sourceAppId`, `sourcePlatform: 'macos'`)
 *  - `NSWorkspace` -> live `services.intentRouter.dispatch(...)`
 *  - `NSNotification`
 *  - `_NSApplicationMain(argc, argv)` -> discovers AppDelegate, executes real CPU IMP
 *    `applicationDidFinishLaunching:`, publishes macOS window & live Global Top Menu Bar,
 *    and enters a non-suspending desktop event loop (`waitReason: 'ui_event'`).
 */

const NS_ALERT_FIRST_BUTTON_RETURN = 1000n;
const DEFAULT_WINDOW_WIDTH = 780;
const DEFAULT_WINDOW_HEIGHT = 520;

function toBigIntPtr(val) {
  if (val === null || val === undefined) return 0n;
  if (typeof val === 'bigint') return BigInt.asUintN(64, val);
  if (typeof val === 'number') return BigInt.asUintN(64, BigInt(Math.trunc(val)));
  return 0n;
}

function slugify(str, fallback = 'item') {
  const s = String(str ?? '')
    .trim()
    .toLowerCase()
    .replace(/:+$/g, '')
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return s || fallback;
}

function formatKeyEquivalent(keyEq) {
  if (typeof keyEq !== 'string') return undefined;
  const trimmed = keyEq.trim();
  if (!trimmed) return undefined;
  if (trimmed.includes('+') || trimmed.startsWith('Cmd') || trimmed.startsWith('⌘')) {
    return trimmed;
  }
  return `Cmd+${trimmed.toUpperCase()}`;
}

function pasteboardTypeToMime(typeStr) {
  if (!typeStr) return 'text/plain';
  const low = String(typeStr).trim().toLowerCase();
  if (low.includes('html') || low === 'text/html') return 'text/html';
  if (low.includes('json') || low === 'application/json') return 'application/json';
  if (low.includes('png') || low === 'image/png') return 'image/png';
  return 'text/plain';
}

export class AppKitBridge {
  constructor({
    objcRuntime,
    pcb = null,
    services = {},
    appId = 'com.omnios.macos.app',
    appName = 'macOS App',
    infoPlist = {},
    launchIntent = null,
  } = {}) {
    if (!objcRuntime) {
      throw new TypeError('AppKitBridge requires an ObjCRuntime instance');
    }

    this.objcRuntime = objcRuntime;
    this.pcb = pcb;
    this.services = services ?? {};
    this.compositor = this.services.compositor ?? null;
    this.clipboard = this.services.clipboard ?? null;
    this.notifications = this.services.notifications ?? null;
    this.intentRouter = this.services.intentRouter ?? null;
    this.eventBus = this.services.eventBus ?? null;

    this.appId = appId || pcb?.appId || 'com.omnios.macos.app';
    this.appName =
      appName ||
      infoPlist?.CFBundleDisplayName ||
      infoPlist?.CFBundleName ||
      'macOS App';
    this.infoPlist = infoPlist && typeof infoPlist === 'object' ? { ...infoPlist } : {};
    this.launchIntent = launchIntent ?? null;

    this._seq = 1;
    this._nsAppPtr = 0n;
    this._generalPasteboardPtr = 0n;
    this._sharedWorkspacePtr = 0n;
    this._fallbackClipboard = new Map();
    this._pasteboardChangeCount = 0;

    // Live UI & Menu registries
    this._windows = new Map(); // windowPtr -> window hostData
    this._windowsByCompositorId = new Map(); // windowId -> windowPtr
    this._viewsByNodeId = new Map(); // nodeId -> viewPtr
    this._menuItemsById = new Map(); // menuItemId -> itemPtr
    this._menuItemsByAction = new Map(); // actionSelName -> itemPtr
    this._menuItemsByLabel = new Map(); // lowerLabel -> itemPtr

    // Event loop & lifecycle state (non-suspending desktop model!)
    this.launched = false;
    this.awaitingEvents = false;
    this.terminated = false;
    this.exitCode = 0;
    this._pendingControl = null;

    // Telemetry / observable history
    this.alerts = [];
    this.openedUrls = [];
    this.receivedEvents = [];
    this.activeModal = null;
    this._lastMenuBar = [];
    this._disposed = false;

    this._registerAppKitClasses();
    this._registerAppKitCFunctions();
  }

  _nextId(prefix) {
    return `${prefix}-${this._seq++}`;
  }

  consumePendingControl() {
    const ctrl = this._pendingControl;
    this._pendingControl = null;
    return ctrl;
  }

  _isCpuHalted(cpu) {
    return Boolean(cpu?.halted || cpu?.exited);
  }

  _isExited(cpu) {
    return Boolean(this._isCpuHalted(cpu) || this.terminated);
  }

  _resolveExitCode(cpu, fallback = 0) {
    if (this._isCpuHalted(cpu)) return cpu.exitCode ?? 0;
    if (this.terminated) return this.exitCode;
    return fallback;
  }

  _markExited(cpu, fallback = 0) {
    const code = this._resolveExitCode(cpu, fallback);
    const appData = this._nsAppPtr !== 0n ? this.objcRuntime.getHostObject(this._nsAppPtr) : null;
    if (appData) {
      appData.running = false;
      appData.terminated = true;
    }
    this.awaitingEvents = false;
    this.terminated = true;
    this.exitCode = code;
    this._pendingControl = { status: 'EXITED', exitCode: code };
    return code;
  }

  getWindowIds() {
    const ids = [];
    for (const winData of this._windows.values()) {
      if (winData.compositorWindowId && !winData.closed) {
        ids.push(winData.compositorWindowId);
      }
    }
    return ids;
  }

  getMenuBar() {
    return this._serializeMenuBar();
  }

  // =========================================================================
  // Class Registration on ObjCRuntime
  // =========================================================================

  _registerAppKitClasses() {
    const rt = this.objcRuntime;
    const bridge = this;

    // ---- NSNotification ----
    rt.registerHostClass('NSNotification', 'NSObject', {
      classMethods: {
        'notificationWithName:object:': (_cls, [namePtr, objPtr]) => {
          return rt.allocObject('NSNotification', {
            name: rt.readNSString(namePtr) ?? '',
            objectPtr: toBigIntPtr(objPtr),
            userInfoPtr: 0n,
          });
        },
      },
      instanceMethods: {
        name: (self) => rt.createNSString(rt.getHostObject(self)?.name ?? ''),
        object: (self) => rt.getHostObject(self)?.objectPtr ?? 0n,
        userInfo: (self) => rt.getHostObject(self)?.userInfoPtr ?? 0n,
      },
    });

    // ---- NSApplication ----
    rt.registerHostClass('NSApplication', 'NSObject', {
      classMethods: {
        sharedApplication: () => bridge._ensureSharedApplication(),
      },
      instanceMethods: {
        delegate: (self) => rt.getHostObject(self)?.delegatePtr ?? 0n,
        'setDelegate:': (self, [delegatePtr]) => {
          const data = rt.getHostObject(self);
          if (!data) return 0n;
          const next = toBigIntPtr(delegatePtr);
          if (data.delegatePtr !== next) {
            if (next !== 0n) rt.retain(next);
            if (data.delegatePtr !== 0n) rt.release(data.delegatePtr);
            data.delegatePtr = next;
          }
          return 0n;
        },
        mainMenu: (self) => rt.getHostObject(self)?.mainMenuPtr ?? 0n,
        'setMainMenu:': (self, [menuPtr]) => {
          const data = rt.getHostObject(self);
          if (!data) return 0n;
          const next = toBigIntPtr(menuPtr);
          if (data.mainMenuPtr !== next) {
            if (next !== 0n) rt.retain(next);
            if (data.mainMenuPtr !== 0n) rt.release(data.mainMenuPtr);
            data.mainMenuPtr = next;
          }
          bridge._syncMenuBar();
          return 0n;
        },
        run: (self, _args, { cpu }) => {
          const ctrl = bridge._enterApplicationRunLoop(cpu, self);
          if (ctrl) {
            bridge._pendingControl = ctrl;
          }
          return 0n;
        },
        'terminate:': (self, _args, { cpu }) => {
          bridge._terminateApplication(cpu, self, 0);
          return 0n;
        },
        'stop:': () => {
          bridge.awaitingEvents = false;
          bridge.terminated = true;
          bridge.exitCode = 0;
          bridge._pendingControl = { status: 'EXITED', exitCode: 0 };
          return 0n;
        },
        windows: (self) => {
          const data = rt.getHostObject(self);
          const open = (data?.windows ?? []).filter((wPtr) => {
            const wd = rt.getHostObject(wPtr);
            return wd && !wd.closed;
          });
          return rt.createNSArray(open);
        },
        keyWindow: (self) => {
          const data = rt.getHostObject(self);
          if (!data) return 0n;
          if (data.keyWindowPtr !== 0n) {
            const wd = rt.getHostObject(data.keyWindowPtr);
            if (wd && !wd.closed) return data.keyWindowPtr;
          }
          return data.windows.find((wPtr) => !rt.getHostObject(wPtr)?.closed) ?? 0n;
        },
        mainWindow: (self) => rt.msgSend(null, self, 'keyWindow', []),
        'activateIgnoringOtherApps:': (self) => {
          const data = rt.getHostObject(self);
          if (data) data.active = true;
          const keyPtr = rt.msgSend(null, self, 'keyWindow', []);
          const keyData = keyPtr !== 0n ? rt.getHostObject(keyPtr) : null;
          if (keyData?.compositorWindowId && bridge.compositor) {
            try {
              bridge.compositor.focusWindow(keyData.compositorWindowId);
            } catch {
              // Ignore if window already closed
            }
          }
          return 1n;
        },
        'setActivationPolicy:': (self, [policy]) => {
          const data = rt.getHostObject(self);
          if (data) data.activationPolicy = Number(policy ?? 0n);
          return 1n;
        },
      },
    });

    // ---- NSView ----
    rt.registerHostClass('NSView', 'NSObject', {
      instanceMethods: {
        init: (self) => {
          bridge._initViewData(self, 'view');
          return self;
        },
        'initWithFrame:': (self, _args, { cpu }) => {
          const frame = bridge._readRectFromCpu(cpu, { x: 0, y: 0, width: 400, height: 300 });
          bridge._initViewData(self, 'view', { frame });
          return self;
        },
        'addSubview:': (self, [childPtr]) => {
          const pData = bridge._initViewData(self, 'view');
          const child = toBigIntPtr(childPtr);
          if (child === 0n || child === self) return 0n;
          const cData = rt.getHostObject(child);
          if (!cData) return 0n;
          if (!pData.subviews.includes(child)) {
            pData.subviews.push(child);
            rt.retain(child);
          }
          cData.superviewPtr = self;
          const winPtr = bridge._findEnclosingWindow(self);
          if (winPtr !== 0n) {
            bridge._propagateWindowPtr(child, winPtr);
            bridge._flushWindowSurface(winPtr);
          }
          return 0n;
        },
        removeFromSuperview: (self) => {
          const data = rt.getHostObject(self);
          if (!data || data.superviewPtr === 0n) return 0n;
          const parentData = rt.getHostObject(data.superviewPtr);
          const winPtr = bridge._findEnclosingWindow(self);
          if (parentData && Array.isArray(parentData.subviews)) {
            const idx = parentData.subviews.indexOf(self);
            if (idx >= 0) {
              parentData.subviews.splice(idx, 1);
            }
          }
          data.superviewPtr = 0n;
          data.windowPtr = 0n;
          if (winPtr !== 0n) {
            bridge._flushWindowSurface(winPtr);
          }
          return 0n;
        },
        subviews: (self) => {
          const data = rt.getHostObject(self);
          return rt.createNSArray(data?.subviews ?? []);
        },
        superview: (self) => rt.getHostObject(self)?.superviewPtr ?? 0n,
        window: (self) => bridge._findEnclosingWindow(self),
        tag: (self) => BigInt.asUintN(64, BigInt(rt.getHostObject(self)?.tag ?? 0)),
        'setTag:': (self, [tagVal]) => {
          const data = bridge._initViewData(self, 'view');
          data.tag = Number(BigInt.asIntN(64, toBigIntPtr(tagVal)));
          const winPtr = bridge._findEnclosingWindow(self);
          if (winPtr !== 0n) bridge._flushWindowSurface(winPtr);
          return 0n;
        },
        'viewWithTag:': (self, [tagVal]) => {
          const targetTag = Number(BigInt.asIntN(64, toBigIntPtr(tagVal)));
          return bridge._findViewWithTag(self, targetTag);
        },
        isHidden: (self) => (rt.getHostObject(self)?.hidden ? 1n : 0n),
        'setHidden:': (self, [flag]) => {
          const data = bridge._initViewData(self, 'view');
          data.hidden = toBigIntPtr(flag) !== 0n;
          const winPtr = bridge._findEnclosingWindow(self);
          if (winPtr !== 0n) bridge._flushWindowSurface(winPtr);
          return 0n;
        },
        'setNeedsDisplay:': (self) => {
          const winPtr = bridge._findEnclosingWindow(self);
          if (winPtr !== 0n) bridge._flushWindowSurface(winPtr);
          return 0n;
        },
      },
    });

    // ---- NSTextField (subclass of NSView) ----
    rt.registerHostClass('NSTextField', 'NSView', {
      classMethods: {
        'labelWithString:': (_cls, [strPtr]) => {
          const text = rt.readNSString(strPtr) ?? '';
          const ptr = rt.allocObject('NSTextField', {});
          bridge._initViewData(ptr, 'label', {
            stringValue: text,
            placeholderString: '',
            editable: false,
            bezeled: false,
            drawsBackground: false,
            selectable: true,
            targetPtr: 0n,
            actionSelPtr: 0n,
          });
          return ptr;
        },
        'textFieldWithString:': (_cls, [strPtr]) => {
          const text = rt.readNSString(strPtr) ?? '';
          const ptr = rt.allocObject('NSTextField', {});
          bridge._initViewData(ptr, 'input', {
            stringValue: text,
            placeholderString: '',
            editable: true,
            bezeled: true,
            drawsBackground: true,
            selectable: true,
            targetPtr: 0n,
            actionSelPtr: 0n,
          });
          return ptr;
        },
      },
      instanceMethods: {
        init: (self) => {
          bridge._initViewData(self, 'input', {
            stringValue: '',
            placeholderString: '',
            editable: true,
            bezeled: true,
            drawsBackground: true,
            selectable: true,
            targetPtr: 0n,
            actionSelPtr: 0n,
          });
          return self;
        },
        'initWithFrame:': (self, _args, { cpu }) => {
          const frame = bridge._readRectFromCpu(cpu, { x: 16, y: 16, width: 320, height: 28 });
          bridge._initViewData(self, 'input', {
            frame,
            stringValue: '',
            placeholderString: '',
            editable: true,
            bezeled: true,
            drawsBackground: true,
            selectable: true,
            targetPtr: 0n,
            actionSelPtr: 0n,
          });
          return self;
        },
        stringValue: (self) => rt.createNSString(rt.getHostObject(self)?.stringValue ?? ''),
        'setStringValue:': (self, [strPtr]) => {
          const data = bridge._initViewData(self, 'label');
          data.stringValue = rt.readNSString(strPtr) ?? '';
          const winPtr = bridge._findEnclosingWindow(self);
          if (winPtr !== 0n) bridge._flushWindowSurface(winPtr);
          return 0n;
        },
        placeholderString: (self) => rt.createNSString(rt.getHostObject(self)?.placeholderString ?? ''),
        'setPlaceholderString:': (self, [strPtr]) => {
          const data = bridge._initViewData(self, 'input');
          data.placeholderString = rt.readNSString(strPtr) ?? '';
          const winPtr = bridge._findEnclosingWindow(self);
          if (winPtr !== 0n) bridge._flushWindowSurface(winPtr);
          return 0n;
        },
        isEditable: (self) => (rt.getHostObject(self)?.editable ? 1n : 0n),
        'setEditable:': (self, [flag]) => {
          const data = bridge._initViewData(self, 'input');
          data.editable = toBigIntPtr(flag) !== 0n;
          data.kind = data.editable ? 'input' : 'label';
          const winPtr = bridge._findEnclosingWindow(self);
          if (winPtr !== 0n) bridge._flushWindowSurface(winPtr);
          return 0n;
        },
        'setBezeled:': (self, [flag]) => {
          const data = bridge._initViewData(self, 'label');
          data.bezeled = toBigIntPtr(flag) !== 0n;
          return 0n;
        },
        'setDrawsBackground:': (self, [flag]) => {
          const data = bridge._initViewData(self, 'label');
          data.drawsBackground = toBigIntPtr(flag) !== 0n;
          return 0n;
        },
        'setSelectable:': (self, [flag]) => {
          const data = bridge._initViewData(self, 'label');
          data.selectable = toBigIntPtr(flag) !== 0n;
          return 0n;
        },
        target: (self) => rt.getHostObject(self)?.targetPtr ?? 0n,
        'setTarget:': (self, [tPtr]) => {
          const data = bridge._initViewData(self, 'input');
          data.targetPtr = toBigIntPtr(tPtr);
          return 0n;
        },
        action: (self) => rt.getHostObject(self)?.actionSelPtr ?? 0n,
        'setAction:': (self, [selPtr]) => {
          const data = bridge._initViewData(self, 'input');
          data.actionSelPtr = bridge._normalizeSelectorArg(selPtr);
          return 0n;
        },
      },
    });

    // ---- NSButton (subclass of NSView) ----
    rt.registerHostClass('NSButton', 'NSView', {
      classMethods: {
        'buttonWithTitle:target:action:': (_cls, [titlePtr, targetPtr, actionPtr]) => {
          const title = rt.readNSString(titlePtr) ?? 'Button';
          const ptr = rt.allocObject('NSButton', {});
          bridge._initViewData(ptr, 'button', {
            title,
            targetPtr: toBigIntPtr(targetPtr),
            actionSelPtr: bridge._normalizeSelectorArg(actionPtr),
            enabled: true,
          });
          return ptr;
        },
      },
      instanceMethods: {
        init: (self) => {
          bridge._initViewData(self, 'button', {
            title: 'Button',
            targetPtr: 0n,
            actionSelPtr: 0n,
            enabled: true,
          });
          return self;
        },
        'initWithFrame:': (self, _args, { cpu }) => {
          const frame = bridge._readRectFromCpu(cpu, { x: 16, y: 16, width: 120, height: 32 });
          bridge._initViewData(self, 'button', {
            frame,
            title: 'Button',
            targetPtr: 0n,
            actionSelPtr: 0n,
            enabled: true,
          });
          return self;
        },
        title: (self) => rt.createNSString(rt.getHostObject(self)?.title ?? ''),
        'setTitle:': (self, [titlePtr]) => {
          const data = bridge._initViewData(self, 'button');
          data.title = rt.readNSString(titlePtr) ?? '';
          const winPtr = bridge._findEnclosingWindow(self);
          if (winPtr !== 0n) bridge._flushWindowSurface(winPtr);
          return 0n;
        },
        target: (self) => rt.getHostObject(self)?.targetPtr ?? 0n,
        'setTarget:': (self, [tPtr]) => {
          const data = bridge._initViewData(self, 'button');
          data.targetPtr = toBigIntPtr(tPtr);
          return 0n;
        },
        action: (self) => rt.getHostObject(self)?.actionSelPtr ?? 0n,
        'setAction:': (self, [selPtr]) => {
          const data = bridge._initViewData(self, 'button');
          data.actionSelPtr = bridge._normalizeSelectorArg(selPtr);
          return 0n;
        },
        isEnabled: (self) => (rt.getHostObject(self)?.enabled !== false ? 1n : 0n),
        'setEnabled:': (self, [flag]) => {
          const data = bridge._initViewData(self, 'button');
          data.enabled = toBigIntPtr(flag) !== 0n;
          const winPtr = bridge._findEnclosingWindow(self);
          if (winPtr !== 0n) bridge._flushWindowSurface(winPtr);
          return 0n;
        },
        'performClick:': (self, _args, { cpu }) => {
          bridge._invokeControlAction(cpu, self);
          return 0n;
        },
      },
    });

    // ---- NSWindow ----
    rt.registerHostClass('NSWindow', 'NSObject', {
      instanceMethods: {
        init: (self) => bridge._initWindow(self, { x: 80, y: 60, width: DEFAULT_WINDOW_WIDTH, height: DEFAULT_WINDOW_HEIGHT }),
        'initWithContentRect:styleMask:backing:defer:': (self, _args, { cpu }) => {
          const rect = bridge._readRectFromCpu(cpu, {
            x: 80,
            y: 60,
            width: DEFAULT_WINDOW_WIDTH,
            height: DEFAULT_WINDOW_HEIGHT,
          });
          const width = rect.width >= 100 && rect.width <= 3840 ? rect.width : DEFAULT_WINDOW_WIDTH;
          const height = rect.height >= 80 && rect.height <= 2160 ? rect.height : DEFAULT_WINDOW_HEIGHT;
          return bridge._initWindow(self, { x: rect.x, y: rect.y, width, height });
        },
        title: (self) => rt.createNSString(rt.getHostObject(self)?.title ?? bridge.appName),
        'setTitle:': (self, [titlePtr]) => {
          const data = rt.getHostObject(self);
          if (!data) return 0n;
          data.title = rt.readNSString(titlePtr) ?? bridge.appName;
          bridge._flushWindowSurface(self);
          return 0n;
        },
        contentView: (self) => {
          const data = rt.getHostObject(self);
          if (!data) return 0n;
          if (!data.contentViewPtr || data.contentViewPtr === 0n) {
            const viewPtr = rt.allocObject('NSView', {});
            bridge._initViewData(viewPtr, 'view', { windowPtr: self });
            data.contentViewPtr = viewPtr;
          }
          return data.contentViewPtr;
        },
        'setContentView:': (self, [viewPtr]) => {
          const data = rt.getHostObject(self);
          if (!data) return 0n;
          const v = toBigIntPtr(viewPtr);
          data.contentViewPtr = v;
          if (v !== 0n) {
            rt.retain(v);
            bridge._propagateWindowPtr(v, self);
          }
          bridge._flushWindowSurface(self);
          return 0n;
        },
        'makeKeyAndOrderFront:': (self) => {
          bridge._presentWindow(self, true);
          return 0n;
        },
        'orderFront:': (self) => {
          bridge._presentWindow(self, true);
          return 0n;
        },
        'orderOut:': (self) => {
          const data = rt.getHostObject(self);
          if (!data) return 0n;
          data.visible = false;
          if (data.compositorWindowId && bridge.compositor) {
            try {
              bridge.compositor.setWindowState(data.compositorWindowId, 'minimized');
            } catch {
              // Ignore if already closed
            }
          }
          return 0n;
        },
        close: (self, _args, { cpu }) => {
          bridge._closeWindow(self, cpu, { fromCompositor: false });
          return 0n;
        },
        frame: (self, _args, { cpu }) => {
          const data = rt.getHostObject(self);
          const f = data?.frame ?? { x: 80, y: 60, width: DEFAULT_WINDOW_WIDTH, height: DEFAULT_WINDOW_HEIGHT };
          if (cpu && typeof cpu.setDReg === 'function') {
            cpu.setDReg(0, f.x);
            cpu.setDReg(1, f.y);
            cpu.setDReg(2, f.width);
            cpu.setDReg(3, f.height);
          }
          return 0n;
        },
        center: (self) => {
          const data = rt.getHostObject(self);
          if (data?.frame) {
            data.frame.x = Math.max(20, Math.round((1440 - data.frame.width) / 2));
            data.frame.y = Math.max(40, Math.round((900 - data.frame.height) / 2));
          }
          return 0n;
        },
        'setReleasedWhenClosed:': (self, [flag]) => {
          const data = rt.getHostObject(self);
          if (data) data.releasedWhenClosed = toBigIntPtr(flag) !== 0n;
          return 0n;
        },
      },
    });

    // ---- NSMenu ----
    rt.registerHostClass('NSMenu', 'NSObject', {
      instanceMethods: {
        init: (self) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.id = data.id ?? bridge._nextId('menu');
            data.title = data.title ?? '';
            data.items = data.items ?? [];
          }
          return self;
        },
        'initWithTitle:': (self, [titlePtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.id = data.id ?? bridge._nextId('menu');
            data.title = rt.readNSString(titlePtr) ?? '';
            data.items = data.items ?? [];
          }
          return self;
        },
        title: (self) => rt.createNSString(rt.getHostObject(self)?.title ?? ''),
        'setTitle:': (self, [titlePtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.title = rt.readNSString(titlePtr) ?? '';
            bridge._syncMenuBar();
          }
          return 0n;
        },
        'addItem:': (self, [itemPtr]) => {
          const data = rt.getHostObject(self);
          const item = toBigIntPtr(itemPtr);
          if (!data || item === 0n) return 0n;
          if (!Array.isArray(data.items)) data.items = [];
          if (!data.items.includes(item)) {
            data.items.push(item);
            rt.retain(item);
          }
          bridge._syncMenuBar();
          return 0n;
        },
        'addItemWithTitle:action:keyEquivalent:': (self, [titlePtr, actionPtr, keyEqPtr]) => {
          const itemPtr = rt.allocObject('NSMenuItem', {
            id: bridge._nextId('menuitem'),
            title: rt.readNSString(titlePtr) ?? '',
            actionSelPtr: bridge._normalizeSelectorArg(actionPtr),
            keyEquivalent: rt.readNSString(keyEqPtr) ?? '',
            targetPtr: 0n,
            submenuPtr: 0n,
            enabled: true,
            tag: 0,
            separator: false,
          });
          rt.msgSend(null, self, 'addItem:', [itemPtr]);
          return itemPtr;
        },
        'insertItem:atIndex:': (self, [itemPtr, idxVal]) => {
          const data = rt.getHostObject(self);
          const item = toBigIntPtr(itemPtr);
          if (!data || item === 0n) return 0n;
          if (!Array.isArray(data.items)) data.items = [];
          const idx = Math.max(0, Math.min(data.items.length, Number(idxVal ?? 0n)));
          data.items.splice(idx, 0, item);
          rt.retain(item);
          bridge._syncMenuBar();
          return 0n;
        },
        'removeItem:': (self, [itemPtr]) => {
          const data = rt.getHostObject(self);
          const item = toBigIntPtr(itemPtr);
          if (!data || !Array.isArray(data.items)) return 0n;
          const idx = data.items.indexOf(item);
          if (idx >= 0) {
            data.items.splice(idx, 1);
            bridge._syncMenuBar();
          }
          return 0n;
        },
        removeAllItems: (self) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.items = [];
            bridge._syncMenuBar();
          }
          return 0n;
        },
        itemArray: (self) => rt.createNSArray(rt.getHostObject(self)?.items ?? []),
        numberOfItems: (self) => BigInt((rt.getHostObject(self)?.items ?? []).length),
        'itemWithTitle:': (self, [titlePtr]) => {
          const target = rt.readNSString(titlePtr) ?? '';
          const items = rt.getHostObject(self)?.items ?? [];
          for (const itemPtr of items) {
            if (rt.getHostObject(itemPtr)?.title === target) return itemPtr;
          }
          return 0n;
        },
        'itemWithTag:': (self, [tagVal]) => {
          const target = Number(BigInt.asIntN(64, toBigIntPtr(tagVal)));
          const items = rt.getHostObject(self)?.items ?? [];
          for (const itemPtr of items) {
            if (rt.getHostObject(itemPtr)?.tag === target) return itemPtr;
          }
          return 0n;
        },
      },
    });

    // ---- NSMenuItem ----
    rt.registerHostClass('NSMenuItem', 'NSObject', {
      classMethods: {
        separatorItem: () =>
          rt.allocObject('NSMenuItem', {
            id: bridge._nextId('sep'),
            title: '',
            actionSelPtr: 0n,
            keyEquivalent: '',
            targetPtr: 0n,
            submenuPtr: 0n,
            enabled: false,
            tag: 0,
            separator: true,
          }),
      },
      instanceMethods: {
        init: (self) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.id = data.id ?? bridge._nextId('menuitem');
            data.title = data.title ?? '';
            data.actionSelPtr = data.actionSelPtr ?? 0n;
            data.keyEquivalent = data.keyEquivalent ?? '';
            data.targetPtr = data.targetPtr ?? 0n;
            data.submenuPtr = data.submenuPtr ?? 0n;
            data.enabled = data.enabled !== false;
            data.tag = data.tag ?? 0;
            data.separator = Boolean(data.separator);
          }
          return self;
        },
        'initWithTitle:action:keyEquivalent:': (self, [titlePtr, actionPtr, keyEqPtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.id = data.id ?? bridge._nextId('menuitem');
            data.title = rt.readNSString(titlePtr) ?? '';
            data.actionSelPtr = bridge._normalizeSelectorArg(actionPtr);
            data.keyEquivalent = rt.readNSString(keyEqPtr) ?? '';
            data.targetPtr = 0n;
            data.submenuPtr = 0n;
            data.enabled = true;
            data.tag = 0;
            data.separator = false;
          }
          return self;
        },
        title: (self) => rt.createNSString(rt.getHostObject(self)?.title ?? ''),
        'setTitle:': (self, [titlePtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.title = rt.readNSString(titlePtr) ?? '';
            bridge._syncMenuBar();
          }
          return 0n;
        },
        submenu: (self) => rt.getHostObject(self)?.submenuPtr ?? 0n,
        'setSubmenu:': (self, [menuPtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            const sub = toBigIntPtr(menuPtr);
            data.submenuPtr = sub;
            if (sub !== 0n) rt.retain(sub);
            bridge._syncMenuBar();
          }
          return 0n;
        },
        target: (self) => rt.getHostObject(self)?.targetPtr ?? 0n,
        'setTarget:': (self, [tPtr]) => {
          const data = rt.getHostObject(self);
          if (data) data.targetPtr = toBigIntPtr(tPtr);
          return 0n;
        },
        action: (self) => rt.getHostObject(self)?.actionSelPtr ?? 0n,
        'setAction:': (self, [selPtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.actionSelPtr = bridge._normalizeSelectorArg(selPtr);
            bridge._syncMenuBar();
          }
          return 0n;
        },
        keyEquivalent: (self) => rt.createNSString(rt.getHostObject(self)?.keyEquivalent ?? ''),
        'setKeyEquivalent:': (self, [keyPtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.keyEquivalent = rt.readNSString(keyPtr) ?? '';
            bridge._syncMenuBar();
          }
          return 0n;
        },
        isEnabled: (self) => (rt.getHostObject(self)?.enabled !== false ? 1n : 0n),
        'setEnabled:': (self, [flag]) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.enabled = toBigIntPtr(flag) !== 0n;
            bridge._syncMenuBar();
          }
          return 0n;
        },
        tag: (self) => BigInt.asUintN(64, BigInt(rt.getHostObject(self)?.tag ?? 0)),
        'setTag:': (self, [tagVal]) => {
          const data = rt.getHostObject(self);
          if (data) data.tag = Number(BigInt.asIntN(64, toBigIntPtr(tagVal)));
          return 0n;
        },
        isSeparatorItem: (self) => (rt.getHostObject(self)?.separator ? 1n : 0n),
      },
    });

    // ---- NSAlert ----
    rt.registerHostClass('NSAlert', 'NSObject', {
      instanceMethods: {
        init: (self) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.messageText = data.messageText ?? '';
            data.informativeText = data.informativeText ?? '';
            data.buttons = data.buttons ?? [];
          }
          return self;
        },
        messageText: (self) => rt.createNSString(rt.getHostObject(self)?.messageText ?? ''),
        'setMessageText:': (self, [strPtr]) => {
          const data = rt.getHostObject(self);
          if (data) data.messageText = rt.readNSString(strPtr) ?? '';
          return 0n;
        },
        informativeText: (self) => rt.createNSString(rt.getHostObject(self)?.informativeText ?? ''),
        'setInformativeText:': (self, [strPtr]) => {
          const data = rt.getHostObject(self);
          if (data) data.informativeText = rt.readNSString(strPtr) ?? '';
          return 0n;
        },
        'addButtonWithTitle:': (self, [titlePtr]) => {
          const data = rt.getHostObject(self);
          const title = rt.readNSString(titlePtr) ?? 'OK';
          if (data) {
            if (!Array.isArray(data.buttons)) data.buttons = [];
            data.buttons.push(title);
          }
          return rt.allocObject('NSButton', { title, enabled: true });
        },
        runModal: (self) => {
          const data = rt.getHostObject(self) ?? {};
          const alertRecord = {
            id: bridge._nextId('alert'),
            messageText: data.messageText || bridge.appName,
            informativeText: data.informativeText || '',
            buttons: data.buttons?.length ? [...data.buttons] : ['OK'],
            ts: new Date().toISOString(),
          };
          bridge.alerts.push(alertRecord);
          bridge.activeModal = alertRecord;

          if (bridge.notifications && typeof bridge.notifications.post === 'function') {
            try {
              bridge.notifications.post({
                appId: bridge.appId,
                platform: 'macos',
                title: alertRecord.messageText,
                body: alertRecord.informativeText,
                category: 'alert',
                actions: alertRecord.buttons.map((b, idx) => ({
                  id: `alert-btn-${idx}`,
                  label: b,
                })),
              });
            } catch {
              // Isolate notification errors
            }
          }

          // Flush active modal onto key window surface
          const keyPtr = bridge._getKeyWindowPtr();
          if (keyPtr !== 0n) {
            bridge._flushWindowSurface(keyPtr);
          }
          return NS_ALERT_FIRST_BUTTON_RETURN;
        },
      },
    });

    // ---- NSPasteboard (backed live by services.clipboard) ----
    rt.registerHostClass('NSPasteboard', 'NSObject', {
      classMethods: {
        generalPasteboard: () => {
          if (bridge._generalPasteboardPtr === 0n) {
            bridge._generalPasteboardPtr = rt.allocObject('NSPasteboard', { name: 'Apple CFPasteboard general' });
          }
          return bridge._generalPasteboardPtr;
        },
      },
      instanceMethods: {
        clearContents: () => {
          bridge._pasteboardChangeCount += 1;
          bridge._fallbackClipboard.clear();
          if (bridge.clipboard && typeof bridge.clipboard.clear === 'function') {
            try {
              bridge.clipboard.clear({ sourceAppId: bridge.appId });
            } catch {
              // Isolate clipboard errors
            }
          }
          return BigInt(bridge._pasteboardChangeCount);
        },
        'stringForType:': (_self, [typePtr]) => {
          const typeStr = typePtr !== 0n ? rt.readNSString(typePtr) : null;
          const mime = pasteboardTypeToMime(typeStr);
          let val = null;
          if (bridge.clipboard && typeof bridge.clipboard.get === 'function') {
            try {
              val = bridge.clipboard.get(mime);
              if (val === null && mime !== 'text/plain') {
                val = bridge.clipboard.get('text/plain');
              }
            } catch {
              val = null;
            }
          } else {
            val = bridge._fallbackClipboard.get(mime) ?? bridge._fallbackClipboard.get('text/plain') ?? null;
          }
          if (val === null || val === undefined) return 0n;
          return rt.createNSString(typeof val === 'string' ? val : JSON.stringify(val));
        },
        'setString:forType:': (_self, [strPtr, typePtr]) => {
          const text = rt.readNSString(strPtr) ?? '';
          const typeStr = typePtr !== 0n ? rt.readNSString(typePtr) : null;
          const mime = pasteboardTypeToMime(typeStr);
          bridge._pasteboardChangeCount += 1;
          bridge._fallbackClipboard.set(mime, text);
          if (mime === 'text/plain') {
            bridge._fallbackClipboard.set('text/plain', text);
          }

          if (bridge.clipboard && typeof bridge.clipboard.set === 'function') {
            try {
              if (mime === 'text/html') {
                bridge.clipboard.set({
                  html: text,
                  text,
                  sourceAppId: bridge.appId,
                  sourcePlatform: 'macos',
                });
              } else {
                bridge.clipboard.set({
                  text,
                  sourceAppId: bridge.appId,
                  sourcePlatform: 'macos',
                });
              }
            } catch {
              return 0n;
            }
          }
          return 1n;
        },
        changeCount: () => BigInt(bridge._pasteboardChangeCount),
      },
    });

    // ---- NSWorkspace (backed live by services.intentRouter) ----
    rt.registerHostClass('NSWorkspace', 'NSObject', {
      classMethods: {
        sharedWorkspace: () => {
          if (bridge._sharedWorkspacePtr === 0n) {
            bridge._sharedWorkspacePtr = rt.allocObject('NSWorkspace', {});
          }
          return bridge._sharedWorkspacePtr;
        },
      },
      instanceMethods: {
        'openURL:': (_self, [urlPtr]) => {
          const urlStr = rt.readNSString(urlPtr);
          if (!urlStr) return 0n;
          bridge.openedUrls.push({ kind: 'url', target: urlStr, ts: new Date().toISOString() });
          if (bridge.intentRouter && typeof bridge.intentRouter.dispatch === 'function') {
            try {
              const res = bridge.intentRouter.dispatch({
                action: 'view',
                uri: urlStr,
                sourcePid: bridge.pcb?.pid ?? null,
              });
              return res?.status === 'NO_HANDLER' ? 0n : 1n;
            } catch {
              return 0n;
            }
          }
          return 1n;
        },
        'openFile:': (_self, [pathPtr]) => {
          const filePath = rt.readNSString(pathPtr);
          if (!filePath) return 0n;
          const dotIdx = filePath.lastIndexOf('.');
          const extension = dotIdx > filePath.lastIndexOf('/') ? filePath.slice(dotIdx).toLowerCase() : null;
          const uri = filePath.startsWith('file://') ? filePath : `file://${filePath}`;
          bridge.openedUrls.push({ kind: 'file', target: filePath, uri, extension, ts: new Date().toISOString() });
          if (bridge.intentRouter && typeof bridge.intentRouter.dispatch === 'function') {
            try {
              const res = bridge.intentRouter.dispatch({
                action: 'view',
                uri,
                extension,
                sourcePid: bridge.pcb?.pid ?? null,
              });
              return res?.status === 'NO_HANDLER' ? 0n : 1n;
            } catch {
              return 0n;
            }
          }
          return 1n;
        },
      },
    });
  }

  _registerAppKitCFunctions() {
    const rt = this.objcRuntime;
    const bridge = this;

    // `_NSApplicationMain(int argc, const char **argv)`
    rt.registerCFunction('NSApplicationMain', (cpu) => {
      const appPtr = bridge._ensureSharedApplication();
      return bridge._enterApplicationRunLoop(cpu, appPtr);
    });
  }

  // =========================================================================
  // Internal AppKit Helpers & Compositor Synchronization
  // =========================================================================

  _ensureSharedApplication() {
    if (this._nsAppPtr !== 0n) return this._nsAppPtr;
    this._nsAppPtr = this.objcRuntime.allocObject('NSApplication', {
      delegatePtr: 0n,
      mainMenuPtr: 0n,
      windows: [],
      keyWindowPtr: 0n,
      running: false,
      terminated: false,
      active: true,
      activationPolicy: 0,
    });
    return this._nsAppPtr;
  }

  _normalizeSelectorArg(selPtrOrStr) {
    const p = toBigIntPtr(selPtrOrStr);
    if (p === 0n) return 0n;
    const obj = this.objcRuntime.getObjectRecord(p);
    if (obj && (obj.className === 'NSString' || obj.className === 'NSMutableString')) {
      return this.objcRuntime.selRegisterName(obj.hostData.value);
    }
    return p;
  }

  _readRectFromCpu(cpu, defaults) {
    if (cpu && typeof cpu.getDReg === 'function') {
      const x = cpu.getDReg(0);
      const y = cpu.getDReg(1);
      const w = cpu.getDReg(2);
      const h = cpu.getDReg(3);
      if (Number.isFinite(w) && Number.isFinite(h) && w >= 1 && h >= 1) {
        return {
          x: Number.isFinite(x) ? Math.round(x) : defaults.x,
          y: Number.isFinite(y) ? Math.round(y) : defaults.y,
          width: Math.round(w),
          height: Math.round(h),
        };
      }
    }
    return { ...defaults };
  }

  _initViewData(ptr, defaultKind, extra = {}) {
    const data = this.objcRuntime.getHostObject(ptr);
    if (!data) return {};
    if (!data.id) data.id = this._nextId(defaultKind);
    if (!data.kind) data.kind = defaultKind;
    if (!Array.isArray(data.subviews)) data.subviews = [];
    if (data.superviewPtr === undefined) data.superviewPtr = 0n;
    if (data.windowPtr === undefined) data.windowPtr = 0n;
    if (data.tag === undefined) data.tag = 0;
    if (data.hidden === undefined) data.hidden = false;
    Object.assign(data, extra);
    this._viewsByNodeId.set(data.id, ptr);
    return data;
  }

  _findEnclosingWindow(viewPtr) {
    let cur = toBigIntPtr(viewPtr);
    let guard = 0;
    while (cur !== 0n && guard++ < 64) {
      const data = this.objcRuntime.getHostObject(cur);
      if (!data) return 0n;
      if (data.windowPtr && data.windowPtr !== 0n) return data.windowPtr;
      cur = data.superviewPtr ?? 0n;
    }
    return 0n;
  }

  _propagateWindowPtr(viewPtr, winPtr) {
    const stack = [toBigIntPtr(viewPtr)];
    const visited = new Set();
    while (stack.length > 0) {
      const cur = stack.pop();
      if (cur === 0n || visited.has(cur)) continue;
      visited.add(cur);
      const data = this.objcRuntime.getHostObject(cur);
      if (!data) continue;
      data.windowPtr = winPtr;
      if (Array.isArray(data.subviews)) {
        for (const child of data.subviews) stack.push(child);
      }
    }
  }

  _findViewWithTag(rootPtr, targetTag) {
    const stack = [toBigIntPtr(rootPtr)];
    const visited = new Set();
    while (stack.length > 0) {
      const cur = stack.pop();
      if (cur === 0n || visited.has(cur)) continue;
      visited.add(cur);
      const data = this.objcRuntime.getHostObject(cur);
      if (!data) continue;
      if (data.tag === targetTag) return cur;
      if (Array.isArray(data.subviews)) {
        for (let i = data.subviews.length - 1; i >= 0; i--) {
          stack.push(data.subviews[i]);
        }
      }
    }
    return 0n;
  }

  _initWindow(self, frame) {
    const rt = this.objcRuntime;
    const data = rt.getHostObject(self);
    if (!data) return self;
    const contentViewPtr = rt.allocObject('NSView', {});
    this._initViewData(contentViewPtr, 'view', { windowPtr: self });

    data.id = data.id ?? this._nextId('nswin');
    data.title = data.title ?? this.appName;
    data.frame = { ...frame };
    data.contentViewPtr = contentViewPtr;
    data.visible = false;
    data.closed = false;
    data.compositorWindowId = null;
    data.releasedWhenClosed = true;

    this._windows.set(self, data);

    const appPtr = this._ensureSharedApplication();
    const appData = rt.getHostObject(appPtr);
    if (appData && !appData.windows.includes(self)) {
      appData.windows.push(self);
    }
    return self;
  }

  _getKeyWindowPtr() {
    if (this._nsAppPtr !== 0n) {
      const appData = this.objcRuntime.getHostObject(this._nsAppPtr);
      if (appData?.keyWindowPtr && appData.keyWindowPtr !== 0n) {
        const kd = this.objcRuntime.getHostObject(appData.keyWindowPtr);
        if (kd && !kd.closed) return appData.keyWindowPtr;
      }
    }
    for (const [winPtr, wd] of this._windows.entries()) {
      if (!wd.closed) return winPtr;
    }
    return 0n;
  }

  _discoverAppDelegateClass() {
    const rt = this.objcRuntime;
    // 1. Explicit NSPrincipalClass if it is an app-defined class (not NSApplication itself)
    const principal = this.infoPlist?.NSPrincipalClass;
    if (typeof principal === 'string' && principal && principal !== 'NSApplication') {
      const rec = rt.getClassRecord(principal);
      if (rec && rec.isAppClass) return rec;
    }
    // 2. Scan loaded app classes for applicationDidFinishLaunching: / applicationWillFinishLaunching:
    for (const rec of rt._classesByName.values()) {
      if (!rec.isAppClass) continue;
      if (
        rec.instanceMethods.has('applicationDidFinishLaunching:') ||
        rec.instanceMethods.has('applicationWillFinishLaunching:')
      ) {
        return rec;
      }
    }
    // 3. Fallback to any app class whose name contains Delegate
    for (const rec of rt._classesByName.values()) {
      if (rec.isAppClass && /delegate/i.test(rec.name)) return rec;
    }
    return null;
  }

  _enterApplicationRunLoop(cpu, appPtr) {
    const rt = this.objcRuntime;
    const appData = rt.getHostObject(appPtr);
    if (!appData) return { status: 'EXITED', exitCode: 1 };

    if (!this.launched) {
      this.launched = true;
      // Ensure delegate is instantiated from Mach-O __objc_classlist if not already set
      if (appData.delegatePtr === 0n) {
        const delegateCls = this._discoverAppDelegateClass();
        if (delegateCls) {
          const inst = rt.allocObject(delegateCls.ptr);
          const inited = rt.msgSend(cpu, inst, 'init', []) || inst;
          if (this._isExited(cpu)) {
            return { status: 'EXITED', exitCode: this._markExited(cpu) };
          }
          appData.delegatePtr = inited;
          rt.retain(inited);
        }
      }

      // Invoke REAL CPU ObjC delegate lifecycle IMPs
      if (appData.delegatePtr !== 0n) {
        const notifPtr = rt.allocObject('NSNotification', {
          name: 'NSApplicationDidFinishLaunchingNotification',
          objectPtr: appPtr,
          userInfoPtr: 0n,
        });
        if (this._objectImplements(appData.delegatePtr, 'applicationWillFinishLaunching:')) {
          rt.msgSend(cpu, appData.delegatePtr, 'applicationWillFinishLaunching:', [notifPtr]);
          if (this._isExited(cpu)) {
            return { status: 'EXITED', exitCode: this._markExited(cpu) };
          }
        }
        if (this._objectImplements(appData.delegatePtr, 'applicationDidFinishLaunching:')) {
          rt.msgSend(cpu, appData.delegatePtr, 'applicationDidFinishLaunching:', [notifPtr]);
          if (this._isExited(cpu)) {
            return { status: 'EXITED', exitCode: this._markExited(cpu) };
          }
        }
      }

      // Deliver any launch intent URLs immediately after launch
      if (this.launchIntent) {
        this._deliverIntentToDelegate(cpu, this.launchIntent);
        if (this._isExited(cpu)) {
          return { status: 'EXITED', exitCode: this._markExited(cpu) };
        }
      }

      // If app created a window without calling makeKeyAndOrderFront:, present it;
      // if app created no window at all, create a minimal default macOS window so it has a surface.
      if (this._windows.size === 0 && !this._isExited(cpu)) {
        const defaultWin = rt.allocObject('NSWindow', {});
        this._initWindow(defaultWin, {
          x: 80,
          y: 60,
          width: DEFAULT_WINDOW_WIDTH,
          height: DEFAULT_WINDOW_HEIGHT,
        });
        this._presentWindow(defaultWin, true);
      } else if (!this._isExited(cpu)) {
        for (const [winPtr, wd] of this._windows.entries()) {
          if (!wd.closed && !wd.compositorWindowId) {
            this._presentWindow(winPtr, true);
          }
        }
      }

      if (this._isExited(cpu)) {
        return { status: 'EXITED', exitCode: this._markExited(cpu) };
      }

      // Ensure live menu bar is synced on all open windows
      this._syncMenuBar();
    }

    if (this._isExited(cpu)) {
      return { status: 'EXITED', exitCode: this._markExited(cpu) };
    }

    appData.running = true;
    this.awaitingEvents = true;
    return { status: 'BLOCKED', waitReason: 'ui_event' };
  }

  _objectImplements(objPtr, selName) {
    if (!objPtr || objPtr === 0n) return false;
    const resolved = this.objcRuntime._resolveReceiverClass(objPtr);
    if (!resolved) return false;
    return Boolean(this.objcRuntime._lookupMethod(resolved.classRec, selName, resolved.isClassMethod));
  }

  _presentWindow(winPtr, makeKey = true) {
    const data = this.objcRuntime.getHostObject(winPtr);
    if (!data || data.closed) return;
    data.visible = true;

    const appPtr = this._ensureSharedApplication();
    const appData = this.objcRuntime.getHostObject(appPtr);
    if (makeKey && appData) {
      appData.keyWindowPtr = winPtr;
    }

    const menuBar = this._serializeMenuBar();
    const uiTree = this._serializeWindowUiTree(winPtr);
    const drawOps = this._buildWindowDrawOps(data);

    if (!this.compositor || !this.pcb) return;

    if (!data.compositorWindowId) {
      const created = this.compositor.createWindow(this.pcb.pid, {
        appId: this.appId,
        platform: 'macos',
        title: data.title || this.appName,
        width: data.frame?.width ?? DEFAULT_WINDOW_WIDTH,
        height: data.frame?.height ?? DEFAULT_WINDOW_HEIGHT,
        x: data.frame?.x,
        y: data.frame?.y,
        chromeStyle: 'macos',
        menuBar,
        uiTree,
        drawOps,
      });
      data.compositorWindowId = created.windowId;
      this._windowsByCompositorId.set(created.windowId, winPtr);
    } else {
      try {
        this.compositor.updateSurface(data.compositorWindowId, {
          title: data.title || this.appName,
          menuBar,
          uiTree,
          drawOps,
        });
        if (makeKey) {
          this.compositor.focusWindow(data.compositorWindowId);
        }
      } catch {
        // Window may have been closed externally
      }
    }
  }

  _flushWindowSurface(winPtr) {
    if (this._disposed || this.terminated) return;
    const data = this.objcRuntime.getHostObject(winPtr);
    if (!data || data.closed || !data.compositorWindowId || !this.compositor) return;
    try {
      this.compositor.updateSurface(data.compositorWindowId, {
        title: data.title || this.appName,
        menuBar: this._serializeMenuBar(),
        uiTree: this._serializeWindowUiTree(winPtr),
        drawOps: this._buildWindowDrawOps(data),
      });
    } catch {
      // Ignore if window already closed
    }
  }

  _syncMenuBar() {
    const menuBar = this._serializeMenuBar();
    this._lastMenuBar = menuBar;
    if (!this.compositor) return;
    for (const wd of this._windows.values()) {
      if (!wd.closed && wd.compositorWindowId) {
        try {
          this.compositor.updateSurface(wd.compositorWindowId, { menuBar });
        } catch {
          // Ignore closed windows
        }
      }
    }
  }

  /**
   * Serializes `NSApp.mainMenu` (`NSMenu`/`NSMenuItem` hierarchy) into Compositor `menuBar` format:
   * `Array<{ id, label, items: Array<{ id, label, shortcut?, disabled?, separator?, action? }> }>`.
   */
  _serializeMenuBar() {
    const rt = this.objcRuntime;
    this._menuItemsById.clear();
    this._menuItemsByAction.clear();
    this._menuItemsByLabel.clear();

    const appData = this._nsAppPtr !== 0n ? rt.getHostObject(this._nsAppPtr) : null;
    const mainMenuPtr = appData?.mainMenuPtr ?? 0n;
    if (mainMenuPtr === 0n) {
      return this._defaultMacMenuBar();
    }

    const mainMenu = rt.getHostObject(mainMenuPtr);
    const topItems = Array.isArray(mainMenu?.items) ? mainMenu.items : [];
    if (topItems.length === 0) {
      return this._defaultMacMenuBar();
    }

    const result = [];
    for (let i = 0; i < topItems.length; i++) {
      const topPtr = topItems[i];
      const topData = rt.getHostObject(topPtr);
      if (!topData) continue;

      const subPtr = topData.submenuPtr ?? 0n;
      const subData = subPtr !== 0n ? rt.getHostObject(subPtr) : null;
      const menuLabel = subData?.title || topData.title || (i === 0 ? this.appName : `Menu ${i + 1}`);
      const menuSlug = slugify(menuLabel, `menu_${i}`);
      const items = [];

      if (subData && Array.isArray(subData.items)) {
        for (let j = 0; j < subData.items.length; j++) {
          const itemPtr = subData.items[j];
          const itemData = rt.getHostObject(itemPtr);
          if (!itemData) continue;

          if (itemData.separator) {
            items.push({
              id: `${menuSlug}.sep_${j}`,
              label: '',
              separator: true,
            });
            continue;
          }

          const actionName = itemData.actionSelPtr ? rt.selGetName(itemData.actionSelPtr) : '';
          const itemId = `${menuSlug}.${slugify(actionName || itemData.title, `item_${j}`)}`;
          itemData.serializedId = itemId;

          this._menuItemsById.set(itemId, itemPtr);
          if (itemData.id) this._menuItemsById.set(itemData.id, itemPtr);
          if (actionName) this._menuItemsByAction.set(actionName, itemPtr);
          if (itemData.title) this._menuItemsByLabel.set(itemData.title.trim().toLowerCase(), itemPtr);

          const entry = {
            id: itemId,
            label: itemData.title || actionName || `Item ${j + 1}`,
          };
          const shortcut = formatKeyEquivalent(itemData.keyEquivalent);
          if (shortcut) entry.shortcut = shortcut;
          if (itemData.enabled === false) entry.disabled = true;
          if (actionName) entry.action = actionName;
          items.push(entry);
        }
      } else {
        // Standalone top-level NSMenuItem without submenu
        const actionName = topData.actionSelPtr ? rt.selGetName(topData.actionSelPtr) : '';
        const itemId = `${menuSlug}.${slugify(actionName || topData.title, 'item_0')}`;
        topData.serializedId = itemId;
        this._menuItemsById.set(itemId, topPtr);
        if (actionName) this._menuItemsByAction.set(actionName, topPtr);
        if (topData.title) this._menuItemsByLabel.set(topData.title.trim().toLowerCase(), topPtr);
        const entry = { id: itemId, label: menuLabel };
        const shortcut = formatKeyEquivalent(topData.keyEquivalent);
        if (shortcut) entry.shortcut = shortcut;
        if (topData.enabled === false) entry.disabled = true;
        if (actionName) entry.action = actionName;
        items.push(entry);
      }

      result.push({
        id: menuSlug,
        label: menuLabel,
        items,
      });
    }

    return result.length > 0 ? result : this._defaultMacMenuBar();
  }

  _defaultMacMenuBar() {
    const appSlug = slugify(this.appName, 'app');
    return [
      {
        id: appSlug,
        label: this.appName,
        items: [
          { id: `${appSlug}.about`, label: `About ${this.appName}`, action: 'orderFrontStandardAboutPanel:' },
          { id: `${appSlug}.sep_0`, label: '', separator: true },
          { id: `${appSlug}.quit`, label: `Quit ${this.appName}`, shortcut: 'Cmd+Q', action: 'terminate:' },
        ],
      },
      {
        id: 'file',
        label: 'File',
        items: [
          { id: 'file.close', label: 'Close Window', shortcut: 'Cmd+W', action: 'performClose:' },
        ],
      },
      {
        id: 'edit',
        label: 'Edit',
        items: [
          { id: 'edit.copy', label: 'Copy', shortcut: 'Cmd+C', action: 'copy:' },
          { id: 'edit.paste', label: 'Paste', shortcut: 'Cmd+V', action: 'paste:' },
        ],
      },
    ];
  }

  _serializeWindowUiTree(winPtr) {
    const rt = this.objcRuntime;
    const winData = rt.getHostObject(winPtr);
    if (!winData) return null;

    const serializeView = (vPtr, depth = 0) => {
      if (vPtr === 0n || depth > 32) return null;
      const obj = rt.getObjectRecord(vPtr);
      const vd = obj?.hostData;
      if (!vd) return null;

      this._viewsByNodeId.set(vd.id, vPtr);

      const node = {
        id: vd.id,
        type: vd.kind || 'view',
        className: obj.className,
        tag: vd.tag ?? 0,
        hidden: Boolean(vd.hidden),
      };

      if (obj.className === 'NSTextField') {
        node.type = vd.editable ? 'input' : 'label';
        node.text = vd.stringValue ?? '';
        node.value = vd.stringValue ?? '';
        node.editable = Boolean(vd.editable);
        if (vd.placeholderString) node.placeholder = vd.placeholderString;
      } else if (obj.className === 'NSButton') {
        node.type = 'button';
        node.label = vd.title ?? 'Button';
        node.text = vd.title ?? 'Button';
        node.enabled = vd.enabled !== false;
        if (vd.actionSelPtr) node.action = rt.selGetName(vd.actionSelPtr);
      }

      if (Array.isArray(vd.subviews) && vd.subviews.length > 0) {
        node.children = [];
        for (const childPtr of vd.subviews) {
          const childNode = serializeView(childPtr, depth + 1);
          if (childNode) node.children.push(childNode);
        }
      }
      return node;
    };

    const rootView =
      winData.contentViewPtr && winData.contentViewPtr !== 0n
        ? serializeView(winData.contentViewPtr, 0)
        : { id: `${winData.id}-root`, type: 'view', children: [] };

    const tree = {
      id: winData.id,
      type: 'window',
      platform: 'macos',
      title: winData.title || this.appName,
      children: rootView ? [rootView] : [],
    };
    if (this.activeModal) {
      tree.modal = { ...this.activeModal };
    }
    return tree;
  }

  _buildWindowDrawOps(winData) {
    const w = winData.frame?.width ?? DEFAULT_WINDOW_WIDTH;
    const h = winData.frame?.height ?? DEFAULT_WINDOW_HEIGHT;
    return [
      { op: 'fillRect', x: 0, y: 0, width: w, height: h, color: '#1e1f24' },
      { op: 'fillRect', x: 0, y: 0, width: w, height: 34, color: '#2a2c34' },
      { op: 'fillText', x: 16, y: 22, text: winData.title || this.appName, color: '#f3f4f6', font: '13px sans-serif' },
    ];
  }

  _closeWindow(winPtr, cpu, { fromCompositor = false } = {}) {
    const rt = this.objcRuntime;
    const data = rt.getHostObject(winPtr);
    if (!data || data.closed) return;
    data.closed = true;
    data.visible = false;

    if (!fromCompositor && data.compositorWindowId && this.compositor) {
      try {
        this.compositor.closeWindow(data.compositorWindowId, { notifyProcess: false });
      } catch {
        // Already closed
      }
    }
    if (data.compositorWindowId) {
      this._windowsByCompositorId.delete(data.compositorWindowId);
      data.compositorWindowId = null;
    }

    // Check remaining open windows
    let remainingOpen = 0;
    for (const wd of this._windows.values()) {
      if (!wd.closed) remainingOpen++;
    }

    if (remainingOpen === 0) {
      const appData = this._nsAppPtr !== 0n ? rt.getHostObject(this._nsAppPtr) : null;
      const delegatePtr = appData?.delegatePtr ?? 0n;
      let shouldTerminate = true;
      if (delegatePtr !== 0n && this._objectImplements(delegatePtr, 'applicationShouldTerminateAfterLastWindowClosed:')) {
        const ret = rt.msgSend(cpu, delegatePtr, 'applicationShouldTerminateAfterLastWindowClosed:', [this._nsAppPtr]);
        if (this._isExited(cpu)) {
          this._markExited(cpu);
          return;
        }
        shouldTerminate = ret !== 0n;
      }
      if (shouldTerminate) {
        this._terminateApplication(cpu, this._nsAppPtr, 0);
      }
    }
  }

  _terminateApplication(cpu, appPtr, exitCode = 0) {
    if (this.terminated) return;
    const rt = this.objcRuntime;
    const appData = appPtr !== 0n ? rt.getHostObject(appPtr) : null;
    const delegatePtr = appData?.delegatePtr ?? 0n;

    if (
      !this._isCpuHalted(cpu) &&
      delegatePtr !== 0n &&
      this._objectImplements(delegatePtr, 'applicationWillTerminate:')
    ) {
      const notifPtr = rt.allocObject('NSNotification', {
        name: 'NSApplicationWillTerminateNotification',
        objectPtr: appPtr,
        userInfoPtr: 0n,
      });
      try {
        rt.msgSend(cpu, delegatePtr, 'applicationWillTerminate:', [notifPtr]);
      } catch {
        // Isolate teardown errors
      }
    }

    const finalExitCode = this._isCpuHalted(cpu) ? (cpu.exitCode ?? 0) : exitCode;

    // Close any remaining Compositor windows cleanly
    for (const wd of this._windows.values()) {
      if (!wd.closed && wd.compositorWindowId && this.compositor) {
        try {
          this.compositor.closeWindow(wd.compositorWindowId, { notifyProcess: false });
        } catch {
          // Ignore
        }
      }
      wd.closed = true;
      wd.compositorWindowId = null;
    }
    this._windowsByCompositorId.clear();

    if (appData) {
      appData.running = false;
      appData.terminated = true;
    }
    this.awaitingEvents = false;
    this.terminated = true;
    this.exitCode = finalExitCode;
    this._pendingControl = { status: 'EXITED', exitCode: finalExitCode };
  }

  _invokeControlAction(cpu, controlPtr) {
    const rt = this.objcRuntime;
    const data = rt.getHostObject(controlPtr);
    if (!data || data.enabled === false) return false;
    const appData = this._nsAppPtr !== 0n ? rt.getHostObject(this._nsAppPtr) : null;
    const targetPtr = data.targetPtr || appData?.delegatePtr || this._nsAppPtr;
    const actionSelPtr = data.actionSelPtr;
    if (!targetPtr || targetPtr === 0n || !actionSelPtr || actionSelPtr === 0n) {
      return false;
    }
    rt.msgSend(cpu, targetPtr, actionSelPtr, [controlPtr]);
    if (this._isExited(cpu)) {
      this._markExited(cpu);
      return true;
    }
    const winPtr = this._findEnclosingWindow(controlPtr) || this._getKeyWindowPtr();
    if (winPtr !== 0n) this._flushWindowSurface(winPtr);
    return true;
  }

  _deliverIntentToDelegate(cpu, intent) {
    const rt = this.objcRuntime;
    const appData = this._nsAppPtr !== 0n ? rt.getHostObject(this._nsAppPtr) : null;
    const delegatePtr = appData?.delegatePtr ?? 0n;
    if (delegatePtr === 0n) return false;

    const rawUri = intent?.uri ?? intent?.url ?? null;
    const urlsList = Array.isArray(intent?.urls)
      ? intent.urls
      : rawUri
        ? [rawUri]
        : [];
    if (urlsList.length === 0) return false;

    const urlClass = rt.getClass('NSURL');
    const urlPtrs = urlsList.map((u) => {
      const nsStr = rt.createNSString(String(u));
      return urlClass !== 0n ? rt.msgSend(cpu, urlClass, 'URLWithString:', [nsStr]) : nsStr;
    });
    const urlsArr = rt.createNSArray(urlPtrs);

    if (this._objectImplements(delegatePtr, 'application:openURLs:')) {
      rt.msgSend(cpu, delegatePtr, 'application:openURLs:', [this._nsAppPtr, urlsArr]);
      if (this._isExited(cpu)) {
        this._markExited(cpu);
        return true;
      }
      const keyPtr = this._getKeyWindowPtr();
      if (keyPtr !== 0n) this._flushWindowSurface(keyPtr);
      return true;
    }
    if (this._objectImplements(delegatePtr, 'application:openFile:')) {
      const pathStr = rt.createNSString(String(urlsList[0]).replace(/^file:\/\//, ''));
      rt.msgSend(cpu, delegatePtr, 'application:openFile:', [this._nsAppPtr, pathStr]);
      if (this._isExited(cpu)) {
        this._markExited(cpu);
        return true;
      }
      const keyPtr = this._getKeyWindowPtr();
      if (keyPtr !== 0n) this._flushWindowSurface(keyPtr);
      return true;
    }
    return false;
  }

  // =========================================================================
  // Live Event Routing from Compositor & IntentRouter (`handleEvent`)
  // =========================================================================

  /**
   * Synchronously handles UI, Global Menu Bar, Intent, and Window events by invoking
   * REAL guest CPU Objective-C IMPs and flushing updated state to Compositor.
   * Non-suspending desktop lifecycle: background/blur/minimize NEVER suspend the app!
   */
  handleEvent(cpu, event) {
    if (!event || typeof event !== 'object') return { handled: false };
    if (this._isExited(cpu)) {
      return { handled: false, exited: true, exitCode: this._markExited(cpu) };
    }
    this.receivedEvents.push({
      type: event.type,
      ts: new Date().toISOString(),
    });

    const rt = this.objcRuntime;
    const appData = this._nsAppPtr !== 0n ? rt.getHostObject(this._nsAppPtr) : null;
    const delegatePtr = appData?.delegatePtr ?? 0n;
    const type = String(event.type ?? '').toLowerCase();

    // 1. Live Global Top Menu Bar Action (`menu_action`)
    if (type === 'menu_action') {
      // Ensure menu index maps are up to date
      this._serializeMenuBar();

      const itemId = event.itemId ?? event.id ?? null;
      const actionReq = event.action ?? null;
      const labelReq = typeof event.label === 'string' ? event.label.trim().toLowerCase() : null;

      let itemPtr = 0n;
      if (itemId && this._menuItemsById.has(itemId)) {
        itemPtr = this._menuItemsById.get(itemId);
      } else if (actionReq && this._menuItemsByAction.has(actionReq)) {
        itemPtr = this._menuItemsByAction.get(actionReq);
      } else if (labelReq && this._menuItemsByLabel.has(labelReq)) {
        itemPtr = this._menuItemsByLabel.get(labelReq);
      }

      if (itemPtr !== 0n) {
        const itemData = rt.getHostObject(itemPtr);
        if (itemData && itemData.enabled !== false && !itemData.separator) {
          const actionSelPtr =
            itemData.actionSelPtr || (actionReq ? rt.selRegisterName(actionReq) : 0n);
          const actionName = actionSelPtr !== 0n ? rt.selGetName(actionSelPtr) : '';

          if (actionName === 'terminate:') {
            this._terminateApplication(cpu, this._nsAppPtr, 0);
            return { handled: true, exited: true, exitCode: this.exitCode };
          }

          const targetPtr = itemData.targetPtr || delegatePtr || this._nsAppPtr;
          if (targetPtr !== 0n && actionSelPtr !== 0n) {
            rt.msgSend(cpu, targetPtr, actionSelPtr, [itemPtr]);
            if (this._isExited(cpu)) {
              return { handled: true, exited: true, exitCode: this._markExited(cpu) };
            }
          }
        }
      } else if (actionReq === 'terminate:') {
        this._terminateApplication(cpu, this._nsAppPtr, 0);
        return { handled: true, exited: true, exitCode: this.exitCode };
      } else if (actionReq && (delegatePtr !== 0n || this._nsAppPtr !== 0n)) {
        const targetPtr = delegatePtr || this._nsAppPtr;
        rt.msgSend(cpu, targetPtr, rt.selRegisterName(actionReq), [0n]);
        if (this._isExited(cpu)) {
          return { handled: true, exited: true, exitCode: this._markExited(cpu) };
        }
      }

      const keyPtr = this._getKeyWindowPtr();
      if (keyPtr !== 0n && !this._isExited(cpu)) {
        this._flushWindowSurface(keyPtr);
      }
      return { handled: true };
    }

    // 2. Button Click / Control Action (`click` / `action`)
    if (type === 'click' || type === 'action') {
      const targetBtn = this._resolveViewFromEvent(event, 'NSButton');
      if (targetBtn !== 0n) {
        this._invokeControlAction(cpu, targetBtn);
        if (this._isExited(cpu)) {
          return { handled: true, exited: true, exitCode: this._markExited(cpu) };
        }
        return { handled: true };
      }
      if (event.action && (delegatePtr !== 0n || this._nsAppPtr !== 0n)) {
        rt.msgSend(cpu, delegatePtr || this._nsAppPtr, rt.selRegisterName(event.action), [0n]);
        if (this._isExited(cpu)) {
          return { handled: true, exited: true, exitCode: this._markExited(cpu) };
        }
        const keyPtr = this._getKeyWindowPtr();
        if (keyPtr !== 0n) this._flushWindowSurface(keyPtr);
        return { handled: true };
      }
      return { handled: false };
    }

    // 3. Text Input / Change (`input` / `change` / `text_input`)
    if (type === 'input' || type === 'change' || type === 'text_input') {
      const targetField = this._resolveViewFromEvent(event, 'NSTextField', true);
      if (targetField !== 0n) {
        const fd = rt.getHostObject(targetField);
        if (fd && fd.editable !== false) {
          fd.stringValue = String(event.value ?? event.text ?? '');
          if (fd.actionSelPtr && fd.actionSelPtr !== 0n) {
            this._invokeControlAction(cpu, targetField);
            if (this._isExited(cpu)) {
              return { handled: true, exited: true, exitCode: this._markExited(cpu) };
            }
          } else {
            const winPtr = this._findEnclosingWindow(targetField) || this._getKeyWindowPtr();
            if (winPtr !== 0n && !this._isExited(cpu)) this._flushWindowSurface(winPtr);
          }
        }
        return { handled: true };
      }
      return { handled: false };
    }

    // 4. Universal Intent / URL / File Open (`intent`)
    if (type === 'intent') {
      this._deliverIntentToDelegate(cpu, event.intent ?? event);
      if (this._isExited(cpu)) {
        return { handled: true, exited: true, exitCode: this._markExited(cpu) };
      }
      return { handled: true };
    }

    // 5. Window Close (`window_close`)
    if (type === 'window_close') {
      const winPtr =
        (event.windowId && this._windowsByCompositorId.get(event.windowId)) ||
        this._getKeyWindowPtr();
      if (winPtr !== 0n) {
        this._closeWindow(winPtr, cpu, { fromCompositor: true });
      } else {
        this._terminateApplication(cpu, this._nsAppPtr, 0);
      }
      if (this._isExited(cpu)) {
        return { handled: true, exited: true, exitCode: this._markExited(cpu) };
      }
      return { handled: true };
    }

    // 6. Desktop lifecycle events (focus, blur, background, minimize) — NEVER suspend!
    if (type === 'focus' && event.windowId) {
      const winPtr = this._windowsByCompositorId.get(event.windowId);
      if (winPtr && appData) {
        appData.keyWindowPtr = winPtr;
        this._syncMenuBar();
      }
      return { handled: true };
    }

    return { handled: false };
  }

  _resolveViewFromEvent(event, expectedClass = null, requireEditable = false) {
    const rt = this.objcRuntime;
    const nodeId = event.nodeId ?? event.targetId ?? event.id ?? null;
    if (nodeId && this._viewsByNodeId.has(nodeId)) {
      return this._viewsByNodeId.get(nodeId);
    }

    // Walk all open windows to match by tag, label/title, or first matching control
    const tag = typeof event.tag === 'number' ? event.tag : null;
    const label = typeof (event.label ?? event.title) === 'string'
      ? (event.label ?? event.title).trim().toLowerCase()
      : null;

    let firstMatch = 0n;
    for (const [winPtr, wd] of this._windows.entries()) {
      if (wd.closed || !wd.contentViewPtr) continue;
      if (tag !== null) {
        const byTag = this._findViewWithTag(wd.contentViewPtr, tag);
        if (byTag !== 0n) return byTag;
      }
      const stack = [wd.contentViewPtr];
      const seen = new Set();
      while (stack.length > 0) {
        const cur = stack.pop();
        if (cur === 0n || seen.has(cur)) continue;
        seen.add(cur);
        const rec = rt.getObjectRecord(cur);
        const vd = rec?.hostData;
        if (!vd) continue;
        const classMatches = !expectedClass || rec.className === expectedClass;
        const editMatches = !requireEditable || vd.editable === true;
        if (classMatches && editMatches) {
          if (firstMatch === 0n) firstMatch = cur;
          const vLabel = String(vd.title ?? vd.placeholderString ?? '').trim().toLowerCase();
          if (label && vLabel === label) return cur;
        }
        if (Array.isArray(vd.subviews)) {
          for (let i = vd.subviews.length - 1; i >= 0; i--) stack.push(vd.subviews[i]);
        }
      }
    }
    return firstMatch;
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    for (const wd of this._windows.values()) {
      if (!wd.closed && wd.compositorWindowId && this.compositor) {
        try {
          this.compositor.closeWindow(wd.compositorWindowId, { notifyProcess: false });
        } catch {
          // Ignore
        }
      }
    }
    this._windows.clear();
    this._windowsByCompositorId.clear();
    this._viewsByNodeId.clear();
    this._menuItemsById.clear();
    this._menuItemsByAction.clear();
    this._menuItemsByLabel.clear();
  }
}

export function createAppKitBridge(opts = {}) {
  return new AppKitBridge(opts);
}
