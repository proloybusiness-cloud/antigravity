/**
 * OmniOS iOS UIKit, ActivityKit (Dynamic Island), Pasteboard, Notifications & SpringBoard Bridge (`F-053`)
 * Zero external dependencies, zero `node:fs` imports.
 *
 * Registers native UIKit & iOS framework ObjC classes and `_UIApplicationMain` onto `ObjCRuntime`,
 * serializes the live `UIWindow`/`UIViewController`/`UIView` hierarchy into OmniOS Compositor
 * semantic `uiTree` + `drawOps` (`chromeStyle: 'ios'`, 390x844), and dispatches real user clicks,
 * text input, URL-scheme intents, and SpringBoard suspend/resume/terminate lifecycle callbacks
 * directly to the guest app's ARM64 Objective-C IMPs.
 */

const F64_BUF = new ArrayBuffer(8);
const F64_VIEW = new DataView(F64_BUF);

function bitsToF64(u64) {
  F64_VIEW.setBigUint64(0, BigInt.asUintN(64, u64), true);
  return F64_VIEW.getFloat64(0, true);
}

function toBigIntPtr(val) {
  if (val === null || val === undefined) return 0n;
  if (typeof val === 'bigint') return BigInt.asUintN(64, val);
  if (typeof val === 'number') return BigInt.asUintN(64, BigInt(Math.trunc(val)));
  return 0n;
}

function getArm64Arg(cpu, addressSpace, index) {
  if (!cpu) return 0n;
  if (typeof cpu.getReg === 'function') {
    if (index < 8) return BigInt.asUintN(64, BigInt(cpu.getReg(index)));
    if (addressSpace && typeof cpu.getSP === 'function') {
      return addressSpace.readU64(cpu.getSP() + BigInt((index - 8) * 8), true);
    }
  }
  return 0n;
}

const IOS_WINDOW_WIDTH = 390;
const IOS_WINDOW_HEIGHT = 844;

const UI_COLOR_PRESETS = Object.freeze({
  whiteColor: '#ffffff',
  blackColor: '#000000',
  clearColor: 'transparent',
  systemBackgroundColor: '#0b1220',
  secondarySystemBackgroundColor: '#162033',
  labelColor: '#f8fafc',
  secondaryLabelColor: '#94a3b8',
  systemBlueColor: '#0a84ff',
  systemGreenColor: '#30d158',
  systemOrangeColor: '#ff9f0a',
  systemRedColor: '#ff453a',
  systemIndigoColor: '#5e5ce6',
  systemTealColor: '#64d2ff',
  darkGrayColor: '#334155',
  lightGrayColor: '#cbd5e1',
});

export class UIKitBridge {
  constructor({
    objcRuntime,
    cpu = null,
    darwinSyscalls = null,
    addressSpace = null,
    compositor = null,
    notifications = null,
    clipboard = null,
    intentRouter = null,
    configStore = null,
    vfs = null,
    permissions = null,
    processManager = null,
    pcb = null,
    appRecord = null,
    infoPlist = null,
    launchOptions = null,
  } = {}) {
    if (!objcRuntime) {
      throw new TypeError('UIKitBridge requires an ObjCRuntime instance');
    }

    this.objcRuntime = objcRuntime;
    this.cpu = cpu;
    this.darwinSyscalls = darwinSyscalls;
    this.addressSpace = addressSpace ?? objcRuntime.addressSpace;
    this.compositor = compositor;
    this.notifications = notifications;
    this.clipboard = clipboard;
    this.intentRouter = intentRouter;
    this.configStore = configStore;
    this.vfs = vfs;
    this.permissions = permissions;
    this.processManager = processManager;
    this.pcb = pcb;
    this.appRecord = appRecord;
    this.infoPlist = infoPlist ?? appRecord?.metadata?.infoPlist ?? {};
    this.launchOptions = launchOptions ?? {};
    this.appId = appRecord?.appId ?? pcb?.appId ?? objcRuntime.appId ?? 'com.omnios.ios.app';
    this.appName =
      appRecord?.name ??
      this.infoPlist?.CFBundleDisplayName ??
      this.infoPlist?.CFBundleName ??
      this.appId;

    this.runLoopActive = false;
    this.shouldExit = false;
    this.exitCode = 0;
    this.lifecycleState = 'NotRunning';
    this.isSuspended = false;

    this.windowId = null;
    this.applicationPtr = 0n;
    this.delegatePtr = 0n;
    this.keyWindowPtr = 0n;
    this.windows = [];
    this.activeAlerts = [];
    this.liveActivities = new Map();
    this.openedUrls = [];
    this.lifecycleHistory = [];
    this.uiTree = null;
    this.drawOps = [];

    this._pasteboardPtr = 0n;
    this._notifCenterPtr = 0n;
    this._idleTimerDisabled = false;
    this._nextNodeSeq = 1;
    this._controlNodeIndex = new Map(); // nodeId -> viewPtr
    this._registered = false;
    this._disposed = false;

    this.registerUIKitClasses();
  }

  setCpu(cpu) {
    this.cpu = cpu;
  }

  setDarwinSyscalls(darwinSyscalls) {
    this.darwinSyscalls = darwinSyscalls;
  }

  _isExited(cpu = this.cpu) {
    return Boolean(this.darwinSyscalls?.hasExited || cpu?.halted || this.shouldExit);
  }

  _resolveExitCode(cpu = this.cpu, fallback = 0) {
    if (this.darwinSyscalls?.hasExited) return this.darwinSyscalls.exitCode;
    if (cpu?.halted) return cpu.exitCode ?? 0;
    if (this.shouldExit) return this.exitCode;
    return fallback;
  }

  _markExited(cpu = this.cpu, fallback = 0) {
    const code = this._resolveExitCode(cpu, fallback);
    this.lifecycleState = 'Terminated';
    this.isSuspended = false;
    this.runLoopActive = false;
    this.shouldExit = true;
    this.exitCode = code;
    return code;
  }

  _allocViewHostData(kind, extra = {}) {
    const seq = this._nextNodeSeq++;
    return {
      kind,
      seq,
      nodeId: `uikit-${kind}-${seq}`,
      accessibilityIdentifier: null,
      tag: 0,
      hidden: false,
      alpha: 1.0,
      backgroundColor: null,
      frame: { x: 0, y: 0, width: IOS_WINDOW_WIDTH, height: 48 },
      subviews: [],
      superview: 0n,
      ...extra,
    };
  }

  _ensureViewHostData(ptr, kind = 'view') {
    const data = this.objcRuntime.getHostObject(ptr);
    if (!data) return null;
    if (!Array.isArray(data.subviews)) {
      Object.assign(data, this._allocViewHostData(kind), data);
    }
    if (!data.kind) data.kind = kind;
    if (!data.nodeId) {
      data.seq = data.seq ?? this._nextNodeSeq++;
      data.nodeId = `uikit-${data.kind}-${data.seq}`;
    }
    return data;
  }

  _readColorHex(colorPtr) {
    const p = toBigIntPtr(colorPtr);
    if (p === 0n) return null;
    const data = this.objcRuntime.getHostObject(p);
    if (data && typeof data.hex === 'string') return data.hex;
    const str = this.objcRuntime.readNSString(p);
    return str || null;
  }

  _decodeProgressArg(argBig, cpu) {
    const p = toBigIntPtr(argBig);
    if (p !== 0n) {
      const obj = this.objcRuntime.getObjectRecord(p);
      if (obj && obj.className === 'NSNumber') {
        const num = Number(obj.hostData?.value);
        if (!Number.isFinite(num) || num < 0) return null;
        return num > 1 && num <= 100 ? Math.min(1, num / 100) : Math.max(0, Math.min(1, num));
      }
    }

    const signed = BigInt.asIntN(64, p);
    if (signed < 0n) return null;

    if (p === 0n) {
      if (cpu && typeof cpu.getDReg === 'function') {
        const d0 = cpu.getDReg(0);
        if (Number.isFinite(d0) && d0 > 0 && d0 <= 1) return d0;
      }
      return 0;
    }

    if (p <= 100n) {
      return Number(p) / 100;
    }
    if (p <= 1000n) {
      return Number(p) / 1000;
    }
    const asF64 = bitsToF64(p);
    if (Number.isFinite(asF64) && asF64 >= 0 && asF64 <= 1) {
      return asF64;
    }
    return null;
  }

  _findSubviewByTag(rootPtr, targetTag, visited = new Set()) {
    const p = toBigIntPtr(rootPtr);
    if (p === 0n || visited.has(p)) return 0n;
    visited.add(p);
    const data = this.objcRuntime.getHostObject(p);
    if (!data) return 0n;
    if (Number(data.tag) === targetTag) return p;
    if (Array.isArray(data.subviews)) {
      for (const child of data.subviews) {
        const hit = this._findSubviewByTag(child, targetTag, visited);
        if (hit !== 0n) return hit;
      }
    }
    return 0n;
  }

  _maybeFlush() {
    if (this._disposed || this._isExited(this.cpu)) return;
    if (this.runLoopActive || this.windowId !== null || this.keyWindowPtr !== 0n) {
      this.flushToCompositor();
    }
  }

  // =========================================================================
  // UIKit & iOS Framework Class Registration on ObjCRuntime
  // =========================================================================

  registerUIKitClasses() {
    if (this._registered) return;
    this._registered = true;
    const rt = this.objcRuntime;

    // ---- UIColor ----
    const colorClassMethods = {
      'colorWithRed:green:blue:alpha:': (_cls, _args, { cpu }) => {
        const clamp255 = (v) => Math.max(0, Math.min(255, Math.round((Number(v) || 0) * 255)));
        const r = clamp255(cpu?.getDReg?.(0) ?? 0);
        const g = clamp255(cpu?.getDReg?.(1) ?? 0);
        const b = clamp255(cpu?.getDReg?.(2) ?? 0);
        const hex = `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
        return rt.allocObject('UIColor', { hex });
      },
    };
    for (const [sel, hex] of Object.entries(UI_COLOR_PRESETS)) {
      colorClassMethods[sel] = () => rt.allocObject('UIColor', { hex });
    }
    rt.registerHostClass('UIColor', 'NSObject', {
      classMethods: colorClassMethods,
      instanceMethods: {
        description: (self) => rt.createNSString(rt.getHostObject(self)?.hex ?? '#000000'),
      },
    });

    // ---- UIFont ----
    rt.registerHostClass('UIFont', 'NSObject', {
      classMethods: {
        'systemFontOfSize:': (_cls, [szArg], { cpu }) => {
          const d0 = cpu?.getDReg?.(0);
          const size = Number.isFinite(d0) && d0 > 0 ? d0 : Number(szArg || 17n);
          return rt.allocObject('UIFont', { name: 'SF Pro', size, weight: 'regular' });
        },
        'boldSystemFontOfSize:': (_cls, [szArg], { cpu }) => {
          const d0 = cpu?.getDReg?.(0);
          const size = Number.isFinite(d0) && d0 > 0 ? d0 : Number(szArg || 17n);
          return rt.allocObject('UIFont', { name: 'SF Pro Bold', size, weight: 'bold' });
        },
        'monospacedSystemFontOfSize:weight:': (_cls, [szArg], { cpu }) => {
          const d0 = cpu?.getDReg?.(0);
          const size = Number.isFinite(d0) && d0 > 0 ? d0 : Number(szArg || 14n);
          return rt.allocObject('UIFont', { name: 'SF Mono', size, weight: 'medium' });
        },
        'fontWithName:size:': (_cls, [namePtr, szArg], { cpu }) => {
          const d0 = cpu?.getDReg?.(0);
          const size = Number.isFinite(d0) && d0 > 0 ? d0 : Number(szArg || 17n);
          return rt.allocObject('UIFont', {
            name: rt.readNSString(namePtr) || 'SF Pro',
            size,
            weight: 'regular',
          });
        },
      },
      instanceMethods: {
        fontName: (self) => rt.createNSString(rt.getHostObject(self)?.name ?? 'SF Pro'),
      },
    });

    // ---- UIView ----
    rt.registerHostClass('UIView', 'NSObject', {
      instanceMethods: {
        init: (self) => {
          this._ensureViewHostData(self, 'view');
          return self;
        },
        'initWithFrame:': (self, _args, { cpu }) => {
          const data = this._ensureViewHostData(self, 'view');
          if (data && cpu && typeof cpu.getDReg === 'function') {
            const x = cpu.getDReg(0);
            const y = cpu.getDReg(1);
            const w = cpu.getDReg(2);
            const h = cpu.getDReg(3);
            if (Number.isFinite(w) && w > 0 && Number.isFinite(h) && h > 0) {
              data.frame = { x: Number.isFinite(x) ? x : 0, y: Number.isFinite(y) ? y : 0, width: w, height: h };
            }
          }
          return self;
        },
        'addSubview:': (self, [childPtr]) => {
          const child = toBigIntPtr(childPtr);
          if (child === 0n || child === self) return 0n;
          const parentData = this._ensureViewHostData(self, 'view');
          const childData = this._ensureViewHostData(child, 'view');
          if (!parentData || !childData) return 0n;
          if (childData.superview && childData.superview !== 0n && childData.superview !== self) {
            const prevParent = rt.getHostObject(childData.superview);
            if (prevParent && Array.isArray(prevParent.subviews)) {
              prevParent.subviews = prevParent.subviews.filter((p) => p !== child);
            }
          }
          if (!parentData.subviews.includes(child)) {
            rt.retain(child);
            parentData.subviews.push(child);
          }
          childData.superview = self;
          this._maybeFlush();
          return 0n;
        },
        removeFromSuperview: (self, _args, { cpu }) => {
          const data = rt.getHostObject(self);
          if (data && data.superview && data.superview !== 0n) {
            const parentData = rt.getHostObject(data.superview);
            if (parentData && Array.isArray(parentData.subviews)) {
              const idx = parentData.subviews.indexOf(self);
              if (idx >= 0) {
                parentData.subviews.splice(idx, 1);
                rt.release(self, cpu);
              }
            }
            data.superview = 0n;
            this._maybeFlush();
          }
          return 0n;
        },
        subviews: (self) => {
          const data = this._ensureViewHostData(self, 'view');
          return rt.createNSArray(data?.subviews ?? []);
        },
        superview: (self) => rt.getHostObject(self)?.superview ?? 0n,
        'setBackgroundColor:': (self, [colorPtr]) => {
          const data = this._ensureViewHostData(self, 'view');
          if (data) {
            data.backgroundColor = this._readColorHex(colorPtr);
            this._maybeFlush();
          }
          return 0n;
        },
        backgroundColor: (self) => {
          const hex = rt.getHostObject(self)?.backgroundColor;
          return hex ? rt.allocObject('UIColor', { hex }) : 0n;
        },
        'setTag:': (self, [tagVal]) => {
          const data = this._ensureViewHostData(self, 'view');
          if (data) {
            data.tag = Number(BigInt.asIntN(64, toBigIntPtr(tagVal)));
            this._maybeFlush();
          }
          return 0n;
        },
        tag: (self) => BigInt.asUintN(64, BigInt(rt.getHostObject(self)?.tag ?? 0)),
        'viewWithTag:': (self, [tagVal]) => {
          const targetTag = Number(BigInt.asIntN(64, toBigIntPtr(tagVal)));
          return this._findSubviewByTag(self, targetTag);
        },
        'setHidden:': (self, [flag]) => {
          const data = this._ensureViewHostData(self, 'view');
          if (data) {
            data.hidden = toBigIntPtr(flag) !== 0n;
            this._maybeFlush();
          }
          return 0n;
        },
        isHidden: (self) => (rt.getHostObject(self)?.hidden ? 1n : 0n),
        'setAlpha:': (self, _args, { cpu }) => {
          const data = this._ensureViewHostData(self, 'view');
          if (data && cpu && typeof cpu.getDReg === 'function') {
            data.alpha = Math.max(0, Math.min(1, cpu.getDReg(0)));
          }
          return 0n;
        },
        'setAccessibilityIdentifier:': (self, [idPtr]) => {
          const data = this._ensureViewHostData(self, 'view');
          if (data) {
            const idStr = rt.readNSString(idPtr);
            data.accessibilityIdentifier = idStr || null;
            if (idStr) data.nodeId = idStr;
            this._maybeFlush();
          }
          return 0n;
        },
        accessibilityIdentifier: (self) => {
          const id = rt.getHostObject(self)?.accessibilityIdentifier;
          return id ? rt.createNSString(id) : 0n;
        },
        'setFrame:': (self, _args, { cpu }) => {
          const data = this._ensureViewHostData(self, 'view');
          if (data && cpu && typeof cpu.getDReg === 'function') {
            data.frame = {
              x: cpu.getDReg(0),
              y: cpu.getDReg(1),
              width: cpu.getDReg(2),
              height: cpu.getDReg(3),
            };
          }
          return 0n;
        },
        setNeedsDisplay: () => {
          this._maybeFlush();
          return 0n;
        },
        setNeedsLayout: () => {
          this._maybeFlush();
          return 0n;
        },
        layoutIfNeeded: () => {
          this._maybeFlush();
          return 0n;
        },
      },
    });

    // ---- UILabel ----
    rt.registerHostClass('UILabel', 'UIView', {
      instanceMethods: {
        init: (self) => {
          const data = this._ensureViewHostData(self, 'label');
          if (data) {
            data.kind = 'label';
            if (data.text === undefined) data.text = '';
          }
          return self;
        },
        'initWithFrame:': (self, _args, { cpu }) => {
          const data = this._ensureViewHostData(self, 'label');
          if (data) {
            data.kind = 'label';
            if (data.text === undefined) data.text = '';
            if (cpu && typeof cpu.getDReg === 'function') {
              const w = cpu.getDReg(2);
              const h = cpu.getDReg(3);
              if (Number.isFinite(w) && w > 0 && Number.isFinite(h) && h > 0) {
                data.frame = { x: cpu.getDReg(0), y: cpu.getDReg(1), width: w, height: h };
              }
            }
          }
          return self;
        },
        text: (self) => rt.createNSString(rt.getHostObject(self)?.text ?? ''),
        'setText:': (self, [strPtr]) => {
          const data = this._ensureViewHostData(self, 'label');
          if (data) {
            data.kind = 'label';
            data.text = rt.readNSString(strPtr) ?? '';
            this._maybeFlush();
          }
          return 0n;
        },
        'setTextColor:': (self, [colorPtr]) => {
          const data = this._ensureViewHostData(self, 'label');
          if (data) {
            data.textColor = this._readColorHex(colorPtr);
            this._maybeFlush();
          }
          return 0n;
        },
        textColor: (self) => {
          const hex = rt.getHostObject(self)?.textColor;
          return hex ? rt.allocObject('UIColor', { hex }) : 0n;
        },
        'setFont:': (self, [fontPtr]) => {
          const data = this._ensureViewHostData(self, 'label');
          if (data) {
            const f = rt.getHostObject(fontPtr);
            data.font = f ? { name: f.name, size: f.size, weight: f.weight } : null;
          }
          return 0n;
        },
        'setTextAlignment:': (self, [align]) => {
          const data = this._ensureViewHostData(self, 'label');
          if (data) data.textAlignment = Number(align);
          return 0n;
        },
        'setNumberOfLines:': (self, [lines]) => {
          const data = this._ensureViewHostData(self, 'label');
          if (data) data.numberOfLines = Number(lines);
          return 0n;
        },
      },
    });

    // ---- UIButton ----
    rt.registerHostClass('UIButton', 'UIView', {
      classMethods: {
        'buttonWithType:': (_cls, [btnType]) => {
          const props = this._allocViewHostData('button', {
            buttonType: Number(btnType),
            title: '',
            titles: new Map(),
            targets: [],
            enabled: true,
          });
          return rt.allocObject('UIButton', props);
        },
      },
      instanceMethods: {
        init: (self) => {
          const data = this._ensureViewHostData(self, 'button');
          if (data) {
            data.kind = 'button';
            if (!(data.titles instanceof Map)) data.titles = new Map();
            if (!Array.isArray(data.targets)) data.targets = [];
            if (data.title === undefined) data.title = '';
            if (data.enabled === undefined) data.enabled = true;
          }
          return self;
        },
        'initWithFrame:': (self) => {
          return rt.msgSend(this.cpu, self, 'init', []);
        },
        'setTitle:forState:': (self, [titlePtr, state]) => {
          const data = this._ensureViewHostData(self, 'button');
          if (data) {
            data.kind = 'button';
            const title = rt.readNSString(titlePtr) ?? '';
            const st = Number(state);
            if (!(data.titles instanceof Map)) data.titles = new Map();
            data.titles.set(st, title);
            if (st === 0 || !data.title) {
              data.title = title;
            }
            this._maybeFlush();
          }
          return 0n;
        },
        'titleForState:': (self, [state]) => {
          const data = rt.getHostObject(self);
          const st = Number(state);
          const title = data?.titles?.get(st) ?? data?.title ?? '';
          return rt.createNSString(title);
        },
        currentTitle: (self) => {
          const data = rt.getHostObject(self);
          return rt.createNSString(data?.titles?.get(0) ?? data?.title ?? '');
        },
        'setTitleColor:forState:': (self, [colorPtr]) => {
          const data = this._ensureViewHostData(self, 'button');
          if (data) data.titleColor = this._readColorHex(colorPtr);
          return 0n;
        },
        'setEnabled:': (self, [flag]) => {
          const data = this._ensureViewHostData(self, 'button');
          if (data) {
            data.enabled = toBigIntPtr(flag) !== 0n;
            this._maybeFlush();
          }
          return 0n;
        },
        isEnabled: (self) => (rt.getHostObject(self)?.enabled !== false ? 1n : 0n),
        'addTarget:action:forControlEvents:': (self, [targetPtr, actionPtr, events]) => {
          const data = this._ensureViewHostData(self, 'button');
          if (data) {
            data.kind = 'button';
            if (!Array.isArray(data.targets)) data.targets = [];
            const tPtr = toBigIntPtr(targetPtr);
            const aPtr = toBigIntPtr(actionPtr);
            const actionName = rt.selGetName(aPtr);
            data.targets.push({
              target: tPtr,
              actionSelPtr: aPtr,
              actionName,
              events: Number(toBigIntPtr(events) & 0xffffffffn),
            });
            this._maybeFlush();
          }
          return 0n;
        },
        'sendActionsForControlEvents:': (self, [events], { cpu }) => {
          const data = rt.getHostObject(self);
          if (!data || data.enabled === false || !Array.isArray(data.targets)) return 0n;
          const mask = Number(toBigIntPtr(events) & 0xffffffffn);
          const activeCpu = cpu ?? this.cpu;
          for (const entry of data.targets) {
            if (mask === 0 || entry.events === 0 || (entry.events & mask) !== 0) {
              const sel = entry.actionSelPtr !== 0n ? entry.actionSelPtr : entry.actionName;
              rt.msgSend(activeCpu, entry.target, sel, [self]);
              if (this._isExited(activeCpu)) {
                this._markExited(activeCpu);
                return 0n;
              }
            }
          }
          this._maybeFlush();
          return 0n;
        },
      },
    });

    // ---- UITextField ----
    rt.registerHostClass('UITextField', 'UIView', {
      instanceMethods: {
        init: (self) => {
          const data = this._ensureViewHostData(self, 'input');
          if (data) {
            data.kind = 'input';
            if (data.text === undefined) data.text = '';
            if (data.placeholder === undefined) data.placeholder = '';
            if (data.delegatePtr === undefined) data.delegatePtr = 0n;
          }
          return self;
        },
        'initWithFrame:': (self) => rt.msgSend(this.cpu, self, 'init', []),
        text: (self) => rt.createNSString(rt.getHostObject(self)?.text ?? ''),
        'setText:': (self, [strPtr]) => {
          const data = this._ensureViewHostData(self, 'input');
          if (data) {
            data.kind = 'input';
            data.text = rt.readNSString(strPtr) ?? '';
            this._maybeFlush();
          }
          return 0n;
        },
        placeholder: (self) => rt.createNSString(rt.getHostObject(self)?.placeholder ?? ''),
        'setPlaceholder:': (self, [strPtr]) => {
          const data = this._ensureViewHostData(self, 'input');
          if (data) {
            data.kind = 'input';
            data.placeholder = rt.readNSString(strPtr) ?? '';
            this._maybeFlush();
          }
          return 0n;
        },
        'setDelegate:': (self, [delPtr]) => {
          const data = this._ensureViewHostData(self, 'input');
          if (data) data.delegatePtr = toBigIntPtr(delPtr);
          return 0n;
        },
        delegate: (self) => rt.getHostObject(self)?.delegatePtr ?? 0n,
        'setBorderStyle:': (self, [style]) => {
          const data = this._ensureViewHostData(self, 'input');
          if (data) data.borderStyle = Number(style);
          return 0n;
        },
        resignFirstResponder: () => 1n,
        becomeFirstResponder: () => 1n,
      },
    });

    // ---- UIStackView ----
    rt.registerHostClass('UIStackView', 'UIView', {
      instanceMethods: {
        init: (self) => {
          const data = this._ensureViewHostData(self, 'stack');
          if (data) {
            data.kind = 'stack';
            if (!Array.isArray(data.arrangedSubviews)) data.arrangedSubviews = [];
            if (data.axis === undefined) data.axis = 1; // vertical
            if (data.spacing === undefined) data.spacing = 8;
          }
          return self;
        },
        'initWithFrame:': (self) => rt.msgSend(this.cpu, self, 'init', []),
        'initWithArrangedSubviews:': (self, [arrPtr], { cpu }) => {
          rt.msgSend(cpu ?? this.cpu, self, 'init', []);
          const arrData = rt.getHostObject(arrPtr);
          if (arrData && Array.isArray(arrData.items)) {
            for (const item of arrData.items) {
              rt.msgSend(cpu ?? this.cpu, self, 'addArrangedSubview:', [item]);
            }
          }
          return self;
        },
        'addArrangedSubview:': (self, [viewPtr], { cpu }) => {
          const v = toBigIntPtr(viewPtr);
          if (v === 0n) return 0n;
          const data = this._ensureViewHostData(self, 'stack');
          if (data) {
            data.kind = 'stack';
            if (!Array.isArray(data.arrangedSubviews)) data.arrangedSubviews = [];
            if (!data.arrangedSubviews.includes(v)) {
              data.arrangedSubviews.push(v);
            }
          }
          rt.msgSend(cpu ?? this.cpu, self, 'addSubview:', [v]);
          return 0n;
        },
        'removeArrangedSubview:': (self, [viewPtr]) => {
          const v = toBigIntPtr(viewPtr);
          const data = rt.getHostObject(self);
          if (data && Array.isArray(data.arrangedSubviews)) {
            data.arrangedSubviews = data.arrangedSubviews.filter((p) => p !== v);
            this._maybeFlush();
          }
          return 0n;
        },
        arrangedSubviews: (self) => rt.createNSArray(rt.getHostObject(self)?.arrangedSubviews ?? []),
        'setAxis:': (self, [axis]) => {
          const data = this._ensureViewHostData(self, 'stack');
          if (data) {
            data.axis = Number(axis);
            this._maybeFlush();
          }
          return 0n;
        },
        axis: (self) => BigInt(rt.getHostObject(self)?.axis ?? 1),
        'setSpacing:': (self, [spArg], { cpu }) => {
          const data = this._ensureViewHostData(self, 'stack');
          if (data) {
            const d0 = cpu?.getDReg?.(0);
            data.spacing = Number.isFinite(d0) && d0 > 0 ? d0 : Number(spArg || 0n);
            this._maybeFlush();
          }
          return 0n;
        },
        spacing: (self) => BigInt(Math.round(rt.getHostObject(self)?.spacing ?? 8)),
      },
    });

    // ---- UIViewController ----
    rt.registerHostClass('UIViewController', 'NSObject', {
      instanceMethods: {
        init: (self) => {
          const data = rt.getHostObject(self);
          if (data) {
            if (data.title === undefined) data.title = this.appName;
            if (data.viewPtr === undefined) data.viewPtr = 0n;
            if (data.viewLoaded === undefined) data.viewLoaded = false;
            if (data.presentedPtr === undefined) data.presentedPtr = 0n;
          }
          return self;
        },
        view: (self, _args, { cpu }) => {
          const data = rt.getHostObject(self);
          if (!data) return 0n;
          if (!data.viewPtr || data.viewPtr === 0n) {
            const v = rt.allocObject('UIView', this._allocViewHostData('view', { nodeId: 'uikit-root-view' }));
            data.viewPtr = v;
            data.viewLoaded = true;
            rt.msgSend(cpu ?? this.cpu, self, 'viewDidLoad', []);
          }
          return data.viewPtr;
        },
        'setView:': (self, [viewPtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            const v = toBigIntPtr(viewPtr);
            rt.retain(v);
            data.viewPtr = v;
            data.viewLoaded = true;
            this._maybeFlush();
          }
          return 0n;
        },
        title: (self) => rt.createNSString(rt.getHostObject(self)?.title ?? ''),
        'setTitle:': (self, [titlePtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.title = rt.readNSString(titlePtr) ?? '';
            this._maybeFlush();
          }
          return 0n;
        },
        viewDidLoad: () => 0n,
        'viewWillAppear:': () => 0n,
        'viewDidAppear:': () => 0n,
        'viewWillDisappear:': () => 0n,
        'presentViewController:animated:completion:': (self, [vcPtr], { cpu }) => {
          const presented = toBigIntPtr(vcPtr);
          if (presented === 0n) return 0n;
          const data = rt.getHostObject(self);
          if (data) data.presentedPtr = presented;
          const rec = rt.getObjectRecord(presented);
          if (rec && rec.className === 'UIAlertController') {
            if (!this.activeAlerts.includes(presented)) {
              rt.retain(presented);
              this.activeAlerts.push(presented);
            }
          } else {
            const activeCpu = cpu ?? this.cpu;
            rt.msgSend(activeCpu, presented, 'view', []);
            if (this._isExited(activeCpu)) {
              this._markExited(activeCpu);
              return 0n;
            }
            rt.msgSend(activeCpu, presented, 'viewWillAppear:', [1n]);
            if (this._isExited(activeCpu)) {
              this._markExited(activeCpu);
              return 0n;
            }
          }
          this._maybeFlush();
          return 0n;
        },
        'dismissViewControllerAnimated:completion:': (self) => {
          const data = rt.getHostObject(self);
          if (data && data.presentedPtr && data.presentedPtr !== 0n) {
            this.activeAlerts = this.activeAlerts.filter((p) => p !== data.presentedPtr);
            data.presentedPtr = 0n;
          } else if (this.activeAlerts.length > 0) {
            this.activeAlerts.pop();
          }
          this._maybeFlush();
          return 0n;
        },
      },
    });

    // ---- UIWindow ----
    rt.registerHostClass('UIWindow', 'UIView', {
      instanceMethods: {
        init: (self) => {
          const data = this._ensureViewHostData(self, 'window');
          if (data) {
            data.kind = 'window';
            data.rootViewControllerPtr = 0n;
            data.isKeyWindow = false;
            data.frame = { x: 0, y: 0, width: IOS_WINDOW_WIDTH, height: IOS_WINDOW_HEIGHT };
          }
          if (!this.windows.includes(self)) this.windows.push(self);
          return self;
        },
        'initWithFrame:': (self, _args, { cpu }) => {
          const data = this._ensureViewHostData(self, 'window');
          if (data) {
            data.kind = 'window';
            data.rootViewControllerPtr = 0n;
            data.isKeyWindow = false;
            data.frame = { x: 0, y: 0, width: IOS_WINDOW_WIDTH, height: IOS_WINDOW_HEIGHT };
            if (cpu && typeof cpu.getDReg === 'function') {
              const w = cpu.getDReg(2);
              const h = cpu.getDReg(3);
              if (Number.isFinite(w) && w > 0 && Number.isFinite(h) && h > 0) {
                data.frame = { x: cpu.getDReg(0), y: cpu.getDReg(1), width: w, height: h };
              }
            }
          }
          if (!this.windows.includes(self)) this.windows.push(self);
          return self;
        },
        'setRootViewController:': (self, [vcPtr], { cpu }) => {
          const data = this._ensureViewHostData(self, 'window');
          if (data) {
            const vc = toBigIntPtr(vcPtr);
            rt.retain(vc);
            data.rootViewControllerPtr = vc;
            if (vc !== 0n) {
              const activeCpu = cpu ?? this.cpu;
              rt.msgSend(activeCpu, vc, 'view', []);
              if (this._isExited(activeCpu)) {
                this._markExited(activeCpu);
                return 0n;
              }
              rt.msgSend(activeCpu, vc, 'viewWillAppear:', [0n]);
              if (this._isExited(activeCpu)) {
                this._markExited(activeCpu);
                return 0n;
              }
            }
            this._maybeFlush();
          }
          return 0n;
        },
        rootViewController: (self) => rt.getHostObject(self)?.rootViewControllerPtr ?? 0n,
        makeKeyAndVisible: (self) => {
          const data = this._ensureViewHostData(self, 'window');
          if (data) {
            data.isKeyWindow = true;
            data.hidden = false;
          }
          this.keyWindowPtr = self;
          if (!this.windows.includes(self)) this.windows.push(self);
          this.flushToCompositor();
          return 0n;
        },
      },
    });

    // ---- UIAlertAction & UIAlertController ----
    rt.registerHostClass('UIAlertAction', 'NSObject', {
      classMethods: {
        'actionWithTitle:style:handler:': (_cls, [titlePtr, style, handlerPtr]) => {
          return rt.allocObject('UIAlertAction', {
            id: `alert-action-${this._nextNodeSeq++}`,
            title: rt.readNSString(titlePtr) ?? 'OK',
            style: Number(style),
            handlerPtr: toBigIntPtr(handlerPtr),
            enabled: true,
          });
        },
      },
      instanceMethods: {
        title: (self) => rt.createNSString(rt.getHostObject(self)?.title ?? ''),
        style: (self) => BigInt(rt.getHostObject(self)?.style ?? 0),
        isEnabled: (self) => (rt.getHostObject(self)?.enabled !== false ? 1n : 0n),
        'setEnabled:': (self, [flag]) => {
          const data = rt.getHostObject(self);
          if (data) data.enabled = toBigIntPtr(flag) !== 0n;
          return 0n;
        },
      },
    });

    rt.registerHostClass('UIAlertController', 'UIViewController', {
      classMethods: {
        'alertControllerWithTitle:message:preferredStyle:': (_cls, [titlePtr, msgPtr, style]) => {
          return rt.allocObject('UIAlertController', {
            nodeId: `uikit-alert-${this._nextNodeSeq++}`,
            title: rt.readNSString(titlePtr) ?? '',
            message: rt.readNSString(msgPtr) ?? '',
            preferredStyle: Number(style),
            actions: [],
          });
        },
      },
      instanceMethods: {
        'addAction:': (self, [actionPtr]) => {
          const act = toBigIntPtr(actionPtr);
          const data = rt.getHostObject(self);
          if (data && act !== 0n) {
            if (!Array.isArray(data.actions)) data.actions = [];
            rt.retain(act);
            data.actions.push(act);
            this._maybeFlush();
          }
          return 0n;
        },
        title: (self) => rt.createNSString(rt.getHostObject(self)?.title ?? ''),
        'setTitle:': (self, [tPtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.title = rt.readNSString(tPtr) ?? '';
            this._maybeFlush();
          }
          return 0n;
        },
        message: (self) => rt.createNSString(rt.getHostObject(self)?.message ?? ''),
        'setMessage:': (self, [mPtr]) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.message = rt.readNSString(mPtr) ?? '';
            this._maybeFlush();
          }
          return 0n;
        },
        actions: (self) => rt.createNSArray(rt.getHostObject(self)?.actions ?? []),
      },
    });

    // ---- UIApplication ----
    rt.registerHostClass('UIApplication', 'NSObject', {
      classMethods: {
        sharedApplication: () => this._ensureApplicationSingleton(),
      },
      instanceMethods: {
        delegate: () => this.delegatePtr,
        'setDelegate:': (_self, [delPtr]) => {
          this.delegatePtr = toBigIntPtr(delPtr);
          return 0n;
        },
        keyWindow: () => this.keyWindowPtr,
        windows: () => rt.createNSArray(this.windows),
        applicationState: () => {
          if (this.lifecycleState === 'Active') return 0n;
          if (this.lifecycleState === 'Inactive') return 1n;
          return 2n; // Background / Suspended
        },
        'setIdleTimerDisabled:': (_self, [flag]) => {
          this._idleTimerDisabled = toBigIntPtr(flag) !== 0n;
          return 0n;
        },
        isIdleTimerDisabled: () => (this._idleTimerDisabled ? 1n : 0n),
        'openURL:': (_self, [urlPtr]) => this._handleOpenUrlRequest(urlPtr),
        'openURL:options:completionHandler:': (_self, [urlPtr]) => this._handleOpenUrlRequest(urlPtr),
        'canOpenURL:': (_self, [urlPtr]) => {
          const uri = rt.readNSString(urlPtr);
          if (!uri || !this.intentRouter) return 0n;
          try {
            const matches = this.intentRouter.resolve({ action: 'view', uri });
            return Array.isArray(matches) && matches.length > 0 ? 1n : 0n;
          } catch {
            return 0n;
          }
        },
      },
    });

    // ---- UIPasteboard (Live-backed by SharedClipboard) ----
    rt.registerHostClass('UIPasteboard', 'NSObject', {
      classMethods: {
        generalPasteboard: () => {
          if (this._pasteboardPtr === 0n) {
            const ptr = rt.allocObject('UIPasteboard', { name: 'general' });
            const rec = rt.getObjectRecord(ptr);
            if (rec) rec.immortal = true;
            this._pasteboardPtr = ptr;
          }
          return this._pasteboardPtr;
        },
      },
      instanceMethods: {
        string: () => {
          if (!this.clipboard) return 0n;
          const text = this.clipboard.get('text/plain');
          return typeof text === 'string' ? rt.createNSString(text) : 0n;
        },
        'setString:': (_self, [strPtr]) => {
          if (!this.clipboard) return 0n;
          const text = rt.readNSString(strPtr);
          if (text !== null) {
            this.clipboard.set({
              text,
              sourceAppId: this.appId,
              sourcePlatform: 'ios',
            });
          }
          return 0n;
        },
        hasStrings: () => {
          if (!this.clipboard) return 0n;
          const text = this.clipboard.get('text/plain');
          return typeof text === 'string' && text.length > 0 ? 1n : 0n;
        },
      },
    });

    // ---- UserNotifications (UNMutableNotificationContent, UNNotificationRequest, UNUserNotificationCenter) ----
    rt.registerHostClass('UNMutableNotificationContent', 'NSObject', {
      instanceMethods: {
        init: (self) => {
          const data = rt.getHostObject(self);
          if (data) {
            data.title = data.title ?? '';
            data.subtitle = data.subtitle ?? '';
            data.body = data.body ?? '';
            data.categoryIdentifier = data.categoryIdentifier ?? 'general';
          }
          return self;
        },
        'setTitle:': (self, [p]) => {
          const data = rt.getHostObject(self);
          if (data) data.title = rt.readNSString(p) ?? '';
          return 0n;
        },
        title: (self) => rt.createNSString(rt.getHostObject(self)?.title ?? ''),
        'setSubtitle:': (self, [p]) => {
          const data = rt.getHostObject(self);
          if (data) data.subtitle = rt.readNSString(p) ?? '';
          return 0n;
        },
        subtitle: (self) => rt.createNSString(rt.getHostObject(self)?.subtitle ?? ''),
        'setBody:': (self, [p]) => {
          const data = rt.getHostObject(self);
          if (data) data.body = rt.readNSString(p) ?? '';
          return 0n;
        },
        body: (self) => rt.createNSString(rt.getHostObject(self)?.body ?? ''),
        'setCategoryIdentifier:': (self, [p]) => {
          const data = rt.getHostObject(self);
          if (data) data.categoryIdentifier = rt.readNSString(p) ?? 'general';
          return 0n;
        },
      },
    });

    rt.registerHostClass('UNNotificationRequest', 'NSObject', {
      classMethods: {
        'requestWithIdentifier:content:trigger:': (_cls, [idPtr, contentPtr]) => {
          const cData = rt.getHostObject(contentPtr);
          return rt.allocObject('UNNotificationRequest', {
            identifier: rt.readNSString(idPtr) ?? `req-${this._nextNodeSeq++}`,
            title: cData?.title ?? '',
            subtitle: cData?.subtitle ?? '',
            body: cData?.body ?? '',
            category: cData?.categoryIdentifier ?? 'general',
          });
        },
      },
      instanceMethods: {
        identifier: (self) => rt.createNSString(rt.getHostObject(self)?.identifier ?? ''),
      },
    });

    const postNotificationRequest = (reqPtr) => {
      if (!this.notifications) return 0n;
      const p = toBigIntPtr(reqPtr);
      const rec = rt.getObjectRecord(p);
      let title = this.appName;
      let body = '';
      let category = 'general';
      let priority = 'normal';

      if (rec?.className === 'UNNotificationRequest' || rec?.className === 'UNMutableNotificationContent') {
        title = rec.hostData?.title || this.appName;
        body = rec.hostData?.body || rec.hostData?.subtitle || '';
        category = rec.hostData?.category || rec.hostData?.categoryIdentifier || 'general';
      } else if (rec?.className === 'NSDictionary' || rec?.className === 'NSMutableDictionary') {
        const js = rt.objcToJs(p);
        if (js && typeof js === 'object') {
          title = String(js.title ?? this.appName);
          body = String(js.body ?? '');
          if (js.category) category = String(js.category);
          if (js.priority) priority = String(js.priority);
        }
      } else {
        const txt = rt.readNSString(p);
        if (txt) body = txt;
      }

      const posted = this.notifications.post({
        appId: this.appId,
        platform: 'ios',
        title,
        body,
        category,
        priority,
      });
      return rt.createNSString(posted.id);
    };

    rt.registerHostClass('UNUserNotificationCenter', 'NSObject', {
      classMethods: {
        currentNotificationCenter: () => {
          if (this._notifCenterPtr === 0n) {
            const ptr = rt.allocObject('UNUserNotificationCenter', {});
            const rec = rt.getObjectRecord(ptr);
            if (rec) rec.immortal = true;
            this._notifCenterPtr = ptr;
          }
          return this._notifCenterPtr;
        },
      },
      instanceMethods: {
        'requestAuthorizationWithOptions:completionHandler:': () => 1n,
        'addNotificationRequest:': (_self, [reqPtr]) => postNotificationRequest(reqPtr),
        'addNotificationRequest:withCompletionHandler:': (_self, [reqPtr]) => postNotificationRequest(reqPtr),
      },
    });

    // ---- OmniLiveActivity & ActivityKit (Dynamic Island Live Activities) ----
    const liveActivityMethods = {
      'startActivityWithTitle:subtitle:leading:trailing:body:progress:': (
        _cls,
        [titlePtr, subtitlePtr, leadingPtr, trailingPtr, bodyPtr, progressArg],
        { cpu }
      ) => {
        const title = rt.readNSString(titlePtr) || this.appName;
        const subtitle = rt.readNSString(subtitlePtr) ?? '';
        const compactLeading = rt.readNSString(leadingPtr);
        const compactTrailing = rt.readNSString(trailingPtr);
        const expandedBody = rt.readNSString(bodyPtr) ?? subtitle;
        const progress = this._decodeProgressArg(progressArg, cpu);

        if (this.notifications) {
          const notif = this.notifications.post({
            appId: this.appId,
            platform: 'ios',
            title,
            body: expandedBody || subtitle || title,
            category: 'live_activity',
            liveActivity: {
              title,
              subtitle,
              compactLeading,
              compactTrailing,
              expandedBody,
              progress,
            },
          });
          const la = notif.liveActivity;
          if (la) {
            this.liveActivities.set(la.id, la);
            return rt.createNSString(la.id);
          }
          return rt.createNSString(notif.id);
        }

        const localId = `la-local-${this.liveActivities.size + 1}`;
        this.liveActivities.set(localId, {
          id: localId,
          appId: this.appId,
          platform: 'ios',
          title,
          subtitle,
          compactLeading,
          compactTrailing,
          expandedBody,
          progress,
          state: 'active',
        });
        return rt.createNSString(localId);
      },

      'updateActivity:title:subtitle:leading:trailing:body:progress:': (
        _cls,
        [idPtr, titlePtr, subtitlePtr, leadingPtr, trailingPtr, bodyPtr, progressArg],
        { cpu }
      ) => {
        let activityId = rt.readNSString(idPtr);
        if (!activityId && this.liveActivities.size > 0) {
          activityId = Array.from(this.liveActivities.keys()).pop();
        }
        if (!activityId) return 0n;

        const patch = {};
        if (toBigIntPtr(titlePtr) !== 0n) {
          const t = rt.readNSString(titlePtr);
          if (t !== null) patch.title = t;
        }
        if (toBigIntPtr(subtitlePtr) !== 0n) {
          const s = rt.readNSString(subtitlePtr);
          if (s !== null) patch.subtitle = s;
        }
        if (toBigIntPtr(leadingPtr) !== 0n) {
          const l = rt.readNSString(leadingPtr);
          if (l !== null) patch.compactLeading = l;
        }
        if (toBigIntPtr(trailingPtr) !== 0n) {
          const tr = rt.readNSString(trailingPtr);
          if (tr !== null) patch.compactTrailing = tr;
        }
        if (toBigIntPtr(bodyPtr) !== 0n) {
          const b = rt.readNSString(bodyPtr);
          if (b !== null) patch.expandedBody = b;
        }
        const progress = this._decodeProgressArg(progressArg, cpu);
        if (progress !== null) {
          patch.progress = progress;
        }

        if (this.notifications) {
          try {
            const updated = this.notifications.updateLiveActivity(activityId, patch);
            this.liveActivities.set(updated.id, updated);
            return 1n;
          } catch {
            return 0n;
          }
        }
        const existing = this.liveActivities.get(activityId);
        if (!existing) return 0n;
        Object.assign(existing, patch);
        return 1n;
      },

      'endActivity:': (_cls, [idPtr]) => {
        let activityId = rt.readNSString(idPtr);
        if (!activityId && this.liveActivities.size > 0) {
          activityId = Array.from(this.liveActivities.keys()).pop();
        }
        if (!activityId) return 0n;

        if (this.notifications) {
          try {
            const ended = this.notifications.endLiveActivity(activityId, {
              dismissalPolicy: 'immediate',
            });
            this.liveActivities.set(ended.id, ended);
            return 1n;
          } catch {
            return 0n;
          }
        }
        const existing = this.liveActivities.get(activityId);
        if (existing) existing.state = 'ended';
        return 1n;
      },
    };

    rt.registerHostClass('OmniLiveActivity', 'NSObject', { classMethods: liveActivityMethods });
    rt.registerHostClass('ActivityKit', 'NSObject', { classMethods: liveActivityMethods });

    // ---- C Function: _UIApplicationMain(argc, argv, principalClassName, delegateClassName) ----
    rt.registerCFunction('UIApplicationMain', (cpu) => {
      return this._runUIApplicationMain(cpu);
    });
  }

  _ensureApplicationSingleton(principalClassName = 'UIApplication') {
    if (this.applicationPtr !== 0n) return this.applicationPtr;
    const clsName = this.objcRuntime.getClass(principalClassName) !== 0n ? principalClassName : 'UIApplication';
    const ptr = this.objcRuntime.allocObject(clsName, { appId: this.appId });
    const rec = this.objcRuntime.getObjectRecord(ptr);
    if (rec) rec.immortal = true;
    this.applicationPtr = ptr;
    return ptr;
  }

  _handleOpenUrlRequest(urlPtr) {
    const uri = this.objcRuntime.readNSString(urlPtr);
    if (!uri) return 0n;
    this.openedUrls.push({ uri, direction: 'outbound', ts: new Date().toISOString() });
    if (this.intentRouter && typeof this.intentRouter.dispatch === 'function') {
      try {
        const res = this.intentRouter.dispatch({
          action: 'view',
          uri,
          sourcePid: this.pcb?.pid ?? null,
        });
        return res && res.status !== 'NO_HANDLER' ? 1n : 0n;
      } catch {
        return 0n;
      }
    }
    return 1n;
  }

  _findAppDelegateClass(requestedName) {
    const rt = this.objcRuntime;
    if (requestedName) {
      const ptr = rt.getClass(requestedName);
      if (ptr !== 0n) return ptr;
    }
    // Search discovered app classes from __objc_classlist for one implementing launch delegate selector
    for (const rec of rt._classesByName.values()) {
      if (
        rec.isAppClass &&
        (rec.instanceMethods.has('application:didFinishLaunchingWithOptions:') ||
          rec.instanceMethods.has('applicationDidFinishLaunching:'))
      ) {
        return rec.ptr;
      }
    }
    for (const rec of rt._classesByName.values()) {
      if (rec.isAppClass) return rec.ptr;
    }
    return rt.getClass('NSObject');
  }

  _runUIApplicationMain(cpu) {
    this.cpu = cpu;
    const rt = this.objcRuntime;

    const principalPtr = getArm64Arg(cpu, this.addressSpace, 2);
    const delegateNamePtr = getArm64Arg(cpu, this.addressSpace, 3);
    const principalName = principalPtr !== 0n ? rt.readNSString(principalPtr) : 'UIApplication';
    const delegateClassName = delegateNamePtr !== 0n ? rt.readNSString(delegateNamePtr) : null;

    const appPtr = this._ensureApplicationSingleton(principalName || 'UIApplication');
    const delegateClassPtr = this._findAppDelegateClass(delegateClassName);

    const rawDelegate = rt.msgSend(cpu, delegateClassPtr, 'alloc', []);
    if (this._isExited(cpu)) {
      return { status: 'EXITED', exitCode: this._markExited(cpu) };
    }
    const delegatePtr = rt.msgSend(cpu, rawDelegate, 'init', []);
    if (this._isExited(cpu)) {
      return { status: 'EXITED', exitCode: this._markExited(cpu) };
    }
    this.delegatePtr = delegatePtr;
    rt.msgSend(cpu, appPtr, 'setDelegate:', [delegatePtr]);
    if (this._isExited(cpu)) {
      return { status: 'EXITED', exitCode: this._markExited(cpu) };
    }

    // Build launchOptions NSDictionary
    const launchEntries = [];
    const launchIntent = this.launchOptions?.intent ?? null;
    if (launchIntent && typeof launchIntent.uri === 'string' && launchIntent.uri.length > 0) {
      const urlObj = rt.msgSend(cpu, rt.getClass('NSURL'), 'URLWithString:', [
        rt.createNSString(launchIntent.uri),
      ]);
      launchEntries.push(['UIApplicationLaunchOptionsURLKey', urlObj]);
    }
    const launchDictPtr = rt.createNSDictionary(launchEntries);

    this.lifecycleState = 'Active';
    this.isSuspended = false;
    this.lifecycleHistory.push({ state: 'Active', event: 'didFinishLaunching', ts: new Date().toISOString() });

    // Invoke REAL ARM64 AppDelegate IMP: application:didFinishLaunchingWithOptions:
    rt.msgSend(cpu, delegatePtr, 'application:didFinishLaunchingWithOptions:', [appPtr, launchDictPtr]);
    if (this._isExited(cpu)) {
      return { status: 'EXITED', exitCode: this._markExited(cpu) };
    }

    // Invoke applicationDidBecomeActive: if implemented
    rt.msgSend(cpu, delegatePtr, 'applicationDidBecomeActive:', [appPtr]);
    if (this._isExited(cpu)) {
      return { status: 'EXITED', exitCode: this._markExited(cpu) };
    }

    // If launched via URL-scheme intent, immediately invoke application:openURL:options:
    if (launchIntent && typeof launchIntent.uri === 'string' && launchIntent.uri.length > 0) {
      this._invokeOpenUrlDelegate(cpu, launchIntent);
      if (this._isExited(cpu)) {
        return { status: 'EXITED', exitCode: this._markExited(cpu) };
      }
    }

    this.runLoopActive = true;
    this.flushToCompositor();
    return { status: 'BLOCKED', waitReason: this.isSuspended ? 'suspended' : 'ui_event' };
  }

  // =========================================================================
  // UIKit -> Compositor Serialization (`uiTree` + `drawOps`)
  // =========================================================================

  _resolveWindowTitle() {
    if (this.keyWindowPtr !== 0n) {
      const winData = this.objcRuntime.getHostObject(this.keyWindowPtr);
      if (winData?.rootViewControllerPtr) {
        const vcData = this.objcRuntime.getHostObject(winData.rootViewControllerPtr);
        if (vcData?.title) return vcData.title;
      }
    }
    return this.appName;
  }

  _serializeViewNode(ptr, visited) {
    const p = toBigIntPtr(ptr);
    if (p === 0n || visited.has(p)) return null;
    visited.add(p);

    const rec = this.objcRuntime.getObjectRecord(p);
    if (!rec) return null;
    const data = rec.hostData ?? {};
    const nodeId = data.accessibilityIdentifier || data.nodeId || `uikit-node-${p.toString(16)}`;
    const cls = rec.className;

    if (cls === 'UILabel' || data.kind === 'label') {
      const node = {
        id: nodeId,
        type: 'label',
        text: String(data.text ?? ''),
        tag: Number(data.tag ?? 0),
        hidden: Boolean(data.hidden),
      };
      if (data.accessibilityIdentifier) node.accessibilityIdentifier = data.accessibilityIdentifier;
      if (data.textColor) node.color = data.textColor;
      this._controlNodeIndex.set(nodeId, p);
      return node;
    }

    if (cls === 'UIButton' || data.kind === 'button') {
      const title = String(data.titles?.get?.(0) ?? data.title ?? 'Button');
      const primaryTarget = Array.isArray(data.targets) && data.targets.length > 0 ? data.targets[0] : null;
      const node = {
        id: nodeId,
        type: 'button',
        label: title,
        text: title,
        action: primaryTarget?.actionName || nodeId,
        tag: Number(data.tag ?? 0),
        enabled: data.enabled !== false,
        hidden: Boolean(data.hidden),
      };
      if (data.accessibilityIdentifier) node.accessibilityIdentifier = data.accessibilityIdentifier;
      this._controlNodeIndex.set(nodeId, p);
      return node;
    }

    if (cls === 'UITextField' || data.kind === 'input') {
      const node = {
        id: nodeId,
        type: 'input',
        value: String(data.text ?? ''),
        text: String(data.text ?? ''),
        placeholder: String(data.placeholder ?? ''),
        tag: Number(data.tag ?? 0),
        hidden: Boolean(data.hidden),
      };
      if (data.accessibilityIdentifier) node.accessibilityIdentifier = data.accessibilityIdentifier;
      this._controlNodeIndex.set(nodeId, p);
      return node;
    }

    const children = [];
    if (Array.isArray(data.subviews)) {
      for (const childPtr of data.subviews) {
        const childNode = this._serializeViewNode(childPtr, visited);
        if (childNode) children.push(childNode);
      }
    }

    const container = {
      id: nodeId,
      type: 'container',
      className: cls,
      tag: Number(data.tag ?? 0),
      hidden: Boolean(data.hidden),
      children,
    };
    if (data.accessibilityIdentifier) container.accessibilityIdentifier = data.accessibilityIdentifier;
    if (data.backgroundColor) container.backgroundColor = data.backgroundColor;
    if (cls === 'UIStackView' || data.kind === 'stack') {
      container.layout = data.axis === 0 ? 'horizontal' : 'vertical';
      container.spacing = Number(data.spacing ?? 8);
    }
    this._controlNodeIndex.set(nodeId, p);
    return container;
  }

  serializeUiTree() {
    this._controlNodeIndex.clear();
    const visited = new Set();
    const children = [];
    const title = this._resolveWindowTitle();

    const winPtr = this.keyWindowPtr !== 0n ? this.keyWindowPtr : (this.windows[0] ?? 0n);
    if (winPtr !== 0n) {
      const winData = this.objcRuntime.getHostObject(winPtr);
      let rootVcViewPtr = 0n;
      if (winData?.rootViewControllerPtr) {
        const vcData = this.objcRuntime.getHostObject(winData.rootViewControllerPtr);
        if (vcData?.viewPtr) {
          rootVcViewPtr = vcData.viewPtr;
          const rootNode = this._serializeViewNode(rootVcViewPtr, visited);
          if (rootNode) children.push(rootNode);
        }
      }
      if (Array.isArray(winData?.subviews)) {
        for (const sub of winData.subviews) {
          if (sub !== rootVcViewPtr) {
            const subNode = this._serializeViewNode(sub, visited);
            if (subNode) children.push(subNode);
          }
        }
      }
    }

    // Serialize any presented UIAlertControllers
    for (const alertPtr of this.activeAlerts) {
      const alertData = this.objcRuntime.getHostObject(alertPtr);
      if (!alertData) continue;
      const alertId = alertData.nodeId || `uikit-alert-${alertPtr.toString(16)}`;
      const actions = [];
      if (Array.isArray(alertData.actions)) {
        for (const actPtr of alertData.actions) {
          const actData = this.objcRuntime.getHostObject(actPtr);
          if (actData) {
            actions.push({
              id: actData.id,
              label: actData.title,
              style: actData.style,
              enabled: actData.enabled !== false,
            });
          }
        }
      }
      children.push({
        id: alertId,
        type: 'alert',
        title: alertData.title ?? '',
        message: alertData.message ?? '',
        actions,
      });
    }

    return {
      id: 'uikit-window-root',
      type: 'container',
      role: 'window',
      platform: 'ios',
      appId: this.appId,
      title,
      lifecycleState: this.lifecycleState,
      children,
    };
  }

  _buildDrawOps(uiTree) {
    const ops = [
      { op: 'fillRect', x: 0, y: 0, width: IOS_WINDOW_WIDTH, height: IOS_WINDOW_HEIGHT, color: '#0f172a' },
      { op: 'fillRect', x: 0, y: 0, width: IOS_WINDOW_WIDTH, height: 56, color: '#1e293b' },
      { op: 'drawText', x: 20, y: 34, text: uiTree.title || this.appName, color: '#f8fafc', font: 'bold 18px sans-serif' },
    ];

    let y = 84;
    const walk = (node) => {
      if (!node || node.hidden) return;
      if (node.type === 'label') {
        ops.push({ op: 'drawText', x: 20, y: y + 20, text: node.text || '', color: node.color || '#e2e8f0', font: '16px sans-serif' });
        y += 40;
      } else if (node.type === 'button') {
        ops.push({ op: 'fillRect', x: 20, y, width: IOS_WINDOW_WIDTH - 40, height: 44, color: '#0a84ff', radius: 10 });
        ops.push({ op: 'drawText', x: 36, y: y + 28, text: node.label || 'Button', color: '#ffffff', font: 'bold 15px sans-serif' });
        y += 56;
      } else if (node.type === 'input') {
        ops.push({ op: 'fillRect', x: 20, y, width: IOS_WINDOW_WIDTH - 40, height: 40, color: '#1e293b', stroke: '#475569' });
        ops.push({
          op: 'drawText',
          x: 32,
          y: y + 25,
          text: node.value || node.placeholder || '',
          color: node.value ? '#f8fafc' : '#64748b',
          font: '14px sans-serif',
        });
        y += 52;
      } else if (node.type === 'alert') {
        ops.push({ op: 'fillRect', x: 32, y: 260, width: IOS_WINDOW_WIDTH - 64, height: 140, color: '#1e293b', stroke: '#38bdf8' });
        ops.push({ op: 'drawText', x: 48, y: 292, text: node.title || 'Alert', color: '#ffffff', font: 'bold 16px sans-serif' });
        ops.push({ op: 'drawText', x: 48, y: 320, text: node.message || '', color: '#cbd5e1', font: '14px sans-serif' });
      }
      if (Array.isArray(node.children)) {
        for (const ch of node.children) walk(ch);
      }
    };
    walk(uiTree);
    return ops;
  }

  flushToCompositor() {
    if (this._disposed) return null;
    const uiTree = this.serializeUiTree();
    const drawOps = this._buildDrawOps(uiTree);
    this.uiTree = uiTree;
    this.drawOps = drawOps;

    if (!this.compositor || !this.pcb) {
      return { windowId: this.windowId, uiTree, drawOps };
    }

    const title = uiTree.title || this.appName;
    if (this.windowId === null) {
      const win = this.compositor.createWindow(this.pcb.pid, {
        appId: this.appId,
        platform: 'ios',
        title,
        width: IOS_WINDOW_WIDTH,
        height: IOS_WINDOW_HEIGHT,
        chromeStyle: 'ios',
        uiTree,
        drawOps,
      });
      this.windowId = win.windowId;
      return win;
    }

    try {
      return this.compositor.updateSurface(this.windowId, {
        title,
        uiTree,
        drawOps,
      });
    } catch {
      // Window may have been closed externally
      return null;
    }
  }

  // =========================================================================
  // Event, Input, Intent & SpringBoard Lifecycle Dispatch
  // =========================================================================

  _collectViewsOfClass(className) {
    const out = [];
    const visited = new Set();
    const walk = (ptr) => {
      const p = toBigIntPtr(ptr);
      if (p === 0n || visited.has(p)) return;
      visited.add(p);
      const rec = this.objcRuntime.getObjectRecord(p);
      if (!rec) return;
      if (rec.className === className) out.push(p);
      const data = rec.hostData;
      if (data?.rootViewControllerPtr) {
        const vcData = this.objcRuntime.getHostObject(data.rootViewControllerPtr);
        if (vcData?.viewPtr) walk(vcData.viewPtr);
      }
      if (Array.isArray(data?.subviews)) {
        for (const ch of data.subviews) walk(ch);
      }
    };
    if (this.keyWindowPtr !== 0n) walk(this.keyWindowPtr);
    for (const w of this.windows) walk(w);
    return out;
  }

  _matchButton(event) {
    const targetId = event.nodeId ?? event.id ?? event.targetId ?? event.target ?? null;
    const targetTag = event.tag !== undefined && event.tag !== null ? Number(event.tag) : null;
    const targetAction = typeof event.action === 'string' ? event.action.trim() : null;
    const targetLabel = typeof (event.label ?? event.text) === 'string' ? String(event.label ?? event.text) : null;

    if (typeof targetId === 'string' && this._controlNodeIndex.has(targetId)) {
      const ptr = this._controlNodeIndex.get(targetId);
      const rec = this.objcRuntime.getObjectRecord(ptr);
      if (rec && rec.className === 'UIButton') return ptr;
    }

    const buttons = this._collectViewsOfClass('UIButton');
    for (const ptr of buttons) {
      const data = this.objcRuntime.getHostObject(ptr);
      if (!data) continue;
      if (targetId && (data.accessibilityIdentifier === targetId || data.nodeId === targetId)) {
        return ptr;
      }
      if (targetTag !== null && Number.isFinite(targetTag) && Number(data.tag) === targetTag) {
        return ptr;
      }
      if (targetAction && Array.isArray(data.targets)) {
        const cleanAct = targetAction.replace(/:$/, '');
        if (
          data.targets.some(
            (t) => t.actionName === targetAction || t.actionName.replace(/:$/, '') === cleanAct
          )
        ) {
          return ptr;
        }
      }
      if (targetLabel && (data.title === targetLabel || data.titles?.get?.(0) === targetLabel)) {
        return ptr;
      }
    }

    // Convenience: if caller sends a generic click with an action matching nodeId
    if (targetAction && this._controlNodeIndex.has(targetAction)) {
      const ptr = this._controlNodeIndex.get(targetAction);
      const rec = this.objcRuntime.getObjectRecord(ptr);
      if (rec && rec.className === 'UIButton') return ptr;
    }
    return 0n;
  }

  _matchTextField(event) {
    const targetId = event.nodeId ?? event.id ?? event.targetId ?? event.target ?? null;
    const targetTag = event.tag !== undefined && event.tag !== null ? Number(event.tag) : null;

    if (typeof targetId === 'string' && this._controlNodeIndex.has(targetId)) {
      const ptr = this._controlNodeIndex.get(targetId);
      const rec = this.objcRuntime.getObjectRecord(ptr);
      if (rec && rec.className === 'UITextField') return ptr;
    }

    const fields = this._collectViewsOfClass('UITextField');
    for (const ptr of fields) {
      const data = this.objcRuntime.getHostObject(ptr);
      if (!data) continue;
      if (targetId && (data.accessibilityIdentifier === targetId || data.nodeId === targetId)) {
        return ptr;
      }
      if (targetTag !== null && Number.isFinite(targetTag) && Number(data.tag) === targetTag) {
        return ptr;
      }
    }
    return fields.length === 1 ? fields[0] : 0n;
  }

  _invokeOpenUrlDelegate(cpu, intent) {
    const rt = this.objcRuntime;
    const uri = typeof intent?.uri === 'string' ? intent.uri : '';
    if (!uri) return false;
    this.openedUrls.push({ uri, direction: 'inbound', ts: new Date().toISOString() });

    const urlStrPtr = rt.createNSString(uri);
    const urlObjPtr = rt.msgSend(cpu, rt.getClass('NSURL'), 'URLWithString:', [urlStrPtr]);
    const optionsPtr = rt.jsToObjC(intent?.extras ?? {});

    if (this.delegatePtr !== 0n) {
      const hasModern =
        rt.msgSend(cpu, this.delegatePtr, 'respondsToSelector:', [
          rt.selRegisterName('application:openURL:options:'),
        ]) !== 0n;
      if (hasModern) {
        rt.msgSend(cpu, this.delegatePtr, 'application:openURL:options:', [
          this.applicationPtr,
          urlObjPtr,
          optionsPtr,
        ]);
      } else {
        rt.msgSend(cpu, this.delegatePtr, 'application:openURL:', [this.applicationPtr, urlObjPtr]);
      }
      if (this._isExited(cpu)) {
        this._markExited(cpu);
        return true;
      }
    }
    this.flushToCompositor();
    return true;
  }

  handleEvent(cpu, event) {
    if (this._disposed || !event || typeof event !== 'object') {
      return { handled: false };
    }
    const activeCpu = cpu ?? this.cpu;
    if (this._isExited(activeCpu)) {
      const exitCode = this._markExited(activeCpu);
      return { handled: false, exited: true, exitCode };
    }
    const rt = this.objcRuntime;
    const type = String(event.type || '').trim().toLowerCase();

    // 1. Window close -> applicationWillTerminate: -> EXITED (preserving IMP _exit code if halted)
    if (type === 'window_close' || type === 'close') {
      if (this.delegatePtr !== 0n) {
        rt.msgSend(activeCpu, this.delegatePtr, 'applicationWillTerminate:', [this.applicationPtr]);
      }
      const exitCode = this._markExited(activeCpu, 0);
      this.lifecycleHistory.push({ state: 'Terminated', event: 'window_close', ts: new Date().toISOString() });
      return { handled: true, exited: true, exitCode };
    }

    // 2. SpringBoard lifecycle transitions (background/suspend & foreground/resume)
    if (type === 'lifecycle') {
      const phase = String(event.state ?? event.action ?? event.phase ?? event.lifecycle ?? '')
        .trim()
        .toLowerCase();

      if (
        phase === 'background' ||
        phase === 'suspend' ||
        phase === 'suspended' ||
        phase === 'enter_background' ||
        phase === 'will_resign_active'
      ) {
        if (this.delegatePtr !== 0n) {
          rt.msgSend(activeCpu, this.delegatePtr, 'applicationWillResignActive:', [this.applicationPtr]);
          if (this._isExited(activeCpu)) {
            const exitCode = this._markExited(activeCpu);
            this.lifecycleHistory.push({ state: 'Terminated', event: phase, ts: new Date().toISOString() });
            return { handled: true, exited: true, exitCode };
          }
          rt.msgSend(activeCpu, this.delegatePtr, 'applicationDidEnterBackground:', [this.applicationPtr]);
          if (this._isExited(activeCpu)) {
            const exitCode = this._markExited(activeCpu);
            this.lifecycleHistory.push({ state: 'Terminated', event: phase, ts: new Date().toISOString() });
            return { handled: true, exited: true, exitCode };
          }
        }
        this.lifecycleState = 'Suspended';
        this.isSuspended = true;
        this.lifecycleHistory.push({ state: 'Suspended', event: phase, ts: new Date().toISOString() });
        this.flushToCompositor();
        return { handled: true, suspended: true, waitReason: 'suspended' };
      }

      if (
        phase === 'foreground' ||
        phase === 'resume' ||
        phase === 'active' ||
        phase === 'enter_foreground' ||
        phase === 'will_enter_foreground' ||
        phase === 'did_become_active'
      ) {
        this.isSuspended = false;
        this.lifecycleState = 'Active';
        if (this.delegatePtr !== 0n) {
          rt.msgSend(activeCpu, this.delegatePtr, 'applicationWillEnterForeground:', [this.applicationPtr]);
          if (this._isExited(activeCpu)) {
            const exitCode = this._markExited(activeCpu);
            this.lifecycleHistory.push({ state: 'Terminated', event: phase, ts: new Date().toISOString() });
            return { handled: true, exited: true, exitCode };
          }
          rt.msgSend(activeCpu, this.delegatePtr, 'applicationDidBecomeActive:', [this.applicationPtr]);
          if (this._isExited(activeCpu)) {
            const exitCode = this._markExited(activeCpu);
            this.lifecycleHistory.push({ state: 'Terminated', event: phase, ts: new Date().toISOString() });
            return { handled: true, exited: true, exitCode };
          }
        }
        this.lifecycleHistory.push({ state: 'Active', event: phase, ts: new Date().toISOString() });
        this.flushToCompositor();
        return { handled: true, resumed: true, waitReason: 'ui_event' };
      }

      if (phase === 'terminate' || phase === 'terminated') {
        if (this.delegatePtr !== 0n) {
          rt.msgSend(activeCpu, this.delegatePtr, 'applicationWillTerminate:', [this.applicationPtr]);
        }
        const exitCode = this._markExited(activeCpu, 0);
        this.lifecycleHistory.push({ state: 'Terminated', event: phase, ts: new Date().toISOString() });
        return { handled: true, exited: true, exitCode };
      }

      return { handled: false };
    }

    // 3. URL Scheme / Document Intent delivery -> application:openURL:options:
    if (type === 'intent') {
      if (this.isSuspended) {
        this.isSuspended = false;
        this.lifecycleState = 'Active';
        if (this.delegatePtr !== 0n) {
          rt.msgSend(activeCpu, this.delegatePtr, 'applicationWillEnterForeground:', [this.applicationPtr]);
          if (this._isExited(activeCpu)) {
            const exitCode = this._markExited(activeCpu);
            return { handled: true, exited: true, exitCode };
          }
          rt.msgSend(activeCpu, this.delegatePtr, 'applicationDidBecomeActive:', [this.applicationPtr]);
          if (this._isExited(activeCpu)) {
            const exitCode = this._markExited(activeCpu);
            return { handled: true, exited: true, exitCode };
          }
        }
      }
      const intentObj = event.intent ?? event;
      this._invokeOpenUrlDelegate(activeCpu, intentObj);
      if (this._isExited(activeCpu)) {
        const exitCode = this._markExited(activeCpu);
        return { handled: true, exited: true, exitCode };
      }
      return { handled: true, waitReason: 'ui_event' };
    }

    // 4. Button click / tap / action -> invoke REAL ARM64 ObjC target/action IMP!
    if (type === 'click' || type === 'action' || type === 'tap') {
      if (this.isSuspended) {
        return { handled: false, ignored: true, reason: 'suspended', waitReason: 'suspended' };
      }

      // Check active UIAlertController actions first
      if (this.activeAlerts.length > 0) {
        const topAlertPtr = this.activeAlerts[this.activeAlerts.length - 1];
        const alertData = rt.getHostObject(topAlertPtr);
        const matchId = event.nodeId ?? event.id ?? event.action ?? null;
        const matchLabel = event.label ?? event.text ?? null;
        if (alertData && Array.isArray(alertData.actions)) {
          const hitAct = alertData.actions.find((actPtr) => {
            const ad = rt.getHostObject(actPtr);
            return ad && ((matchId && ad.id === matchId) || (matchLabel && ad.title === matchLabel));
          });
          if (hitAct) {
            this.activeAlerts.pop();
            this.flushToCompositor();
            return { handled: true, alertAction: rt.getHostObject(hitAct)?.title ?? null };
          }
        }
      }

      const btnPtr = this._matchButton(event);
      if (btnPtr !== 0n) {
        // UIControlEventTouchUpInside = 1 << 6 = 0x40
        rt.msgSend(activeCpu, btnPtr, 'sendActionsForControlEvents:', [0x40n]);
        if (this._isExited(activeCpu)) {
          const exitCode = this._markExited(activeCpu);
          return { handled: true, exited: true, exitCode, buttonPtr: btnPtr };
        }
        this.flushToCompositor();
        return { handled: true, buttonPtr: btnPtr };
      }

      // Direct selector fallback on delegate if caller dispatched a named selector action
      if (typeof event.action === 'string' && this.delegatePtr !== 0n) {
        const sel = event.action.trim();
        const hasSel =
          rt.msgSend(activeCpu, this.delegatePtr, 'respondsToSelector:', [rt.selRegisterName(sel)]) !== 0n;
        if (hasSel) {
          rt.msgSend(activeCpu, this.delegatePtr, sel, [this.applicationPtr]);
          if (this._isExited(activeCpu)) {
            const exitCode = this._markExited(activeCpu);
            return { handled: true, exited: true, exitCode, action: sel };
          }
          this.flushToCompositor();
          return { handled: true, action: sel };
        }
      }

      return { handled: false };
    }

    // 5. Text input / change -> update UITextField & flush uiTree
    if (type === 'input' || type === 'change' || type === 'text_input') {
      if (this.isSuspended) {
        return { handled: false, ignored: true, reason: 'suspended', waitReason: 'suspended' };
      }
      const fieldPtr = this._matchTextField(event);
      if (fieldPtr !== 0n) {
        const nextText = String(event.value ?? event.text ?? '');
        const strPtr = rt.createNSString(nextText);
        rt.msgSend(activeCpu, fieldPtr, 'setText:', [strPtr]);
        if (this._isExited(activeCpu)) {
          const exitCode = this._markExited(activeCpu);
          return { handled: true, exited: true, exitCode, fieldPtr };
        }
        const fieldData = rt.getHostObject(fieldPtr);
        if (fieldData?.delegatePtr && fieldData.delegatePtr !== 0n) {
          rt.msgSend(activeCpu, fieldData.delegatePtr, 'textFieldDidChangeSelection:', [fieldPtr]);
          if (this._isExited(activeCpu)) {
            const exitCode = this._markExited(activeCpu);
            return { handled: true, exited: true, exitCode, fieldPtr };
          }
        }
        this.flushToCompositor();
        return { handled: true, fieldPtr };
      }
      return { handled: false };
    }

    // 6. Interactive Notification Action
    if (type === 'notification_action') {
      if (this.delegatePtr !== 0n) {
        const payloadObj = rt.jsToObjC({
          notificationId: event.notificationId ?? null,
          actionId: event.actionId ?? null,
          input: event.input ?? null,
        });
        rt.msgSend(activeCpu, this.delegatePtr, 'userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:', [
          this._notifCenterPtr,
          payloadObj,
          0n,
        ]);
        if (this._isExited(activeCpu)) {
          const exitCode = this._markExited(activeCpu);
          return { handled: true, exited: true, exitCode };
        }
        this.flushToCompositor();
      }
      return { handled: true };
    }

    return { handled: false };
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    this.runLoopActive = false;
    this._controlNodeIndex.clear();
    this.windows = [];
    this.activeAlerts = [];
  }
}

export function createUIKitBridge(opts = {}) {
  return new UIKitBridge(opts);
}
