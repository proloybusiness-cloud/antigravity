/**
 * OmniOS Android Platform Runtime (`os/runtimes/android/android-runtime.mjs`, Contract 5)
 * - Registers `'dalvik'` CPU/VM engine in `CpuRegistry`
 * - `inspectPackage(buffer, filenameHint)` parses real APK, AXML, resources.arsc, multidex DEX, and flat intents
 * - `installPackage(inspection, buffer, services)` provisions `/data/data/<pkg>/{files,cache,shared_prefs,databases}`
 * - `createExecutionContext(pcb, appRecord, services, launchOptions)` reads `${installDir}/.package.bin` with kernel UID 0
 * - `AndroidExecutionContext`: strictly synchronous `step(budget)` returning `waitReason: 'ui_event'` when idle with open Activity,
 *   waking via `deliverEvent(event)`, with `getDebugState()` and idempotent `dispose()`.
 * - Zero external dependencies; pure VFS-backed runtime without host filesystem access.
 */

import { OmniOSError, ERROR_CODES } from '../../common/errors.mjs';
import { createDalvikVM, registerDalvikCpu, DalvikGuestException } from '../../cpu/dalvik.mjs';
import { parseApk } from './apk-parser.mjs';
import { createAndroidFrameworkBridge } from './framework-bridge.mjs';

const ROOT_VFS_CTX = Object.freeze({ uid: 0, gid: 0 });
const MAX_PENDING_CALLS = 1024;
const MAX_PENDING_EVENTS = 1024;

function classNameToDescriptor(name) {
  if (!name || typeof name !== 'string') return '';
  if (name.startsWith('L') && name.endsWith(';')) return name;
  return `L${name.replace(/\./g, '/')};`;
}

export class AndroidExecutionContext {
  constructor({ pcb, appRecord, apk, vm, bridge, services, launchOptions = {} }) {
    this.pcb = pcb;
    this.appRecord = appRecord;
    this.apk = apk;
    this.vm = vm;
    this.bridge = bridge;
    this.services = services;
    this.launchOptions = launchOptions;

    this._pendingCalls = [];
    this._pendingEvents = [];
    this._disposed = false;
    this._exited = false;
    this._exitCode = 0;

    // Schedule initial launcher Activity (or main static entry if no Activity class exists)
    this._scheduleInitialEntry();
  }

  _scheduleInitialEntry() {
    const launcherName = this.apk.launcherActivity || this.appRecord?.entryPoint || '';
    const launcherDesc = classNameToDescriptor(launcherName);

    if (launcherDesc && this.vm.classesByName.has(launcherDesc)) {
      let activityObj;
      try {
        activityObj = this.vm.createObject(launcherDesc, null, {
          title: this.apk.label || this.appRecord?.name || this.apk.packageName,
          intent: this.bridge.launchIntent,
        });
      } catch (err) {
        if (err instanceof DalvikGuestException) {
          this.vm.lastUncaughtException = err.exception;
          return;
        }
        throw err;
      }
      this.bridge.activity = activityObj;

      // Queue Activity constructor & standard Android Activity lifecycle: <init> -> onCreate -> onStart -> onResume
      if (this.vm.findMethod(launcherDesc, '<init>()V', { includeSuper: false })?.code) {
        this._pendingCalls.push({
          classType: launcherDesc,
          signature: '<init>()V',
          args: [],
          receiver: activityObj,
          phase: 'CREATED',
        });
      }
      const onCreate = this.vm.findMethod(launcherDesc, 'onCreate(Landroid/os/Bundle;)V', {
        includeSuper: true,
      });
      if (onCreate?.code) {
        this._pendingCalls.push({
          classType: launcherDesc,
          signature: 'onCreate(Landroid/os/Bundle;)V',
          args: [null],
          receiver: activityObj,
          phase: 'CREATED',
        });
      }
      const onStart = this.vm.findMethod(launcherDesc, 'onStart()V', { includeSuper: true });
      if (onStart?.code) {
        this._pendingCalls.push({
          classType: launcherDesc,
          signature: 'onStart()V',
          args: [],
          receiver: activityObj,
          phase: 'STARTED',
        });
      }
      const onResume = this.vm.findMethod(launcherDesc, 'onResume()V', { includeSuper: true });
      if (onResume?.code) {
        this._pendingCalls.push({
          classType: launcherDesc,
          signature: 'onResume()V',
          args: [],
          receiver: activityObj,
          phase: 'RESUMED',
        });
      }
      return;
    }

    // Fallback for headless DEX tests: find any static main([Ljava/lang/String;)V or main()V
    for (const cls of this.vm.classesByName.values()) {
      const mainArr = cls.methods.get('main([Ljava/lang/String;)V');
      if (mainArr?.code) {
        const strArgs = this.launchOptions?.args ?? [];
        let argsArr;
        try {
          argsArr = this.vm.createArray('[Ljava/lang/String;', strArgs.length);
        } catch (err) {
          if (err instanceof DalvikGuestException) {
            this.vm.lastUncaughtException = err.exception;
            return;
          }
          throw err;
        }
        for (let i = 0; i < strArgs.length; i++) argsArr.data[i] = String(strArgs[i]);
        this._pendingCalls.push({
          classType: cls.classType,
          signature: 'main([Ljava/lang/String;)V',
          args: [argsArr],
          receiver: null,
          phase: 'RUNNING',
        });
        return;
      }
      const mainVoid = cls.methods.get('main()V');
      if (mainVoid?.code) {
        this._pendingCalls.push({
          classType: cls.classType,
          signature: 'main()V',
          args: [],
          receiver: null,
          phase: 'RUNNING',
        });
        return;
      }
    }
  }

  enqueueCallback(call) {
    if (this._disposed || this._exited) return false;
    if (this._pendingCalls.length >= MAX_PENDING_CALLS) return false;
    this._pendingCalls.push(call);
    return true;
  }

  beginTeardown(teardownCalls = []) {
    if (this._disposed || this._exited) return;
    this._pendingCalls = this._pendingCalls.filter(
      (c) => c.phase !== 'STARTED' && c.phase !== 'RESUMED'
    );
    const maxNonTeardown = Math.max(0, MAX_PENDING_CALLS - teardownCalls.length);
    if (this._pendingCalls.length > maxNonTeardown) {
      this._pendingCalls.length = maxNonTeardown;
    }
    for (const call of teardownCalls) {
      this._pendingCalls.push(call);
    }
  }

  markFinished() {
    this._exited = true;
    this._exitCode = 0;
  }

  /**
   * Strictly synchronous execution slice driven by the Kernel Scheduler.
   * NEVER returns a Promise; respects `instructionsExecuted <= budget`.
   */
  step(instructionBudget = 1000) {
    if (this._disposed || this._exited) {
      return {
        status: 'EXITED',
        instructionsExecuted: 0,
        exitCode: this._exitCode,
      };
    }

    const budget = Number.isFinite(instructionBudget) && instructionBudget >= 0 ? Math.trunc(instructionBudget) : 0;
    this.bridge?.beginTick?.();
    try {
      return this._stepTick(budget);
    } finally {
      this.bridge?.flushCompositorSurfaceIfDirty?.();
    }
  }

  _stepTick(budget) {
    let remaining = budget;
    let totalExecuted = 0;

    if (this.vm.callStack.length === 0 && this.vm.lastUncaughtException) {
      const faultRes = this.vm.step(0);
      this._exited = true;
      this._pendingCalls.length = 0;
      return {
        status: 'FAULT',
        instructionsExecuted: totalExecuted,
        fault: faultRes.fault,
      };
    }

    while (remaining > 0) {
      // 1. Drain incoming Compositor / Intent events into bridge (which may enqueue Dalvik callbacks)
      if (this.vm.callStack.length === 0 && this._pendingEvents.length > 0) {
        const evt = this._pendingEvents.shift();
        try {
          this.bridge.handleEvent(evt);
        } catch (err) {
          if (err instanceof DalvikGuestException) {
            this.vm._unwindException(err.exception);
            const faultRes = this.vm.step(0);
            this._exited = true;
            this._pendingCalls.length = 0;
            return {
              status: 'FAULT',
              instructionsExecuted: totalExecuted,
              fault: faultRes.fault,
            };
          }
          this._exited = true;
          this._pendingCalls.length = 0;
          return {
            status: 'FAULT',
            instructionsExecuted: totalExecuted,
            fault: err,
          };
        }
        if (this._exited || this.bridge.finished) {
          this._exited = true;
          return {
            status: 'EXITED',
            instructionsExecuted: totalExecuted,
            exitCode: this._exitCode,
          };
        }
      }

      // 2. Pop next scheduled Dalvik call if VM call stack is idle
      if (this.vm.callStack.length === 0 && this._pendingCalls.length > 0) {
        const nextCall = this._pendingCalls.shift();
        if (nextCall.phase) {
          this.bridge.activityState = nextCall.phase;
        }
        try {
          this.vm.startMethod(nextCall.classType, nextCall.signature, nextCall.args, nextCall.receiver);
        } catch (err) {
          this._exited = true;
          this._pendingCalls.length = 0;
          return {
            status: 'FAULT',
            instructionsExecuted: totalExecuted,
            fault: err,
          };
        }
        if (this.vm.callStack.length === 0 && this.vm.lastUncaughtException) {
          const faultRes = this.vm.step(0);
          this._exited = true;
          this._pendingCalls.length = 0;
          return {
            status: 'FAULT',
            instructionsExecuted: totalExecuted,
            fault: faultRes.fault,
          };
        }
      }

      // 3. If VM has nothing left to execute, surface uncaught faults first, then teardown / BLOCKED / EXITED
      if (this.vm.callStack.length === 0) {
        if (this.vm.lastUncaughtException) {
          const faultRes = this.vm.step(0);
          this._exited = true;
          this._pendingCalls.length = 0;
          return {
            status: 'FAULT',
            instructionsExecuted: totalExecuted,
            fault: faultRes.fault,
          };
        }
        if (this._pendingCalls.length > 0) {
          continue;
        }
        if (this.bridge._finishing) {
          this.bridge._finalizeActivityFinish();
          this._exited = true;
          return {
            status: 'EXITED',
            instructionsExecuted: totalExecuted,
            exitCode: this._exitCode,
          };
        }
        if (this._pendingEvents.length > 0) {
          continue;
        }
        if (this.bridge.windowId && !this.bridge.finished) {
          this.bridge.activityState = 'RESUMED';
          return {
            status: 'BLOCKED',
            instructionsExecuted: totalExecuted,
            waitReason: 'ui_event',
          };
        }
        this._exited = true;
        return {
          status: 'EXITED',
          instructionsExecuted: totalExecuted,
          exitCode: this._exitCode,
        };
      }

      // 4. Execute Dalvik instructions within remaining budget
      const stepRes = this.vm.step(remaining);
      const ran = stepRes.instructionsExecuted ?? 0;
      totalExecuted += ran;
      remaining -= ran;

      if (stepRes.status === 'FAULT') {
        this._exited = true;
        this._pendingCalls.length = 0;
        return {
          status: 'FAULT',
          instructionsExecuted: totalExecuted,
          fault: stepRes.fault,
        };
      }

      if (this.bridge.finished) {
        this._exited = true;
        return {
          status: 'EXITED',
          instructionsExecuted: totalExecuted,
          exitCode: this._exitCode,
        };
      }

      if (stepRes.status === 'YIELD') {
        return {
          status: 'YIELD',
          instructionsExecuted: totalExecuted,
        };
      }

      // If stepRes.status === 'EXITED' (current method returned), loop to pick up next lifecycle/callback call!
    }

    if (
      budget > 0 &&
      this.bridge._finishing &&
      this.vm.callStack.length === 0 &&
      this._pendingCalls.length === 0
    ) {
      this.bridge._finalizeActivityFinish();
      this._exited = true;
      return {
        status: 'EXITED',
        instructionsExecuted: totalExecuted,
        exitCode: this._exitCode,
      };
    }

    // Budget exhausted cleanly
    return {
      status: 'YIELD',
      instructionsExecuted: totalExecuted,
    };
  }

  /**
   * Receives input/intent/window events from Compositor or IntentRouter and wakes process if BLOCKED.
   */
  deliverEvent(event) {
    if (this._disposed || this._exited) return;
    if (!event || typeof event !== 'object') return;
    if (this._pendingEvents.length >= MAX_PENDING_EVENTS) {
      this._pendingEvents.splice(0, Math.max(1, MAX_PENDING_EVENTS >> 2));
    }
    this._pendingEvents.push(event);
    try {
      if (this.pcb?.state === 'BLOCKED' && typeof this.services?.processManager?.wake === 'function') {
        this.services.processManager.wake(this.pcb.pid);
      }
    } catch (err) {
      this.bridge._recordInternalLog('W', 'AndroidRuntime', `Process wake skipped: ${err?.message ?? err}`);
    }
  }

  getDebugState() {
    const vmDebug = this.vm.getDebugState();
    return {
      ...vmDebug,
      packageName: this.apk.packageName,
      activityState: this.bridge.activityState,
      windowId: this.bridge.windowId,
      pendingCalls: this._pendingCalls.length,
      pendingEvents: this._pendingEvents.length,
      logsCount: this.bridge.logs.length,
      toastsCount: this.bridge.toasts.length,
      disposed: this._disposed,
    };
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    this._exited = true;
    this._pendingCalls.length = 0;
    this._pendingEvents.length = 0;
    if (this.bridge) {
      if (!this.bridge.finished) {
        this.bridge.finished = true;
        this.bridge.activityState = 'DESTROYED';
        if (this.bridge.windowId && this.services?.compositor) {
          const wid = this.bridge.windowId;
          this.bridge.windowId = null;
          try {
            this.services.compositor.closeWindow(wid, { notifyProcess: false, reason: 'disposed' });
          } catch (err) {
            this.bridge._recordInternalLog('W', 'AndroidRuntime', `Window dispose ignored: ${err?.message ?? err}`);
          }
        }
      }
      this.bridge.dispose?.();
    }
  }
}

export class AndroidRuntime {
  constructor({ cpuRegistry = null } = {}) {
    this.platform = 'android';
    this.arch = 'dalvik';
    if (cpuRegistry) {
      registerDalvikCpu(cpuRegistry);
    }
  }

  inspectPackage(buffer, _filenameHint = '') {
    const apk = parseApk(buffer);
    return {
      format: 'android-apk',
      platform: 'android',
      arch: 'dalvik',
      appId: apk.packageName,
      name: apk.label || apk.packageName,
      version: apk.versionName || String(apk.versionCode || '1.0.0'),
      entryPoint: apk.launcherActivity || '',
      permissions: [...apk.permissions],
      intents: apk.intents.map((i) => ({ ...i })),
      sectionsOrClasses: [...apk.classes],
      importsOrMethods: apk.methods.slice(0, 2000),
      rawMetadata: {
        packageName: apk.packageName,
        label: apk.label,
        versionCode: apk.versionCode,
        versionName: apk.versionName,
        minSdkVersion: apk.minSdkVersion,
        targetSdkVersion: apk.targetSdkVersion,
        launcherActivity: apk.launcherActivity,
        activities: apk.activities,
        services: apk.services,
        receivers: apk.receivers,
        providers: apk.providers,
        dexCount: apk.dexFiles.length,
        hasResourcesArsc: Boolean(apk.resources),
        manifestFormat: apk.manifestFormat,
        signing: {
          signed: apk.signing.signed,
          v1: apk.signing.v1,
          v2: apk.signing.v2,
          v3: apk.signing.v3,
          schemes: apk.signing.schemes,
          hasApkSigningBlock: apk.signing.hasApkSigningBlock,
        },
        nativeLibs: apk.nativeLibs,
      },
    };
  }

  installPackage(inspection, _buffer, services = {}) {
    if (services.cpuRegistry && !services.cpuRegistry.has('dalvik')) {
      registerDalvikCpu(services.cpuRegistry);
    }

    // Provision private Android container directories owned by the sandboxed app UID
    const vfs = services.vfs;
    const dataDir = inspection?.dataDir;
    const uid = inspection?.uid ?? 10000;
    const gid = inspection?.gid ?? uid;
    if (vfs && dataDir) {
      const subdirs = ['files', 'cache', 'shared_prefs', 'databases'];
      for (const sub of subdirs) {
        const target = `${dataDir}/${sub}`;
        vfs.mkdir(target, { recursive: true, mode: 0o700, ...ROOT_VFS_CTX });
        if (typeof vfs.chown === 'function') {
          vfs.chown(target, uid, gid, { ...ROOT_VFS_CTX });
        }
      }
    }

    return {
      platform: 'android',
      format: 'android-apk',
      arch: 'dalvik',
      entryPoint: inspection.entryPoint,
      permissions: inspection.permissions,
      intents: inspection.intents,
      metadata: inspection.rawMetadata,
    };
  }

  createExecutionContext(pcb, appRecord, services = {}, launchOptions = {}) {
    if (services.cpuRegistry && !services.cpuRegistry.has('dalvik')) {
      registerDalvikCpu(services.cpuRegistry);
    }

    // Load original APK bytes from `${installDir}/.package.bin` with kernel UID 0 (Landmine #2)
    let apkBytes = launchOptions?.packageBytes ?? null;
    if (!apkBytes) {
      const vfs = services.vfs;
      if (!vfs) {
        throw new OmniOSError('AndroidRuntime requires VFS to load installed APK package', {
          code: ERROR_CODES.EINVAL,
        });
      }
      const pkgPath = `${appRecord.installDir}/.package.bin`;
      apkBytes = vfs.readFile(pkgPath, { ...ROOT_VFS_CTX });
    }

    const apk = parseApk(apkBytes);

    // Ensure private Android container subdirectories exist (idempotent across fresh launches)
    if (services.vfs && appRecord.dataDir) {
      for (const sub of ['files', 'cache', 'shared_prefs', 'databases']) {
        const target = `${appRecord.dataDir}/${sub}`;
        try {
          services.vfs.stat(target, { ...ROOT_VFS_CTX });
        } catch (err) {
          if (err?.code === 'ENOENT') {
            services.vfs.mkdir(target, { recursive: true, mode: 0o700, ...ROOT_VFS_CTX });
            if (typeof services.vfs.chown === 'function') {
              services.vfs.chown(target, pcb.uid, pcb.gid, { ...ROOT_VFS_CTX });
            }
          }
        }
      }
    }

    const maxTotalInstructions =
      pcb?.quotas?.maxTotalInstructions && Number.isFinite(pcb.quotas.maxTotalInstructions)
        ? pcb.quotas.maxTotalInstructions
        : Infinity;

    const maxMemoryBytes =
      pcb?.quotas?.maxMemoryBytes && Number.isFinite(pcb.quotas.maxMemoryBytes)
        ? pcb.quotas.maxMemoryBytes
        : 64 * 1024 * 1024;

    const vmOpts = {
      dexFiles: apk.dexFiles,
      maxCallDepth: 256,
      maxTotalInstructions,
      maxMemoryBytes,
      pid: pcb.pid,
    };

    const vm =
      services.cpuRegistry && services.cpuRegistry.has('dalvik')
        ? services.cpuRegistry.create('dalvik', vmOpts)
        : createDalvikVM(vmOpts);

    let execCtx = null;
    const bridge = createAndroidFrameworkBridge({
      vm,
      apk,
      pcb,
      appRecord,
      services,
      launchOptions,
      enqueueCallback: (call) => execCtx?.enqueueCallback(call),
      beginTeardown: (calls) => execCtx?.beginTeardown(calls),
      onFinish: () => execCtx?.markFinished(),
    });
    vm.setBridge(bridge);

    execCtx = new AndroidExecutionContext({
      pcb,
      appRecord,
      apk,
      vm,
      bridge,
      services,
      launchOptions,
    });
    return execCtx;
  }
}

export function createAndroidRuntime(opts = {}) {
  return new AndroidRuntime(opts);
}
