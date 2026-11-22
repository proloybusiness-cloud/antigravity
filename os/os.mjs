/**
 * OmniOS Unified Operating System Runtime Bootstrapper (`os/os.mjs`, F-061)
 * Wires M1 Microkernel, M2 OS Services & 6 Core Daemons, M3/M4 4-Platform + Universal CPU Engines & Runtimes,
 * M5 Multi-Syntax Shell Interpreter, 7 Built-in System Apps, Spotlight Universal Search, and App Hub Sample Seeding.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { OmniOSError, ERROR_CODES } from './common/errors.mjs';
import { createKernel, KERNEL_STATES } from './kernel/kernel.mjs';

import { registerDalvikCpu } from './cpu/dalvik.mjs';
import { registerX86Cpu } from './cpu/x86_64.mjs';
import { registerArm64Cpu } from './cpu/arm64.mjs';

import { UserManager } from './security/users.mjs';
import { PermissionBroker, registerSecurityService } from './security/permissions.mjs';
import { createPathTranslator } from './vfs/path-translator.mjs';
import { createVirtualMounts } from './vfs/virtual-mounts.mjs';
import { VFS, registerVfsService } from './vfs/vfs.mjs';
import {
  UnifiedConfigStore,
  registerConfigService,
  registerConfigSyscalls,
} from './store/unified-config.mjs';
import { IPCManager } from './ipc/ipc.mjs';
import { IntentRouter } from './ipc/router.mjs';
import { SharedClipboard } from './ipc/clipboard.mjs';
import { NotificationCenter, registerIpcBrokerService } from './ipc/notifications.mjs';
import { Compositor, registerCompositorService } from './compositor/compositor.mjs';
import { PackageManager, registerPackageService } from './pkg/package-manager.mjs';

import { createAndroidRuntime } from './runtimes/android/android-runtime.mjs';
import { createWindowsRuntime } from './runtimes/windows/windows-runtime.mjs';
import { createIOSRuntime } from './runtimes/ios/ios-runtime.mjs';
import { createMacOSRuntime } from './runtimes/macos/macos-runtime.mjs';
import { createUniversalRuntime, registerWasmCpu } from './runtimes/universal/wasm-runtime.mjs';

import { createShellInterpreter } from './apps/shell-interpreter.mjs';
import { createSystemAppRegistry } from './apps/registry.mjs';
import { createSpotlightSearch } from './server/search.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_PACKAGES_DIR = path.join(REPO_ROOT, 'packages');

export const SAMPLE_PACKAGE_MANIFESTS = Object.freeze([
  Object.freeze({
    filename: 'android-calc.apk',
    platform: 'android',
    category: 'Utilities',
    icon: 'calculator',
    description: 'Android Dalvik bytecode calculator app (.apk)',
  }),
  Object.freeze({
    filename: 'android-notes-sharer.apk',
    platform: 'android',
    category: 'Productivity',
    icon: 'notes',
    description: 'Android Dalvik notes & cross-platform intent sharer (.apk)',
  }),
  Object.freeze({
    filename: 'win-sysinfo.exe',
    platform: 'windows',
    category: 'System',
    icon: 'terminal',
    description: 'Windows x86-64 PE32+ console system info utility (.exe)',
  }),
  Object.freeze({
    filename: 'win-notepad.exe',
    platform: 'windows',
    category: 'Productivity',
    icon: 'notepad',
    description: 'Windows x86-64 PE32+ Win32 GUI Notepad (.exe)',
  }),
  Object.freeze({
    filename: 'ios-weather-island.ipa',
    platform: 'ios',
    category: 'Weather',
    icon: 'weather',
    description: 'iOS ARM64 Mach-O UIKit Weather & Dynamic Island Live Activity app (.ipa)',
  }),
  Object.freeze({
    filename: 'macos-studio.app.zip',
    platform: 'macos',
    category: 'Developer',
    icon: 'studio',
    description: 'macOS Universal (ARM64 + x86-64) AppKit Studio app (.app)',
  }),
  Object.freeze({
    filename: 'universal-canvas.uapp',
    platform: 'universal',
    category: 'Graphics',
    icon: 'canvas',
    description: 'Universal WebAssembly/WASI interactive Canvas2D studio (.uapp)',
  }),
]);

const MAX_PUMP_TICKS = 50;

export class OmniOS {
  constructor(config = {}) {
    if (config !== null && config !== undefined && typeof config !== 'object') {
      throw new OmniOSError('OmniOS config must be an object', { code: ERROR_CODES.EINVAL });
    }
    const cfg = config ?? {};

    this.version = '1.0.0';
    this._config = {
      dataDir: cfg.dataDir ?? null,
      dbPath: cfg.dbPath ?? null,
      autoStartScheduler: Boolean(cfg.autoStartScheduler ?? false),
      tickMs: typeof cfg.tickMs === 'number' && Number.isFinite(cfg.tickMs) && cfg.tickMs > 0 ? cfg.tickMs : 16,
      packagesDir: typeof cfg.packagesDir === 'string' && cfg.packagesDir.length > 0
        ? cfg.packagesDir
        : DEFAULT_PACKAGES_DIR,
      seedSamples: cfg.seedSamples !== false,
      shellMode: typeof cfg.shellMode === 'string' && cfg.shellMode.length > 0 ? cfg.shellMode : null,
    };

    this._server = null;
    this._postBootKey = null;
    this._postBootPromise = null;
    this._unsubs = [];

    // 1. Create Microkernel Core (M1)
    const kernelOpts = {
      dataDir: this._config.dataDir,
      dbPath: this._config.dbPath,
      autoStartScheduler: this._config.autoStartScheduler,
      tickMs: this._config.tickMs,
    };
    if (cfg.dmesgCapacity !== undefined) kernelOpts.dmesgCapacity = cfg.dmesgCapacity;
    if (cfg.baseQuantum !== undefined) kernelOpts.baseQuantum = cfg.baseQuantum;
    if (cfg.panicDumpWriter !== undefined) kernelOpts.panicDumpWriter = cfg.panicDumpWriter;

    this.kernel = createKernel(kernelOpts);
    this.processManager = this.kernel.processManager;
    this.scheduler = this.kernel.scheduler;
    this.serviceManager = this.kernel.serviceManager;
    this.eventBus = this.kernel.eventBus;
    this.syscalls = this.kernel.syscalls;
    this.cpuRegistry = this.kernel.cpuRegistry;

    // 2. Register ALL 4 CPU / Bytecode Engines onto kernel.cpuRegistry
    registerDalvikCpu(this.cpuRegistry);
    registerX86Cpu(this.cpuRegistry);
    registerArm64Cpu(this.cpuRegistry);
    registerWasmCpu(this.cpuRegistry);

    // 3. Construct ALL M2 Services lazily bound to `{ kernel }`
    this.users = new UserManager({ kernel: this.kernel });
    this.permissions = new PermissionBroker({ kernel: this.kernel, userManager: this.users });
    this.pathTranslator = createPathTranslator();
    this.virtualMounts = createVirtualMounts({
      kernel: this.kernel,
      processManager: this.processManager,
    });
    this.vfs = new VFS({
      kernel: this.kernel,
      userManager: this.users,
      pathTranslator: this.pathTranslator,
      virtualMounts: this.virtualMounts,
    });
    this.configStore = new UnifiedConfigStore({ kernel: this.kernel });
    this.config = this.configStore;
    this.ipc = new IPCManager({ kernel: this.kernel });
    this.intentRouter = new IntentRouter({ kernel: this.kernel, configStore: this.configStore });
    this.clipboard = new SharedClipboard({ kernel: this.kernel });
    this.notifications = new NotificationCenter({
      kernel: this.kernel,
      configStore: this.configStore,
    });

    const compositorOpts = {
      kernel: this.kernel,
      processManager: this.processManager,
      configStore: this.configStore,
    };
    if (cfg.viewport !== undefined && cfg.viewport !== null) {
      compositorOpts.viewport = cfg.viewport;
    }
    if (this._config.shellMode !== null) {
      compositorOpts.shellMode = this._config.shellMode;
    }
    this.compositor = new Compositor(compositorOpts);

    this.pkgManager = new PackageManager({
      kernel: this.kernel,
      vfs: this.vfs,
      configStore: this.configStore,
      ipc: this.ipc,
      intentRouter: this.intentRouter,
      clipboard: this.clipboard,
      notifications: this.notifications,
      users: this.users,
      permissions: this.permissions,
      compositor: this.compositor,
    });
    this.ospm = this.pkgManager;
    this.packages = this.pkgManager;
    this.formatDetector = this.pkgManager.detector;

    // Security facade matching Contract 4 + SCOPE.md
    this.security = Object.freeze({
      users: this.users,
      permissions: this.permissions,
      checkPermission: (req) => this.permissions.checkPermission(req),
      assertPermission: (req) => this.permissions.assertPermission(req),
      setGrant: (appId, capability, state, opts) => this.permissions.setGrant(appId, capability, state, opts),
      getGrant: (appId, capability) => this.permissions.getGrant(appId, capability),
      listGrants: (appId) => this.permissions.listGrants(appId),
      getAuditLog: (opts) => this.permissions.getAuditLog(opts),
      resolvePrompt: (promptId, decision) => this.permissions.resolvePrompt(promptId, decision),
      getPendingPrompts: () => this.permissions.getPendingPrompts(),
    });

    // 4. Instantiate & Register ALL 5 Platform Runtimes onto pkgManager
    const androidRuntime = createAndroidRuntime({ cpuRegistry: this.cpuRegistry });
    const windowsRuntime = createWindowsRuntime({ cpuRegistry: this.cpuRegistry });
    const iosRuntime = createIOSRuntime();
    const macosRuntime = createMacOSRuntime();
    const universalRuntime = createUniversalRuntime({ cpuRegistry: this.cpuRegistry });

    this.runtimes = Object.freeze({
      android: androidRuntime,
      windows: windowsRuntime,
      ios: iosRuntime,
      macos: macosRuntime,
      universal: universalRuntime,
    });

    this.pkgManager.registerRuntime('android', androidRuntime);
    this.pkgManager.registerRuntime('windows', windowsRuntime);
    this.pkgManager.registerRuntime('ios', iosRuntime);
    this.pkgManager.registerRuntime('macos', macosRuntime);
    this.pkgManager.registerRuntime('universal', universalRuntime);

    // 5. Register EXACT 6 M2 Daemons in strict topological dependency order + Config Syscalls
    registerSecurityService(this.serviceManager, {
      userManager: this.users,
      permissionBroker: this.permissions,
      kernel: this.kernel,
      deps: [],
      essential: true,
    });
    registerConfigService(this.serviceManager, this.configStore, {
      kernel: this.kernel,
      deps: [],
      essential: true,
    });
    registerConfigSyscalls(this.syscalls, this.configStore);

    registerVfsService(this.serviceManager, this.vfs, {
      kernel: this.kernel,
      deps: ['securityd'],
      essential: true,
    });
    registerIpcBrokerService(this.serviceManager, {
      ipc: this.ipc,
      router: this.intentRouter,
      clipboard: this.clipboard,
      notifications: this.notifications,
      kernel: this.kernel,
      deps: ['configd'],
      essential: true,
    });
    registerCompositorService(this.serviceManager, this.compositor, {
      kernel: this.kernel,
      deps: ['configd', 'ipc-brokerd'],
      essential: true,
    });
    registerPackageService(this.serviceManager, this.pkgManager, {
      kernel: this.kernel,
      deps: ['securityd', 'vfsd', 'configd', 'ipc-brokerd', 'compositord'],
      essential: true,
    });

    // 6. Instantiate M5 Subsystems (Shell Interpreter, System Apps Registry, Spotlight Search)
    this.shell = createShellInterpreter(this);
    this.systemApps = createSystemAppRegistry(this);
    this.search = createSpotlightSearch(this);

    // 7. Wire IntentRouter unified launcher
    this.intentRouter.setLauncher(async (appId, { intent } = {}) => this.launchApp(appId, { intent }));

    // 8. Wire idempotent post-boot init on `kernel:booted` AND restore system intents on uninstall
    this._unsubs.push(
      this.eventBus.on('kernel:booted', (bootReport) => {
        const bootKey = bootReport?.bootedAt ?? `boot-${Date.now()}`;
        this._ensurePostBootInit(bootKey).catch((err) => {
          this.kernel.log('warn', 'omnios', `Post-boot initialization warning: ${err?.message ?? String(err)}`);
        });
      })
    );

    this._unsubs.push(
      this.eventBus.on('pkg:uninstalled', (ev) => {
        if (ev?.appId && this.systemApps.resolveId(ev.appId)) {
          try {
            this.systemApps.registerIntents();
          } catch (err) {
            this.kernel.log('warn', 'omnios', `Failed restoring system app intents: ${err?.message ?? String(err)}`);
          }
        }
      })
    );
  }

  _ensurePostBootInit(bootKey = null) {
    const effectiveKey = bootKey ?? this.kernel.bootReport?.bootedAt ?? 'boot-default';
    if (this._postBootKey === effectiveKey && this._postBootPromise) {
      return this._postBootPromise;
    }
    this._postBootKey = effectiveKey;
    this._postBootPromise = this._runPostBootInit().catch((err) => {
      // Allow retry if post-boot init failed
      if (this._postBootKey === effectiveKey) {
        this._postBootKey = null;
        this._postBootPromise = null;
      }
      throw err;
    });
    return this._postBootPromise;
  }

  async _runPostBootInit() {
    if (
      this.kernel.state !== KERNEL_STATES.RUNNING &&
      this.kernel.state !== KERNEL_STATES.SAFE_MODE
    ) {
      return;
    }

    // Apply initial shellMode if explicitly configured
    if (this._config.shellMode && this.configStore.isReady()) {
      try {
        this.compositor.setShellMode(this._config.shellMode);
        this.configStore.system.set('system.shellMode', this._config.shellMode);
      } catch (err) {
        this.kernel.log('warn', 'omnios', `Failed applying initial shellMode: ${err?.message ?? String(err)}`);
      }
    }

    // Register built-in system app intents
    this.systemApps.registerIntents();

    // Index Windows HKCR / Registry associations into IntentRouter
    if (this.configStore.isReady()) {
      try {
        this.intentRouter.indexRegistryAssociations(this.configStore);
      } catch (err) {
        this.kernel.log('warn', 'omnios', `Failed indexing registry associations: ${err?.message ?? String(err)}`);
      }
    }

    // Seed sample packages into VFS `/packages/` and App Hub catalog
    if (this._config.seedSamples && this.vfs.isReady && this.pkgManager.isReady()) {
      await this._seedSamplePackages();
    }
  }

  async _seedSamplePackages() {
    try {
      this.vfs.mkdir('/packages', { recursive: true, mode: 0o755, uid: 0, gid: 0 });
    } catch (err) {
      if (err?.code !== 'EEXIST') {
        this.kernel.log('warn', 'omnios', `Failed creating /packages in VFS: ${err?.message ?? String(err)}`);
        return;
      }
    }

    let seededCount = 0;
    for (const manifest of SAMPLE_PACKAGE_MANIFESTS) {
      const hostPath = path.join(this._config.packagesDir, manifest.filename);
      let fileBuf;
      try {
        fileBuf = await fs.readFile(hostPath);
      } catch (readErr) {
        if (readErr?.code === 'ENOENT') {
          continue;
        }
        this.kernel.log(
          'warn',
          'omnios',
          `Skipping sample package ${manifest.filename}: ${readErr?.message ?? String(readErr)}`
        );
        continue;
      }

      if (
        this.kernel.state !== KERNEL_STATES.RUNNING &&
        this.kernel.state !== KERNEL_STATES.SAFE_MODE
      ) {
        return;
      }

      try {
        const bytes = new Uint8Array(fileBuf.buffer, fileBuf.byteOffset, fileBuf.byteLength);
        const vfsPath = `/packages/${manifest.filename}`;
        this.vfs.writeFile(vfsPath, bytes, { uid: 0, gid: 0, mode: 0o644 });

        const insp = await this.pkgManager.inspect(bytes, manifest.filename);
        const architectures = Array.isArray(insp.rawMetadata?.architectures)
          ? insp.rawMetadata.architectures
          : [insp.arch];

        this.pkgManager.registerCatalogEntry({
          catalogId: insp.appId,
          appId: insp.appId,
          name: insp.name,
          platform: insp.platform,
          format: insp.format,
          version: insp.version,
          description: manifest.description,
          icon: manifest.icon,
          packagePath: vfsPath,
          sha256: insp.sha256,
          sizeBytes: insp.sizeBytes,
          metadata: {
            filename: manifest.filename,
            arch: insp.arch,
            architectures,
            category: manifest.category,
            description: manifest.description,
            ...(insp.rawMetadata?.spotlight ? { spotlight: insp.rawMetadata.spotlight } : {}),
          },
        });
        seededCount += 1;
      } catch (seedErr) {
        this.kernel.log(
          'warn',
          'omnios',
          `Failed seeding sample package ${manifest.filename}: ${seedErr?.message ?? String(seedErr)}`
        );
      }
    }

    this.kernel.log('info', 'omnios', `Seeded ${seededCount} sample packages into /packages and App Hub catalog`, {
      seededCount,
      packagesDir: this._config.packagesDir,
    });
  }

  async boot({ safeMode = false } = {}) {
    if (
      this.kernel.state === KERNEL_STATES.RUNNING ||
      this.kernel.state === KERNEL_STATES.SAFE_MODE
    ) {
      await this._ensurePostBootInit(this.kernel.bootReport?.bootedAt ?? null);
      return this.kernel.bootReport;
    }
    const report = await this.kernel.boot({ safeMode });
    await this._ensurePostBootInit(report?.bootedAt ?? null);
    return report;
  }

  async recover({ safeMode = false } = {}) {
    this._postBootKey = null;
    this._postBootPromise = null;
    const report = await this.kernel.recover({ safeMode });
    await this._ensurePostBootInit(report?.bootedAt ?? null);
    return report;
  }

  async launchApp(appId, opts = {}) {
    const launchOpts = opts && typeof opts === 'object' ? opts : {};
    const preferSystem = launchOpts.preferSystem === true || launchOpts.platform === 'system';
    const canonicalSystemId = this.systemApps.resolveId(appId);
    const installedPkg =
      !preferSystem && typeof appId === 'string' && this.pkgManager.isReady()
        ? this.pkgManager.get(appId)
        : null;

    let result;
    if (preferSystem && canonicalSystemId) {
      result = await this.systemApps.launch(canonicalSystemId, launchOpts);
    } else if (installedPkg) {
      result = await this.pkgManager.launch(installedPkg.appId, launchOpts);
    } else if (canonicalSystemId) {
      result = await this.systemApps.launch(canonicalSystemId, launchOpts);
    } else {
      result = await this.pkgManager.launch(appId, launchOpts);
    }

    const rawTicks = Number.isInteger(launchOpts.stepTicks) ? launchOpts.stepTicks : 0;
    const shouldPump = launchOpts.pump === true || rawTicks > 0;
    if (shouldPump && this.scheduler) {
      const ticks = Math.min(Math.max(rawTicks || 10, 1), MAX_PUMP_TICKS);
      this.scheduler.step(ticks);
    }

    const windowIds = this.compositor
      .listWindows({ pid: result.pid })
      .map((w) => w.windowId);

    return {
      pid: result.pid,
      appId: result.appId,
      platform: result.platform,
      windowIds,
    };
  }

  stopApp(pidOrAppId, opts = {}) {
    const stopOpts = opts && typeof opts === 'object' ? opts : {};
    const stoppedSet = new Set();

    if (typeof pidOrAppId === 'number' && Number.isInteger(pidOrAppId)) {
      const sysRes = this.systemApps.stop(pidOrAppId, stopOpts);
      for (const pid of sysRes.stoppedPids) stoppedSet.add(pid);
      if (stoppedSet.size === 0) {
        const pkgRes = this.pkgManager.stop(pidOrAppId, stopOpts);
        for (const pid of pkgRes.stoppedPids) stoppedSet.add(pid);
      }
      return { stoppedPids: Array.from(stoppedSet) };
    }

    if (typeof pidOrAppId === 'string') {
      const canonicalSystemId = this.systemApps.resolveId(pidOrAppId);
      if (canonicalSystemId) {
        const sysRes = this.systemApps.stop(canonicalSystemId, stopOpts);
        for (const pid of sysRes.stoppedPids) stoppedSet.add(pid);
      }
      if (this.pkgManager.isReady()) {
        const pkgRes = this.pkgManager.stop(pidOrAppId, stopOpts);
        for (const pid of pkgRes.stoppedPids) stoppedSet.add(pid);
      }
      return { stoppedPids: Array.from(stoppedSet) };
    }

    throw new OmniOSError('stopApp() requires a PID number or appId string', {
      code: ERROR_CODES.EINVAL,
    });
  }

  getStatus() {
    const diag = this.kernel.getDiagnostics();
    return {
      ok: true,
      os: 'OmniOS',
      version: this.version,
      status: this.kernel.state,
      ...diag,
    };
  }

  async startServer(serverOpts = {}) {
    if (
      this.kernel.state !== KERNEL_STATES.RUNNING &&
      this.kernel.state !== KERNEL_STATES.SAFE_MODE
    ) {
      await this.boot();
    }
    const { createHttpServer } = await import('./server/http-server.mjs');
    const server = createHttpServer(this, serverOpts);
    const addr = await server.start(serverOpts);
    this._server = server;
    return { server, ...addr };
  }

  async shutdown() {
    if (this._server) {
      const srv = this._server;
      this._server = null;
      try {
        await srv.stop();
      } catch (err) {
        this.kernel.log('warn', 'omnios', `Error stopping attached HTTP server: ${err?.message ?? String(err)}`);
      }
    }

    while (this._unsubs.length > 0) {
      const unsub = this._unsubs.pop();
      if (typeof unsub === 'function') unsub();
    }

    try {
      this.systemApps.stopAll();
    } catch (err) {
      this.kernel.log('warn', 'omnios', `Error stopping system apps: ${err?.message ?? String(err)}`);
    }

    try {
      this.search?.dispose?.();
    } catch (err) {
      this.kernel.log('warn', 'omnios', `Error disposing Spotlight search: ${err?.message ?? String(err)}`);
    }

    this._postBootKey = null;
    this._postBootPromise = null;
    await this.kernel.shutdown();
  }
}

export function createOmniOS(config = {}) {
  return new OmniOS(config);
}

export async function bootOmniOS(config = {}) {
  const os = createOmniOS(config);
  const safeMode = Boolean(config && typeof config === 'object' ? config.safeMode : false);
  await os.boot({ safeMode });
  return os;
}
