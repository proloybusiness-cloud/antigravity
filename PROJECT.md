# Project: OmniOS — All-in-One Cross-Platform Operating System

**Mission**: Build **OmniOS**, a genuine, cross-platform all-in-one operating system fusing **Android**, **Windows**, **iOS**, and **macOS** (plus **Universal WebAssembly/WASI**) that can authentically inspect, install, sandbox, and execute real apps from all 4 platforms side-by-side inside a unified hybrid desktop/mobile OS shell and headless CLI — with zero mocked/hardcoded app behavior.

---

## Architecture

### Core Architectural Principles & Verified Host Constraints
- **Zero-Dependency Cross-Platform Stack**: **Node.js 24 ESM (`.mjs`)** (`node >=22.13.0`, host verified `v24.22.3`, **0 external runtime npm dependencies**), leveraging built-in `node:sqlite` (WAL persistence), `node:zlib`, `node:crypto`, `node:http` (`upgrade` for pure-JS RFC 6455 WebSocket), `node:test`, `WebAssembly`, `DataView`, and `BigUint64Array`. Runs identically on Linux, macOS, Windows, and Docker (`node:24-alpine`).
- **Frontend Stack**: Zero-build **HTML5 / CSS3 / Native ES Modules / Canvas2D** in `ui/` — 100% offline-safe (no external CDN fonts/scripts), zero fake state (all UI interactions dispatch real REST/WebSocket requests to the live OS kernel and headless compositor).
- **Host Environment Facts (Verified Step 0)**:
  - Linux x86_64 Debian 12, 2 vCPU, 7.8 GiB RAM, 20 GB disk. No `/dev/kvm`, QEMU, Wine, Docker, Android SDK, or Apple SDKs — hence pure userspace microkernel + real binary loaders & CPU/bytecode VMs.
  - Pre-installed external verification tools: `/usr/lib/chromium/chromium` (`156.0.8078.79` — **MUST use `/usr/lib/chromium/chromium --headless=new --no-sandbox --disable-gpu` directly**, bypassing `/usr/bin/chromium` dash wrapper bug), `llvm-mc`, `llvm-objdump`, `llvm-readobj`, `clang`, `nasm`, `python3` (`zipfile`, `plistlib`), `file`, `zip`/`unzip`, `sqlite3`.
- **Zero-Fake / Anti-Mocking Execution Invariant**: Every Android (`.apk`), Windows (`.exe`/`.dll`/`.msix`/`.bat`), iOS (`.ipa`), macOS (`.app`/Mach-O), and Universal (`.uapp`/`.wasm`) app runs inside an isolated Kernel Process (`PID`) with sparse 4KB R/W/X virtual memory pages, executes real parsed bytecode/machine instructions through `IExecutionContext.step(budget)` under the preemptive Kernel Scheduler, and interacts with the OS exclusively through real ABI/syscall/framework bridges. Both SDK-built sample apps and externally supplied binaries follow the exact same parser → loader → CPU/VM → syscall execution path with zero app-name special-casing.
- **Non-Destructive Repository Coexistence**: Legacy Gen-1 `antigravity-flow` files (`src/*.mjs`, `public/*`, `workflows/*.json`, `test/system.test.mjs`) remain intact under `npm run start:flow`, `npm run test:legacy`, and `npm run validate`, while **OmniOS** resides cleanly in `os/`, `ui/`, `sdk/`, `packages/`, and `tests/` and becomes the primary runnable product (`npm start`, `npm run cli`, `npm run sdk:build`, `npm test`, `Dockerfile`, `README.md`) serving `PORT=3777` (with both `/api/health` and `/api/v1/health`).

### Layered Architecture Diagram

```text
+======================================================================================+
| LAYER 6: USER INTERFACES (Cross-Platform Web/Desktop GUI + Headless/Interactive CLI) |
|  [ui/ Unified 4-Platform Adaptive Shell GUI]     [os/cli/ OmniOS CLI & Multi-Shell]  |
|   - 5 Live Adaptive Modes: Unified Hybrid |      - Local headless OR --remote <url>  |
|     Windows | macOS | iOS | Android              - POSIX + Win CMD + macOS defaults  |
|   - Live Compositor Client (UI Tree + Canvas2D)  - Android am/pm + ospm + --json     |
+=====================================▲==================================▲=============+
                                      | HTTP REST (/api/v1, /api/health) | Direct /
                                      | + RFC 6455 WebSocket (/ws)       | Remote HTTP
+=====================================▼==================================▼=============+
| LAYER 5: TRANSPORT SERVER & BUILT-IN SYSTEM APPS (`os/os.mjs`, `os/server/`, `os/apps/`)
|  - HTTP REST v1, Zero-Dep RFC 6455 WebSocket Bus, Spotlight Universal Search Index   |
|  - 7 Kernel-Backed System Apps (real processes + real Compositor windows):           |
|    OmniTerm | OmniFiles | Activity Monitor | App Hub | Settings | Inspector | Notes  |
+=====================================▲================================================+
                                      |
+=====================================▼================================================+
| LAYER 4: 4-PLATFORM RUNTIMES, CPU/BYTECODE ENGINES & SDK (`os/cpu/`, `os/runtimes/`, `sdk/`)
|  [os/cpu/]       CpuRegistry | Dalvik VM | x86/x86-64 Emulator | ARM64 Emulator      |
|  [os/runtimes/]                                                                      |
|   ├── android/   APK + AXML + resources.arsc + DEX 035-041 + Dalvik VM + Framework   |
|   ├── windows/   PE32/PE32+ + .msix/.msi + IAT + x86/x86-64 + Win32 + .bat/.cmd      |
|   ├── apple/     Mach-O 64/Universal Fat + bplist00/XML plist + ObjC ABI2/Swift      |
|   ├── ios/       IPA + ARM64 Mach-O + UIKit/Foundation/SpringBoard/Dynamic Island    |
|   ├── macos/     .app/.dmg/.pkg + ARM64/x86-64 Mach-O + Darwin XNU BSD + AppKit/Menu |
|   └── universal/ .uapp / .wasm (V8 WebAssembly + WASI Preview 1 + omni_os_v1 ABI)    |
|  [sdk/]          Pure-JS Deterministic Assemblers & Packagers -> packages/*.{apk,    |
|                  exe,ipa,app.zip,uapp} (externally verifiable binaries)              |
+=====================================▲================================================+
                                      | Uniform IPlatformRuntime / IExecutionContext
+=====================================▼================================================+
| LAYER 3: OS SERVICES & HEADLESS WINDOW COMPOSITOR (`os/{vfs,store,ipc,security,compositor,pkg}/`)
|  - Unified SQLite POSIX VFS + /proc + /dev + 4-Platform PathTranslator               |
|  - Unified Config Store (Win Registry + Apple Defaults/plist + Android SharedPrefs)  |
|  - IPC Channels/Pipes/SHM + Universal Intent/URL/File Router + Clipboard + Notifs    |
|  - Users/Groups/Sandbox UIDs + Permission Broker (Android/TCC/Gatekeeper/UAC/WASI)   |
|  - Headless Display Server (Windows, Z-Order, Snap Layouts, UI Tree + DrawOps, Input)|
|  - Zero-Dep ZIP/ZIP64 Codec + Magic-Byte Detector + ospm Package Manager             |
+=====================================▲================================================+
                                      | Syscalls & Kernel Events
+=====================================▼================================================+
| LAYER 2: MICROKERNEL CORE (`os/kernel/`)                                             |
|  Bootloader/Init (4 Stages, PID 0/1) | ServiceManager (deps/health/restart) | dmesg  |
|  Panic + Safe Recovery | Process & Thread Manager (PCB FSM/Signals/FDs/Quotas)       |
|  Preemptive/Cooperative Scheduler | Virtual Memory Manager (4KB R/W/X, __PAGEZERO)   |
+=====================================▲================================================+
                                      |
+=====================================▼================================================+
| LAYER 1: PERSISTENT STORAGE & COMMON PRIMITIVES (`os/common/`, `node:sqlite` WAL)    |
+======================================================================================+
```

---

## Code Layout

Every Implementation milestone owns a **strictly disjoint** set of directories/files. Concurrent Workers MUST NEVER write the same file.

```text
/home/antigravity/proloybusiness-cloud/antigravity/
├── PROJECT.md                            # Master architecture, contracts & milestones (Orchestrator)
├── TEST_INFRA.md                         # E2E test architecture & coverage matrix (E2E Orchestrator)
├── TEST_READY.md                         # E2E suite completion signal (E2E Orchestrator)
├── package.json                          # [M7] Primary OmniOS scripts + preserved legacy Flow scripts
├── Dockerfile                            # [M7] node:24-alpine booting OmniOS on PORT=3777 (/api/health)
├── docker-compose.yml                    # [M7] Persistent /app/data volume for OmniOS SQLite + packages
├── README.md                             # [M7] OmniOS architecture, Quickstart (CLI+GUI), 4-Platform guide
├── .github/workflows/ci.yml              # [M7] CI running validate + OmniOS tests + legacy tests
├── os/
│   ├── os.mjs                            # [M5] Top-level createOmniOS(config) unified runtime factory
│   ├── common/                           # [M1]
│   │   ├── errors.mjs                    #      Structured OS error classes & POSIX/Win32/WASI codes
│   │   ├── binary.mjs                    #      LE/BE BinaryReader/Writer, CRC-32, Adler-32, LEB128, MUTF-8
│   │   └── storage-sqlite.mjs            #      Unified WAL node:sqlite wrapper & schema migration runner
│   ├── kernel/                           # [M1]
│   │   ├── event-bus.mjs                 #      Typed KernelEventBus
│   │   ├── vmm.mjs                       #      Per-PID sparse 4KB R/W/X AddressSpace, __PAGEZERO, heap
│   │   ├── process.mjs                   #      ProcessManager, PCB FSM, Threads, Signals, FDs/Streams, Quotas
│   │   ├── scheduler.mjs                 #      Preemptive/Cooperative priority round-robin Scheduler
│   │   ├── services.mjs                  #      Systemd-like ServiceManager (deps, health, restart backoff)
│   │   ├── syscalls.mjs                  #      Unified SyscallDispatcher
│   │   ├── boot.mjs                      #      4-stage deterministic Bootloader & Init (PID 0/1)
│   │   └── kernel.mjs                    #      OmniKernel coordinator, dmesg ring buffer, panic/recover
│   ├── cpu/
│   │   ├── registry.mjs                  # [M1] CpuRegistry (arch -> CPU/VM factory)
│   │   ├── dalvik.mjs                    # [M3] Real Dalvik DEX register bytecode interpreter VM
│   │   ├── x86_64.mjs                    # [M3] Real x86 & x86-64 CPU emulator (Win64/x86/SysV ABI)
│   │   └── arm64.mjs                     # [M4] Real ARM64 (AArch64) CPU emulator & Apple ABI
│   ├── vfs/                              # [M2]
│   │   ├── path-translator.mjs           #      Transparent 4-platform PathTranslator + case-insensitivity
│   │   ├── virtual-mounts.mjs            #      Dynamic /proc/*, /dev/{null,zero,urandom}, /tmp mounts
│   │   └── vfs.mjs                       #      Persistent SQLite POSIX VFS (inodes, symlinks/ELOOP, perms)
│   ├── store/                            # [M2]
│   │   └── unified-config.mjs            #      Unified Config Store + Win Registry + Apple Defaults + Android SP
│   ├── ipc/                              # [M2]
│   │   ├── ipc.mjs                       #      Named channels, pipes, RPC, Shared Memory (SHM)
│   │   ├── router.mjs                    #      Universal Intent / URL-Scheme / File-Association Router
│   │   ├── clipboard.mjs                 #      Multi-MIME Shared Clipboard & 20-item history
│   │   └── notifications.mjs             #      Unified Notification Center & Dynamic Island Live Activities
│   ├── security/                         # [M2]
│   │   ├── users.mjs                     #      Users, groups, sandbox UIDs (10000+), POSIX ACLs
│   │   └── permissions.mjs               #      Unified Permission Broker (Android/TCC/Gatekeeper/UAC/WASI) + Audit
│   ├── compositor/                       # [M2]
│   │   └── compositor.mjs                #      Headless Display Server (Windows, Snap, UI Tree + DrawOps, Input)
│   ├── pkg/                              # [M2]
│   │   ├── zip.mjs                       #      Zero-dep PKZIP/ZIP64 reader/writer (STORE/DEFLATE, CRC32, ZIP-slip/bomb)
│   │   ├── format-detector.mjs           #      Magic-byte & archive structure auto-detector (all formats)
│   │   └── package-manager.mjs           #      ospm installer/inspector/launcher + App Hub catalog DB
│   ├── runtimes/
│   │   ├── android/                      # [M3] axml-parser.mjs, resources-arsc.mjs, dex-parser.mjs, apk-parser.mjs,
│   │   │                                 #      framework-bridge.mjs, android-runtime.mjs
│   │   ├── windows/                      # [M3] pe-parser.mjs, win-pkg-parser.mjs (.msix/.msi), win32-bridge.mjs,
│   │   │                                 #      batch-runner.mjs, windows-runtime.mjs
│   │   ├── apple/                        # [M4] macho-parser.mjs, plist-parser.mjs (bplist00+XML),
│   │   │                                 #      darwin-syscalls.mjs, objc-runtime.mjs
│   │   ├── ios/                          # [M4] ipa-parser.mjs, uikit-bridge.mjs, ios-runtime.mjs
│   │   ├── macos/                        # [M4] app-bundle-parser.mjs (.app/.dmg/.pkg), appkit-bridge.mjs, macos-runtime.mjs
│   │   └── universal/                    # [M4] wasi-bridge.mjs, wasm-runtime.mjs
│   ├── apps/                             # [M5] registry.mjs, shell-interpreter.mjs, terminal-app.mjs, files-app.mjs,
│   │                                     #      monitor-app.mjs, apphub-app.mjs, settings-app.mjs, inspector-app.mjs, notes-app.mjs
│   ├── server/                           # [M5] websocket.mjs (RFC 6455), search.mjs (Spotlight), http-server.mjs
│   └── cli/                              # [M5] omnios-cli.mjs (headless, interactive REPL, --remote, --json)
├── sdk/
│   ├── android-builder.mjs               # [M3] Pure-JS real DEX + AXML + APK assembler/packager
│   ├── windows-builder.mjs               # [M3] Pure-JS real PE32+ x86-64 .exe assembler/linker
│   ├── ios-builder.mjs                   # [M4] Pure-JS real ARM64 Mach-O + bplist00 + .ipa packager
│   ├── macos-builder.mjs                 # [M4] Pure-JS real Mach-O ARM64/Universal + .app bundle packager
│   ├── universal-builder.mjs             # [M4] Pure-JS real WASM (\0asm) + .uapp packager
│   └── build-samples.mjs                 # [M4] Deterministically builds all 7 sample packages in packages/
├── packages/                             # [M3: android-*.apk, win-*.exe; M4: ios-*.ipa, macos-*.app.zip, universal-*.uapp]
├── ui/                                   # [M6] Unified 4-Platform Adaptive Shell & Live Compositor GUI
│   ├── index.html                        #      Shell frame + overlays (Spotlight, Start, Control Center, Shade, Modals)
│   ├── styles/                           #      base.css, hybrid.css, mode-windows.css, mode-macos.css, mode-ios.css, mode-android.css
│   └── js/                               #      ws-client.js, compositor-ui.js, canvas-renderer.js, shell-modes.js, overlays.js, app.js
├── tests/
│   ├── unit/                             # [M1–M6] Milestone unit/integration tests: m1-kernel.test.mjs .. m6-gui.test.mjs
│   └── e2e/                              # [E2E Track] Opaque-box Tiers 1-4 test suite + harness (T5 added in M7 Phase 2)
├── src/                                  # [PRESERVED LEGACY] Antigravity Flow Gen-1 backend
├── public/                               # [PRESERVED LEGACY] Antigravity Flow Gen-1 UI
├── workflows/                            # [PRESERVED LEGACY] Antigravity Flow Gen-1 workflows
└── test/system.test.mjs                  # [PRESERVED LEGACY] Antigravity Flow Gen-1 tests
```

### Canonical Commands
- `node os/server/http-server.mjs` (promoted to `npm start` in M7): Boot OmniOS Kernel + HTTP/WS Daemon + Hybrid Web Shell (`PORT=3777`, `GET /api/health` & `GET /api/v1/health`).
- `node os/cli/omnios-cli.mjs <cmd>` (promoted to `npm run cli` in M7): Headless/interactive/remote OS CLI.
- `node sdk/build-samples.mjs` (promoted to `npm run sdk:build` in M7): Deterministically assemble & package all 7 real 4-platform + Universal sample binaries into `packages/`.
- `node --test tests/unit/m<N>-*.test.mjs`: Per-milestone unit & integration verification.
- `node --test tests/unit/*.test.mjs`: Full unit & integration test suite.
- `node --test tests/e2e/**/*.test.mjs` (runner documented in `TEST_READY.md`): Full opaque-box E2E test suite (Tiers 1–4).
- `npm run validate` / `node --test test/system.test.mjs`: Preserved legacy Gen-1 Flow verification.

---

## Feature Inventory

Every Survey feature from `survey_1`, `survey_2`, and `survey_3` is accounted for and assigned to exactly one milestone (**90 / 90 assigned, 0 unassigned**).

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F-001 | 4-Stage Bootloader & Init | Deterministic boot (`EARLY_BOOT`→`CORE_SUBSYSTEMS`→`STORAGE_AND_STATE`→`OS_SERVICES`→`RUNNING`), stage timings, PID 0 `kernel_idle` & PID 1 `omnid` | M1 | survey_3 |
| F-002 | Systemd-like ServiceManager | Manage core daemons (`vfsd`, `configd`, `ipc-brokerd`, `securityd`, `pkgd`, `compositord`) with dep-order startup, health probes & restart backoff | M1 | survey_3 |
| F-003 | Kernel `dmesg` Ring Buffer | Bounded structured kernel log (`{ seq, ts, uptimeMs, level, subsystem, message, meta }`) with subsystem & severity filtering | M1 | survey_3 |
| F-004 | Kernel Panic & Safe Recovery | `kernel.panic()` persists crash dump to SQLite & halts user scheduling; `kernel.recover({ safeMode })` reboots cleanly without crashing host Node | M1 | survey_3 |
| F-005 | Runtime Diagnostics Snapshot | `kernel.getDiagnostics()` reporting state, uptime, boot report, services, process count, VMM stats, dmesg tail, last panic | M1 | survey_3 |
| F-006 | Process Control Block & FSM | Strict PCB lifecycle (`CREATED→READY⇄RUNNING⇄BLOCKED\|STOPPED→ZOMBIE→TERMINATED`), orphan reparenting to PID 1, process tree | M1 | survey_3 |
| F-007 | Multi-Thread TCB Support | Per-process threads (`Map<tid, TCB>`) tracking independent execution context/register state | M1 | survey_3 |
| F-008 | Preemptive/Cooperative Scheduler | Priority-weighted round-robin scheduler over `READY` threads with background ticks AND deterministic synchronous `step()`/`runUntilIdle()` | M1 | survey_3 |
| F-009 | POSIX Signal Handling | `SIGTERM(15)`, `SIGKILL(9)`, `SIGINT(2)`, `SIGSTOP(19)`, `SIGCONT(18)`, `SIGSEGV(11)`, `SIGILL(4)`, `SIGXCPU`, `SIGALRM(14)`, `SIGUSR1(10)` with resource cleanup | M1 | survey_3 |
| F-010 | Process Streams & FD Table | Per-PID `stdin`/`stdout`/`stderr` ring buffers + live events and file descriptor table (`0,1,2,3+`) closed on exit | M1 | survey_3 |
| F-011 | Process Sandbox Quotas | Per-PID limits on RAM bytes, instructions/tick, total instructions, open FDs, and windows; runaway fault kills only offending PID | M1 | survey_1, survey_2, survey_3 |
| F-012 | Sparse 4KB-Page Virtual Memory | Per-PID isolated `AddressSpace` (`Map<pageNum, Page>`), `mmap`/`munmap`/`mprotect`, non-allocating `__PAGEZERO` unmapped guard region | M1 | survey_2, survey_3 |
| F-013 | Hardware-Style R/W/X Enforcement | Enforce `PROT_NONE/READ/WRITE/EXEC` on every read/write/fetch; raise `MemoryFaultError(SIGSEGV)` on unmapped, RO write, or NX exec | M1 | survey_2, survey_3 |
| F-014 | Per-PID Heap Allocator & Telemetry | Free-list `alloc`/`realloc`/`free` with block coalescing, `ENOMEM` quota enforcement, and `getStats()` region/page telemetry | M1 | survey_3 |
| F-015 | SyscallDispatcher, EventBus, CpuRegistry & WAL SQLite | Core dispatch infrastructure, `CpuRegistry` (`arch → CpuFactory`), binary codec utilities (LE/BE, CRC-32, Adler-32, LEB128, MUTF-8), WAL SQLite schema runner | M1 | survey_1, survey_2, survey_3 |
| F-016 | Persistent SQLite POSIX VFS | Inode/dirent/blob/xattr storage with `stat`/`lstat`/`readdir`/`readFile`/`writeFile`/`mkdir`/`unlink`/`rename`/`chmod`/`chown`/`open` | M2 | survey_1, survey_3 |
| F-017 | Transparent 4-Platform PathTranslator | Bidirectional translation across POSIX `/`, Windows `C:\...` (case-insensitive preserving), macOS `/Applications` & `/Users`, Android `/sdcard` & `/data/data`, iOS `/var/mobile/Containers` | M2 | survey_2, survey_3 |
| F-018 | Shared Cross-Platform User Space | `/home/user/{Documents,Downloads,Desktop,Pictures}` map to identical canonical inodes across Windows, macOS, Android, and iOS | M2 | survey_2, survey_3 |
| F-019 | Symlinks, `ELOOP` & Live VFS Events | `symlink`/`readlink` with max-depth 16 cycle detection (`ELOOP`), path traversal jail enforcement, and live `vfs:changed` bus events | M2 | survey_2, survey_3 |
| F-020 | Dynamic Virtual Mounts (`/proc`, `/dev`, `/tmp`) | Dynamic `/proc/<pid>/status`, `/proc/uptime`, `/dev/null`, `/dev/zero`, `/dev/urandom`, and ephemeral `/tmp` mount | M2 | survey_3 |
| F-021 | Unified Config Store & Windows Registry | SQLite-backed typed config exposing `HKCR`/`HKCU`/`HKLM`/`HKU`/`HKCC` (`REG_SZ`/`EXPAND_SZ`/`BINARY`/`DWORD`/`MULTI_SZ`/`QWORD`) + unprivileged HKLM virtualization | M2 | survey_2, survey_3 |
| F-022 | Apple Defaults/Plist & Android SharedPrefs Sync | `NSUserDefaults` (`NSGlobalDomain`, `<bundleId>`, XML plist export) & Android `SharedPreferences` atomic transactions synced live on `system.*` keys | M2 | survey_2, survey_3 |
| F-023 | IPC Channels, Named Pipes, RPC & Shared Memory | `createChannel`/`send`/`recv`/`subscribe`, request/reply RPC (Binder/XPC/Named Pipes), and `shmCreate`/`shmAttach`/`shmRead`/`shmWrite` | M2 | survey_3 |
| F-024 | Universal Intent, URL-Scheme & File-Assoc Router | Auto-indexed from Android `<intent-filter>`, Apple `CFBundleURLTypes`/`DocumentTypes`, Windows `HKCR`, and Universal manifest; ranked resolution + Share Sheet chooser | M2 | survey_2, survey_3 |
| F-025 | Multi-MIME Shared Clipboard | Unified clipboard (`text/plain`, `text/html`, `application/json`, `image/png`) + 20-entry history shared across all 4 platforms & UI | M2 | survey_2, survey_3 |
| F-026 | Unified Notification Center & Live Activities | Priority/category notification queue, interactive action buttons, DND filtering, and iOS Dynamic Island `liveActivity` payloads | M2 | survey_2, survey_3 |
| F-027 | Users, Groups, Sandbox UIDs & POSIX ACLs | `root(0)`, `user(1000)`, per-app isolated sandbox UIDs (`10000+`), strict per-app container isolation & POSIX mode checks | M2 | survey_2, survey_3 |
| F-028 | Unified Permission Broker & Audit Log | Maps Android runtime permissions, iOS TCC, macOS Gatekeeper/entitlements, Windows UAC, and WASI rights to 14 canonical capabilities (`allow`/`deny`/`prompt`) + SQLite Audit Log | M2 | survey_2, survey_3 |
| F-029 | Headless Window Compositor Server | Kernel-space `compositord` managing `CompositorWindow` lifecycle, bounds, z-order, focus, Snap Layout states, and active Global Menu Bar | M2 | survey_2, survey_3 |
| F-030 | Dual-Mode Compositor Surface Engine | Retained Semantic UI Scene Graph (`uiTree`) + 2D Vector/Pixel Drawlist (`drawOps`) with monotonic `surfaceRevision` diff tracking | M2 | survey_2, survey_3 |
| F-031 | Compositor Input Event Router | Routes click, action, text input, keydown, canvas pointer, and menu actions directly to owning process `ExecutionContext.deliverEvent()` | M2 | survey_2, survey_3 |
| F-032 | Zero-Dep PKZIP / ZIP64 Codec | EOCD backward scan, ZIP64 EOCD, Central Directory authority (Data Descriptor bit 3), UTF-8 bit 11, STORE(0)/DEFLATE(8), CRC-32, ZIP-slip & ZIP-bomb defenses | M2 | survey_2, survey_3 |
| F-033 | Magic-Byte Package Format Auto-Detector | Identifies `.apk`, `.exe`/`.dll`, `.msix`/`.appx`, `.msi` (CFBF), `.ipa`, `.app`/Mach-O/Fat (guarding Java `.class`), `.dmg` (`koly`), `.pkg` (`xar!`), `.uapp`/`.wasm` purely from bytes | M2 | survey_1, survey_2, survey_3 |
| F-034 | `ospm` Package Manager Core & App Hub DB | `inspect`, `install`, `list`, `get`, `launch`, `stop`, `uninstall`, SHA-256 verification, SQLite `installed_packages` & App Hub catalog | M2 | survey_1, survey_3 |
| F-035 | Structured Error & Fault Isolation Contracts | Typed non-crashing error hierarchy across parsers, VFS, security, and runtimes ensuring malformed/faulty apps never crash the kernel | M2 | survey_2 |
| F-036 | Android `.apk` Package Loader & Verifier | Unpack `.apk` ZIP respecting APK Signing Block v2/v3 (`APK Sig Block 42`) before Central Directory; extract manifest, `classes*.dex`, `resources.arsc`, `res/`, `assets/` | M3 | survey_2, survey_3 |
| F-037 | Android Binary XML (AXML) & `resources.arsc` | Decode/encode `ResChunk_header` (`0x0003`), UTF-8/UTF-16 `ResStringPool`, XML tree + typed `Res_value`, and `ResTable` (`0x0002`, `FLAG_SPARSE`, `FLAG_OFFSET16`), plus plain XML fallback | M3 | survey_2, survey_3 |
| F-038 | Android DEX Parser (`035`–`041`) | Parse 112B/120B `header_item`, verify Adler-32 & SHA-1, decode MUTF-8/LEB128/ULEB128p1, string/type/proto/field/method/class tables, `code_item` & `try_item` (with odd-`insns_size` padding) | M3 | survey_2, survey_3 |
| F-039 | Dalvik/ART Register Bytecode VM | Execute real Dalvik opcodes (`10x`..`51l`, `35c`, `3rc`), top-reg `p0..pN` params, ALU/branches/switches/arrays/objects/fields/invokes, `try/catch` unwinding, `INT32_MIN/-1` wrap, `ArithmeticException`, step-budgeted via Scheduler | M3 | survey_1, survey_2, survey_3 |
| F-040 | Android Framework API & Lifecycle Bridge | `Activity` lifecycle (`onCreate`..`onDestroy`), `Context`, `Intent`, `View`/`LinearLayout`/`TextView`/`Button`/`EditText`, layout inflation, `SharedPreferences`, `Log`, `Toast`, `Notification`, `ContentResolver`, `Service`, `ClipboardManager`, `/sdcard` & `/data/data` VFS | M3 | survey_2, survey_3 |
| F-041 | Windows PE32 (`0x10B`) & PE32+ (`0x20B`) Loader | Parse DOS `MZ`/`e_lfanew`, `PE\0\0`, COFF, Optional Header, 16 DataDirs (`CERTIFICATE_TABLE` file-offset rule), `<=96` sections mapped into VMM R/W/X pages, base relocations (`HIGHLOW`/`DIR64`), Exports & ILT/IAT resolution (`OriginalFirstThunk==0` fallback) | M3 | survey_1, survey_2, survey_3 |
| F-042 | Windows `.msix`/`.appx` & `.msi` Package Support | Unpack `.msix`/`.appx` ZIP + `AppxManifest.xml` + `AppxBlockMap.xml`; parse `.msi` OLE CFBF (`D0 CF 11 E0 A1 B1 1A E1`) header/directory/metadata streams | M3 | survey_2 |
| F-043 | x86 & x86-64 CPU Emulator | 16 GPRs (32-bit zero-ext, 16/8-bit preserve), RIP, RFLAGS, XMM0–15, REX/ModR/M/SIB/RIP-relative, MOV/LEA/PUSH/POP/ALU/Jcc/CALL/RET/string ops/SSE2 scalar/`SYSCALL`; Win64 (`RCX/RDX/R8/R9`+32B shadow) & x86 (`__stdcall`/`__cdecl`) ABIs | M3 | survey_1, survey_2, survey_3 |
| F-044 | Win32 Core Subsystem API Bridge | `kernel32` (StdIO/Console/Files/Heap/VirtualAlloc/Process/Time/LastError), `user32` (`MessageBox`, `RegisterClassEx`, `CreateWindowEx`, controls, `GetMessage`/`DispatchMessage`/`DefWindowProc` w/ re-entrant `WNDPROC`, Clipboard), `gdi32` (2D DrawOps), `advapi32` (Registry) | M3 | survey_2, survey_3 |
| F-045 | Windows `.bat` / `.cmd` Batch Interpreter | `@ECHO`, `SET`/`SET /A`, `%VAR%`/`!VAR!`, `IF`, `FOR`, `GOTO`, `CALL`, `EXIT`, file cmds, pipes/redirection, preserving exact `.bat` vs `.cmd` `ERRORLEVEL` behavior | M3 | survey_2, survey_3 |
| F-046 | Pure-JS Android SDK Builder & Sample APKs | `sdk/android-builder.mjs` emitting valid ZIP+AXML+DEX (`packages/android-calc.apk`, `packages/android-notes-sharer.apk`) verifiable via Python `zipfile` + Adler-32/SHA-1 | M3 | survey_1, survey_2, survey_3 |
| F-047 | Pure-JS Windows PE32+ SDK Builder & Sample EXEs | `sdk/windows-builder.mjs` assembling valid PE32+ x86-64 (`packages/win-sysinfo.exe`, `packages/win-notepad.exe`) verifiable via `llvm-objdump` | M3 | survey_1, survey_2, survey_3 |
| F-048 | Mach-O 64-bit & Universal Fat Binary Loader | Parse Fat (`0xCAFEBABE`/`0xCAFEBABF` BE, Java `.class` guard) & `mach_header_64` (`0xFEEDFACF`), `LC_SEGMENT_64` (`__PAGEZERO` guard), `LC_MAIN` (`__TEXT.vmaddr + entryoff`), `LC_SYMTAB`/`DYSYMTAB`/`LOAD_DYLIB`/`RPATH`, `LC_DYLD_INFO_ONLY` & `LC_DYLD_CHAINED_FIXUPS`, `LC_CODE_SIGNATURE` (`0xFADE7171`), `LC_ENCRYPTION_INFO_64` (`cryptid!=0` -> `E_ENCRYPTED_BINARY`) | M4 | survey_1, survey_2, survey_3 |
| F-049 | Apple `bplist00` & XML Plist Codec | Big-endian `bplist00` parser/writer (8B header, markers `0x00..0xD0`, 2001 CF epoch dates, signed 8/16B ints, cycle guard, 32B trailer) + XML 1.0 plist | M4 | survey_2, survey_3 |
| F-050 | ARM64 (AArch64) CPU Emulator & Apple ABI | Fixed 32-bit A64 decode/exec (`X0..X30`, `SP`/`XZR` reg-31 semantics, `PC`, `NZCV`, `V0..V31`, `ADR`/`ADRP`, `MOVZ/N/K`, ALU, `LDR/STR/LDP/STP`, `B/BL/B.cond/CBZ/RET`, `SVC #0x80`, scalar FP) respecting Apple ABI (`X18` reserved, variadics on stack, 16B SP) | M4 | survey_1, survey_2, survey_3 |
| F-051 | Darwin / XNU BSD Syscall & Mach Trap Layer | Shared iOS/macOS BSD syscalls (`exit`, `read`, `write`, `open`, `close`, `unlink`, `chdir`, `getpid`, `getuid`, `stat/stat64`, `mmap`, `munmap`, `lseek`, `gettimeofday`, `sysctl`, `getentropy`, `*_nocancel`) & Mach traps; Carry flag error signaling (`PSTATE.C=1` ARM64 / `RFLAGS.CF=1` x86-64) + positive `errno` | M4 | survey_2, survey_3 |
| F-052 | Objective-C ABI2 & Swift Runtime Bridge | Parse `__objc_classlist`/`__objc_selrefs`/`__objc_methname`; nil-safe `objc_msgSend`/`objc_msgSendSuper2`, ARC refcounting, class/superclass dispatch (app IMP + host classes), Foundation (`NSObject`, `NSString`, `NSArray`, `NSDictionary`, `NSUserDefaults`, `NSFileManager`, `NSLog`) & Swift `swiftcall` (`X20`/`R13`) | M4 | survey_2, survey_3 |
| F-053 | iOS `.ipa` Loader, UIKit & SpringBoard Sandbox | Unpack `Payload/*.app/Info.plist`, mount strict UUID container `/var/mobile/Containers/Data/Application/<UUID>`, `UIApplicationMain`, `UIWindow`/`UIViewController`/`UIView`/`UILabel`/`UIButton`/`UITextField`/`UIAlertController`, `UIPasteboard`, Dynamic Island Live Activity, URL schemes, Suspend lifecycle | M4 | survey_2, survey_3 |
| F-054 | macOS `.app` Bundle, `.dmg` (`koly`) & `.pkg` (XAR) Loader | Load `.app` (`Contents/Info.plist`, `Contents/MacOS/<exec>` ARM64 & x86-64 via `CpuRegistry`), parse UDIF `.dmg` 512B BE `koly` trailer & XML `blkx`, parse `.pkg` XAR (`0x78617221`) TOC + CPIO payload | M4 | survey_2, survey_3 |
| F-055 | macOS Cocoa / AppKit Bridge & Global Menu Bar | `NSApplicationMain`, `NSApplication`, `NSWindow`, `NSView`, `NSTextField`, `NSButton`, live Global Top Menu Bar `NSMenu`/`NSMenuItem`, `NSAlert`, `NSUserDefaults`, `NSPasteboard`, `NSWorkspace`, Spotlight indexing, non-suspending lifecycle | M4 | survey_2, survey_3 |
| F-056 | Universal `.uapp` / WebAssembly & WASI Runtime | Validate `\0asm` v1 modules, execute sandboxed `WebAssembly` with `wasi_snapshot_preview1` (`args`, `environ`, `clock`, `fd_*`, `path_*`, `random`, `proc_exit`) + `omni_os_v1` Compositor/UI/Canvas/IPC host imports | M4 | survey_2, survey_3 |
| F-057 | Pure-JS iOS SDK Builder & Sample IPA | `sdk/ios-builder.mjs` emitting valid ARM64 Mach-O + `bplist00` `packages/ios-weather-island.ipa` verifiable via `llvm-objdump` & Python `plistlib` | M4 | survey_1, survey_2, survey_3 |
| F-058 | Pure-JS macOS SDK Builder & Sample `.app` | `sdk/macos-builder.mjs` emitting valid Mach-O ARM64/Universal `packages/macos-studio.app.zip` verifiable via `llvm-objdump` & Python `plistlib` | M4 | survey_1, survey_2, survey_3 |
| F-059 | Pure-JS Universal WASM SDK Builder | `sdk/universal-builder.mjs` emitting valid `\0asm` `packages/universal-canvas.uapp` verifiable via `WebAssembly.validate` | M4 | survey_2, survey_3 |
| F-060 | Deterministic Sample Build Pipeline | `sdk/build-samples.mjs` generating all 7 authentic sample packages in `packages/` deterministically with zero external dependencies | M4 | survey_1, survey_3 |
| F-061 | Unified OmniOS Runtime Bootstrapper | `os/os.mjs` exporting `createOmniOS(config)` wiring microkernel, services, all 5 runtimes, 7 system apps, and App Hub catalog | M5 | survey_3 |
| F-062 | HTTP REST API v1 & Health Endpoints | `os/server/http-server.mjs` serving `GET /api/health`, `GET /api/v1/health`, full `/api/v1/{kernel,processes,vfs,config,ipc,security,packages,compositor,shell,search}` + static `ui/` | M5 | survey_1, survey_3 |
| F-063 | Zero-Dep RFC 6455 WebSocket Server (`/ws`) | Pure-JS WebSocket over `http.Server` `'upgrade'` pushing live compositor diffs, stdout, notifications, permission prompts, intent choosers, kernel events | M5 | survey_3 |
| F-064 | Spotlight Universal Search Engine | `/api/v1/search?q=...` indexing installed apps (incl. macOS Spotlight metadata), VFS files, active processes, settings, and quick actions | M5 | survey_2, survey_3 |
| F-065 | Headless & Remote OmniOS CLI | `os/cli/omnios-cli.mjs`: `boot`, `shell`, `exec`, `status`, `dmesg`, `services`, `ps`, `kill`, `vfs`, `reg`, `defaults`, `prefs`, `ospm`, `intent`, `clipboard`, `notify`, `sdk` with `--json`, `--data-dir`, `--remote` | M5 | survey_1, survey_3 |
| F-066 | Multi-Syntax Shell Interpreter | Unified command engine supporting POSIX (`ls`/`cat`/`mkdir`/`rm`/`ps`/`kill`/`dmesg`), Windows (`dir`/`type`/`tasklist`/`taskkill`/`reg`), macOS (`defaults`/`open`), Android (`am`/`pm`/`prefs`), `ospm`, `intent`, `clip`, pipes & redirects | M5 | survey_3 |
| F-067 | Built-in System App: OmniTerm | Kernel-backed terminal window wired live to the multi-syntax Shell Interpreter | M5 | survey_3 |
| F-068 | Built-in System App: OmniFiles | Unified File Manager with Finder Column, Explorer `C:\` Drive, and Mobile `/sdcard` & `/var/mobile` views, create/edit/delete/symlink/Open-With | M5 | survey_3 |
| F-069 | Built-in System App: Activity / Task Monitor | Live PID table, Process Tree, real `SIGTERM`/`SIGKILL`/`SIGSTOP`/`SIGCONT`, VMM page/heap stats, Service health/restart, live `dmesg` | M5 | survey_3 |
| F-070 | Built-in System App: App Hub | 4-platform catalog, package upload/inspect/install/launch/stop/uninstall with permission & binary metadata preview | M5 | survey_3 |
| F-071 | Built-in System App: Settings & Privacy Center | Shell Mode switcher, system toggles, per-app Permission Matrix (Android/TCC/Gatekeeper/UAC), Registry/Defaults/SharedPrefs editor, Audit Log | M5 | survey_3 |
| F-072 | Built-in System Apps: Binary Inspector & OmniNotes | Deep header/section/DEX/Mach-O/PE/plist & live PID register/VMM Inspector + cross-platform OmniNotes editor | M5 | survey_3 |
| F-073 | Live WebSocket + REST GUI Client (`ui/`) | Real-time frontend with zero fake state; every click, drag, key, toggle, and menu item dispatches directly to the running OmniOS kernel | M6 | survey_1, survey_3 |
| F-074 | Multi-Window Compositor Canvas & Dual Renderer | Drag, resize, focus/z-order, minimize/maximize, Retained Semantic UI Tree renderer + HTML5 `<canvas>` 2D DrawOp renderer | M6 | survey_3 |
| F-075 | Adaptive Window Chrome | Per-platform (macOS traffic lights, Windows right controls, iOS/Android mobile frame) and unified chrome styles | M6 | survey_3 |
| F-076 | Adaptive 5-Mode Shell Switcher | Live switch between `Unified Hybrid`, `Windows`, `macOS`, `iOS`, and `Android` modes without closing running apps, persisted in Config Store | M6 | survey_3 |
| F-077 | macOS Shell UX | Dynamic Global Top Menu Bar updating on window focus, Floating Magnified Dock with platform badges & running dots, Spotlight (`Cmd/Ctrl+Space`) | M6 | survey_3 |
| F-078 | Windows Shell UX | Taskbar + Start Menu (Pinned + All 4-platform apps + search), Window Snap Layouts (Left/Right/Quadrant tiling), System Tray | M6 | survey_3 |
| F-079 | iOS Shell UX | Expandable **Dynamic Island** Live Activity pill, pull-down **Control Center** (Wi-Fi/BT/Brightness/Volume/Dark Mode/DND), SpringBoard & App Library, Home Gesture Bar | M6 | survey_3 |
| F-080 | Android Shell UX | Pull-down **Notification Shade & Quick Settings Tiles**, slide-up **App Drawer**, **3-Button Nav Bar** (Back, Home, **Recents** card stack killing real PIDs) | M6 | survey_3 |
| F-081 | Live Universal Share Sheet / Intent Chooser Modal | Interactive app picker modal triggered by kernel `intent:chooser` WebSocket events | M6 | survey_3 |
| F-082 | Live Security & Permission Prompt Modal | Interactive Android/TCC/Gatekeeper/UAC permission dialog replying directly to kernel `PermissionBroker` | M6 | survey_3 |
| F-083 | Drag-and-Drop Binary Package Uploader | Drop `.apk`/`.exe`/`.ipa`/`.app.zip`/`.uapp` onto Desktop/App Hub/OmniFiles to inspect and install into the live OS | M6 | survey_3 |
| F-084 | Offline-Safe Responsive Dark/Light Design System | Zero-CDN CSS themes synchronized live with Registry/Defaults/SharedPrefs `system.theme` | M6 | survey_3 |
| F-085 | 5-Platform Concurrent Interop E2E Verification | `.apk` + `.exe` + `.ipa` + `.app` + `.uapp` running concurrently under Scheduler, sharing VFS files, Clipboard, Unified Preferences, Intents & Notifications | M7 | survey_2, survey_3 |
| F-086 | Headless Chromium CDP Browser E2E Verification | Drive `/usr/lib/chromium/chromium --headless=new --no-sandbox --disable-gpu` verifying zero console errors, live WS, 5 Shell Modes, window ops & real binary app click-to-execution | M7 | survey_1, survey_3 |
| F-087 | Packaging, Deployment & CI Alignment | Update `package.json`, `Dockerfile`, `docker-compose.yml`, `README.md`, `.github/workflows/ci.yml` promoting OmniOS while preserving `npm run validate` & `npm run test:legacy` | M7 | survey_1, survey_3 |
| F-088 | Phase 1: 100% E2E Test Pass (Tiers 1–4) | Poll `TEST_READY.md` and pass 100% of E2E Testing Track Tiers 1 → 2 → 3 → 4 sequentially | M7 | project_pattern |
| F-089 | Phase 2: Tier 5 Adversarial Binary/VMM/VFS Hardening | White-box Challenger-first adversarial fuzzing & hardening for all 29 binary/CPU/VMM/VFS edge cases (ZIP-slip/bomb, corrupt DEX/PE/Mach-O/bplist, FairPlay, `__PAGEZERO`, NX/RO, runaway loops, symlink loops) | M7 | survey_2, survey_3 |
| F-090 | Phase 2: Tier 5 Security, WS/HTTP & Panic Hardening | White-box adversarial testing of permission bypass attempts, malformed RFC 6455 WebSocket/HTTP payloads, and kernel panic/safe-mode recovery | M7 | survey_3 |

---

## Milestones

| # | Name | Scope (Features) | Dependencies | Owned Paths (Disjoint) | Status | Sub-orchestrator Conv ID |
|---|------|------------------|--------------|------------------------|--------|--------------------------|
| M1 | Microkernel Core, VMM & Preemptive Scheduler | F-001 – F-015 | none | `os/common/`, `os/kernel/`, `os/cpu/registry.mjs`, `tests/unit/m1-kernel.test.mjs` | DONE (56/56 PASS, 5/5 Gate) | `d1df76990b6abbeaa4bca9e285816b70` |
| M2 | Unified VFS, Config/Registry, IPC/Intents, Security, Headless Compositor & `ospm` Core | F-016 – F-035 | M1 | `os/vfs/`, `os/store/`, `os/ipc/`, `os/security/`, `os/compositor/`, `os/pkg/`, `tests/unit/m2-services.test.mjs` | DONE (104/104 PASS, 5/5 Gate, 14/14 CLEAN) | `10d074c024a1e7f0ac9656fa78a1c5ad` |
| M3 | Android & Windows Runtimes, Dalvik & x86/x86-64 Engines, SDK Builders & Sample `.apk`/`.exe` | F-036 – F-047 | M1, M2 | `os/cpu/dalvik.mjs`, `os/cpu/x86_64.mjs`, `os/runtimes/android/`, `os/runtimes/windows/`, `sdk/android-builder.mjs`, `sdk/windows-builder.mjs`, `packages/android-*.apk`, `packages/win-*.exe`, `tests/unit/m3-android-windows.test.mjs` | DONE (133/133 M3 @ 128 MB / 293/293 PASS, 5/5 Gate, 16/16 CLEAN) | `6bc7c90af3fb76efaa4616ee834e7446` |
| M4 | iOS, macOS & Universal WASM Runtimes, ARM64/ObjC/Darwin Engine, SDK Builders & Sample `.ipa`/`.app`/`.uapp` | F-048 – F-060 | M1, M2 *(M3 optional for Intel macOS slice via `CpuRegistry`; run after M2, integrate Intel slice test in M5/M7 or after M3)* | `os/cpu/arm64.mjs`, `os/runtimes/apple/`, `os/runtimes/ios/`, `os/runtimes/macos/`, `os/runtimes/universal/`, `sdk/ios-builder.mjs`, `sdk/macos-builder.mjs`, `sdk/universal-builder.mjs`, `sdk/build-samples.mjs`, `packages/ios-*.ipa`, `packages/macos-*.app.zip`, `packages/universal-*.uapp`, `tests/unit/m4-ios-macos-universal.test.mjs` | DONE (29/29 M4 / 189/189 PASS, 5/5 Gate, 3/3 CLEAN) | `d02534ba17de909b978fe4b9364d86ed` |
| M5 | Transport Server (HTTP + RFC 6455 WS), Spotlight, Headless/Remote CLI & 7 Built-in System Apps | F-061 – F-072 | M1, M2, M3, M4 | `os/os.mjs`, `os/server/`, `os/cli/`, `os/apps/`, `tests/unit/m5-server-cli-apps.test.mjs` | DONE (13/13 M5 / 335/335 M1–M5 PASS, 5/5 Gate, 2/2 CLEAN) | `ebf3d870652dcf36f39461eca9ee9670` |
| M6 | Unified 4-Platform Adaptive Shell & Live Compositor Web/Desktop GUI | F-073 – F-084 | M5 | `ui/`, `tests/unit/m6-gui.test.mjs` | IN_PROGRESS | `5428fc7460b97c6d8f31f137a6794495` |
| M7 | Final Milestone — Packaging Alignment, Phase 1 (100% Tiers 1–4 E2E) & Phase 2 (Tier 5 Adversarial Hardening) | F-085 – F-090 | M1–M6 + `TEST_READY.md` | `package.json`, `Dockerfile`, `docker-compose.yml`, `README.md`, `.github/workflows/ci.yml`, `tests/e2e/tier5-*`, cross-cutting bugfixes | PLANNED | — |
| E2E | E2E Testing Track (Parallel) | Opaque-box Tiers 1–4 suite covering F-001 – F-086 | Parallel from `PROJECT.md` | `TEST_INFRA.md`, `TEST_READY.md`, `tests/e2e/` | DONE (50 files / 286 tests, `TEST_READY.md` PUBLISHED, 5/5 Gate) | `d97896297da86f3ce0a0d8a48a774634` |

---

## Interface Contracts

All milestones MUST conform strictly to these cross-module contracts.

### Contract 1: `IKernel`, `IProcessManager`, `IScheduler` & `IAddressSpace` (`os/kernel/`, `os/common/`)
```js
// Boot, Services, dmesg, Panic/Recover
kernel.boot() // -> Promise<{ status: 'RUNNING', stages: Array<{name, durationMs}>, bootMs: number }>
kernel.shutdown() // -> Promise<void>
kernel.panic(code, reason, context) // -> PanicDump (persisted to SQLite)
kernel.recover({ safeMode = false } = {}) // -> Promise<BootReport>
kernel.getDiagnostics() // -> { state, uptimeMs, bootReport, services, processCount, memoryStats, dmesgTail, lastPanic }
kernel.dmesg({ limit = 200, subsystem, level } = {}) // -> DmesgEntry[]
serviceManager.register({ name, deps = [], start, stop, healthCheck, maxRestarts = 3 })
serviceManager.startAll() / stopAll() / restart(name) / getStatus()

// Process & Preemptive Scheduler
processManager.spawn({ name, appId, platform, arch, uid, gid, cwd, env, args, priority, quotas, executionContext }) // -> PCB
processManager.kill(pid, signal = 'SIGTERM') // -> { ok, pid, signal, state }
processManager.get(pid) / processManager.list() / processManager.getTree()
processManager.writeStdin(pid, data)
scheduler.start(tickMs = 16) / scheduler.stop()
scheduler.step(maxTicks = 1) // -> { ticksRun, instructionsExecuted, activePids }
scheduler.runUntilIdle(pid, maxTicks = 500) // -> ProcessSummary

// Per-PID Sparse 4KB Page VMM (PROT_NONE=0, PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4)
addrSpace.mmap(addrHint, size, perms, label) // -> number (baseAddr)
addrSpace.reserveGuard(baseAddr, size, label) // -> void (e.g. __PAGEZERO 0..0x100000000 without allocating RAM!)
addrSpace.munmap(baseAddr, size) / addrSpace.mprotect(baseAddr, size, perms)
addrSpace.read(addr, length) // -> Uint8Array (throws MemoryFaultError SIGSEGV on unmapped/guard/!PROT_READ)
addrSpace.write(addr, bytes) // -> void (throws MemoryFaultError SIGSEGV on unmapped/guard/!PROT_WRITE)
addrSpace.fetch(addr, length) // -> Uint8Array (throws MemoryFaultError SIGSEGV on unmapped/guard/!PROT_EXEC)
addrSpace.alloc(size) // -> number (throws MemoryFaultError ENOMEM on quota exceeded)
addrSpace.free(ptr) / addrSpace.realloc(ptr, size)
addrSpace.getStats() // -> { mappedPages, usedBytes, peakBytes, maxBytes, regions }
```

### Contract 2: `IVFS` & `IPathTranslator` (`os/vfs/`)
```js
pathTranslator.toCanonical(rawPath, { platform = 'posix', cwd = '/home/user', appId = '', containerUuid = '' } = {})
// -> { canonicalPath, mount, caseInsensitive, originalPath }
pathTranslator.toPlatform(canonicalPath, platform /* 'posix'|'windows'|'macos'|'android'|'ios' */, opts) // -> string

// Mandatory Shared User Space Mappings (all resolve to identical canonical /home/user/* inodes):
// Windows: C:\Users\user\* -> /home/user/* ; C:\Windows\* -> /system/windows/* ; C:\Program Files\* -> /apps/windows/* ; Z:\* -> /*
// macOS:   /Users/user/* -> /home/user/* ; /Applications/* -> /apps/macos/* ; /Users/user/Library/* -> /var/appdata/macos/Library/*
// Android: /sdcard/* & /storage/emulated/0/* -> /home/user/* ; /data/data/<pkg>/* -> /var/appdata/android/<pkg>/*
// iOS:     /var/mobile/Documents/* -> /home/user/Documents/* ; /var/mobile/Containers/Data/Application/<uuid>/* -> /var/appdata/ios/<uuid>/*

vfs.stat(path, ctx) / vfs.lstat(path, ctx) / vfs.readdir(path, ctx)
vfs.readFile(path, { encoding, ...ctx }) / vfs.writeFile(path, data, { mode = 0o644, append = false, ...ctx })
vfs.mkdir(path, { recursive = false, mode = 0o755, ...ctx }) / vfs.unlink(path, ctx) / vfs.rmdir(path, ctx)
vfs.rename(oldPath, newPath, ctx) / vfs.symlink(target, linkPath, ctx) / vfs.readlink(path, ctx)
vfs.chmod(path, mode, ctx) / vfs.chown(path, uid, gid, ctx) / vfs.open(path, flags, ctx)
// Errors MUST set err.code in: 'ENOENT'|'EACCES'|'EEXIST'|'EISDIR'|'ENOTDIR'|'ELOOP'|'ENOSPC'|'EBADF'|'EINVAL'
```

### Contract 3: `IUnifiedConfigStore` (`os/store/`)
```js
configStore.registry.setValue(hive, keyPath, valueName, type, data, ctx)
configStore.registry.getValue(hive, keyPath, valueName, ctx) // -> { type, data } | null
configStore.registry.enumKey(hive, keyPath, ctx) // -> { subkeys, values }
configStore.registry.deleteValue(hive, keyPath, valueName, ctx)
configStore.defaults.set(domain, key, value, ctx) / get(domain, key, ctx) / readDomain(domain, ctx) / exportPlistXml(domain)
configStore.sharedPrefs.edit(packageName, prefName, ops, ctx) / getAll(packageName, prefName, ctx)
configStore.system.get(key) / set(key, value) / getAll()
// Synced keys: system.theme, system.shellMode, system.volume, system.brightness, system.wifi, system.bluetooth, system.dnd, system.locale
```

### Contract 4: `IIPCManager`, `IIntentRouter`, `IClipboard`, `INotificationCenter`, `ISecurityManager` (`os/ipc/`, `os/security/`)
```js
ipc.createChannel(name, ownerPid) / send(channel, fromPid, payload) / recv(channel, pid) / subscribe(channel, fn)
ipc.shmCreate(name, size, ownerPid) / shmWrite(id, offset, bytes) / shmRead(id, offset, length)
intentRouter.registerHandlers(appId, handlers) / resolve({ action, uri, mimeType, extension, scheme })
intentRouter.dispatch({ action, uri, mimeType, extras, sourcePid, preferredAppId })
// -> { status: 'DELIVERED'|'CHOOSER_REQUIRED'|'NO_HANDLER', targetAppId?, pid?, candidates? }
clipboard.set({ text, html, json, mime, sourceAppId }) / get() / history(limit = 20)
notifications.post({ appId, platform, title, body, priority, category, actions, liveActivity })
notifications.list({ includeDismissed = false }) / dismiss(id) / clearAll() / invokeAction(id, actionId) / getLiveActivities()
security.checkPermission({ appId, pid, platform, capability, nativePermission }) // -> Promise<{ granted, policy, reason }>
security.setGrant(appId, capability, state /* 'allow'|'deny'|'prompt' */)
security.getAuditLog({ appId, limit = 100 })
```

### Contract 5: `ICpuRegistry`, `IFormatDetector`, `IPlatformRuntime`, `IExecutionContext`, `IPackageManager` (`os/cpu/`, `os/pkg/`, `os/runtimes/`)
```js
cpuRegistry.register(arch /* 'dalvik'|'x86_64'|'x86'|'arm64'|'wasm' */, CpuFactory)
cpuRegistry.get(arch) // -> CpuFactory | null

formatDetector.detect(buffer, filenameHint)
// -> { format: 'android-apk'|'windows-pe'|'windows-msix'|'windows-msi'|'windows-bat'|'ios-ipa'|'macos-app'|'macos-macho'|'macos-dmg'|'macos-pkg'|'universal-uapp'|'universal-wasm'|'unknown', platform, magicHex, details }

// Implemented uniformly by Android, Windows, iOS, macOS, Universal runtimes:
runtime.platform // 'android'|'windows'|'ios'|'macos'|'universal'
runtime.inspectPackage(buffer, filenameHint) // -> PackageInspection
runtime.installPackage(inspection, buffer, services) // -> InstalledAppRecord
runtime.createExecutionContext(pcb, appRecord, services, launchOptions) // -> IExecutionContext

execCtx.step(instructionBudget) // -> { status: 'YIELD'|'BLOCKED'|'EXITED'|'FAULT', instructionsExecuted, exitCode?, fault?, waitReason? }
execCtx.deliverEvent(event) // -> void
execCtx.getDebugState() // -> { arch, pc, sp, registers, instructionsExecuted, lastSyscall, stackTop }
execCtx.dispose() // -> void

pkgManager.inspect(bufferOrVfsPath) / install(bufferOrVfsPath, opts) / list({ platform }) / get(appId)
pkgManager.launch(appId, { args, env, intent }) // -> { pid, appId, platform, windowIds }
pkgManager.stop(pidOrAppId) / uninstall(appId, { purgeData })
```

### Contract 6: `ICompositor` (`os/compositor/`)
```js
compositor.createWindow(pid, { appId, platform, title, icon, width, height, x, y, chromeStyle, menuBar, uiTree, drawOps })
compositor.updateSurface(windowId, { title?, menuBar?, uiTree?, drawOps?, appendDrawOps? })
compositor.moveWindow(windowId, x, y) / resizeWindow(windowId, width, height) / focusWindow(windowId)
compositor.setWindowState(windowId, state /* 'normal'|'minimized'|'maximized'|'snapped-left'|'snapped-right'|'snapped-tl'|'snapped-tr'|'snapped-bl'|'snapped-br'|'fullscreen' */)
compositor.closeWindow(windowId) / dispatchInput(windowId, event)
compositor.getSnapshot() // -> { shellMode, focusedWindowId, activeMenuBar, windows }
```

### Contract 7: HTTP REST API v1, Health & RFC 6455 WebSocket (`os/server/`)
- **HTTP**: `GET /api/health` (200 OK `{ ok: true, os: 'OmniOS', status }`), `GET /api/v1/health`, `/api/v1/kernel/{status,dmesg,services,services/:name/:action,panic,recover}`, `/api/v1/processes{,/tree,/:pid,/:pid/signal,/:pid/stdin}`, `/api/v1/vfs/{ls,stat,file,mkdir,rename,symlink,resolve,mounts}`, `/api/v1/config/{system,registry,defaults,prefs}`, `/api/v1/ipc/{intents/resolve,intents/dispatch,clipboard,notifications,notifications/:id/dismiss,notifications/:id/action}`, `/api/v1/security/{permissions,audit,users}`, `/api/v1/packages{,/catalog,/inspect,/install,/:appId/launch,/:appId/stop,/:appId}`, `/api/v1/compositor/{snapshot,shell-mode,windows/:id/{move,resize,focus,state,close,input}}`, `POST /api/v1/shell/exec`, `GET /api/v1/search?q=...`, static `ui/`.
- **WebSocket (`/ws`)**: RFC 6455 JSON envelopes `{ type, seq?, ts, payload }` — Server→Client: `compositor:snapshot`, `compositor:window_created`, `compositor:window_updated`, `compositor:surface_patch`, `compositor:window_closed`, `process:update`, `process:stdout`, `notification:posted`, `notification:updated`, `config:changed`, `permission:prompt`, `intent:chooser`, `kernel:event`; Client→Server: `compositor:{input,move,resize,focus,state,close,menu_action}`, `shell:mode`, `permission:decision`, `intent:choice`, `terminal:exec`, `ping`.

### Contract 8: Headless & Remote CLI (`os/cli/omnios-cli.mjs`)
- Flags: `--json`, `--data-dir <dir>`, `--remote <url>`, `--port <n>`, `--host <addr>`.
- Commands: `boot`, `shell`, `exec "<cmd>"`, `status`, `dmesg`, `services [restart <name>]`, `ps`, `kill <pid> [--signal SIG]`, `vfs ls|cat|write|mkdir|rm|symlink|resolve <path> [--platform ...]`, `reg get|set|list`, `defaults read|write`, `prefs get|set`, `ospm inspect|install|list|launch|stop|uninstall`, `intent resolve|dispatch`, `clipboard get|set`, `notify send|list|dismiss`, `sdk build-samples`.

---

## Authoritative Binary & Edge-Case Invariants (All 29 Spec Cases)

Workers implementing M2, M3, M4, and M7 MUST satisfy every binary & adversarial edge case mined in Survey 2:
1. **ZIP/ZIP64 (M2)**: Reject ZIP-slip (`..`, leading `/`, drive letters, NUL -> `E_PATH_TRAVERSAL`); enforce decompressed byte cap & ratio (`E_ARCHIVE_BOMB`); locate Central Directory via EOCD `centralDirOffset` (required for APK v2/v3 Signing Block!); trust Central Directory `compSize`/`uncompSize`/`crc32` when Flag Bit 3 (`0x0008`) is set.
2. **AXML & `resources.arsc` (M3)**: Reject `chunk.size < headerSize` or `size == 0` or OOB (`E_MALFORMED_AXML`); support `FLAG_OFFSET16 (0x02)` (`off16 * 4`, `0xFFFF == NO_ENTRY`) & `FLAG_SPARSE (0x01)`.
3. **DEX & Dalvik VM (M3)**: Validate Adler-32 & SHA-1, `header_size` (`0x70` v035–040 / `0x78` v041), `type_ids/proto_ids <= 65535`, MUTF-8 (`0xC0 0x80` -> `\u0000`), reject >5B LEB128; skip 2-byte padding when `tries_size > 0 && (insns_size & 1) == 1`; `div/rem` by `0` throws `ArithmeticException`, `INT32_MIN / -1` wraps to `INT32_MIN`; enforce step-budget (`E_CPU_QUOTA`) & stack depth (`StackOverflowError`).
4. **PE32/PE32+, x86/x86-64 & `.bat`/`.cmd` (M3)**: Validate `e_lfanew >= 64` & bounds, `NumberOfSections <= 96`, clamp `NumberOfRvaAndSizes`; map `min(SizeOfRawData, VirtualSize)` & zero-fill `.bss`; fallback to `FirstThunk` when `OriginalFirstThunk == 0`; treat `CERTIFICATE_TABLE` (dir index 4) as raw file offset (not RVA); 32-bit GPR writes zero upper 32 bits while 16/8-bit preserve upper bits; RIP-relative uses next instruction address; `.bat` preserves `ERRORLEVEL` on successful `SET` whereas `.cmd` resets to `0`.
5. **Mach-O, ARM64, Darwin, ObjC & `bplist00` (M4)**: Guard `0xCAFEBABE` Fat magic against Java `.class` (`nfat_arch <= 32` + valid `cputype`); reject `LC_ENCRYPTION_INFO_64.cryptid != 0` with `E_ENCRYPTED_BINARY`; reserve `__PAGEZERO` as virtual guard without allocating 4 GiB RAM; compute `LC_MAIN` entry VA as `__TEXT.vmaddr + slide + entryoff`; ARM64 reg 31 = `SP` for load/store base & non-flag `ADD/SUB (imm)`, `XZR`/`WZR` elsewhere; Apple ARM64 variadics read from 8B stack slots; Darwin XNU syscalls signal errors with Carry flag `1` + positive `errno`; `objc_msgSend(nil, ...)` returns `0`; `bplist00` tracks recursion stack (`E_CYCLIC_PLIST`), decodes `0x13` (8/16B int) as signed, and uses 2001-01-01T00:00:00Z epoch.
6. **WASM/WASI & VFS (M2/M4)**: Windows VFS adapter does case-insensitive lookup while preserving creation case and blocking traversal; WASI validates `iovs_len`/linear-memory bounds (`WASI_EINVAL`/`WASI_EFAULT`/`WASI_ENOTCAPABLE`).

---

## Verification & External Anti-Mocking Criteria
- **External Toolchain Cross-Checks**: Generated `.exe` and Mach-O `.ipa`/`.app` binaries MUST be inspectable by `llvm-objdump --private-headers` / `llvm-readobj`; `.apk`/`.ipa`/`.app.zip` archives MUST pass Python `zipfile.ZipFile.testzip() == None`; `bplist00` plists MUST round-trip through Python `plistlib.loads()`; DEX Adler-32/SHA-1 MUST verify independently; `.wasm` binaries MUST pass `WebAssembly.validate()`.
- **Browser E2E**: All headless browser checks MUST invoke `/usr/lib/chromium/chromium --headless=new --no-sandbox --disable-gpu`.
- **Audit Veto**: Every milestone passes through independent Reviewers (2), Challengers (2), and Forensic Auditor (`teamwork_preview_auditor`). Any `INTEGRITY VIOLATION` is an unconditional binary veto.
