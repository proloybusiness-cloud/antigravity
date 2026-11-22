# OmniOS — E2E Testing Track Completion Signal (`TEST_READY.md`)

**Status**: **READY** (All 7 Sub-Milestones `SM-1`–`SM-7` PASSED Unanimous 5/5 Gates; Forensic Integrity Auditor: `CLEAN`)  
**Published At**: `2026-11-21T03:22:30Z`  
**Publisher**: OmniOS E2E Testing Track Sub-Orchestrator (`sub_orch_e2e_gen2`, continuing locked `sub_orch_e2e` gates)  
**Master Spec**: `PROJECT.md` (Contracts 1–8, Features `F-001`–`F-086`, All 29 Authoritative Binary/VMM/VFS/Security Edge Cases)  
**Test Architecture**: `TEST_INFRA.md`  
**Design Discipline**: Strictly **Requirement-Driven & Opaque-Box** — pure Node.js 24 ESM (`0` external npm dependencies), `0` private `os/*/*` imports, `0` skipped/stubbed tests, `0` `assert.*` inside `try/catch`, dynamic runtime-nonce binary generation cross-verified by real external host toolchains (`llvm-objdump`, `llvm-readobj`, Python 3 `zipfile`/`plistlib`, `file`, `WebAssembly.validate`) and live headless Chromium CDP (`/usr/lib/chromium/chromium --headless=new --no-sandbox --disable-gpu`).

---

## 1. Test Runner Commands

Run from the repository root (`/home/antigravity/proloybusiness-cloud/antigravity`):

```bash
# 0. Syntax Check (all 50 .mjs files under tests/e2e/)
find tests/e2e -type f -name '*.mjs' -print0 | xargs -0 -n1 node --check

# 1. Harness, Dynamic/Malformed Binary Fixtures, External Oracles & Chromium CDP Self-Test (26 tests)
node --test tests/e2e/harness.selftest.mjs

# 2. Tier 1 — Isolated Feature Happy-Path Coverage (16 files, 106 tests)
node --test tests/e2e/tier1/*.test.mjs

# 3. Tier 2 — Boundary, Corner, Negative & All 29 Edge Cases (16 files, 108 tests)
node --test tests/e2e/tier2/*.test.mjs

# 4. Tier 3 — Cross-Feature Pairwise Interaction Matrix (6 files, 36 tests)
node --test tests/e2e/tier3/*.test.mjs

# 5. Tier 4 — Real-World Multi-Platform & Live Chromium CDP Workflows (5 files, 10 scenarios)
node --test tests/e2e/tier4/*.test.mjs

# 6. Full E2E Suite (Tiers 1–4 Sequential / Combined — 43 test files, 260 E2E tests)
node --test tests/e2e/tier1/*.test.mjs tests/e2e/tier2/*.test.mjs tests/e2e/tier3/*.test.mjs tests/e2e/tier4/*.test.mjs
```

> **M7 Phase 1 Execution Order**: Run sequentially Tier 1 → Tier 2 → Tier 3 → Tier 4 and require **100% pass (260 / 260 E2E tests + 26 / 26 harness self-tests = 286 / 286 PASS, 0 skipped)** before advancing to M7 Phase 2 (Tier 5 Adversarial Hardening).  
> **Chromium Runtime Note**: Browser tests invoke `/usr/lib/chromium/chromium --headless=new --no-sandbox --disable-gpu` directly via `tests/e2e/lib/cdp-client.mjs` (zero npm dependencies, bypassing the Debian `/usr/bin/chromium` dash wrapper).

---

## 2. Independently Verified Coverage Summary

| Suite / Category | Directory / File | `.mjs` Files | Verified Tests | `TEST_INFRA.md` Minimum | Verified Pre-Integration Gate Status |
|---|---|---:|---:|---:|---|
| **Harness & Fixture Libraries** | `tests/e2e/lib/*.mjs` | 6 | — | 6 modules | **PASSED & LOCKED** (`SM-1`, `458 / 458` live named exports resolved) |
| **Harness & External Oracle Self-Test** | `tests/e2e/harness.selftest.mjs` | 1 | **26** | 100% PASS | **PASSED & LOCKED** (`26 / 26 PASS`, real LLVM/Python/WASM/Chromium oracles) |
| **Tier 1 — Isolated Happy Paths (`FA-01`–`FA-16`)** | `tests/e2e/tier1/*.test.mjs` | 16 | **106** | ≥80 (≥5/area) | **PASSED & LOCKED** (`SM-2` & `SM-3`, 6–7 tests/file, `106 / 106` fail-loud) |
| **Tier 2 — Boundary/Negative & 29 Edge Cases (`FA-01`–`FA-16`)** | `tests/e2e/tier2/*.test.mjs` | 16 | **108** | ≥80 (≥5/area, 29/29 edges) | **PASSED & LOCKED** (`SM-4` & `SM-5`, 6–8 tests/file, `108 / 108` fail-loud) |
| **Tier 3 — Cross-Feature Pairwise Matrix (`P-01`–`P-06`)** | `tests/e2e/tier3/*.test.mjs` | 6 | **36** | ≥30 | **PASSED & LOCKED** (`SM-6`, 6 tests/file, `36 / 36` fail-loud) |
| **Tier 4 — Real-World Multi-Platform & CDP Scenarios (`S-01`–`S-05`)** | `tests/e2e/tier4/*.test.mjs` | 5 | **10** | ≥10 | **PASSED & LOCKED** (`SM-7` Iter 4 Unanimous 5/5, 2 scenarios/file, `10 / 10` fail-loud) |
| **Grand Total** | **`tests/e2e/`** | **50** | **286** (`26` selftest + `260` E2E) | **≥200 E2E** | **100% READY (`50 / 50` `node --check`, `2,887` substantive `assert.*`, `0` violations)** |

### Per-File Verified Test Counts (43 E2E Test Files = 260 Tests)
- **Tier 1 (`106` tests across 16 files)**: `fa01` (6), `fa02` (6), `fa03` (6), `fa04` (6), `fa05` (6), `fa06` (7), `fa07` (6), `fa08` (7), `fa09` (7), `fa10` (7), `fa11` (7), `fa12` (7), `fa13` (7), `fa14` (7), `fa15` (7), `fa16` (7).
- **Tier 2 (`108` tests across 16 files)**: `fa01` (6), `fa02` (6), `fa03` (6), `fa04` (6), `fa05` (6), `fa06` (7), `fa07` (7), `fa08` (7), `fa09` (7), `fa10` (8), `fa11` (7), `fa12` (8), `fa13` (7), `fa14` (7), `fa15` (7), `fa16` (6).
- **Tier 3 (`36` tests across 6 files)**: `p01` (6), `p02` (6), `p03` (6), `p04` (6), `p05` (6), `p06` (6).
- **Tier 4 (`10` scenarios across 5 files)**: `s01` (2), `s02` (2), `s03` (2), `s04` (2), `s05` (2).

---

## 3. Feature Checklist (`F-001`–`F-086` = 86 / 86 Covered, 0 Uncovered)

| Feature | Name | Area | Tier 1 | Tier 2 | Tier 3 / Tier 4 | Status |
|---|---|---|---|---|---|---|
| `F-001` | 4-Stage Bootloader & Init | `FA-01` | `tier1/fa01-boot-services-diag.test.mjs` | `tier2/fa01-boot-services-diag.test.mjs` | `p06`, `s01`, `s02`, `s03` | `[x]` |
| `F-002` | Systemd-like ServiceManager | `FA-01` | `tier1/fa01-boot-services-diag.test.mjs` | `tier2/fa01-boot-services-diag.test.mjs` | `p06`, `s03` | `[x]` |
| `F-003` | Kernel `dmesg` Ring Buffer | `FA-01` | `tier1/fa01-boot-services-diag.test.mjs` | `tier2/fa01-boot-services-diag.test.mjs` | `p04`, `p06`, `s01`, `s03` | `[x]` |
| `F-004` | Kernel Panic & Safe Recovery | `FA-01` | `tier1/fa01-boot-services-diag.test.mjs` | `tier2/fa01-boot-services-diag.test.mjs` | `p06`, `s03` | `[x]` |
| `F-005` | Runtime Diagnostics Snapshot | `FA-01` | `tier1/fa01-boot-services-diag.test.mjs` | `tier2/fa01-boot-services-diag.test.mjs` | `p06`, `s02`, `s03` | `[x]` |
| `F-006` | Process Control Block & FSM | `FA-02` | `tier1/fa02-process-scheduler-signals.test.mjs` | `tier2/fa02-process-scheduler-signals.test.mjs` | `p01`, `p04`, `s01`, `s03` | `[x]` |
| `F-007` | Multi-Thread TCB Support | `FA-02` | `tier1/fa02-process-scheduler-signals.test.mjs` | `tier2/fa02-process-scheduler-signals.test.mjs` | `p04`, `s01` | `[x]` |
| `F-008` | Preemptive/Cooperative Scheduler | `FA-02` | `tier1/fa02-process-scheduler-signals.test.mjs` | `tier2/fa02-process-scheduler-signals.test.mjs` | `p04`, `s01` | `[x]` |
| `F-009` | POSIX Signal Handling | `FA-02` | `tier1/fa02-process-scheduler-signals.test.mjs` | `tier2/fa02-process-scheduler-signals.test.mjs` | `p04`, `s01`, `s03`, `s04` | `[x]` |
| `F-010` | Process Streams & FD Table | `FA-02` | `tier1/fa02-process-scheduler-signals.test.mjs` | `tier2/fa02-process-scheduler-signals.test.mjs` | `p05`, `s02` | `[x]` |
| `F-011` | Process Sandbox Quotas | `FA-03` | `tier1/fa03-vmm-quotas-isolation.test.mjs` | `tier2/fa03-vmm-quotas-isolation.test.mjs` | `p04`, `s01` | `[x]` |
| `F-012` | Sparse 4KB-Page Virtual Memory | `FA-03` | `tier1/fa03-vmm-quotas-isolation.test.mjs` | `tier2/fa03-vmm-quotas-isolation.test.mjs` | `p04`, `s01`, `s03` | `[x]` |
| `F-013` | Hardware-Style R/W/X Enforcement | `FA-03` | `tier1/fa03-vmm-quotas-isolation.test.mjs` | `tier2/fa03-vmm-quotas-isolation.test.mjs` | `p04`, `s01` | `[x]` |
| `F-014` | Per-PID Heap Allocator & Telemetry | `FA-03` | `tier1/fa03-vmm-quotas-isolation.test.mjs` | `tier2/fa03-vmm-quotas-isolation.test.mjs` | `p04`, `s03` | `[x]` |
| `F-015` | SyscallDispatcher, EventBus, CpuRegistry & WAL SQLite | `FA-02` | `tier1/fa02-process-scheduler-signals.test.mjs` | `tier2/fa02-process-scheduler-signals.test.mjs` | `p06`, `s01` | `[x]` |
| `F-016` | Persistent SQLite POSIX VFS | `FA-04` | `tier1/fa04-unified-vfs-paths.test.mjs` | `tier2/fa04-unified-vfs-paths.test.mjs` | `p01`, `p06`, `s01`, `s03` | `[x]` |
| `F-017` | Transparent 4-Platform PathTranslator | `FA-04` | `tier1/fa04-unified-vfs-paths.test.mjs` | `tier2/fa04-unified-vfs-paths.test.mjs` | `p01`, `s01`, `s03` | `[x]` |
| `F-018` | Shared Cross-Platform User Space | `FA-04` | `tier1/fa04-unified-vfs-paths.test.mjs` | `tier2/fa04-unified-vfs-paths.test.mjs` | `p01`, `s01`, `s03` | `[x]` |
| `F-019` | Symlinks, `ELOOP` & Live VFS Events | `FA-04` | `tier1/fa04-unified-vfs-paths.test.mjs` | `tier2/fa04-unified-vfs-paths.test.mjs` | `p01`, `s03` | `[x]` |
| `F-020` | Dynamic Virtual Mounts (`/proc`, `/dev`, `/tmp`) | `FA-04` | `tier1/fa04-unified-vfs-paths.test.mjs` | `tier2/fa04-unified-vfs-paths.test.mjs` | `p01`, `s03` | `[x]` |
| `F-021` | Unified Config Store & Windows Registry | `FA-05` | `tier1/fa05-unified-config-store.test.mjs` | `tier2/fa05-unified-config-store.test.mjs` | `p02`, `p06`, `s01`, `s02`, `s03` | `[x]` |
| `F-022` | Apple Defaults/Plist & Android SharedPrefs Sync | `FA-05` | `tier1/fa05-unified-config-store.test.mjs` | `tier2/fa05-unified-config-store.test.mjs` | `p02`, `p06`, `s01`, `s02`, `s03` | `[x]` |
| `F-023` | IPC Channels, Named Pipes, RPC & Shared Memory | `FA-06` | `tier1/fa06-ipc-intents-clipboard-notifs.test.mjs` | `tier2/fa06-ipc-intents-clipboard-notifs.test.mjs` | `p03`, `p04`, `s01` | `[x]` |
| `F-024` | Universal Intent, URL-Scheme & File-Assoc Router | `FA-06` | `tier1/fa06-ipc-intents-clipboard-notifs.test.mjs` | `tier2/fa06-ipc-intents-clipboard-notifs.test.mjs` | `p03`, `s01`, `s03`, `s05` | `[x]` |
| `F-025` | Multi-MIME Shared Clipboard | `FA-06` | `tier1/fa06-ipc-intents-clipboard-notifs.test.mjs` | `tier2/fa06-ipc-intents-clipboard-notifs.test.mjs` | `p03`, `s01`, `s03` | `[x]` |
| `F-026` | Unified Notification Center & Live Activities | `FA-06` | `tier1/fa06-ipc-intents-clipboard-notifs.test.mjs` | `tier2/fa06-ipc-intents-clipboard-notifs.test.mjs` | `p03`, `s01`, `s04` | `[x]` |
| `F-027` | Users, Groups, Sandbox UIDs & POSIX ACLs | `FA-07` | `tier1/fa07-security-permissions-audit.test.mjs` | `tier2/fa07-security-permissions-audit.test.mjs` | `p04`, `p06`, `s05` | `[x]` |
| `F-028` | Unified Permission Broker & Audit Log | `FA-07` | `tier1/fa07-security-permissions-audit.test.mjs` | `tier2/fa07-security-permissions-audit.test.mjs` | `p04`, `p06`, `s05` | `[x]` |
| `F-029` | Headless Window Compositor Server | `FA-08` | `tier1/fa08-compositor-surfaces-input.test.mjs` | `tier2/fa08-compositor-surfaces-input.test.mjs` | `p05`, `s04`, `s05` | `[x]` |
| `F-030` | Dual-Mode Compositor Surface Engine | `FA-08` | `tier1/fa08-compositor-surfaces-input.test.mjs` | `tier2/fa08-compositor-surfaces-input.test.mjs` | `p05`, `s04`, `s05` | `[x]` |
| `F-031` | Compositor Input Event Router | `FA-08` | `tier1/fa08-compositor-surfaces-input.test.mjs` | `tier2/fa08-compositor-surfaces-input.test.mjs` | `p05`, `s03`, `s04`, `s05` | `[x]` |
| `F-032` | Zero-Dep PKZIP / ZIP64 Codec | `FA-09` | `tier1/fa09-archives-detect-ospm.test.mjs` | `tier2/fa09-archives-detect-ospm.test.mjs` | `s02` | `[x]` |
| `F-033` | Magic-Byte Package Format Auto-Detector | `FA-09` | `tier1/fa09-archives-detect-ospm.test.mjs` | `tier2/fa09-archives-detect-ospm.test.mjs` | `s01`, `s02`, `s05` | `[x]` |
| `F-034` | `ospm` Package Manager Core & App Hub DB | `FA-09` | `tier1/fa09-archives-detect-ospm.test.mjs` | `tier2/fa09-archives-detect-ospm.test.mjs` | `p06`, `s01`, `s02`, `s05` | `[x]` |
| `F-035` | Structured Error & Fault Isolation Contracts | `FA-03` | `tier1/fa03-vmm-quotas-isolation.test.mjs` | `tier2/fa03-vmm-quotas-isolation.test.mjs` | `p04`, `s01` | `[x]` |
| `F-036` | Android `.apk` Package Loader & Verifier | `FA-10` | `tier1/fa10-android-apk-dalvik.test.mjs` | `tier2/fa10-android-apk-dalvik.test.mjs` | `p01`, `s01`, `s02`, `s03`, `s05` | `[x]` |
| `F-037` | Android Binary XML (AXML) & `resources.arsc` | `FA-10` | `tier1/fa10-android-apk-dalvik.test.mjs` | `tier2/fa10-android-apk-dalvik.test.mjs` | `s02` | `[x]` |
| `F-038` | Android DEX Parser (`035`–`041`) | `FA-10` | `tier1/fa10-android-apk-dalvik.test.mjs` | `tier2/fa10-android-apk-dalvik.test.mjs` | `s02` | `[x]` |
| `F-039` | Dalvik/ART Register Bytecode VM | `FA-10` | `tier1/fa10-android-apk-dalvik.test.mjs` | `tier2/fa10-android-apk-dalvik.test.mjs` | `s01`, `s02`, `s03`, `s05` | `[x]` |
| `F-040` | Android Framework API & Lifecycle Bridge | `FA-10` | `tier1/fa10-android-apk-dalvik.test.mjs` | `tier2/fa10-android-apk-dalvik.test.mjs` | `p01`, `p03`, `s01`, `s03`, `s05` | `[x]` |
| `F-041` | Windows PE32 (`0x10B`) & PE32+ (`0x20B`) Loader | `FA-11` | `tier1/fa11-windows-pe-x86-win32-batch.test.mjs` | `tier2/fa11-windows-pe-x86-win32-batch.test.mjs` | `p01`, `p04`, `s01`, `s02`, `s03` | `[x]` |
| `F-042` | Windows `.msix`/`.appx` & `.msi` Package Support | `FA-11` | `tier1/fa11-windows-pe-x86-win32-batch.test.mjs` | `tier2/fa11-windows-pe-x86-win32-batch.test.mjs` | — | `[x]` |
| `F-043` | x86 & x86-64 CPU Emulator | `FA-11` | `tier1/fa11-windows-pe-x86-win32-batch.test.mjs` | `tier2/fa11-windows-pe-x86-win32-batch.test.mjs` | `s01`, `s02`, `s03` | `[x]` |
| `F-044` | Win32 Core Subsystem API Bridge | `FA-11` | `tier1/fa11-windows-pe-x86-win32-batch.test.mjs` | `tier2/fa11-windows-pe-x86-win32-batch.test.mjs` | `p01`, `p02`, `s01`, `s02`, `s03` | `[x]` |
| `F-045` | Windows `.bat` / `.cmd` Batch Interpreter | `FA-11` | `tier1/fa11-windows-pe-x86-win32-batch.test.mjs` | `tier2/fa11-windows-pe-x86-win32-batch.test.mjs` | — | `[x]` |
| `F-046` | Pure-JS Android SDK Builder & Sample APKs | `FA-10` | `tier1/fa10-android-apk-dalvik.test.mjs` | `tier2/fa10-android-apk-dalvik.test.mjs` | `s01`, `s05` | `[x]` |
| `F-047` | Pure-JS Windows PE32+ SDK Builder & Sample EXEs | `FA-11` | `tier1/fa11-windows-pe-x86-win32-batch.test.mjs` | `tier2/fa11-windows-pe-x86-win32-batch.test.mjs` | `s01`, `s03` | `[x]` |
| `F-048` | Mach-O 64-bit & Universal Fat Binary Loader | `FA-12` | `tier1/fa12-apple-ios-ipa-uikit.test.mjs` | `tier2/fa12-apple-ios-ipa-uikit.test.mjs` | `p01`, `s01`, `s02` | `[x]` |
| `F-049` | Apple `bplist00` & XML Plist Codec | `FA-12` | `tier1/fa12-apple-ios-ipa-uikit.test.mjs` | `tier2/fa12-apple-ios-ipa-uikit.test.mjs` | `p02`, `s02` | `[x]` |
| `F-050` | ARM64 (AArch64) CPU Emulator & Apple ABI | `FA-12` | `tier1/fa12-apple-ios-ipa-uikit.test.mjs` | `tier2/fa12-apple-ios-ipa-uikit.test.mjs` | `s01`, `s02` | `[x]` |
| `F-051` | Darwin / XNU BSD Syscall & Mach Trap Layer | `FA-12` | `tier1/fa12-apple-ios-ipa-uikit.test.mjs` | `tier2/fa12-apple-ios-ipa-uikit.test.mjs` | `p01`, `s01`, `s02` | `[x]` |
| `F-052` | Objective-C ABI2 & Swift Runtime Bridge | `FA-12` | `tier1/fa12-apple-ios-ipa-uikit.test.mjs` | `tier2/fa12-apple-ios-ipa-uikit.test.mjs` | `s01`, `s02` | `[x]` |
| `F-053` | iOS `.ipa` Loader, UIKit & SpringBoard Sandbox | `FA-12` | `tier1/fa12-apple-ios-ipa-uikit.test.mjs` | `tier2/fa12-apple-ios-ipa-uikit.test.mjs` | `p01`, `p03`, `s01`, `s02`, `s04` | `[x]` |
| `F-054` | macOS `.app` Bundle, `.dmg` (`koly`) & `.pkg` (XAR) Loader | `FA-13` | `tier1/fa13-macos-appkit-universal-wasm.test.mjs` | `tier2/fa13-macos-appkit-universal-wasm.test.mjs` | `p01`, `s01`, `s02`, `s03`, `s04` | `[x]` |
| `F-055` | macOS Cocoa / AppKit Bridge & Global Menu Bar | `FA-13` | `tier1/fa13-macos-appkit-universal-wasm.test.mjs` | `tier2/fa13-macos-appkit-universal-wasm.test.mjs` | `p05`, `s01`, `s02`, `s03`, `s04` | `[x]` |
| `F-056` | Universal `.uapp` / WebAssembly & WASI Runtime | `FA-13` | `tier1/fa13-macos-appkit-universal-wasm.test.mjs` | `tier2/fa13-macos-appkit-universal-wasm.test.mjs` | `s01`, `s02`, `s04`, `s05` | `[x]` |
| `F-057` | Pure-JS iOS SDK Builder & Sample IPA | `FA-12` | `tier1/fa12-apple-ios-ipa-uikit.test.mjs` | `tier2/fa12-apple-ios-ipa-uikit.test.mjs` | `s01` | `[x]` |
| `F-058` | Pure-JS macOS SDK Builder & Sample `.app` | `FA-13` | `tier1/fa13-macos-appkit-universal-wasm.test.mjs` | `tier2/fa13-macos-appkit-universal-wasm.test.mjs` | `s01`, `s04` | `[x]` |
| `F-059` | Pure-JS Universal WASM SDK Builder | `FA-13` | `tier1/fa13-macos-appkit-universal-wasm.test.mjs` | `tier2/fa13-macos-appkit-universal-wasm.test.mjs` | `s01`, `s04` | `[x]` |
| `F-060` | Deterministic Sample Build Pipeline | `FA-13` | `tier1/fa13-macos-appkit-universal-wasm.test.mjs` | `tier2/fa13-macos-appkit-universal-wasm.test.mjs` | `s01` | `[x]` |
| `F-061` | Unified OmniOS Runtime Bootstrapper | `FA-14` | `tier1/fa14-http-ws-spotlight.test.mjs` | `tier2/fa14-http-ws-spotlight.test.mjs` | `p06`, `s01`–`s05` | `[x]` |
| `F-062` | HTTP REST API v1 & Health Endpoints | `FA-14` | `tier1/fa14-http-ws-spotlight.test.mjs` | `tier2/fa14-http-ws-spotlight.test.mjs` | `p01`–`p06`, `s01`–`s05` | `[x]` |
| `F-063` | Zero-Dep RFC 6455 WebSocket Server (`/ws`) | `FA-14` | `tier1/fa14-http-ws-spotlight.test.mjs` | `tier2/fa14-http-ws-spotlight.test.mjs` | `p02`, `p03`, `p05`, `s04`, `s05` | `[x]` |
| `F-064` | Spotlight Universal Search Engine | `FA-14` | `tier1/fa14-http-ws-spotlight.test.mjs` | `tier2/fa14-http-ws-spotlight.test.mjs` | `p05`, `s03`, `s04` | `[x]` |
| `F-065` | Headless & Remote OmniOS CLI | `FA-15` | `tier1/fa15-cli-shell-system-apps.test.mjs` | `tier2/fa15-cli-shell-system-apps.test.mjs` | `p05`, `p06`, `s02` | `[x]` |
| `F-066` | Multi-Syntax Shell Interpreter | `FA-15` | `tier1/fa15-cli-shell-system-apps.test.mjs` | `tier2/fa15-cli-shell-system-apps.test.mjs` | `p05`, `s02`, `s03` | `[x]` |
| `F-067` | Built-in System App: OmniTerm | `FA-15` | `tier1/fa15-cli-shell-system-apps.test.mjs` | `tier2/fa15-cli-shell-system-apps.test.mjs` | `p05`, `s03` | `[x]` |
| `F-068` | Built-in System App: OmniFiles | `FA-15` | `tier1/fa15-cli-shell-system-apps.test.mjs` | `tier2/fa15-cli-shell-system-apps.test.mjs` | `s03` | `[x]` |
| `F-069` | Built-in System App: Activity / Task Monitor | `FA-15` | `tier1/fa15-cli-shell-system-apps.test.mjs` | `tier2/fa15-cli-shell-system-apps.test.mjs` | `s03` | `[x]` |
| `F-070` | Built-in System App: App Hub | `FA-15` | `tier1/fa15-cli-shell-system-apps.test.mjs` | `tier2/fa15-cli-shell-system-apps.test.mjs` | `s03`, `s05` | `[x]` |
| `F-071` | Built-in System App: Settings & Privacy Center | `FA-15` | `tier1/fa15-cli-shell-system-apps.test.mjs` | `tier2/fa15-cli-shell-system-apps.test.mjs` | `s03` | `[x]` |
| `F-072` | Built-in System Apps: Binary Inspector & OmniNotes | `FA-15` | `tier1/fa15-cli-shell-system-apps.test.mjs` | `tier2/fa15-cli-shell-system-apps.test.mjs` | `s03`, `s04` | `[x]` |
| `F-073` | Live WebSocket + REST GUI Client (`ui/`) | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s04`, `s05` | `[x]` |
| `F-074` | Multi-Window Compositor Canvas & Dual Renderer | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s04`, `s05` | `[x]` |
| `F-075` | Adaptive Window Chrome | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s04` | `[x]` |
| `F-076` | Adaptive 5-Mode Shell Switcher | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `p02`, `p05`, `s04` | `[x]` |
| `F-077` | macOS Shell UX | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s04` | `[x]` |
| `F-078` | Windows Shell UX | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s04` | `[x]` |
| `F-079` | iOS Shell UX | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s04` | `[x]` |
| `F-080` | Android Shell UX | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s04` | `[x]` |
| `F-081` | Live Universal Share Sheet / Intent Chooser Modal | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s05` | `[x]` |
| `F-082` | Live Security & Permission Prompt Modal | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s05` | `[x]` |
| `F-083` | Drag-and-Drop Binary Package Uploader | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s05` | `[x]` |
| `F-084` | Offline-Safe Responsive Dark/Light Design System | `FA-16` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s04` | `[x]` |
| `F-085` | 5-Platform Concurrent Interop E2E Verification | `T3/T4` | — | — | `p01`–`p06`, `s01`, `s02`, `s03` | `[x]` |
| `F-086` | Headless Chromium CDP Browser E2E Verification | `T3/T4` | `tier1/fa16-web-shell-gui-cdp.test.mjs` | `tier2/fa16-web-shell-gui-cdp.test.mjs` | `s04`, `s05` | `[x]` |

---

## 4. Authoritative 29 Binary/VMM/VFS/Security Edge-Case Coverage (`29 / 29`)

All 29 spec edge cases in `PROJECT.md` are parameterized in `tests/e2e/lib/fixtures-malformed.mjs` (`MALFORMED_CORPUS_INDEX`, verified by `harness.selftest.mjs`) and actively exercised in Tier 2:
- **ZIP/ZIP64 & Format Detection (`tier2/fa09`)**: `#1` ZIP-slip (`..`, leading `/`, drive letter, NUL), `#2` ZIP bomb decompressed byte/ratio cap, `#4` Data Descriptor bit 3 Central Directory authority, `#19` Java `.class` `0xCAFEBABE` vs Mach-O Fat guard.
- **Android APK/AXML/ARSC/DEX/Dalvik (`tier2/fa10`)**: `#3` APK v2/v3 Signing Block before Central Directory, `#5` AXML `chunk.size == 0` / `< headerSize` / OOB, `#6` `resources.arsc` `FLAG_OFFSET16` & `FLAG_SPARSE`, `#7` DEX bad Adler-32/SHA-1/header_size/endian/`type_ids>65535`, `#8` MUTF-8 `0xC0 0x80` & >5B LEB128, `#9` odd-`insns_size` `try_item` 2B padding, `#10` Dalvik `div/rem` by `0` (`ArithmeticException`) & `INT32_MIN / -1` wrap, `#11` Dalvik infinite loop `goto 0` & deep recursion.
- **Windows PE/x86-64/Batch (`tier2/fa11`)**: `#12` bad `e_lfanew` (`<64`, past EOF), `NumberOfSections > 96`, `NumberOfRvaAndSizes > 16`, `#13` `.bss` `VirtualSize > SizeOfRawData`, `#14` `OriginalFirstThunk == 0` IAT fallback, `#15` `CERTIFICATE_TABLE` raw file offset rule, `#16` x86-64 32-bit zero-ext vs 16/8-bit preserve, `#17` RIP-relative next-RIP address, `#18` `.bat` vs `.cmd` `ERRORLEVEL` after successful `SET`.
- **Apple Mach-O/ARM64/Darwin/ObjC/`bplist00` (`tier2/fa12`)**: `#20` FairPlay `LC_ENCRYPTION_INFO_64.cryptid != 0` (`E_ENCRYPTED_BINARY`), `#21` `__PAGEZERO` 4GiB virtual guard deref (`SIGSEGV`, no 4GiB RAM alloc — also `tier2/fa03`), `#22` `LC_MAIN` entry VA (`__TEXT.vmaddr + slide + entryoff`), `#23` ARM64 reg-31 `SP` vs `XZR`, `#24` Apple ARM64 variadics on 8B stack slots, `#25` Darwin XNU Carry flag `1` + positive `errno`, `#26` `objc_msgSend(nil)` returns `0`, `#27` cyclic `bplist00` (`E_CYCLIC_PLIST`), signed 8B negative int (`0x13`), 2001 CF epoch date.
- **VFS & WASI (`tier2/fa04`, `tier2/fa13`)**: `#28` Windows case-insensitive VFS preserving creation case + traversal jail + `ELOOP`, `#29` WASI `fd_write` OOB / `iovs_len > 1024` / ungranted dir (`WASI_EINVAL`/`WASI_EFAULT`/`WASI_ENOTCAPABLE`).

---

## 5. Independent Final Verification Gate Sign-Off

Every sub-milestone (`SM-1` through `SM-7`) passed independent 5-agent verification gates (2 Reviewers + 2 Challengers + 1 Forensic Integrity Auditor). Final whole-track SM-7 Iteration 4 gate:
- **Forensic Integrity Auditor (`e2e_sm7_i4_aud1`)**: **`CLEAN`** — `50/50` `node --check`, `26/26` `harness.selftest.mjs`, `260/260` fail-loud `E_OMNIOS_NOT_IMPLEMENTED`, `0` `assert.*` in `194` `try/catch` blocks, `0` skips/stubs/tautologies, `0` private `os/*/*` imports, `0` external npm deps, `458/458` live `lib/` named exports, `86/86` features + `29/29` edge cases, `0` `.agents/teamwork/` hygiene leaks, `git diff --name-only` empty.
- **Reviewer 1 (`e2e_sm7_i4_rev1`)**: **`APPROVE`** — `92/92` live Node/Chromium probes + full 50-file / 286-test whole-track gates PASS.
- **Reviewer 2 (`e2e_sm7_i4_rev2`)**: **`APPROVE`** — `118/118` live Node/Chromium probes + line-by-line Tier 4 contract review PASS.
- **Challenger 1 (`e2e_sm7_i4_chal1`)**: **`CONFIRM`** — `245/245` adversarial probes (`s03`, `s05` JS + Chromium CDP, `s01`, `s02`) PASS.
- **Challenger 2 (`e2e_sm7_i4_chal2`)**: **`CONFIRM`** — `38/38` Iter 3 re-challenge + `21/21` strict adversarial live Chromium CDP probes (`s04`) PASS.
