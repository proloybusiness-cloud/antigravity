# OmniOS — E2E Test Infrastructure & Coverage Matrix (`TEST_INFRA.md`)

**Track**: E2E Testing Track (`sub_orch_e2e`, Parallel Dual Track)  
**Source of Truth**: `.agents/teamwork/ORIGINAL_REQUEST.md` & `PROJECT.md` (Public Contracts 1–8 & Features `F-001`–`F-086`)  
**Runtime Requirement**: Pure Node.js 24 ESM (`node >=22.13.0`, **0 external npm dependencies**) + `/usr/lib/chromium/chromium --headless=new --no-sandbox --disable-gpu`  
**Design Discipline**: Strictly **Requirement-Driven & Opaque-Box** — tests interact exclusively with public user-facing OS interfaces (`os/os.mjs` `createOmniOS()`, HTTP REST `/api/health` & `/api/v1/*`, RFC 6455 WebSocket `/ws`, Headless/Remote CLI `os/cli/omnios-cli.mjs`, real 4-platform binary packages, and live Web GUI `ui/` via Chromium CDP). Zero private internal module imports.

---

## 1. Test Architecture & Anti-Hardcoding Strategy

### 1.1 Opaque-Box Verification Channels
Every test exercises one or more documented public surfaces:
1. **HTTP REST API v1 (`GET /api/health`, `/api/v1/*`)**: Primary surface for kernel diagnostics, services, processes, VFS, unified config/Registry/Defaults/SharedPrefs, IPC/Intents/Clipboard/Notifications, security/permissions/audit, `ospm` package lifecycle, compositor actions, shell exec, and Spotlight search.
2. **RFC 6455 WebSocket Bus (`/ws`)**: Driven via Node 24 native global `WebSocket` for real-time compositor snapshots/diffs, `process:stdout`, `notification:posted`, `config:changed`, `permission:prompt`, `intent:chooser`, and client control messages.
3. **Headless & Remote CLI (`node os/cli/omnios-cli.mjs`)**: Invoked as isolated child processes with `--data-dir <tmp>` / `--remote <url>` and `--json` across all subcommands (`boot`, `exec`, `status`, `dmesg`, `services`, `ps`, `kill`, `vfs`, `reg`, `defaults`, `prefs`, `ospm`, `intent`, `clipboard`, `notify`, `sdk`).
4. **Public Runtime Factory (`import { createOmniOS } from '../../os/os.mjs'`)**: Used strictly for Contract 1–6 public programmatic operations (e.g., VMM `PROT_NONE`/`READ`/`WRITE`/`EXEC` page-fault enforcement, `__PAGEZERO` virtual guard verification, deterministic `scheduler.step()`/`runUntilIdle()`, `ipc.shmCreate`/`shmRead`/`shmWrite`, `pathTranslator.toCanonical`/`toPlatform`, `formatDetector.detect`). Never imports private `os/*/*` modules.
5. **Live Web/Desktop Shell GUI (`ui/` via Headless Chromium CDP)**: Zero-dependency Node 24 WebSocket CDP driver launching `/usr/lib/chromium/chromium --headless=new --no-sandbox --disable-gpu --remote-debugging-port=0` against a live ephemeral OmniOS HTTP/WS server, asserting zero uncaught `Runtime.exceptionThrown` / `console.error`, real DOM/Canvas2D state, all 5 Adaptive Shell Modes, window drag/focus/snap, Global Menu Bar updates, Dynamic Island, Control Center, Notification Shade, App Hub drag-and-drop upload, and real binary app click-to-execution.

### 1.2 Dynamic Binary Generation & External Oracle Anti-Hardcoding
To prove zero mocked/hardcoded app execution across Android, Windows, iOS, macOS, and Universal WASM:
- `tests/e2e/lib/fixtures-android-win.mjs` and `tests/e2e/lib/fixtures-apple-wasm.mjs` construct **brand-new standards-compliant binaries on the fly** parameterized with unique runtime-generated nonces, arithmetic operands, filenames, Registry/Defaults/SharedPrefs keys, clipboard strings, and window titles (never reusing static sample names).
- `tests/e2e/harness.selftest.mjs` cross-verifies every generated fixture format against **independent external host tools**:
  - Windows PE32+ `.exe` → `llvm-objdump --private-headers -d` & `llvm-readobj --file-headers --coff-imports`
  - Apple Mach-O 64-bit ARM64 & Universal Fat (`.ipa` & `.app.zip`) → `llvm-objdump --macho --private-headers`
  - ZIP / `.apk` / `.ipa` / `.app.zip` / `.msix` → Python 3 `zipfile.ZipFile.testzip() == None`
  - Apple `bplist00` & XML `Info.plist` → Python 3 `plistlib.loads()` round-trip equality
  - DEX v035/v039 → independent Adler-32 (`bytes[0x0C..]`) & SHA-1 (`bytes[0x20..]`) verification
  - WebAssembly `.wasm` → host `WebAssembly.validate()` === `true`
  - Live headless browser → `/usr/lib/chromium/chromium --headless=new --no-sandbox --disable-gpu` CDP round-trip.

### 1.3 Directory Layout (`tests/e2e/`)
```text
tests/e2e/
├── harness.selftest.mjs                           # Self-test & external oracle verification of fixtures + CDP driver
├── lib/
│   ├── env.mjs                                    # Ephemeral OS server, isolated temp dataDir, CLI runner, WS & public facade helpers
│   ├── cdp-client.mjs                             # Zero-dep Node 24 WebSocket CDP client for /usr/lib/chromium/chromium
│   ├── binary-utils.mjs                           # Pure-JS LE/BE codecs, CRC32, Adler32, SHA1, LEB128, MUTF-8, ZIP, AXML, bplist00
│   ├── fixtures-android-win.mjs                   # Dynamic custom .apk, PE32/PE32+ .exe, .msix, .msi, .bat/.cmd builders
│   ├── fixtures-apple-wasm.mjs                    # Dynamic custom .ipa, .app.zip (ARM64/Fat), .dmg, .pkg, .uapp/.wasm builders
│   └── fixtures-malformed.mjs                     # Deterministic adversarial corpus generator for all 29 PROJECT.md edge cases
├── tier1/                                         # 16 files (FA-01..FA-16), >=5 happy-path tests each (>=80 tests)
├── tier2/                                         # 16 files (FA-01..FA-16), >=5 boundary/corner/negative tests each (>=80 tests)
├── tier3/                                         # 6 files (P-01..P-06), pairwise cross-feature combinations (>=30 tests)
└── tier4/                                         # 5 files (S-01..S-05), >=10 real-world multi-platform & browser E2E scenarios
```

---

## 2. Requirement-Driven Feature Area Inventory (`F-001`–`F-086` = 100% Covered)

| Area ID | Requirement Feature Area | `PROJECT.md` Feature IDs | Primary Channels | Tier 1 Min | Tier 2 Min |
|---|---|---|---|---:|---:|
| **FA-01** | OS Boot, System Services, `dmesg` & Panic/Recovery | `F-001`, `F-002`, `F-003`, `F-004`, `F-005` | REST, CLI, Public API | ≥5 | ≥5 |
| **FA-02** | Process Lifecycle, Threads, Scheduler, Signals & Streams | `F-006`, `F-007`, `F-008`, `F-009`, `F-010`, `F-015` | REST, CLI, Public API | ≥5 | ≥5 |
| **FA-03** | Virtual Memory R/W/X Protection, Heap & Sandbox Quotas | `F-011`, `F-012`, `F-013`, `F-014`, `F-035` | Public API, REST | ≥5 | ≥5 |
| **FA-04** | Unified Cross-Platform VFS, Path Translation & Virtual Mounts | `F-016`, `F-017`, `F-018`, `F-019`, `F-020` | REST, CLI, Public API | ≥5 | ≥5 |
| **FA-05** | Unified Config Store: Registry, Apple Defaults & Android SharedPrefs | `F-021`, `F-022` | REST, CLI, Public API | ≥5 | ≥5 |
| **FA-06** | Cross-Platform IPC, Universal Intent Router, Clipboard & Notifications | `F-023`, `F-024`, `F-025`, `F-026` | REST, WS, CLI, Public API | ≥5 | ≥5 |
| **FA-07** | Users, Sandbox UIDs, Unified Permission Broker & Audit Log | `F-027`, `F-028` | REST, WS, Public API | ≥5 | ≥5 |
| **FA-08** | Headless Window Compositor, Dual Surfaces & Input Routing | `F-029`, `F-030`, `F-031` | REST, WS, Public API | ≥5 | ≥5 |
| **FA-09** | Zero-Dep PKZIP/ZIP64, Magic-Byte Format Detector & `ospm` | `F-032`, `F-033`, `F-034` | REST, CLI, Public API | ≥5 | ≥5 |
| **FA-10** | Android Runtime: APK, AXML/arsc, DEX, Dalvik VM & Framework | `F-036`, `F-037`, `F-038`, `F-039`, `F-040`, `F-046` | REST, CLI, Dynamic `.apk` | ≥5 | ≥5 |
| **FA-11** | Windows Runtime: PE32/PE32+, MSIX/MSI, x86/x64, Win32 & Batch | `F-041`, `F-042`, `F-043`, `F-044`, `F-045`, `F-047` | REST, CLI, Dynamic `.exe`/`.bat`/`.cmd` | ≥5 | ≥5 |
| **FA-12** | Apple Core & iOS Runtime: Mach-O, Plist, ARM64, ObjC, IPA & UIKit | `F-048`, `F-049`, `F-050`, `F-051`, `F-052`, `F-053`, `F-057` | REST, CLI, Dynamic `.ipa` | ≥5 | ≥5 |
| **FA-13** | macOS & Universal WASM Runtimes: `.app`/`.dmg`/`.pkg`, AppKit, WASI & SDK | `F-054`, `F-055`, `F-056`, `F-058`, `F-059`, `F-060` | REST, CLI, Dynamic `.app`/`.uapp` | ≥5 | ≥5 |
| **FA-14** | Unified Bootstrapper, HTTP REST v1, RFC 6455 WS & Spotlight Search | `F-061`, `F-062`, `F-063`, `F-064` | HTTP REST, WS | ≥5 | ≥5 |
| **FA-15** | Headless/Remote CLI, Multi-Syntax Shell & 7 Built-in System Apps | `F-065`, `F-066`, `F-067`, `F-068`, `F-069`, `F-070`, `F-071`, `F-072` | CLI, REST, WS | ≥5 | ≥5 |
| **FA-16** | Live Adaptive 5-Mode Web/Desktop Shell GUI (Headless Chromium CDP) | `F-073`, `F-074`, `F-075`, `F-076`, `F-077`, `F-078`, `F-079`, `F-080`, `F-081`, `F-082`, `F-083`, `F-084` | Chromium CDP + WS + REST | ≥5 | ≥5 |
| **T3/T4** | Cross-Platform Concurrent Interop & Browser E2E Verification | `F-085`, `F-086` (+ full pairwise/E2E across `F-001`–`F-084`) | All channels + Chromium CDP | — | — |

**Feature Accounting Audit**: 86 / 86 features (`F-001` through `F-086`) explicitly mapped; zero omitted features.

---

## 3. Authoritative 29 Edge-Case Mapping (Tier 2 Mandatory Coverage)

All 29 binary, CPU, VFS, security, and runtime edge cases from `PROJECT.md` are explicitly tested in Tier 2:
- **FA-03 (`tier2/fa03`)**: Unmapped/RO/NX `SIGSEGV`, `__PAGEZERO` 4GiB virtual guard (no 4GiB RAM alloc), `ENOMEM` quota exhaustion, runaway CPU instruction quota (`E_CPU_QUOTA`/`SIGXCPU`).
- **FA-04 (`tier2/fa04`)**: Symlink cycle `ELOOP` (depth > 16), `../../` path traversal jail escape, Windows case-insensitive lookup preserving creation case (`#28`).
- **FA-07 (`tier2/fa07`)**: Sandbox container cross-app escape denial (`EACCES`), denied capability audit logging, unprivileged `HKLM` virtualization.
- **FA-09 (`tier2/fa09`)**: ZIP-slip (`../../etc/passwd`, `C:\Windows\evil.dll`, NUL `#1`), ZIP bomb byte/ratio cap (`#2`), Data Descriptor flag bit 3 (`#4`), Java `.class` `0xCAFEBABE` not misidentified as Mach-O Fat (`#19`).
- **FA-10 (`tier2/fa10`)**: APK v2/v3 Signing Block before CD (`#3`), AXML `chunk.size == 0` / `< headerSize` / OOB (`#5`), `resources.arsc` `FLAG_OFFSET16` & `FLAG_SPARSE` (`#6`), DEX bad Adler-32/SHA-1/header_size/endian/`type_ids>65535` (`#7`), MUTF-8 `0xC0 0x80` & overlong >5B LEB128 (`#8`), odd-`insns_size` `try_item` 2B padding (`#9`), Dalvik `div/rem` by 0 (`ArithmeticException`) & `INT32_MIN / -1` wrap (`#10`), Dalvik infinite loop `goto 0` & deep recursion (`#11`).
- **FA-11 (`tier2/fa11`)**: PE bad `e_lfanew` (`<64`, past EOF) & `NumberOfSections > 96` & `NumberOfRvaAndSizes > 16` (`#12`), `.bss` `VirtualSize > SizeOfRawData` vs padding (`#13`), `OriginalFirstThunk == 0` IAT fallback (`#14`), `CERTIFICATE_TABLE` raw file offset rule (`#15`), x86-64 32-bit zero-ext vs 16/8-bit preserve (`#16`), RIP-relative next-RIP calculation (`#17`), `.bat` vs `.cmd` `ERRORLEVEL` after successful `SET` (`#18`).
- **FA-12 (`tier2/fa12`)**: FairPlay `LC_ENCRYPTION_INFO_64.cryptid != 0` (`E_ENCRYPTED_BINARY`, `#20`), `__PAGEZERO` deref fault (`#21`), `LC_MAIN` entry VA = `__TEXT.vmaddr + slide + entryoff` (`#22`), ARM64 reg-31 `SP` vs `XZR` (`#23`), Apple ARM64 variadic args on 8B stack slots (`#24`), Darwin XNU Carry flag `1` + positive `errno` (`#25`), `objc_msgSend(nil)` returning `0` (`#26`), cyclic `bplist00` (`E_CYCLIC_PLIST`) & signed 8B negative int (`0x13`) & 2001 CF epoch date (`#27`).
- **FA-13 (`tier2/fa13`)**: WASI `fd_write` OOB / `iovs_len > 1024` / ungranted dir (`WASI_EINVAL`/`WASI_EFAULT`/`WASI_ENOTCAPABLE`, `#29`), malformed `.dmg` `koly` & `.pkg` `xar!`.

---

## 4. Tier 3 Pairwise Cross-Feature Matrix (`tests/e2e/tier3/`)

| File | Feature Pairs Exercised Together |
|---|---|
| `p01-vfs-cross-platform-interop.test.mjs` | Windows `.exe` (`C:\Users\user\Documents\`) × macOS `.app` (`/Users/user/Documents/`) × Android `.apk` (`/sdcard/Documents/`) × iOS `.ipa` (`/var/mobile/Documents/`) + case-insensitive lookup + symlinks + `/proc/<pid>` |
| `p02-config-sync-and-shell-modes.test.mjs` | Windows Registry (`HKCU`) × Apple `NSUserDefaults` (`NSGlobalDomain`/plist) × Android `SharedPreferences` × Unified `system.*` keys (`theme`, `shellMode`, `dnd`, `volume`, `brightness`) × WebSocket `config:changed` broadcast |
| `p03-intents-clipboard-notifications.test.mjs` | Android `Intent` (`ACTION_SEND`/`ACTION_VIEW`) × iOS URL scheme (`omniweather://`) × macOS file association × Multi-handler Share Sheet (`CHOOSER_REQUIRED`) × Multi-MIME Shared Clipboard across 4 platforms × Notifications & Dynamic Island Live Activity + DND filter |
| `p04-security-quotas-isolation.test.mjs` | Permission Broker (`deny`/`allow`/`prompt`) × VFS/IPC/Registry access enforcement × Security Audit Log × Runaway CPU/Memory/Faulting app process isolation alongside healthy sibling processes |
| `p05-compositor-ws-cli-sync.test.mjs` | Headless Compositor windows/focus/snap/Global Menu Bar × RFC 6455 WebSocket live diffs × Live Shell Mode switching preserving open windows × Remote CLI (`--remote`) + Multi-Syntax Shell (`OmniTerm`) + Spotlight Search |
| `p06-panic-recovery-persistence.test.mjs` | Kernel Panic (`panic()`) + SQLite crash dump × Safe Recovery (`recover({ safeMode })`) × SQLite persistence across reboot for VFS files, installed packages, Registry/Defaults/SharedPrefs, permissions, and Audit Log |

---

## 5. Tier 4 Real-World Application Scenarios (`tests/e2e/tier4/`)

| File | Real-World End-to-End Scenarios (≥10 Total Workflows) |
|---|---|
| `s01-five-platform-concurrent-workflow.test.mjs` | **Scenario 1 (`F-085`)**: Simultaneous 5-platform execution — install & launch `.apk` + `.exe` + `.ipa` + `.app.zip` + `.uapp` concurrently under preemptive Scheduler; share files through unified `/home/user/Documents/`, exchange clipboard entries across platforms, sync preferences (`system.theme` / `HKCU` / `NSGlobalDomain` / `SharedPreferences`), route cross-platform Intents, emit Dynamic Island Live Activity + Notifications, verify clean multi-process teardown.<br>**Scenario 2**: Multi-process workload resilience — while 4 healthy platform apps run concurrently, launch a 5th faulting/runaway binary; prove ONLY the faulting PID terminates (`SIGSEGV`/`SIGXCPU`) while all 4 healthy apps keep running and responding to inputs. |
| `s02-dynamic-custom-binaries-antihardcode.test.mjs` | **Scenario 3**: Freshly generated on-the-fly custom Android `.apk` (runtime-nonce arithmetic + unique VFS file write + UI button click), Windows PE32+ `.exe` (runtime-nonce x86-64 computation + Win32 file/Registry write + stdout), iOS `.ipa` (runtime-nonce ARM64 Mach-O + `bplist00` + `NSUserDefaults` + Live Activity), macOS `.app.zip` (runtime-nonce Universal Fat Mach-O + AppKit Global Menu Bar + `/Users/user/Documents/` write), and Universal `.uapp` (runtime-nonce `\0asm` WASM WASI output) — cross-verified by `llvm-objdump`, Python `zipfile`/`plistlib`, and `WebAssembly.validate`, then installed via `ospm` and executed live with exact nonce-derived output assertions!<br>**Scenario 4**: End-to-end CLI-only headless workflow (`omnios-cli.mjs` local + `--remote` + `--json`) inspecting, installing, launching, messaging, snapshotting, and uninstalling custom binaries. |
| `s03-cross-platform-productivity-handoff.test.mjs` | **Scenario 5**: Authoring & Handoff Pipeline — Windows `.exe` writes report to `C:\Users\user\Documents\`, copies summary to Win32 Clipboard → Android `.apk` reads `/sdcard/Documents/`, appends calculation, dispatches `ACTION_SEND` Intent → macOS `.app` receives/reads `/Users/user/Documents/`, updates `NSUserDefaults` → Spotlight `/api/v1/search` indexes and finds both the document and installed apps.<br>**Scenario 6**: Built-in System Apps End-to-End Admin Session — launch `OmniTerm`, `OmniFiles`, `Activity Monitor`, `App Hub`, `Settings`, `Binary Inspector`, and `OmniNotes`, execute cross-syntax commands (`dir`, `ls`, `reg`, `defaults`, `prefs`, `ps`, `kill`), inspect a live binary PID's registers & VMM map, and verify crash/recovery preserving user data. |
| `s04-chromium-cdp-five-modes-desktop.test.mjs` | **Scenario 7 (`F-086`)**: Live Headless Chromium CDP Shell Tour — boot real OmniOS server, navigate `/usr/lib/chromium/chromium` to `http://127.0.0.1:<port>/`, assert 0 console/page errors, verify live `/ws` connection, switch across all **5 Adaptive Shell Modes** (`unified`, `windows`, `macos`, `ios`, `android`) while keeping live compositor windows open, verify persisted mode in Config Store.<br>**Scenario 8 (`F-086`)**: Live Window Manipulation & Platform UX Chrome — open multiple platform windows, drag/focus/raise z-order, apply Windows Snap Layouts, verify macOS Global Top Menu Bar updates on focus switch, open Spotlight (`Ctrl+Space`), expand iOS Dynamic Island & Control Center toggles (verifying real kernel Config Store updates), pull down Android Notification Shade & Recents process kill. |
| `s05-chromium-cdp-app-lifecycle-security.test.mjs` | **Scenario 9 (`F-086`)**: Drag-and-Drop / App Hub Binary Upload → Real Click-to-Execution Loop in Chromium — upload a freshly built dynamic custom binary (with unique runtime token) through the live Web GUI, inspect metadata, install, launch, click an interactive control inside its rendered Compositor window, and assert real kernel execution output + UI surface update in DOM/Canvas2D.<br>**Scenario 10 (`F-086`)**: Live Security Permission Prompt & Share Sheet Chooser Loop — trigger kernel `permission:prompt` and multi-handler `intent:chooser` events, interact with the live modals in Chromium, and verify kernel `PermissionBroker` decision + Audit Log entry + chosen app launch. |

---

## 6. Coverage Thresholds & Quality Invariants

- **Tier 1**: ≥5 isolated happy-path tests per Feature Area × 16 areas = **≥80 tests**.
- **Tier 2**: ≥5 boundary/corner/negative tests per Feature Area × 16 areas = **≥80 tests**, explicitly covering **29 / 29** `PROJECT.md` binary/VFS/CPU/security edge cases.
- **Tier 3**: **≥30 pairwise tests** across 6 files covering all major feature-pair interactions.
- **Tier 4**: **≥10 multi-step real-world scenarios** across 5 files covering `F-085`, `F-086`, 5-platform simultaneous interop, dynamic anti-hardcoding binaries, and headless Chromium CDP workflows.
- **Zero-Stub / Zero-Skip Policy**: Every test MUST contain real contract assertions and MUST fail cleanly (never skip or return early) if the target OS implementation is absent or broken.
- **Zero-Dependency Policy**: Zero external npm packages; pure Node.js 24 built-ins + pre-installed host verification tools.
- **Canonical Runners**:
  - Self-test: `node --test tests/e2e/harness.selftest.mjs`
  - Tier 1: `node --test tests/e2e/tier1/*.test.mjs`
  - Tier 2: `node --test tests/e2e/tier2/*.test.mjs`
  - Tier 3: `node --test tests/e2e/tier3/*.test.mjs`
  - Tier 4: `node --test tests/e2e/tier4/*.test.mjs`
  - Full Suite: `node --test tests/e2e/tier1/*.test.mjs tests/e2e/tier2/*.test.mjs tests/e2e/tier3/*.test.mjs tests/e2e/tier4/*.test.mjs`
