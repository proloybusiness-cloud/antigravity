# OmniOS (Antigravity Gen-2)

**OmniOS** is a lightweight, zero-runtime-dependency, multi-platform OS kernel, binary execution engine, and adaptive desktop/mobile web shell built purely on **Node.js 24** (`node:sqlite`, `node:http`, pure ES modules) and vanilla HTML/CSS/Canvas UI.

It boots in ~150 ms in ~80 MB RSS and runs even on low-spec ("potato") PCs.

## Features
- **Zero External NPM Runtime Dependencies**: Runs natively on Node.js 24 (`node:sqlite` WAL storage).
- **4-Platform Binary Compatibility + Universal WASM/WASI**:
  - **Android**: `.apk` parser (`AXML`, `resources.arsc`, `DEX` + Dalvik bytecode VM, Activity/View/Intent/SharedPreferences bridge).
  - **Windows**: `.exe`/`.dll` PE32/PE32+ (`x86`/`x86_64` CPU engine, Win32 APIs/GDI, Registry, `.msix`, `.msi`, `.bat`/`.cmd` interpreter).
  - **Apple (iOS & macOS)**: `.ipa`, `.app.zip`, `.dmg`, `.pkg` (Mach-O 64 + Fat universal, ARM64 CPU engine, ObjC/Darwin XNU ABI, `bplist00`).
  - **Universal**: `.uapp` / `.wasm` with WASI `fd_write`/`fd_read`/env/args sandboxing.
- **OS Kernel & Services**: `OmniKernel` boot stages/panic recovery, preemptive `Scheduler`, 64-bit paged `VMM`, `VirtualFileSystem` with symlinks & case-insensitive Windows overlay, `ProcessManager`, `IPCManager` + `IntentRouter` + `NotificationCenter` + `PermissionBroker` + auditing, and `Compositor`.
- **Adaptive 5-Mode Web UI (`ui/`)**: Instant switching between `Unified`, `Windows`, `macOS`, `iOS` (SpringBoard + Dynamic Island + Control Center), and `Android` (Shade + Quick Settings + Drawer + Recents), plus Spotlight (`Ctrl+Space`), Terminal, Activity Monitor, File Manager, Settings, and App Hub.
- **Potato-PC / Lite Mode**: Disables GPU-heavy glass blur, layered shadows, and animations in the browser and trims kernel `dmesg` ring, scheduler tick wakeup frequency, and SQLite memory cache on low-spec machines.

## Quick Start (Requires Node.js >= 24)

```bash
# Start OmniOS HTTP/WebSocket desktop server on http://127.0.0.1:3777
npm start

# Start OmniOS in lightweight Potato-PC mode (256 MB V8 heap cap, Lite UI & low-RAM kernel/SQLite tuning)
npm run start:lite

# Or start with Lite mode flags directly
OMNIOS_LITE=1 node os/server/http-server.mjs
node os/cli/omnios-cli.mjs boot --serve --lite
```

Open `http://127.0.0.1:3777/` in your browser (append `?lite=1` to force Lite UI mode, or toggle **Performance Profile -> Lite Mode** in Control Center).

## CLI & SDK

```bash
# Headless / remote OmniOS CLI
npm run cli -- --help
npm run cli -- boot --lite --json
npm run cli -- exec "uname -a && ls /"
npm run cli -- ospm list

# Rebuild sample multi-platform packages (.apk, .exe, .ipa, .app.zip, .uapp)
npm run sdk:build
```

## Docker (Lean Node 24 Alpine)

```bash
docker compose up -d
# Or enable Potato-PC Lite mode:
OMNIOS_LITE=1 docker compose up -d
```

Health endpoints: `GET /api/health` and `GET /api/v1/health`.

## Testing

```bash
# Full OmniOS Unit + Legacy suite (runs sequentially)
npm test

# E2E Verification Suite (Selftest + Tiers 1–4)
npm run test:e2e

# Individual tiers
npm run test:e2e:tier1
npm run test:e2e:tier2
npm run test:e2e:tier3
npm run test:e2e:tier4
```

## Legacy Antigravity Flow (Gen-1) Coexistence
Original workflow automation scripts remain preserved and functional:

```bash
npm run start:flow
npm run cli:flow -- workflows list
npm run validate
npm run test:legacy
```
