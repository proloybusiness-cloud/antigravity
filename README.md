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

## Bootable Live ISO (Oracle VirtualBox / VMware Workstation / Daily-Driver USB)

Download pre-built hybrid **BIOS + UEFI** `x86_64` Live ISOs from GitHub Releases:

- **OmniOS 2.1 NextGen Pro** (`~1.77–1.85 GiB`, full daily-driver KDE Plasma 6.6 Wayland desktop + real open-source apps + Liquid Glass / Windows 12 Fluent themes + pre-installed VirtualBox Guest Additions + live Optical/USB auto-mount):
  - Release page: [`omnios-v2.1-pro-iso`](https://github.com/proloybusiness-cloud/antigravity/releases/tag/omnios-v2.1-pro-iso) (`omnios-v2-pro-x86_64.iso` + `omnios-v2-pro-x86_64.iso.sha256`)
- **OmniOS Potato-PC Lite** (`~708 MB`, runs on `< 1 GB` RAM):
  - Release page: [`omnios-v2.0.0-live-iso`](https://github.com/proloybusiness-cloud/antigravity/releases/tag/omnios-v2.0.0-live-iso) (`omnios-live-x86_64.iso` + `omnios-live-x86_64.iso.sha256`)

Verify the downloaded ISO checksum:

```bash
# Linux
sha256sum -c omnios-v2-pro-x86_64.iso.sha256

# macOS
shasum -a 256 -c omnios-v2-pro-x86_64.iso.sha256
```

```powershell
# Windows PowerShell
Get-FileHash omnios-v2-pro-x86_64.iso -Algorithm SHA256
```

Or build either edition locally with Docker:

```bash
# Default — OmniOS 2.1 NextGen Pro Daily-Driver Desktop ISO (~1.77–1.85 GiB, strictly < 2.0 GiB)
# KDE Plasma 6.6 Wayland + Customized MacTahoe/Fluent 12 Liquid Glass Themes +
# Firefox, LibreOffice, VLC, GIMP, Kate, Dolphin, Konsole (Zsh/Fastfetch), Wine 11,
# Discover + Flathub, PipeWire Audio, NetworkManager, VirtualBox Guest Additions,
# Open-VM-Tools, Live Optical/USB Auto-Mount & OmniOS Hub
./scripts/build-iso.sh --edition pro

# Potato-PC Lite Kiosk Edition (~708 MB, runs on < 1 GB RAM)
./scripts/build-iso.sh --edition lite
```

**GRUB2 Boot Profiles (BIOS & UEFI)**:
1. **Liquid Glass Desktop (Default)** — macOS 29 + Windows 12 dark Liquid Glass fusion (`omnios.mode=full`)
2. **Windows 12 Fluent Acrylic Mode** — centered floating acrylic taskbar preset (`omnios.preset=fluent12`)
3. **Safe Software Graphics (nomodeset)** — universal `simpledrm` + Mesa `llvmpipe` compatibility mode (`omnios.safe_gfx=1 nomodeset`)
4. **Server + CLI Console** — headless low-RAM mode starting OmniOS Hub & interactive CLI shell without GUI (`omnios.mode=headless`)
5. **Copy to RAM (Free Optical Drive)** — copies the live system into RAM (requires >= 4 GB RAM) and releases `/dev/sr0` so you can freely swap CDs or insert Guest Additions ISO on a 1-optical-drive VM (`omnios.toram=1`)

**OmniOS 2.1 NextGen Pro in Oracle VirtualBox**:
1. **Machine -> New**: Name `OmniOS 2.1 Pro`, select `omnios-v2-pro-x86_64.iso`, Type **Linux**, Version **Other Linux (64-bit)** (both Legacy BIOS and EFI are supported).
2. **Resources & Display**: **4 GB RAM** recommended (2 GB minimum; **4 GB+ required** for `Copy to RAM`), **2+ vCPUs**, **128 MB Video Memory**. Graphics controller **VMSVGA** (with 3D Acceleration OFF or ON), **VBoxSVGA**, and **VBoxVGA** all boot cleanly straight to Plasma 6.6 Liquid Glass with zero blank-screen loops.
3. **Pre-Installed Guest Additions, Clipboard & Drag-and-Drop**:
   - Alpine native **VirtualBox Guest Additions (`7.0.22`)** are pre-installed and start automatically inside VirtualBox (providing dynamic display resize, seamless mouse, bidirectional clipboard, host-to-guest file/folder drag-and-drop, and shared folder automounts without needing to manually compile `VBoxLinuxAdditions.run`).
   - Enable host forwarding in VirtualBox: **Devices -> Shared Clipboard -> Bidirectional** and **Devices -> Drag and Drop -> Bidirectional** (or **Host to Guest**). Dragging files or folders from your host PC onto the OmniOS desktop copies them directly to `~/Desktop/` with a desktop notification toast.
   - Auto-mount VirtualBox Shared Folders appear automatically at `/media/sf_<name>`, on the **Desktop**, and in **Dolphin -> VirtualBox Shared Folders** (recommended for Guest → Host file transfer as well).
4. **Live Optical Discs & USB Drives**:
   - Inserting any CD/DVD ISO (including VirtualBox's Guest Additions CD) or FAT32/exFAT/NTFS/ext4 USB drive auto-mounts it under `/run/media/omnios/<label>` and displays it immediately on the **Desktop**, in **Dolphin -> Removable Devices**, and in the top-bar **Device Notifier** (cleanly removed upon eject).
   - If your VM has only 1 optical drive, boot the 5th GRUB entry **Copy to RAM (Free Optical Drive)** (or attach a 2nd virtual optical drive in Storage settings) so `/dev/sr0` is free for inserting additional discs while running live.

**OmniOS 2.1 NextGen Pro in VMware Workstation**:
1. **File -> New Virtual Machine -> Typical -> Installer disc image file (iso)** -> select `omnios-v2-pro-x86_64.iso`.
2. **Guest OS**: **Linux** -> **Other Linux 6.x kernel 64-bit** (both BIOS and UEFI firmware are supported).
3. **Resources**: **4 GB RAM** (2 GB minimum), **2+ vCPUs**, **3D graphics acceleration ON** recommended for silky 60fps KWin glass blur (auto-falls back to Mesa `llvmpipe` if disabled), **NAT** or **Bridged** networking (auto-connects `eth0` via NetworkManager DHCP).
4. **Power on**: Auto-logs directly into **OmniOS 2.1 NextGen Pro** (user: `omnios` / password: `omnios`, passwordless `sudo`; `Ctrl+Alt+F3` login TTY, `Ctrl+Alt+F4` root shell). Switch anytime between **OmniOS Liquid Glass Dark (macOS 29)**, **OmniOS Windows 12 Fluent**, and **OmniOS Silk Glass Light** via **OmniOS Theme Studio** on the dock, or access **OmniOS Hub** from your host browser at `http://<vm-ip>:3777/`.

## Testing

```bash
# Full OmniOS Unit + Legacy suite (runs sequentially)
npm test

# E2E Verification Suite (Selftest + Tiers 1–5)
npm run test:e2e

# Individual tiers
npm run test:e2e:tier1
npm run test:e2e:tier2
npm run test:e2e:tier3
npm run test:e2e:tier4
npm run test:e2e:tier5
```

## Legacy Antigravity Flow (Gen-1) Coexistence
Original workflow automation scripts remain preserved and functional:

```bash
npm run start:flow
npm run cli:flow -- workflows list
npm run validate
npm run test:legacy
```
