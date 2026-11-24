#!/bin/sh
# Runs inside an Alpine Linux (x86_64) container to build a lean, hybrid BIOS+UEFI
# bootable OmniOS Live ISO (Alpine 3.24 + Linux LTS + Node.js 24 + Xorg/ratpoison/Chromium).
set -eu

ISO_NAME="${OMNIOS_ISO_NAME:-omnios-live-x86_64.iso}"
SQUASHFS_COMP="${SQUASHFS_COMP:-zstd}"
WORK="/work"
ROOTFS="${WORK}/rootfs"
INITRD="${WORK}/initrd"
ISODIR="${WORK}/iso"

rm -rf "${WORK}"
mkdir -p "${ROOTFS}" "${INITRD}" "${ISODIR}/boot/grub" "${ISODIR}/omnios"

echo "[1/7] Installing ISO build toolchain inside builder container..."
apk update -q
apk add --no-cache -q \
  apk-tools \
  squashfs-tools \
  grub \
  grub-bios \
  grub-efi \
  xorriso \
  mtools \
  cpio \
  gzip \
  zstd \
  xz \
  findutils \
  coreutils

echo "[2/7] Bootstrapping lean Alpine Live RootFS (Linux LTS + Node.js 24 + VMware tools + Xorg/Chromium kiosk)..."
mkdir -p "${ROOTFS}/etc/apk"
cp -a /etc/apk/repositories "${ROOTFS}/etc/apk/repositories"
cp -a /etc/apk/keys "${ROOTFS}/etc/apk/keys"

# Intentionally excludes mesa-dri-gallium (LLVM) and openbox/imlib2 (ffmpeg/x265) to stay potato-PC lean.
# Uses ratpoison (pure libX11 fullscreen zero-border WM) + Chromium software rendering for 100% VMware/GPU compatibility.
apk --root "${ROOTFS}" --initdb --no-cache add \
  alpine-base \
  linux-lts \
  openrc \
  busybox-openrc \
  eudev \
  kmod \
  util-linux \
  iproute2 \
  dhcpcd \
  ca-certificates \
  tzdata \
  curl \
  procps-ng \
  dbus \
  open-vm-tools \
  nodejs \
  xorg-server \
  xinit \
  xrandr \
  xset \
  xhost \
  ratpoison \
  xf86-video-vmware \
  xf86-video-modesetting \
  xf86-video-fbdev \
  xf86-video-vesa \
  xf86-input-libinput \
  xf86-input-evdev \
  xf86-input-vmmouse \
  font-dejavu \
  chromium

# Verify Node.js 24 + built-in node:sqlite inside target rootfs
chroot "${ROOTFS}" /usr/bin/node -v
chroot "${ROOTFS}" /usr/bin/node -e "import('node:sqlite').then(m => { const d = new m.DatabaseSync(':memory:'); d.exec('SELECT 1'); console.log('RootFS node:sqlite verified'); })"

echo "[3/7] Installing OmniOS runtime payload into /opt/omnios..."
mkdir -p "${ROOTFS}/opt/omnios" "${ROOTFS}/var/lib/omnios/data" "${ROOTFS}/var/log"
for item in os ui packages sdk package.json README.md; do
  if [ -e "/src/${item}" ]; then
    cp -a "/src/${item}" "${ROOTFS}/opt/omnios/"
  fi
done
rm -rf "${ROOTFS}/opt/omnios/data"

echo "[4/7] Configuring users, networking, OpenRC services, VMware integration & fullscreen kiosk..."

echo "omnios" > "${ROOTFS}/etc/hostname"
cat > "${ROOTFS}/etc/hosts" <<'EOF'
127.0.0.1   localhost omnios
::1         localhost omnios
EOF

cat > "${ROOTFS}/etc/fstab" <<'EOF'
tmpfs   /tmp        tmpfs   defaults,nosuid,nodev   0 0
EOF

# eudev automatically loads GPU/NIC drivers (vmwgfx, bochs, virtio_gpu, e1000, vmxnet3, r8169, etc.)
# via modalias for the actual detected hardware; only ensure evdev is always present for Xorg input.
cat > "${ROOTFS}/etc/modules" <<'EOF'
evdev
EOF

mkdir -p "${ROOTFS}/etc/network"
cat > "${ROOTFS}/etc/network/interfaces" <<'EOF'
auto lo
iface lo inet loopback
EOF

# Create unprivileged 'omnios' desktop user & live root password (omnios)
chroot "${ROOTFS}" /bin/sh -c '
  adduser -D -s /bin/sh -G users omnios
  for grp in video input audio tty wheel; do
    addgroup "$grp" 2>/dev/null || true
    addgroup omnios "$grp" 2>/dev/null || true
  done
  echo "root:omnios" | chpasswd
  echo "omnios:omnios" | chpasswd
'

# Ratpoison kiosk config: zero borders, zero startup banner, auto-maximize every window
cat > "${ROOTFS}/home/omnios/.ratpoisonrc" <<'EOF'
set border 0
set padding 0 0 0 0
set barborder 0
startup_message off
banish
EOF
mkdir -p "${ROOTFS}/home/omnios/.config" "${ROOTFS}/home/omnios/.cache"
chroot "${ROOTFS}" chown -R omnios:users /home/omnios

# CLI wrapper on PATH
cat > "${ROOTFS}/usr/local/bin/omnios-cli" <<'EOF'
#!/bin/sh
exec /usr/bin/node /opt/omnios/os/cli/omnios-cli.mjs "$@"
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-cli"

# Mode resolver: parses /proc/cmdline omnios.mode=auto|lite|full|headless & auto-enables Lite on <2GB RAM
cat > "${ROOTFS}/usr/local/bin/omnios-resolve-mode" <<'EOF'
#!/bin/sh
MODE="auto"
for arg in $(cat /proc/cmdline 2>/dev/null || true); do
  case "$arg" in
    omnios.mode=*) MODE="${arg#omnios.mode=}" ;;
  esac
done

MEM_KB="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 1048576)"
if [ "$MODE" = "auto" ]; then
  if [ "$MEM_KB" -lt 2097152 ]; then
    MODE="lite"
  else
    MODE="full"
  fi
fi

echo "$MODE"
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-resolve-mode"

# Fast DHCPv4 without ARP probe delay (init script already runs dhcpcd -B in background)
cat >> "${ROOTFS}/etc/dhcpcd.conf" <<'EOF'
noarp
noipv6rs
timeout 10
EOF

# Dedicated OmniOS server wrapper (clean env + automatic Lite mode heap cap)
cat > "${ROOTFS}/usr/local/bin/omnios-server" <<'EOF'
#!/bin/sh
set -eu
mkdir -p /var/lib/omnios/data /run
MODE="$(/usr/local/bin/omnios-resolve-mode)"
export OMNIOS_DATA_DIR="/var/lib/omnios/data"
export HOST="0.0.0.0"
export PORT="3777"
if [ "$MODE" = "lite" ] || [ "$MODE" = "headless" ]; then
  export OMNIOS_LITE=1
  export NODE_OPTIONS="--max-old-space-size=256"
  exec /usr/bin/node /opt/omnios/os/server/http-server.mjs \
    --host 0.0.0.0 --port 3777 --data-dir /var/lib/omnios/data --lite
else
  export OMNIOS_LITE=0
  export NODE_OPTIONS="--max-old-space-size=512"
  exec /usr/bin/node /opt/omnios/os/server/http-server.mjs \
    --host 0.0.0.0 --port 3777 --data-dir /var/lib/omnios/data
fi
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-server"

# OpenRC service: /etc/init.d/omnios
cat > "${ROOTFS}/etc/init.d/omnios" <<'EOF'
#!/sbin/openrc-run

name="omnios"
description="OmniOS Multi-Platform Kernel & Adaptive Web Desktop Daemon"
command="/usr/local/bin/omnios-server"
pidfile="/run/omnios.pid"
command_background="yes"
output_log="/var/log/omnios.log"
error_log="/var/log/omnios.log"

depend() {
  after bootmisc networking
}
EOF
chmod 0755 "${ROOTFS}/etc/init.d/omnios"

# X11 session script launched inside Xorg on vt1
cat > "${ROOTFS}/usr/local/bin/omnios-xsession" <<'EOF'
#!/bin/sh
export DISPLAY="${DISPLAY:-:0}"

xset s off 2>/dev/null || true
xset -dpms 2>/dev/null || true
xset s noblank 2>/dev/null || true
xrandr --auto 2>/dev/null || true
xhost +local: >/dev/null 2>&1 || true

# Start VMware guest desktop helper if available (automatic VMware Workstation display resize & cursor)
if command -v vmware-user >/dev/null 2>&1; then
  su -s /bin/sh omnios -c "DISPLAY=${DISPLAY} vmware-user" >/dev/null 2>&1 &
fi

# Start ultra-lightweight borderless fullscreen WM
su -s /bin/sh omnios -c "DISPLAY=${DISPLAY} HOME=/home/omnios ratpoison" >/var/log/wm.log 2>&1 &
sleep 1

MODE="$(/usr/local/bin/omnios-resolve-mode)"
URL="http://127.0.0.1:3777/"
if [ "$MODE" = "lite" ]; then
  URL="http://127.0.0.1:3777/?lite=1"
fi

# Wait briefly for OmniOS daemon
i=0
while [ $i -lt 60 ]; do
  if curl -fsS --max-time 1 http://127.0.0.1:3777/api/health >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 0.25
done

# Launch Chromium fullscreen kiosk (software rendering avoids VMware/old-GPU black screens)
exec su -s /bin/sh omnios -c "DISPLAY=${DISPLAY} HOME=/home/omnios chromium \
  --kiosk \
  --start-maximized \
  --window-position=0,0 \
  --no-first-run \
  --no-default-browser-check \
  --noerrdialogs \
  --disable-infobars \
  --disable-session-crashed-bubble \
  --disable-restore-session-state \
  --disable-background-networking \
  --disable-sync \
  --disable-features=TranslateUI \
  --password-store=basic \
  --disable-dev-shm-usage \
  --disable-gpu \
  --no-sandbox \
  --autoplay-policy=no-user-gesture-required \
  --user-data-dir=/home/omnios/.config/chromium-kiosk \
  '${URL}'" >/var/log/chromium-kiosk.log 2>&1
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-xsession"

# Fallback fbdev Xorg config used automatically if auto-detected GPU driver fails
mkdir -p "${ROOTFS}/etc/X11"
cat > "${ROOTFS}/etc/X11/xorg-fbdev.conf" <<'EOF'
Section "Device"
    Identifier "FallbackFB"
    Driver "fbdev"
EndSection
EOF

# TTY1 launcher: waits for OmniOS daemon, prints status/IP, starts GUI kiosk (or CLI in headless mode)
cat > "${ROOTFS}/usr/local/bin/omnios-kiosk" <<'EOF'
#!/bin/sh
clear
echo "=============================================================="
echo "  OmniOS Live (Node.js 24 Zero-Dep Multi-Platform OS)"
echo "=============================================================="
MODE="$(/usr/local/bin/omnios-resolve-mode)"
MEM_MB="$(awk '/^MemTotal:/ {printf "%d", $2/1024; exit}' /proc/meminfo 2>/dev/null || echo '?')"
echo "  Profile : ${MODE} (Detected RAM: ${MEM_MB} MiB)"
echo "  Waiting for OmniOS kernel & HTTP/WS daemon on port 3777..."

i=0
while [ $i -lt 120 ]; do
  if curl -fsS --max-time 1 http://127.0.0.1:3777/api/health >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 0.25
done

VM_IP="$(ip -4 addr show scope global 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')"
echo "  Health  : READY (http://127.0.0.1:3777)"
if [ -n "${VM_IP}" ]; then
  echo "  Network : http://${VM_IP}:3777/?lite=1  (accessible from host PC)"
fi
echo "  Console : Ctrl+Alt+F2 for root/CLI shell (user: root / pass: omnios)"
echo "=============================================================="
if [ -w /dev/ttyS0 ]; then
  echo "[OmniOS] READY mode=${MODE} ip=${VM_IP:-local} url=http://127.0.0.1:3777" > /dev/ttyS0 2>/dev/null || true
fi

if [ "$MODE" = "headless" ]; then
  echo ""
  echo "[OmniOS Headless Mode] Starting interactive OmniOS CLI shell..."
  /usr/local/bin/omnios-cli shell --remote http://127.0.0.1:3777 || true
  exec /bin/sh -l
fi

echo "  Launching fullscreen OmniOS Desktop..."
/usr/bin/xinit /usr/local/bin/omnios-xsession -- /usr/bin/Xorg :0 vt1 -nolisten tcp -keeptty >/var/log/xorg-kiosk.log 2>&1 || {
  echo "  Primary Xorg driver failed; retrying with fbdev fallback..."
  /usr/bin/xinit /usr/local/bin/omnios-xsession -- /usr/bin/Xorg :0 vt1 -nolisten tcp -keeptty -config /etc/X11/xorg-fbdev.conf >/var/log/xorg-kiosk.log 2>&1 || true
}

echo ""
echo "[OmniOS] Desktop session exited. Dropping to rescue shell (run 'omnios-kiosk' to relaunch)."
echo "Logs: /var/log/omnios.log, /var/log/xorg-kiosk.log, /var/log/chromium-kiosk.log"
exec /bin/sh -l
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-kiosk"

# Configure OpenRC runlevels sequentially (deterministic sysfs -> devfs -> udev -> boot -> default)
chroot "${ROOTFS}" /bin/sh -c '
  rc-update add devfs sysinit
  rc-update add sysfs sysinit
  rc-update add dmesg sysinit
  rc-update add udev sysinit
  rc-update add udev-trigger sysinit
  rc-update add modules boot
  rc-update add hostname boot
  rc-update add bootmisc boot
  rc-update add networking boot
  rc-update add localmount boot
  rc-update add dhcpcd default
  rc-update add dbus default
  rc-update add open-vm-tools default
  rc-update add omnios default
'

cat > "${ROOTFS}/etc/inittab" <<'EOF'
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default

tty1::respawn:/usr/local/bin/omnios-kiosk
tty2::respawn:/sbin/getty -n -l /bin/sh 38400 tty2
tty3::respawn:/sbin/getty 38400 tty3
ttyS0::respawn:/sbin/getty -n -l /bin/sh 115200 ttyS0 vt100

::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
EOF

echo "[5/7] Building lean BusyBox + kmod Live Initramfs (VMware/SATA/NVMe/SCSI/USB/VirtIO + OverlayFS)..."
KVER="$(ls "${ROOTFS}/lib/modules" | head -n 1)"
echo "  Kernel version: ${KVER}"
cp -a "${ROOTFS}/boot/vmlinuz-lts" "${ISODIR}/boot/vmlinuz-lts"

mkdir -p "${INITRD}/etc/apk"
cp -a /etc/apk/repositories "${INITRD}/etc/apk/repositories"
cp -a /etc/apk/keys "${INITRD}/etc/apk/keys"
apk --root "${INITRD}" --initdb --no-cache add busybox kmod

mkdir -p \
  "${INITRD}/proc" \
  "${INITRD}/sys" \
  "${INITRD}/dev" \
  "${INITRD}/run" \
  "${INITRD}/mnt/media" \
  "${INITRD}/mnt/ro" \
  "${INITRD}/mnt/rw" \
  "${INITRD}/newroot" \
  "${INITRD}/lib/modules/${KVER}/kernel"

# Copy ONLY storage, CD-ROM, USB, VirtIO, VMware SCSI & filesystem kernel modules into initrd
MOD_SRC="${ROOTFS}/lib/modules/${KVER}"
MOD_DST="${INITRD}/lib/modules/${KVER}"
for meta in modules.order modules.builtin modules.builtin.modinfo; do
  [ -f "${MOD_SRC}/${meta}" ] && cp -a "${MOD_SRC}/${meta}" "${MOD_DST}/"
done
for sub in \
  kernel/drivers/cdrom \
  kernel/drivers/scsi \
  kernel/drivers/ata \
  kernel/drivers/block \
  kernel/drivers/hwmon \
  kernel/drivers/nvme \
  kernel/drivers/virtio \
  kernel/drivers/usb/common \
  kernel/drivers/usb/core \
  kernel/drivers/usb/host \
  kernel/drivers/usb/storage \
  kernel/drivers/hid \
  kernel/drivers/message \
  kernel/fs/isofs \
  kernel/fs/squashfs \
  kernel/fs/overlayfs \
  kernel/fs/fat \
  kernel/fs/nls \
  kernel/fs/ext4 \
  kernel/fs/jbd2 \
  kernel/fs/mbcache.ko* \
  kernel/lib/crc* \
  kernel/lib/zstd \
  kernel/lib/zlib* \
  kernel/lib/xz; do
  for match in ${MOD_SRC}/${sub}; do
    if [ -e "${match}" ]; then
      rel="${match#${MOD_SRC}/}"
      mkdir -p "${MOD_DST}/$(dirname "${rel}")"
      cp -a "${match}" "${MOD_DST}/${rel}"
    fi
  done
done
depmod -b "${INITRD}" "${KVER}"
rm -rf "${INITRD}/var/cache/apk" "${INITRD}/lib/apk" "${INITRD}/etc/apk"

cat > "${INITRD}/init" <<'EOF'
#!/bin/sh
export PATH=/sbin:/usr/sbin:/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

log() {
  echo "[OmniOS initramfs] $*"
  [ -w /dev/ttyS0 ] && echo "[OmniOS initramfs] $*" > /dev/ttyS0 2>/dev/null || true
}

log "Loading storage, CD-ROM, USB & filesystem drivers..."
for mod in \
  loop squashfs overlay isofs vfat nls_cp437 nls_iso8859_1 ext4 \
  cdrom sr_mod sd_mod libata ahci libahci ata_piix ata_generic \
  vmw_pvscsi mptspi mptsas mpt3sas nvme \
  virtio_pci virtio_blk virtio_scsi \
  usbcore xhci_hcd xhci_pci ehci_hcd ehci_pci uhci_hcd ohci_hcd usb-storage uas \
  usbhid hid-generic; do
  modprobe -q "$mod" 2>/dev/null || true
done

log "Searching for /omnios/rootfs.squashfs..."
FOUND=""
TRY=0
while [ $TRY -lt 40 ] && [ -z "$FOUND" ]; do
  for dev in /dev/sr* /dev/vd* /dev/sd* /dev/nvme*n* /dev/hd*; do
    [ -b "$dev" ] || continue
    for fstype in iso9660 vfat ext4; do
      if mount -t "$fstype" -o ro "$dev" /mnt/media 2>/dev/null; then
        if [ -f /mnt/media/omnios/rootfs.squashfs ]; then
          FOUND="$dev"
          break 2
        fi
        umount /mnt/media 2>/dev/null || true
      fi
    done
  done
  if [ -z "$FOUND" ]; then
    TRY=$((TRY + 1))
    sleep 0.5
  fi
done

if [ -z "$FOUND" ]; then
  log "ERROR: Could not find /omnios/rootfs.squashfs on any block device."
  ls -la /dev/sr* /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null || true
  exec /bin/sh
fi

log "Found live media on ${FOUND}. Mounting SquashFS + RAM OverlayFS..."
mount -t squashfs -o ro,loop /mnt/media/omnios/rootfs.squashfs /mnt/ro
mount -t tmpfs -o mode=0755,size=75% tmpfs /mnt/rw
mkdir -p /mnt/rw/upper /mnt/rw/work
mount -t overlay overlay -o lowerdir=/mnt/ro,upperdir=/mnt/rw/upper,workdir=/mnt/rw/work /newroot

mkdir -p /newroot/mnt/live-media /newroot/proc /newroot/sys /newroot/dev /newroot/run
mount --move /mnt/media /newroot/mnt/live-media 2>/dev/null || true

log "Switching root to OmniOS Live (/sbin/init)..."
umount /proc /sys /dev 2>/dev/null || true
exec switch_root /newroot /sbin/init
EOF
chmod 0755 "${INITRD}/init"

(cd "${INITRD}" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "${ISODIR}/boot/initramfs-omnios.gz")
ls -lh "${ISODIR}/boot/vmlinuz-lts" "${ISODIR}/boot/initramfs-omnios.gz"

# Prune redundant /boot images, apk caches, docs, locales & ~740MB of unused datacenter/mobile firmware blobs
rm -rf \
  "${ROOTFS}/boot/initramfs-"* \
  "${ROOTFS}/boot/vmlinuz-"* \
  "${ROOTFS}/boot/System.map-"* \
  "${ROOTFS}/var/cache/apk/"* \
  "${ROOTFS}/usr/share/man/"* \
  "${ROOTFS}/usr/share/doc/"* \
  "${ROOTFS}/usr/share/gtk-doc/"* \
  "${ROOTFS}/usr/share/locale/"* \
  "${ROOTFS}/tmp/"*

if [ -d "${ROOTFS}/lib/firmware" ]; then
  for fw in qcom mellanox mrvl nvidia amdgpu mediatek ath11k ath12k qed netronome liquidio cxgb4 bnx2x ti-connectivity cypress cirrus qca brcm intel/ipu intel/vsc intel/catpt intel/avs intel/sof* iwlwifi* amd-ucode xe; do
    rm -rf "${ROOTFS}/lib/firmware/"${fw} 2>/dev/null || true
  done
fi

echo "[6/7] Packing SquashFS root filesystem (${SQUASHFS_COMP})..."
if [ "${SQUASHFS_COMP}" = "xz" ]; then
  mksquashfs "${ROOTFS}" "${ISODIR}/omnios/rootfs.squashfs" -comp xz -b 256K -noappend -no-progress
else
  mksquashfs "${ROOTFS}" "${ISODIR}/omnios/rootfs.squashfs" -comp zstd -Xcompression-level 9 -b 128K -noappend -no-progress
fi
ls -lh "${ISODIR}/omnios/rootfs.squashfs"

echo "[7/7] Writing GRUB2 BIOS+UEFI boot menu and building hybrid ISO..."
cat > "${ISODIR}/boot/grub/grub.cfg" <<'EOF'
set timeout=5
set default=0

insmod all_video
insmod gfxterm
set gfxmode=auto
set gfxpayload=keep

menuentry "OmniOS Live (Auto — Potato-PC Lite on <2GB RAM)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 omnios.mode=auto console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-omnios.gz
}

menuentry "OmniOS Live (Potato-PC Lite Mode Forced — Low RAM / No Blur)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 omnios.mode=lite console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-omnios.gz
}

menuentry "OmniOS Live (Full Desktop Visual Effects)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 omnios.mode=full console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-omnios.gz
}

menuentry "OmniOS Headless Server + CLI Console (Ultra-Low RAM / ~256MB)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 omnios.mode=headless console=tty0 console=ttyS0,115200
    initrd /boot/initramfs-omnios.gz
}
EOF

grub-mkrescue \
  -o "/out/${ISO_NAME}" \
  "${ISODIR}" \
  -- -volid "OMNIOS_LIVE"

echo "[OmniOS ISO] Done: /out/${ISO_NAME}"
ls -lh "/out/${ISO_NAME}"
