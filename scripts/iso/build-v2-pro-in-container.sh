#!/bin/sh
# Runs inside an Alpine Linux (x86_64) container to build the flagship
# OmniOS v2.1 NextGen Pro Daily-Driver Live ISO (Hybrid BIOS + UEFI).
#
# Stack:
#   - Alpine Linux 3.24 + Linux 6.18 LTS + SquashFS/OverlayFS RAM Live Root (with Copy-to-RAM option)
#   - KDE Plasma 6.6.6 Wayland + KWin Blur/Animations + SDDM Wayland + Kvantum Glass
#   - Real Open-Source Themes Customized for OmniOS v2.1:
#       * MacTahoe-kde -> OmniOS Liquid Glass Dark & Silk Light (macOS 29 style)
#       * Fluent-kde   -> OmniOS Fluent 12 Dark (Windows 12 style)
#       * MacTahoe-icon-theme + MacTahoe-gtk-theme + WhiteSur-cursors
#       * Bespoke OmniOS v2.1 Liquid Glass 16:9 Wallpapers & Orb Branding
#   - Real Open-Source Daily-Driver Apps:
#       * Firefox, LibreOffice (Writer/Calc/Impress), VLC, Elisa, GIMP, Gwenview,
#         Okular, Kate, KWrite, Dolphin, Konsole (Zsh + Fastfetch + btop),
#         Spectacle, KCalc, KClock, Ark, GParted, Plasma System Monitor,
#         Discover Software Center + Flatpak (Flathub), Wine 11, Node.js 24
#   - OmniOS Core Service (Node.js 24, http://127.0.0.1:3777) + OmniOS Hub
#   - PipeWire Audio, NetworkManager Wi-Fi/Ethernet, Bluetooth, Open-VM-Tools,
#     VirtualBox Guest Additions (Clipboard, Host->Guest DnD, Resize, Shared Folders),
#     and Live Optical/USB Auto-Mount (UDisks2 + Polkit + Solid + Desktop Icon Sync)
set -eu

ISO_NAME="${OMNIOS_ISO_NAME:-omnios-v2-pro-x86_64.iso}"
SQUASHFS_COMP="${SQUASHFS_COMP:-zstd}"
SQUASHFS_ZSTD_LEVEL="${SQUASHFS_ZSTD_LEVEL:-9}"
WORK="/work"
ROOTFS="${WORK}/rootfs"
INITRD="${WORK}/initrd"
ISODIR="${WORK}/iso"
THEMES_SRC="${WORK}/themes-src"

rm -rf "${WORK}"
mkdir -p "${ROOTFS}" "${INITRD}" "${ISODIR}/boot/grub" "${ISODIR}/omnios" "${THEMES_SRC}"

echo "[1/8] Installing ISO build toolchain inside builder container..."
apk update -q
apk add --no-cache -q \
  apk-tools \
  bash \
  ca-certificates \
  git \
  curl \
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
  coreutils \
  sed \
  tar \
  gtk-update-icon-cache

echo "[2/8] Bootstrapping OmniOS v2.1 Pro RootFS (Plasma 6.6 + Daily-Driver Apps + PipeWire + NetworkManager + VirtualBox/VMware Tools + Optical/USB Auto-Mount)..."
mkdir -p "${ROOTFS}/etc/apk"
cp -a /etc/apk/repositories "${ROOTFS}/etc/apk/repositories"
cp -a /etc/apk/keys "${ROOTFS}/etc/apk/keys"

apk --root "${ROOTFS}" --initdb --no-cache add \
  alpine-base \
  linux-lts \
  openrc \
  busybox-openrc \
  eudev \
  kmod \
  util-linux \
  iproute2 \
  ca-certificates \
  tzdata \
  curl \
  wget \
  git \
  procps-ng \
  sudo \
  bash \
  zsh \
  fastfetch \
  btop \
  nano \
  vim \
  python3 \
  zip \
  unzip \
  xdg-user-dirs \
  xdg-utils \
  dbus \
  dbus-openrc \
  dbus-x11 \
  elogind \
  elogind-openrc \
  polkit-elogind \
  polkit-openrc \
  polkit-kde-agent-1 \
  udisks2 \
  udisks2-openrc \
  solid \
  dosfstools \
  ntfs-3g \
  exfatprogs \
  gvfs \
  gvfs-fuse \
  plasma-disks \
  upower \
  bluez \
  bluez-openrc \
  networkmanager \
  networkmanager-openrc \
  networkmanager-cli \
  networkmanager-wifi \
  wpa_supplicant \
  pipewire \
  pipewire-pulse \
  pipewire-alsa \
  wireplumber \
  open-vm-tools \
  open-vm-tools-gtk \
  virtualbox-guest-additions \
  virtualbox-guest-additions-openrc \
  virtualbox-guest-additions-udev \
  virtualbox-guest-additions-x11 \
  xvfb \
  xclip \
  xrandr \
  mesa-dri-gallium \
  mesa-egl \
  mesa-gbm \
  mesa-gles \
  mesa-vulkan-swrast \
  xorg-server \
  xwayland \
  xcb-util-cursor \
  xf86-video-modesetting \
  xf86-video-fbdev \
  xf86-video-vesa \
  xf86-input-libinput \
  sddm \
  sddm-openrc \
  sddm-kcm \
  plasma-desktop \
  plasma-workspace \
  kwin \
  kscreen \
  kscreenlocker \
  kglobalacceld \
  milou \
  layer-shell-qt \
  plasma-activities-stats \
  plasma-nm \
  plasma-pa \
  plasma-systemmonitor \
  plasma-browser-integration \
  plasma-integration \
  xdg-desktop-portal \
  xdg-desktop-portal-kde \
  xdg-desktop-portal-gtk \
  kde-gtk-config \
  breeze \
  breeze-gtk \
  breeze-icons \
  kvantum \
  powerdevil \
  bluedevil \
  kinfocenter \
  kwallet-pam \
  kdialog \
  qt6-qtsvg \
  qt6-qtimageformats \
  qt6-qtwayland \
  dolphin \
  kio-extras \
  ffmpegthumbs \
  kdegraphics-thumbnailers \
  konsole \
  kate \
  kwrite \
  spectacle \
  gwenview \
  okular \
  kcalc \
  kclock \
  ark \
  elisa \
  gparted \
  firefox \
  libreoffice-writer \
  libreoffice-calc \
  libreoffice-impress \
  libreoffice-kf6 \
  vlc \
  vlc-qt \
  gimp \
  wine \
  flatpak \
  discover \
  discover-backend-flatpak \
  font-inter \
  font-noto \
  font-noto-emoji \
  font-jetbrains-mono-nerd \
  font-dejavu \
  nodejs

# Verify Node.js 24 + built-in node:sqlite inside target rootfs
chroot "${ROOTFS}" /usr/bin/node -v
chroot "${ROOTFS}" /usr/bin/node -e "import('node:sqlite').then(m => { const d = new m.DatabaseSync(':memory:'); d.exec('SELECT 1'); console.log('RootFS node:sqlite verified'); })"

echo "[3/8] Installing OmniOS runtime payload, OS identity & bespoke Liquid Glass assets..."
mkdir -p \
  "${ROOTFS}/opt/omnios" \
  "${ROOTFS}/var/lib/omnios/data" \
  "${ROOTFS}/var/log" \
  "${ROOTFS}/usr/share/wallpapers/OmniOS-NextGen-Dark/contents/images" \
  "${ROOTFS}/usr/share/wallpapers/OmniOS-NextGen-Light/contents/images" \
  "${ROOTFS}/usr/share/icons/hicolor/scalable/apps" \
  "${ROOTFS}/usr/share/pixmaps"

for item in os ui packages sdk package.json README.md; do
  if [ -e "/src/${item}" ]; then
    cp -a "/src/${item}" "${ROOTFS}/opt/omnios/"
  fi
done
rm -rf "${ROOTFS}/opt/omnios/data"

# Bespoke OmniOS v2 Liquid Glass Wallpapers
cp -a "/src/ui/assets/wallpaper-dark.jpg" "${ROOTFS}/usr/share/wallpapers/OmniOS-NextGen-Dark/contents/images/1920x1080.jpg"
cp -a "/src/ui/assets/wallpaper-light.jpg" "${ROOTFS}/usr/share/wallpapers/OmniOS-NextGen-Light/contents/images/1920x1080.jpg"

cat > "${ROOTFS}/usr/share/wallpapers/OmniOS-NextGen-Dark/metadata.json" <<'EOF'
{
  "KPlugin": {
    "Authors": [{ "Name": "OmniOS Design Studio" }],
    "Id": "OmniOS-NextGen-Dark",
    "License": "MIT",
    "Name": "OmniOS Liquid Glass Dark"
  }
}
EOF

cat > "${ROOTFS}/usr/share/wallpapers/OmniOS-NextGen-Light/metadata.json" <<'EOF'
{
  "KPlugin": {
    "Authors": [{ "Name": "OmniOS Design Studio" }],
    "Id": "OmniOS-NextGen-Light",
    "License": "MIT",
    "Name": "OmniOS Silk Glass Light"
  }
}
EOF

# Custom OmniOS v2 Orb Emblem SVG (launcher, dock, SDDM, About)
cat > "${ROOTFS}/usr/share/icons/hicolor/scalable/apps/omnios-logo.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" fill="none">
  <defs>
    <linearGradient id="bg" x1="12" y1="8" x2="116" y2="120" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#0b182e"/>
      <stop offset="55%" stop-color="#0d2b4e"/>
      <stop offset="100%" stop-color="#091526"/>
    </linearGradient>
    <linearGradient id="ring1" x1="18" y1="18" x2="110" y2="110" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#38bdf8"/>
      <stop offset="50%" stop-color="#0ea5e9"/>
      <stop offset="100%" stop-color="#22d3ee"/>
    </linearGradient>
    <linearGradient id="ring2" x1="110" y1="22" x2="22" y2="106" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#fbbf24"/>
      <stop offset="55%" stop-color="#38bdf8"/>
      <stop offset="100%" stop-color="#34d399"/>
    </linearGradient>
  </defs>
  <rect x="6" y="6" width="116" height="116" rx="28" fill="url(#bg)" stroke="rgba(255,255,255,0.22)" stroke-width="2.5"/>
  <circle cx="64" cy="64" r="36" stroke="url(#ring1)" stroke-width="10" stroke-linecap="round"/>
  <path d="M64 28 A36 36 0 0 1 100 64" stroke="url(#ring2)" stroke-width="10" stroke-linecap="round"/>
  <circle cx="64" cy="64" r="13" fill="#f8fafc"/>
  <circle cx="64" cy="64" r="6" fill="#0ea5e9"/>
</svg>
EOF
cp -a "${ROOTFS}/usr/share/icons/hicolor/scalable/apps/omnios-logo.svg" "${ROOTFS}/usr/share/pixmaps/omnios-logo.svg"

# OS identity (/etc/os-release)
cat > "${ROOTFS}/etc/os-release" <<'EOF'
NAME="OmniOS"
ID=omnios
ID_LIKE=alpine
VERSION_ID=2.1
PRETTY_NAME="OmniOS 2.1 NextGen Pro"
ANSI_COLOR="0;36"
HOME_URL="https://github.com/proloybusiness-cloud/antigravity"
LOGO=omnios-logo
EOF

echo "[4/8] Installing & customizing real open-source next-gen themes (MacTahoe + Fluent 12 + WhiteSur Cursors)..."
fetch_theme() {
  repo="$1"
  name="${repo#*/}"
  if [ -d "/themes-cache/${name}" ]; then
    cp -a "/themes-cache/${name}" "${THEMES_SRC}/${name}"
  else
    git clone --depth=1 -q "https://github.com/${repo}.git" "${THEMES_SRC}/${name}"
  fi
}

fetch_theme vinceliuice/MacTahoe-kde
fetch_theme vinceliuice/Fluent-kde
fetch_theme vinceliuice/MacTahoe-icon-theme
fetch_theme vinceliuice/MacTahoe-gtk-theme
fetch_theme vinceliuice/WhiteSur-cursors

mkdir -p \
  "${ROOTFS}/usr/share/color-schemes" \
  "${ROOTFS}/usr/share/plasma/desktoptheme" \
  "${ROOTFS}/usr/share/plasma/layout-templates" \
  "${ROOTFS}/usr/share/plasma/look-and-feel" \
  "${ROOTFS}/usr/share/aurorae/themes" \
  "${ROOTFS}/usr/share/Kvantum" \
  "${ROOTFS}/usr/share/sddm/themes" \
  "${ROOTFS}/usr/share/icons" \
  "${ROOTFS}/usr/share/themes"

# 4a. Install MacTahoe KDE (Plasma 6 Liquid Glass Dark & Light)
bash "${THEMES_SRC}/MacTahoe-kde/install.sh" -d "${ROOTFS}/usr"

# 4b. Install Fluent KDE (Windows 12 Acrylic Dark) — assemble Fluent-round-dark cleanly
cp -a "${THEMES_SRC}/Fluent-kde/color-schemes/FluentDark.colors" "${ROOTFS}/usr/share/color-schemes/"
cp -a "${THEMES_SRC}/Fluent-kde/color-schemes/FluentLight.colors" "${ROOTFS}/usr/share/color-schemes/"
mkdir -p "${ROOTFS}/usr/share/plasma/desktoptheme/Fluent-round-dark"
cp -a "${THEMES_SRC}/Fluent-kde/plasma/desktoptheme/Fluent-round"/* "${ROOTFS}/usr/share/plasma/desktoptheme/Fluent-round-dark/"
cp -a "${THEMES_SRC}/Fluent-kde/color-schemes/FluentDark.colors" "${ROOTFS}/usr/share/plasma/desktoptheme/Fluent-round-dark/colors"
sed -i 's|Name=Fluent-round|Name=Fluent-round-dark|' "${ROOTFS}/usr/share/plasma/desktoptheme/Fluent-round-dark/metadata.desktop" 2>/dev/null || true
cat > "${ROOTFS}/usr/share/plasma/desktoptheme/Fluent-round-dark/metadata.json" <<'EOF'
{
  "KPlugin": {
    "Authors": [{ "Name": "Vince Liuice" }],
    "Category": "Plasma 6.0 theme",
    "Description": "Fluent round dark Plasma 6 theme",
    "EnabledByDefault": true,
    "Id": "Fluent-round-dark",
    "License": "GPL-3.0",
    "Name": "Fluent-round-dark",
    "Version": "2.0"
  },
  "X-Plasma-API": "5.0"
}
EOF
cp -a "${THEMES_SRC}/Fluent-kde/Kvantum/Fluent-round" "${ROOTFS}/usr/share/Kvantum/"
if [ -d "${THEMES_SRC}/Fluent-kde/aurorae/Fluent-round-dark" ]; then
  mkdir -p "${ROOTFS}/usr/share/aurorae/themes/Fluent-round-dark"
  cp -a "${THEMES_SRC}/Fluent-kde/aurorae/Fluent-round-dark"/* "${ROOTFS}/usr/share/aurorae/themes/Fluent-round-dark/"
  cat > "${ROOTFS}/usr/share/aurorae/themes/Fluent-round-dark/metadata.json" <<'EOF'
{
  "KPackageStructure": "aurorae",
  "KPlugin": {
    "Authors": [{ "Name": "Vince Liuice" }],
    "Category": "Plasma 6 Window Decorations",
    "Description": "Fluent-round-dark window decorations",
    "EnabledByDefault": true,
    "Id": "Fluent-round-dark",
    "License": "GPL_V3",
    "Name": "Fluent-round-dark",
    "ServiceTypes": ["aurorae"],
    "Version": "2.0"
  }
}
EOF
fi

# 4c. Install MacTahoe Icon Theme (glossy squircle icons: MacTahoe, MacTahoe-dark, MacTahoe-light) & WhiteSur Cursors
bash "${THEMES_SRC}/MacTahoe-icon-theme/install.sh" -d "${ROOTFS}/usr/share/icons" -t default
cp -a "${THEMES_SRC}/WhiteSur-cursors/dist" "${ROOTFS}/usr/share/icons/WhiteSur-cursors"

# 4d. Install Pre-Built MacTahoe GTK Theme (Dark & Light for Firefox, GIMP, GParted)
tar -xJf "${THEMES_SRC}/MacTahoe-gtk-theme/release/MacTahoe-Dark.tar.xz" -C "${ROOTFS}/usr/share/themes/"
tar -xJf "${THEMES_SRC}/MacTahoe-gtk-theme/release/MacTahoe-Light.tar.xz" -C "${ROOTFS}/usr/share/themes/"
ls -la "${ROOTFS}/usr/share/themes" "${ROOTFS}/usr/share/icons" | head -n 40

# 4e. Build custom branded SDDM Glass Login Theme ("OmniOS-Glass") based on MacTahoe-6.0
cp -a "${THEMES_SRC}/MacTahoe-kde/sddm/MacTahoe-6.0" "${ROOTFS}/usr/share/sddm/themes/OmniOS-Glass"
cp -a "/src/ui/assets/wallpaper-dark.jpg" "${ROOTFS}/usr/share/sddm/themes/OmniOS-Glass/Background.jpeg"
cp -a "/src/ui/assets/wallpaper-dark.jpg" "${ROOTFS}/usr/share/sddm/themes/OmniOS-Glass/Preview.jpeg"
cp -a "${ROOTFS}/usr/share/icons/hicolor/scalable/apps/omnios-logo.svg" "${ROOTFS}/usr/share/sddm/themes/OmniOS-Glass/default-logo.svg"
sed -i 's/^Name=.*/Name=OmniOS Glass/' "${ROOTFS}/usr/share/sddm/themes/OmniOS-Glass/metadata.desktop"
sed -i 's/^Theme-Id=.*/Theme-Id=OmniOS-Glass/' "${ROOTFS}/usr/share/sddm/themes/OmniOS-Glass/metadata.desktop"
sed -i 's/^background=.*/background=Background.jpeg/' "${ROOTFS}/usr/share/sddm/themes/OmniOS-Glass/theme.conf" 2>/dev/null || true

# 4f. Create 3 Custom Modified OmniOS v2 Plasma 6 Global Themes:
#     1) org.omnios.liquidglass.dark  (Default — macOS 29 + Windows 12 Liquid Glass Fusion)
#     2) org.omnios.fluent12.dark     (Windows 12 Centered Floating Fluent Taskbar)
#     3) org.omnios.liquidglass.light (Silk Glass Light Mode)

# --- Theme 1: OmniOS Liquid Glass Dark (Default) ---
LG_DARK="${ROOTFS}/usr/share/plasma/look-and-feel/org.omnios.liquidglass.dark"
cp -a "${ROOTFS}/usr/share/plasma/look-and-feel/com.github.vinceliuice.MacTahoe-Dark" "${LG_DARK}"
mkdir -p "${LG_DARK}/contents/splash/images"
cp -a "/src/ui/assets/wallpaper-dark.jpg" "${LG_DARK}/contents/splash/images/background.jpeg"
cp -a "${ROOTFS}/usr/share/icons/hicolor/scalable/apps/omnios-logo.svg" "${LG_DARK}/contents/splash/images/logo.svg"
cat > "${LG_DARK}/metadata.json" <<'EOF'
{
  "KPackageStructure": "Plasma/LookAndFeel",
  "KPlugin": {
    "Authors": [{ "Name": "OmniOS Design Studio (based on MacTahoe by vinceliuice)" }],
    "Category": "Global Themes (Plasma 6)",
    "Description": "OmniOS 2.1 Flagship Liquid Glass Dark — Floating top glass bar, centered clock, translucent pill dock & Kvantum frosted windows.",
    "Id": "org.omnios.liquidglass.dark",
    "License": "GPLv3",
    "Name": "OmniOS Liquid Glass Dark",
    "Version": "2.1"
  }
}
EOF
rm -f "${LG_DARK}/metadata.desktop"

cat > "${LG_DARK}/contents/defaults" <<'EOF'
[kcminputrc][Mouse]
cursorTheme=WhiteSur-cursors

[kdeglobals][General]
ColorScheme=MacTahoeDark
font=Inter,10,-1,5,400,0,0,0,0,0
fixed=JetBrainsMono Nerd Font,10,-1,5,400,0,0,0,0,0
smallestReadableFont=Inter,8,-1,5,400,0,0,0,0,0
toolBarFont=Inter,10,-1,5,400,0,0,0,0,0
menuFont=Inter,10,-1,5,400,0,0,0,0,0

[kdeglobals][Icons]
Theme=MacTahoe-dark

[kdeglobals][KDE]
LookAndFeelPackage=org.omnios.liquidglass.dark
widgetStyle=kvantum-dark

[kwinrc][DesktopSwitcher]
LayoutName=org.kde.breeze.desktop

[kwinrc][WindowSwitcher]
LayoutName=org.kde.breeze.desktop

[kwinrc][org.kde.kdecoration2]
BorderSize=None
ButtonsOnLeft=XAI
ButtonsOnRight=
library=org.kde.kwin.aurorae
theme=__aurorae__svg__MacTahoe-Dark

[plasmarc][Theme]
name=MacTahoe-Dark

[Wallpaper]
Image=OmniOS-NextGen-Dark
defaultWallpaperTheme=OmniOS-NextGen-Dark
defaultFileSuffix=.jpg
defaultWidth=1920
defaultHeight=1080
EOF

mkdir -p "${LG_DARK}/contents/layouts"
cat > "${LG_DARK}/contents/layouts/org.kde.plasma.desktop-layout.js" <<'EOF'
// OmniOS 2.1 NextGen Pro — Liquid Glass Fusion Layout (macOS 29 + Windows 12)
var allDesktops = desktops();
for (var i = 0; i < allDesktops.length; i++) {
    var d = allDesktops[i];
    d.wallpaperPlugin = "org.kde.image";
    d.currentConfigGroup = ["Wallpaper", "org.kde.image", "General"];
    d.writeConfig("Image", "file:///usr/share/wallpapers/OmniOS-NextGen-Dark/contents/images/1920x1080.jpg");
    d.writeConfig("FillMode", 2);
}

// 1. Floating Translucent Top Menu & Control Bar
var topPanel = new Panel;
topPanel.location = "top";
topPanel.height = 34;
topPanel.floating = true;

var launcher = topPanel.addWidget("org.kde.plasma.kickoff");
launcher.currentConfigGroup = ["General"];
launcher.writeConfig("icon", "omnios-logo");
launcher.writeConfig("favoritesPortedToKAstats", "true");
launcher.writeConfig("favorites", [
    "omnios-hub.desktop",
    "org.kde.dolphin.desktop",
    "firefox.desktop",
    "libreoffice-writer.desktop",
    "libreoffice-calc.desktop",
    "vlc.desktop",
    "gimp.desktop",
    "org.kde.kate.desktop",
    "org.kde.konsole.desktop",
    "org.kde.plasma-systemmonitor.desktop",
    "org.kde.discover.desktop",
    "omnios-appearance.desktop",
    "systemsettings.desktop"
]);
launcher.currentConfigGroup = ["Shortcuts"];
launcher.writeConfig("global", "Alt+F1");

topPanel.addWidget("org.kde.plasma.appmenu");
topPanel.addWidget("org.kde.plasma.panelspacer");

var clock = topPanel.addWidget("org.kde.plasma.digitalclock");
clock.currentConfigGroup = ["Appearance"];
clock.writeConfig("showDate", true);
clock.writeConfig("dateDisplayFormat", "BesideTime");
clock.writeConfig("autoFontAndSize", false);
clock.writeConfig("fontFamily", "Inter");
clock.writeConfig("fontWeight", 600);
clock.writeConfig("fontSize", 10);

topPanel.addWidget("org.kde.plasma.panelspacer");
topPanel.addWidget("org.kde.plasma.systemtray");
topPanel.addWidget("org.kde.plasma.marginsseparator");
topPanel.addWidget("org.kde.plasma.showdesktop");

// 2. Floating Glass Pill Dock (Bottom — Dodge Windows, Fit Content)
var dock = new Panel;
dock.location = "bottom";
dock.lengthMode = "fit";
dock.floating = true;
dock.hiding = "dodgewindows";
dock.height = 58;

var tasks = dock.addWidget("org.kde.plasma.icontasks");
tasks.currentConfigGroup = ["General"];
tasks.writeConfig("launchers", [
    "applications:omnios-hub.desktop",
    "applications:org.kde.dolphin.desktop",
    "applications:firefox.desktop",
    "applications:libreoffice-writer.desktop",
    "applications:libreoffice-calc.desktop",
    "applications:vlc.desktop",
    "applications:gimp.desktop",
    "applications:org.kde.kate.desktop",
    "applications:org.kde.konsole.desktop",
    "applications:org.kde.plasma-systemmonitor.desktop",
    "applications:org.kde.discover.desktop",
    "applications:omnios-appearance.desktop",
    "applications:systemsettings.desktop"
]);
tasks.writeConfig("indicateAudioStreams", true);
tasks.writeConfig("maxStripes", 1);
EOF

# --- Theme 2: OmniOS Windows 12 Fluent Dark ---
FL_DARK="${ROOTFS}/usr/share/plasma/look-and-feel/org.omnios.fluent12.dark"
cp -a "${LG_DARK}" "${FL_DARK}"
mkdir -p "${FL_DARK}/contents/splash/images"
cp -a "/src/ui/assets/wallpaper-dark.jpg" "${FL_DARK}/contents/splash/images/background.jpeg"
cp -a "${ROOTFS}/usr/share/icons/hicolor/scalable/apps/omnios-logo.svg" "${FL_DARK}/contents/splash/images/logo.svg"
cat > "${FL_DARK}/metadata.json" <<'EOF'
{
  "KPackageStructure": "Plasma/LookAndFeel",
  "KPlugin": {
    "Authors": [{ "Name": "OmniOS Design Studio (based on Fluent by vinceliuice)" }],
    "Category": "Global Themes (Plasma 6)",
    "Description": "OmniOS Windows 12 Fluent Acrylic — Centered floating taskbar, Fluent rounded glass windows & right-aligned window controls.",
    "Id": "org.omnios.fluent12.dark",
    "License": "GPLv3",
    "Name": "OmniOS Windows 12 Fluent",
    "Version": "2.1"
  }
}
EOF
cat > "${FL_DARK}/contents/defaults" <<'EOF'
[kcminputrc][Mouse]
cursorTheme=WhiteSur-cursors

[kdeglobals][General]
ColorScheme=FluentDark
font=Inter,10,-1,5,400,0,0,0,0,0
fixed=JetBrainsMono Nerd Font,10,-1,5,400,0,0,0,0,0

[kdeglobals][Icons]
Theme=MacTahoe-dark

[kdeglobals][KDE]
LookAndFeelPackage=org.omnios.fluent12.dark
widgetStyle=kvantum-dark

[kwinrc][org.kde.kdecoration2]
BorderSize=None
ButtonsOnLeft=
ButtonsOnRight=IAX
library=org.kde.kwin.aurorae
theme=__aurorae__svg__Fluent-round-dark

[plasmarc][Theme]
name=Fluent-round-dark

[Wallpaper]
Image=OmniOS-NextGen-Dark
defaultWallpaperTheme=OmniOS-NextGen-Dark
defaultFileSuffix=.jpg
defaultWidth=1920
defaultHeight=1080
EOF
cat > "${FL_DARK}/contents/layouts/org.kde.plasma.desktop-layout.js" <<'EOF'
// OmniOS 2.1 — Windows 12 Fluent Floating Taskbar Layout
var allDesktops = desktops();
for (var i = 0; i < allDesktops.length; i++) {
    var d = allDesktops[i];
    d.wallpaperPlugin = "org.kde.image";
    d.currentConfigGroup = ["Wallpaper", "org.kde.image", "General"];
    d.writeConfig("Image", "file:///usr/share/wallpapers/OmniOS-NextGen-Dark/contents/images/1920x1080.jpg");
    d.writeConfig("FillMode", 2);
}

var taskbar = new Panel;
taskbar.location = "bottom";
taskbar.floating = true;
taskbar.height = 48;

taskbar.addWidget("org.kde.plasma.panelspacer");

var startBtn = taskbar.addWidget("org.kde.plasma.kickoff");
startBtn.currentConfigGroup = ["General"];
startBtn.writeConfig("icon", "omnios-logo");
startBtn.currentConfigGroup = ["Shortcuts"];
startBtn.writeConfig("global", "Alt+F1");

var tasks = taskbar.addWidget("org.kde.plasma.icontasks");
tasks.currentConfigGroup = ["General"];
tasks.writeConfig("launchers", [
    "applications:omnios-hub.desktop",
    "applications:org.kde.dolphin.desktop",
    "applications:firefox.desktop",
    "applications:libreoffice-writer.desktop",
    "applications:vlc.desktop",
    "applications:gimp.desktop",
    "applications:org.kde.kate.desktop",
    "applications:org.kde.konsole.desktop",
    "applications:org.kde.discover.desktop",
    "applications:omnios-appearance.desktop",
    "applications:systemsettings.desktop"
]);

taskbar.addWidget("org.kde.plasma.panelspacer");
taskbar.addWidget("org.kde.plasma.systemtray");
var clock = taskbar.addWidget("org.kde.plasma.digitalclock");
clock.currentConfigGroup = ["Appearance"];
clock.writeConfig("showDate", true);
taskbar.addWidget("org.kde.plasma.showdesktop");
EOF

# --- Theme 3: OmniOS Silk Glass Light (macOS 29 Light) ---
LG_LIGHT="${ROOTFS}/usr/share/plasma/look-and-feel/org.omnios.liquidglass.light"
cp -a "${LG_DARK}" "${LG_LIGHT}"
mkdir -p "${LG_LIGHT}/contents/splash/images"
cp -a "/src/ui/assets/wallpaper-light.jpg" "${LG_LIGHT}/contents/splash/images/background.jpeg"
cp -a "${ROOTFS}/usr/share/icons/hicolor/scalable/apps/omnios-logo.svg" "${LG_LIGHT}/contents/splash/images/logo.svg"
cat > "${LG_LIGHT}/metadata.json" <<'EOF'
{
  "KPackageStructure": "Plasma/LookAndFeel",
  "KPlugin": {
    "Authors": [{ "Name": "OmniOS Design Studio (based on MacTahoe by vinceliuice)" }],
    "Category": "Global Themes (Plasma 6)",
    "Description": "OmniOS 2.1 Silk Glass Light — Bright alabaster frosted glass, floating top bar & liquid glass dock.",
    "Id": "org.omnios.liquidglass.light",
    "License": "GPLv3",
    "Name": "OmniOS Silk Glass Light",
    "Version": "2.1"
  }
}
EOF
cat > "${LG_LIGHT}/contents/defaults" <<'EOF'
[kcminputrc][Mouse]
cursorTheme=WhiteSur-cursors

[kdeglobals][General]
ColorScheme=MacTahoeLight
font=Inter,10,-1,5,400,0,0,0,0,0
fixed=JetBrainsMono Nerd Font,10,-1,5,400,0,0,0,0,0

[kdeglobals][Icons]
Theme=MacTahoe-light

[kdeglobals][KDE]
LookAndFeelPackage=org.omnios.liquidglass.light
widgetStyle=kvantum

[kwinrc][org.kde.kdecoration2]
BorderSize=None
ButtonsOnLeft=XAI
ButtonsOnRight=
library=org.kde.kwin.aurorae
theme=__aurorae__svg__MacTahoe-Light

[plasmarc][Theme]
name=MacTahoe-Light

[Wallpaper]
Image=OmniOS-NextGen-Light
defaultWallpaperTheme=OmniOS-NextGen-Light
defaultFileSuffix=.jpg
defaultWidth=1920
defaultHeight=1080
EOF
sed -i 's/OmniOS-NextGen-Dark/OmniOS-NextGen-Light/g' "${LG_LIGHT}/contents/layouts/org.kde.plasma.desktop-layout.js"

# Normalize ownership & permissions across all system runtime and theme asset directories
chown -R root:root \
  "${ROOTFS}/opt/omnios" \
  "${ROOTFS}/usr/share/themes" \
  "${ROOTFS}/usr/share/icons" \
  "${ROOTFS}/usr/share/plasma" \
  "${ROOTFS}/usr/share/sddm" \
  "${ROOTFS}/usr/share/Kvantum" \
  "${ROOTFS}/usr/share/aurorae" \
  "${ROOTFS}/usr/share/color-schemes" \
  "${ROOTFS}/usr/share/wallpapers"
chmod -R a+rX \
  "${ROOTFS}/usr/share/themes" \
  "${ROOTFS}/usr/share/icons" \
  "${ROOTFS}/usr/share/sddm/themes/OmniOS-Glass"

# Rebuild hicolor icon cache AFTER installing omnios-logo.svg and themes
chroot "${ROOTFS}" /usr/bin/gtk-update-icon-cache -f -t /usr/share/icons/hicolor

echo "[5/8] Configuring users, PAM/SDDM, Plasma 6 defaults, Zsh/Fastfetch, Firefox, Flatpak & OpenRC services..."

echo "omnios" > "${ROOTFS}/etc/hostname"
cat > "${ROOTFS}/etc/hosts" <<'EOF'
127.0.0.1   localhost omnios
::1         localhost omnios
EOF

cat > "${ROOTFS}/etc/fstab" <<'EOF'
tmpfs   /tmp        tmpfs   defaults,nosuid,nodev   0 0
EOF

cat > "${ROOTFS}/etc/modules" <<'EOF'
evdev
fuse
sr_mod
cdrom
isofs
udf
usb-storage
uas
EOF

mkdir -p "${ROOTFS}/etc/network"
cat > "${ROOTFS}/etc/network/interfaces" <<'EOF'
auto lo
iface lo inet loopback
EOF

# Ensure /bin/zsh is in /etc/shells (required by pam_shells.so in sddm-autologin)
grep -qxF "/bin/zsh" "${ROOTFS}/etc/shells" 2>/dev/null || echo "/bin/zsh" >> "${ROOTFS}/etc/shells"
grep -qxF "/bin/bash" "${ROOTFS}/etc/shells" 2>/dev/null || echo "/bin/bash" >> "${ROOTFS}/etc/shells"

# Create desktop user 'omnios' (password: omnios) with passwordless sudo & full hardware/NM/audio/storage/VBox groups
chroot "${ROOTFS}" /bin/sh -c '
  adduser -D -s /bin/zsh -G users omnios
  for grp in wheel video render input audio tty plugdev netdev cdrom lp storage disk vboxsf vboxdrmipc; do
    addgroup "$grp" 2>/dev/null || true
    addgroup omnios "$grp" 2>/dev/null || true
  done
  echo "root:omnios" | chpasswd
  echo "omnios:omnios" | chpasswd
'

# VirtualBox Guest Additions Alpine path fix, /media mount root & non-VirtualBox autostart hygiene
ln -sf /usr/sbin/VBoxDRMClient "${ROOTFS}/usr/bin/VBoxDRMClient"
mkdir -p "${ROOTFS}/media" "${ROOTFS}/etc/xdg/autostart"
chmod 0755 "${ROOTFS}/media"
cat > "${ROOTFS}/etc/xdg/autostart/vboxclient.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=vboxclient
Hidden=true
EOF
chmod 0644 "${ROOTFS}/etc/xdg/autostart/vboxclient.desktop"

# udev rules for live optical discs & USB removable media (hide live boot ISO; auto-mount all other optical/USB media)
mkdir -p "${ROOTFS}/etc/udev/rules.d"
cat > "${ROOTFS}/etc/udev/rules.d/99-omnios-media.rules" <<'EOF'
# Hide the live boot medium from accidental eject/Desktop clutter (matches both v2.0 and v2.1 volids)
SUBSYSTEM=="block", ENV{ID_FS_LABEL}=="OMNIOS_V2_PRO|OMNIOS_V21_PRO", ENV{UDISKS_IGNORE}="1", ENV{UDISKS_PRESENTATION_HIDE}="1"

# Ensure all other optical drives & USB storage are treated as auto-mountable removable media
SUBSYSTEM=="block", KERNEL=="sr[0-9]*", ENV{ID_FS_LABEL}!="OMNIOS_V2_PRO", ENV{ID_FS_LABEL}!="OMNIOS_V21_PRO", ENV{UDISKS_AUTO}="1", ENV{UDISKS_SYSTEM}="0"
SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{ID_FS_USAGE}=="filesystem", ENV{UDISKS_AUTO}="1", ENV{UDISKS_SYSTEM}="0"
EOF
chmod 0644 "${ROOTFS}/etc/udev/rules.d/99-omnios-media.rules"

# Polkit rule allowing omnios / wheel / plugdev / storage / cdrom passwordless optical & removable media mount/eject
mkdir -p "${ROOTFS}/etc/polkit-1/rules.d"
cat > "${ROOTFS}/etc/polkit-1/rules.d/50-omnios-removable-media.rules" <<'EOF'
polkit.addRule(function(action, subject) {
    var allowed = [
        "org.freedesktop.udisks2.filesystem-mount",
        "org.freedesktop.udisks2.filesystem-mount-system",
        "org.freedesktop.udisks2.filesystem-mount-other-seat",
        "org.freedesktop.udisks2.filesystem-unmount-others",
        "org.freedesktop.udisks2.eject-media",
        "org.freedesktop.udisks2.eject-media-system",
        "org.freedesktop.udisks2.eject-media-other-seat",
        "org.freedesktop.udisks2.power-off-drive",
        "org.freedesktop.udisks2.power-off-drive-system",
        "org.freedesktop.udisks2.power-off-drive-other-seat",
        "org.freedesktop.udisks2.encrypted-unlock",
        "org.freedesktop.udisks2.encrypted-unlock-system",
        "org.freedesktop.udisks2.loop-setup"
    ];
    if (allowed.indexOf(action.id) >= 0 &&
        (subject.user === "omnios" ||
         subject.isInGroup("wheel") ||
         subject.isInGroup("plugdev") ||
         subject.isInGroup("storage") ||
         subject.isInGroup("cdrom"))) {
        return polkit.Result.YES;
    }
});
EOF
chroot "${ROOTFS}" /bin/sh -c '
  chown root:polkitd /etc/polkit-1/rules.d
  chmod 0750 /etc/polkit-1/rules.d
  chown root:root /etc/polkit-1/rules.d/50-omnios-removable-media.rules
  chmod 0644 /etc/polkit-1/rules.d/50-omnios-removable-media.rules
'

mkdir -p "${ROOTFS}/etc/sudoers.d"
echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > "${ROOTFS}/etc/sudoers.d/10-omnios"
chmod 0440 "${ROOTFS}/etc/sudoers.d/10-omnios"

# Configure NetworkManager cleanly
mkdir -p "${ROOTFS}/etc/NetworkManager/conf.d"
cat > "${ROOTFS}/etc/NetworkManager/conf.d/10-omnios.conf" <<'EOF'
[main]
dhcp=internal
plugins=keyfile

[ifupdown]
managed=true
EOF

# Configure SDDM with native Wayland DisplayServer, Auto-Login into Plasma 6 Wayland & OmniOS-Glass Theme
# Remove conflicting /etc/sddm.conf installed by sddm-breeze (higher precedence than /etc/sddm.conf.d/*)
rm -f "${ROOTFS}/etc/sddm.conf"
mkdir -p "${ROOTFS}/etc/sddm.conf.d"
cat > "${ROOTFS}/etc/sddm.conf.d/10-omnios.conf" <<'EOF'
[Autologin]
User=omnios
Session=plasma
Relogin=false

[General]
DisplayServer=wayland
GreeterEnvironment=QT_WAYLAND_SHELL_INTEGRATION=layer-shell
InputMethod=

[Wayland]
CompositorCommand=kwin_wayland --drm --no-lockscreen --no-global-shortcuts --locale1

[Theme]
Current=OmniOS-Glass
CursorTheme=WhiteSur-cursors
Font=Inter,10,-1,5,400,0,0,0,0,0

[Users]
MaximumUid=60513
MinimumUid=1000
EOF

# System-wide UTF-8 locale (read by pam_env.so and SDDM/sddm-helper via /etc/locale.conf)
cat > "${ROOTFS}/etc/environment" <<'EOF'
LANG=C.UTF-8
LC_ALL=C.UTF-8
CHARSET=UTF-8
EOF
chmod 0644 "${ROOTFS}/etc/environment"

cat > "${ROOTFS}/etc/locale.conf" <<'EOF'
LANG=C.UTF-8
LC_ALL=C.UTF-8
EOF
chmod 0644 "${ROOTFS}/etc/locale.conf"

# Raise D-Bus session activation timeout so Plasma services never time out under heavy/emulated boot load
if [ -f "${ROOTFS}/usr/share/dbus-1/session.conf" ]; then
  sed -i 's|<limit name="service_start_timeout">120000</limit>|<limit name="service_start_timeout">300000</limit>|' "${ROOTFS}/usr/share/dbus-1/session.conf"
fi

# Universal VM / No-3D GPU Wayland/Qt/GTK environment detection (never sets KWIN_DRM_NO_AMS=1)
mkdir -p "${ROOTFS}/etc/profile.d"
cat > "${ROOTFS}/etc/profile.d/omnios-desktop.sh" <<'EOF'
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export QT_QPA_PLATFORMTHEME=kde
export MOZ_ENABLE_WAYLAND=1
export GTK_USE_PORTAL=1
export XDG_CURRENT_DESKTOP=KDE

_DMI="$(cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/bios_vendor 2>/dev/null || true)"
_HAS_RENDER=0
for _rn in /dev/dri/renderD*; do
  [ -c "$_rn" ] && _HAS_RENDER=1 && break
done
_IS_VBOX_PCI=0
for _pci in /sys/bus/pci/devices/*; do
  [ -d "$_pci" ] && [ -r "$_pci/vendor" ] && [ -r "$_pci/device" ] || continue
  _v="$(cat "$_pci/vendor" 2>/dev/null || true)"
  _d="$(cat "$_pci/device" 2>/dev/null || true)"
  if [ "$_v" = "0x80ee" ] && { [ "$_d" = "0xcafe" ] || [ "$_d" = "0xbeef" ]; }; then
    _IS_VBOX_PCI=1
    break
  fi
done

# Software cursor fixes offset/invisible cursor on VirtualBox, VMware, and QEMU Wayland
if [ "$_IS_VBOX_PCI" -eq 1 ] || printf '%s' "$_DMI" | grep -qiE 'virtualbox|innotek|qemu|kvm|bochs|vmware'; then
  export KWIN_FORCE_SW_CURSOR=1
fi

# Force Mesa llvmpipe software GL + disable XWayland Glamor on:
#  - Safe Software Graphics (omnios.safe_gfx=1) or nomodeset
#  - Oracle VirtualBox (VMSVGA 3D OFF has no render node; VMSVGA 3D ON has Mesa 26/Wayland svga3d bugs; VBoxSVGA/VBoxVGA have no 3D)
#  - Any DRM device without a 3D render node (bochs, simpledrm, vmwgfx 3D OFF, vboxvideo)
# NOTE: NEVER set KWIN_DRM_NO_AMS=1 here — simpledrm requires DRM Atomic Modesetting!
if grep -qwE 'omnios\.safe_gfx=1|nomodeset' /proc/cmdline 2>/dev/null \
   || [ "$_IS_VBOX_PCI" -eq 1 ] \
   || printf '%s' "$_DMI" | grep -qiE 'virtualbox|innotek' \
   || [ "$_HAS_RENDER" -eq 0 ]; then
  export LIBGL_ALWAYS_SOFTWARE=1
  export KWIN_FORCE_SW_CURSOR=1
  export XWAYLAND_NO_GLAMOR=1
fi
unset _DMI _HAS_RENDER _rn _IS_VBOX_PCI _pci _v _d
EOF
chmod 0644 "${ROOTFS}/etc/profile.d/omnios-desktop.sh"

# Ensure /bin/zsh login shells (used by SDDM wayland-session) also source omnios-desktop.sh
mkdir -p "${ROOTFS}/etc/zsh"
cat > "${ROOTFS}/etc/zsh/zprofile" <<'EOF'
if [ -r /etc/profile.d/omnios-desktop.sh ]; then
  emulate sh -c '. /etc/profile.d/omnios-desktop.sh'
fi
EOF
chmod 0644 "${ROOTFS}/etc/zsh/zprofile"

# CLI wrapper & server wrapper
cat > "${ROOTFS}/usr/local/bin/omnios-cli" <<'EOF'
#!/bin/sh
exec /usr/bin/node /opt/omnios/os/cli/omnios-cli.mjs "$@"
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-cli"

cat > "${ROOTFS}/usr/local/bin/omnios-server" <<'EOF'
#!/bin/sh
set -eu
mkdir -p /var/lib/omnios/data /run
export OMNIOS_DATA_DIR="/var/lib/omnios/data"
export HOST="0.0.0.0"
export PORT="3777"
if grep -qw "omnios.mode=headless" /proc/cmdline 2>/dev/null; then
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

# One-Click OmniOS Appearance Switcher (macOS 29 Liquid Glass / Windows 12 Fluent / Silk Light)
cat > "${ROOTFS}/usr/local/bin/omnios-appearance" <<'EOF'
#!/bin/sh
CHOICE="${1:-}"
if [ -z "$CHOICE" ]; then
  CHOICE="$(kdialog --title "OmniOS 2.1 Appearance Studio" \
    --icon omnios-logo \
    --menu "Select your OmniOS NextGen Desktop Experience:" \
    "liquid-dark"  "OmniOS Liquid Glass Dark  (macOS 29 + Floating Dock)" \
    "fluent-12"    "OmniOS Windows 12 Fluent  (Centered Acrylic Taskbar)" \
    "silk-light"   "OmniOS Silk Glass Light   (Bright Liquid Glass)" 2>/dev/null || true)"
fi

case "$CHOICE" in
  liquid-dark)
    plasma-apply-lookandfeel --apply org.omnios.liquidglass.dark --resetLayout || true
    plasma-apply-wallpaperimage /usr/share/wallpapers/OmniOS-NextGen-Dark/contents/images/1920x1080.jpg || true
    mkdir -p "$HOME/.config/Kvantum" "$HOME/.config/gtk-3.0" "$HOME/.config/gtk-4.0"
    printf '[General]\ntheme=MacTahoeDark\n' > "$HOME/.config/Kvantum/kvantum.kvconfig"
    sed -i 's/^gtk-theme-name=.*/gtk-theme-name=MacTahoe-Dark/' "$HOME/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-4.0/settings.ini" 2>/dev/null || true
    sed -i 's/^gtk-icon-theme-name=.*/gtk-icon-theme-name=MacTahoe-dark/' "$HOME/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-4.0/settings.ini" 2>/dev/null || true
    sed -i 's/^gtk-application-prefer-dark-theme=.*/gtk-application-prefer-dark-theme=1/' "$HOME/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-4.0/settings.ini" 2>/dev/null || true
    ;;
  fluent-12)
    plasma-apply-lookandfeel --apply org.omnios.fluent12.dark --resetLayout || true
    plasma-apply-wallpaperimage /usr/share/wallpapers/OmniOS-NextGen-Dark/contents/images/1920x1080.jpg || true
    mkdir -p "$HOME/.config/Kvantum" "$HOME/.config/gtk-3.0" "$HOME/.config/gtk-4.0"
    printf '[General]\ntheme=Fluent-roundDark\n' > "$HOME/.config/Kvantum/kvantum.kvconfig"
    sed -i 's/^gtk-theme-name=.*/gtk-theme-name=MacTahoe-Dark/' "$HOME/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-4.0/settings.ini" 2>/dev/null || true
    sed -i 's/^gtk-icon-theme-name=.*/gtk-icon-theme-name=MacTahoe-dark/' "$HOME/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-4.0/settings.ini" 2>/dev/null || true
    sed -i 's/^gtk-application-prefer-dark-theme=.*/gtk-application-prefer-dark-theme=1/' "$HOME/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-4.0/settings.ini" 2>/dev/null || true
    ;;
  silk-light)
    plasma-apply-lookandfeel --apply org.omnios.liquidglass.light --resetLayout || true
    plasma-apply-wallpaperimage /usr/share/wallpapers/OmniOS-NextGen-Light/contents/images/1920x1080.jpg || true
    mkdir -p "$HOME/.config/Kvantum" "$HOME/.config/gtk-3.0" "$HOME/.config/gtk-4.0"
    printf '[General]\ntheme=MacTahoe\n' > "$HOME/.config/Kvantum/kvantum.kvconfig"
    sed -i 's/^gtk-theme-name=.*/gtk-theme-name=MacTahoe-Light/' "$HOME/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-4.0/settings.ini" 2>/dev/null || true
    sed -i 's/^gtk-icon-theme-name=.*/gtk-icon-theme-name=MacTahoe-light/' "$HOME/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-4.0/settings.ini" 2>/dev/null || true
    sed -i 's/^gtk-application-prefer-dark-theme=.*/gtk-application-prefer-dark-theme=0/' "$HOME/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-4.0/settings.ini" 2>/dev/null || true
    ;;
esac
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-appearance"

# Desktop launchers for OmniOS Hub & OmniOS Appearance Studio
cat > "${ROOTFS}/usr/share/applications/omnios-hub.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=OmniOS Hub
GenericName=Multi-Platform App Runtime & Kernel Studio
Comment=Run Android (.apk), Windows (.exe), macOS/iOS (.ipa/.app) & Universal (.uapp) apps inside OmniOS
Exec=/usr/bin/firefox --new-window http://127.0.0.1:3777/
Icon=omnios-logo
Terminal=false
Categories=System;Utility;Development;
StartupNotify=true
EOF

cat > "${ROOTFS}/usr/share/applications/omnios-appearance.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=OmniOS Theme Studio
GenericName=Switch Liquid Glass / Windows 12 Fluent / Silk Light
Comment=Switch instantly between OmniOS Liquid Glass (macOS 29), Windows 12 Fluent, and Silk Light themes
Exec=/usr/local/bin/omnios-appearance
Icon=preferences-desktop-theme
Terminal=false
Categories=Settings;DesktopSettings;
StartupNotify=true
EOF

# Firefox pre-configuration (OmniOS v2 homepage, bookmarks, zero first-run nags)
mkdir -p "${ROOTFS}/usr/lib/firefox/distribution"
cat > "${ROOTFS}/usr/lib/firefox/distribution/policies.json" <<'EOF'
{
  "policies": {
    "DisableTelemetry": true,
    "DisablePocket": true,
    "OverrideFirstRunPage": "",
    "OverridePostUpdatePage": "",
    "Homepage": {
      "URL": "http://127.0.0.1:3777/",
      "StartPage": "homepage"
    },
    "Bookmarks": [
      { "Title": "OmniOS Hub", "URL": "http://127.0.0.1:3777/", "Placement": "toolbar" },
      { "Title": "OmniOS Kernel Health", "URL": "http://127.0.0.1:3777/api/v1/kernel/status", "Placement": "toolbar" },
      { "Title": "Flathub App Store", "URL": "https://flathub.org/", "Placement": "toolbar" },
      { "Title": "GitHub", "URL": "https://github.com/proloybusiness-cloud/antigravity", "Placement": "toolbar" }
    ]
  }
}
EOF

# Pre-configure Flathub remote for Discover Software Center
mkdir -p "${ROOTFS}/var/lib/flatpak/repo"
chroot "${ROOTFS}" /bin/sh -c 'flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo 2>/dev/null || true'

# Custom Fastfetch OmniOS v2 Logo & Config
mkdir -p "${ROOTFS}/etc/fastfetch"
cat > "${ROOTFS}/etc/fastfetch/omnios-ascii.txt" <<'EOF'
$1         ▄▄▄▄▄▄▄▄▄▄▄▄
$1      ▄████████████████▄
$1    ▄████▀▀        ▀▀████▄
$2   ████▀   ▄▄████▄▄   ▀████
$2  ████   ▄██████████▄   ████
$2  ████   ████████████   ████
$3  ████   ▀██████████▀   ████
$3   ████▄   ▀▀████▀▀   ▄████
$3    ▀████▄▄        ▄▄████▀
$1      ▀████████████████▀
$1         ▀▀▀▀▀▀▀▀▀▀▀▀
EOF

cat > "${ROOTFS}/etc/fastfetch/config.jsonc" <<'EOF'
{
  "logo": {
    "source": "/etc/fastfetch/omnios-ascii.txt",
    "color": { "1": "cyan", "2": "blue", "3": "yellow" },
    "padding": { "top": 1, "left": 1, "right": 2 }
  },
  "modules": [
    "title",
    "separator",
    "os",
    "kernel",
    "uptime",
    "de",
    "wm",
    "theme",
    "icons",
    "terminal",
    "cpu",
    "gpu",
    "memory",
    "localip",
    "break",
    "colors"
  ]
}
EOF

# Pre-seed user 'omnios' home directory with polished Plasma 6, KWin, Kvantum, GTK, Konsole & Zsh configs
HOMEDIR="${ROOTFS}/home/omnios"
mkdir -p \
  "${HOMEDIR}/Desktop" \
  "${HOMEDIR}/Documents" \
  "${HOMEDIR}/Downloads" \
  "${HOMEDIR}/Pictures" \
  "${HOMEDIR}/Music" \
  "${HOMEDIR}/Videos" \
  "${HOMEDIR}/.config/Kvantum" \
  "${HOMEDIR}/.config/gtk-3.0" \
  "${HOMEDIR}/.config/gtk-4.0" \
  "${HOMEDIR}/.config/autostart" \
  "${HOMEDIR}/.config/plasma-workspace/env" \
  "${HOMEDIR}/.local/share/konsole"

# Sourced automatically by startplasma-wayland before launching kwin_wayland
mkdir -p "${ROOTFS}/etc/skel/.config/plasma-workspace/env" "${ROOTFS}/etc/skel/.config/autostart" "${ROOTFS}/etc/xdg"
cp -a "${ROOTFS}/etc/profile.d/omnios-desktop.sh" "${HOMEDIR}/.config/plasma-workspace/env/omnios-env.sh"
cp -a "${ROOTFS}/etc/profile.d/omnios-desktop.sh" "${ROOTFS}/etc/skel/.config/plasma-workspace/env/omnios-env.sh"
chmod 0755 \
  "${HOMEDIR}/.config/plasma-workspace/env/omnios-env.sh" \
  "${ROOTFS}/etc/skel/.config/plasma-workspace/env/omnios-env.sh"

# Pre-seed KDE Plasma 6 kded6 removable device automounter across user home, /etc/skel, and /etc/xdg
for cfgdir in "${HOMEDIR}/.config" "${ROOTFS}/etc/skel/.config" "${ROOTFS}/etc/xdg"; do
  mkdir -p "${cfgdir}"
  cat > "${cfgdir}/kded6rc" <<'EOF'
[Module-device_automounter]
autoload=true
EOF
  cat > "${cfgdir}/kded_device_automounterrc" <<'EOF'
[General]
AutomountEnabled=true
AutomountOnLogin=true
AutomountOnPlugin=true
AutomountUnknownDevices=true
EOF
done

# Copy welcome desktop shortcut for OmniOS Hub
cp -a "${ROOTFS}/usr/share/applications/omnios-hub.desktop" "${HOMEDIR}/Desktop/"
cp -a "${ROOTFS}/usr/share/applications/omnios-appearance.desktop" "${HOMEDIR}/Desktop/"
chmod +x "${HOMEDIR}/Desktop/"*.desktop

cat > "${HOMEDIR}/.config/kdeglobals" <<'EOF'
[General]
ColorScheme=MacTahoeDark
Name=MacTahoeDark
TerminalApplication=konsole
TerminalService=org.kde.konsole.desktop
font=Inter,10,-1,5,400,0,0,0,0,0
fixed=JetBrainsMono Nerd Font,10,-1,5,400,0,0,0,0,0
menuFont=Inter,10,-1,5,400,0,0,0,0,0
smallestReadableFont=Inter,8,-1,5,400,0,0,0,0,0
toolBarFont=Inter,10,-1,5,400,0,0,0,0,0

[Icons]
Theme=MacTahoe-dark

[KDE]
LookAndFeelPackage=org.omnios.liquidglass.dark
SingleClick=false
widgetStyle=kvantum-dark

[WM]
activeFont=Inter,10,-1,5,600,0,0,0,0,0
EOF

cat > "${HOMEDIR}/.config/plasmarc" <<'EOF'
[Theme]
name=MacTahoe-Dark
EOF

cat > "${HOMEDIR}/.config/kcminputrc" <<'EOF'
[Mouse]
cursorSize=24
cursorTheme=WhiteSur-cursors
EOF

cat > "${HOMEDIR}/.config/Kvantum/kvantum.kvconfig" <<'EOF'
[General]
theme=MacTahoeDark
EOF

cat > "${HOMEDIR}/.config/kwinrc" <<'EOF'
[Compositing]
GLCore=true
LatencyPolicy=Medium
WindowsBlockCompositing=false

[Desktops]
Number=2
Rows=1

[Effect-blur]
BlurStrength=12
NoiseStrength=2

[Effect-magiclamp]
AnimationDuration=220

[ModifierOnlyShortcuts]
Meta=org.kde.plasmashell,/PlasmaShell,org.kde.PlasmaShell,activateLauncherMenu

[Plugins]
blurEnabled=true
contrastEnabled=true
magiclampEnabled=true
overviewEnabled=true
scaleEnabled=true
slideEnabled=true

[Windows]
Placement=Centered

[org.kde.kdecoration2]
BorderSize=None
ButtonsOnLeft=XAI
ButtonsOnRight=
library=org.kde.kwin.aurorae
theme=__aurorae__svg__MacTahoe-Dark
EOF

cat > "${HOMEDIR}/.config/kscreenlockerrc" <<'EOF'
[Daemon]
Autolock=false
LockOnResume=false
Timeout=0

[Greeter][Wallpaper][org.kde.image][General]
Image=file:///usr/share/wallpapers/OmniOS-NextGen-Dark/contents/images/1920x1080.jpg
EOF

cat > "${HOMEDIR}/.config/powerdevilrc" <<'EOF'
[AC][Display]
DimDisplayWhenIdle=false
TurnOffDisplayWhenIdle=false

[AC][SuspendAndShutdown]
AutoSuspendAction=0

[Battery][Display]
DimDisplayWhenIdle=false
TurnOffDisplayWhenIdle=false

[Battery][SuspendAndShutdown]
AutoSuspendAction=0
EOF

cat > "${HOMEDIR}/.config/gtk-3.0/settings.ini" <<'EOF'
[Settings]
gtk-theme-name=MacTahoe-Dark
gtk-icon-theme-name=MacTahoe-dark
gtk-cursor-theme-name=WhiteSur-cursors
gtk-font-name=Inter 10
gtk-application-prefer-dark-theme=1
EOF
cp -a "${HOMEDIR}/.config/gtk-3.0/settings.ini" "${HOMEDIR}/.config/gtk-4.0/settings.ini"

# Translucent Blurred Konsole Profile
cat > "${HOMEDIR}/.local/share/konsole/OmniOS.colorscheme" <<'EOF'
[Background]
Color=10,16,28

[BackgroundIntense]
Color=18,27,44

[Foreground]
Color=241,245,249

[ForegroundIntense]
Color=255,255,255

[General]
Blur=true
ColorRandomization=false
Description=OmniOS Liquid Glass
Opacity=0.84
Wallpaper=
EOF

cat > "${HOMEDIR}/.local/share/konsole/OmniOS.profile" <<'EOF'
[Appearance]
ColorScheme=OmniOS
Font=JetBrainsMono Nerd Font,10.5,-1,5,400,0,0,0,0,0

[General]
Command=/bin/zsh
Name=OmniOS
Parent=FALLBACK/

[Scrolling]
HistorySize=10000
EOF

cat > "${HOMEDIR}/.config/konsolerc" <<'EOF'
[Desktop Entry]
DefaultProfile=OmniOS.profile

[MainWindow]
MenuBar=Disabled
ToolBarsMovable=Disabled
EOF

# Keep kactivitymanagerd fast & headless on D-Bus so plasmashell never times out waiting for ActivityManager
if [ -f "${ROOTFS}/usr/share/dbus-1/services/org.kde.ActivityManager.service" ]; then
  sed -i 's|^Exec=/usr/lib/libexec/kactivitymanagerd|Exec=/usr/bin/env QT_QPA_PLATFORM=offscreen /usr/lib/libexec/kactivitymanagerd|' \
    "${ROOTFS}/usr/share/dbus-1/services/org.kde.ActivityManager.service"
fi

cat > "${HOMEDIR}/.config/autostart/omnios-kactivity.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=OmniOS Activity Manager
Exec=/usr/bin/env QT_QPA_PLATFORM=offscreen /usr/lib/libexec/kactivitymanagerd
OnlyShowIn=KDE;
X-KDE-autostart-phase=0
EOF

# Mask heavy non-essential background autostart daemons on live boot (apps remain launchable from menu/dock)
for skip_autostart in \
  org.gnome.Evolution-alarm-notify.desktop \
  org.kde.discover.notifier.desktop \
  spectacle.desktop \
  org.kde.kclockd-autostart.desktop; do
  cat > "${HOMEDIR}/.config/autostart/${skip_autostart}" <<'EOF'
[Desktop Entry]
Hidden=true
EOF
done

# First-login preset applier (supports GRUB "Windows 12 Fluent Mode" boot parameter!)
cat > "${HOMEDIR}/.config/autostart/omnios-firstboot.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=OmniOS First Boot Session Setup
Exec=/usr/local/bin/omnios-session-init
OnlyShowIn=KDE;
X-KDE-autostart-phase=2
EOF

cat > "${ROOTFS}/usr/local/bin/omnios-session-init" <<'EOF'
#!/bin/sh
# Start VMware guest desktop agent only when running inside VMware Workstation
if [ -x /usr/bin/vmware-checkvm ] && /usr/bin/vmware-checkvm >/dev/null 2>&1 && command -v vmware-user >/dev/null 2>&1; then
  vmware-user >/dev/null 2>&1 &
fi

# Apply optional GRUB preset (e.g., omnios.preset=fluent12) once
FLAG="$HOME/.config/.omnios-preset-applied"
if [ ! -f "$FLAG" ]; then
  touch "$FLAG"
  if grep -qw "omnios.preset=fluent12" /proc/cmdline 2>/dev/null; then
    sleep 3
    /usr/local/bin/omnios-appearance fluent-12 >/dev/null 2>&1 || true
  fi
fi
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-session-init"

# VirtualBox User Session Integration (Wayland + X11, strictly guarded by /dev/vboxguest & /dev/vboxuser)
cat > "${ROOTFS}/etc/xdg/autostart/omnios-vbox-session.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=OmniOS VirtualBox Session Integration
Exec=/usr/local/bin/omnios-vbox-session
OnlyShowIn=KDE;
X-KDE-autostart-after=panel
EOF
chmod 0644 "${ROOTFS}/etc/xdg/autostart/omnios-vbox-session.desktop"

cat > "${ROOTFS}/usr/local/bin/omnios-vbox-session" <<'EOF'
#!/bin/sh
# OmniOS v2.1 VirtualBox User Session Integration (Wayland + X11)
[ -c /dev/vboxguest ] && [ -c /dev/vboxuser ] || exit 0
[ -z "${SSH_CONNECTION:-}" ] || exit 0

# Clean stale non-writable VBoxClient PID files
for f in "$HOME"/.vboxclient-*.pid; do
  [ -e "$f" ] && { [ -w "$f" ] || rm -f "$f"; }
done

# Wait up to 15s for X11/XWayland DISPLAY and wake lazy KWin XWayland socket
_w=0
while [ -z "${DISPLAY:-}" ] && [ "$_w" -lt 30 ]; do
  for sock in /tmp/.X11-unix/X*; do
    case "$(basename "$sock")" in
      X97|X98|X99) continue ;;
    esac
    if [ -S "$sock" ]; then
      DISPLAY=":$(basename "$sock" | sed 's/^X//')"
      export DISPLAY
      break
    fi
  done
  [ -n "${DISPLAY:-}" ] && break
  sleep 0.5
  _w=$((_w + 1))
done

if [ -n "${DISPLAY:-}" ]; then
  # Trigger KWin lazy XWayland launch & give Xwl::DataBridge time to bind CLIPBOARD
  xrandr --query >/dev/null 2>&1 || true
  xclip -o -selection clipboard >/dev/null 2>&1 || true
  sleep 1
fi

if [ "${XDG_SESSION_TYPE:-}" = "wayland" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
  # --- KDE Plasma 6.6 Wayland Mode ---
  # (a) Bidirectional Shared Clipboard: Host->Guest via VBoxClient on XWayland + Guest->Host via Klipper bridge
  if [ -n "${DISPLAY:-}" ]; then
    /usr/sbin/VBoxClient --clipboard >/dev/null 2>&1 || true
    /usr/local/bin/omnios-vbox-clipbridge >/dev/null 2>&1 &
  fi
  # (b) Host->Guest File & Folder Drag-and-Drop via isolated Xvfb :99 Xdnd receiver
  /usr/local/bin/omnios-vbox-dnd-bridge >/dev/null 2>&1 &
  # Note: Dynamic display resize on VMSVGA is handled by root VBoxDRMClient (OpenRC omnios-vbox),
  #       on VBoxSVGA/VBoxVGA natively by vboxvideo.ko, and Shared Folders by omnios-media-desktop-sync.
else
  # --- Pure X11 Session Mode ---
  /usr/sbin/VBoxClient --clipboard >/dev/null 2>&1 || true
  /usr/sbin/VBoxClient --draganddrop >/dev/null 2>&1 || true
  /usr/sbin/VBoxClient --seamless >/dev/null 2>&1 || true
  /usr/sbin/VBoxClient --vmsvga >/dev/null 2>&1 || true
fi
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-vbox-session"

# Klipper D-Bus <-> XWayland Bidirectional Clipboard Bridge (echo-loop-safe)
cat > "${ROOTFS}/usr/local/bin/omnios-vbox-clipbridge" <<'EOF'
#!/usr/bin/env python3
"""OmniOS v2.1 Klipper D-Bus <-> XWayland Clipboard Bridge for VirtualBox."""
import os
import signal
import subprocess
import sys
import time

if not os.environ.get("OMNIOS_CLIPBRIDGE_FORCE") and not os.path.exists("/dev/vboxguest"):
    sys.exit(0)
if not os.environ.get("DISPLAY"):
    sys.exit(0)

import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib


def main():
    try:
        DBusGMainLoop(set_as_default=True)
        bus = dbus.SessionBus()
    except Exception:
        sys.exit(0)

    klipper_iface = None
    for _ in range(30):
        try:
            proxy = bus.get_object("org.kde.klipper", "/klipper")
            cand = dbus.Interface(proxy, "org.kde.klipper.klipper")
            cand.getClipboardContents()
            klipper_iface = cand
            break
        except Exception:
            time.sleep(1.0)

    if klipper_iface is None:
        sys.exit(0)

    state = {"last_synced": None}

    def on_klipper_change(*_args):
        try:
            wl_text = str(klipper_iface.getClipboardContents() or "")
            if not wl_text:
                return
            wl_bytes = wl_text.encode("utf-8")
            try:
                cur = subprocess.run(
                    ["xclip", "-o", "-selection", "clipboard"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=1.5,
                )
                if cur.returncode == 0 and cur.stdout == wl_bytes:
                    state["last_synced"] = wl_text
                    return
            except Exception:
                pass

            res = subprocess.run(
                ["xclip", "-i", "-selection", "clipboard"],
                input=wl_bytes,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            )
            if res.returncode == 0:
                state["last_synced"] = wl_text
        except Exception:
            pass

    bus.add_signal_receiver(
        on_klipper_change,
        signal_name="clipboardHistoryUpdated",
        dbus_interface="org.kde.klipper.klipper",
        path="/klipper",
    )

    loop = GLib.MainLoop()

    def _quit(*_args):
        loop.quit()

    signal.signal(signal.SIGTERM, _quit)
    signal.signal(signal.SIGINT, _quit)
    loop.run()


if __name__ == "__main__":
    main()
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-vbox-clipbridge"

# Isolated Xvfb :99 Host->Guest File & Folder Drag-and-Drop Receiver (libX11 Xdnd v5 + VBoxClient --draganddrop)
cat > "${ROOTFS}/usr/local/bin/omnios-vbox-dnd-bridge" <<'EOF'
#!/usr/bin/env python3
"""OmniOS v2.1 Isolated Xvfb :99 Host->Guest Drag-and-Drop Bridge for VirtualBox."""
import atexit
import ctypes
from ctypes import c_char, c_char_p, c_int, c_long, c_short, c_uint, c_ulong, c_void_p
import os
import select
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse

SELF_TEST = os.environ.get("OMNIOS_DND_SELF_TEST") == "1"
NO_VBOXCLIENT = os.environ.get("OMNIOS_DND_NO_VBOXCLIENT") == "1"
if not SELF_TEST and not os.path.exists("/dev/vboxguest"):
    sys.exit(0)

XA_ATOM = 4
PropModeReplace = 0
AnyPropertyType = 0
CurrentTime = 0
SelectionNotify = 31
ClientMessage = 33
NoEventMask = 0


class XClientMessageData(ctypes.Union):
    _fields_ = [
        ("b", c_char * 20),
        ("s", c_short * 10),
        ("l", c_long * 5),
    ]


class XClientMessageEvent(ctypes.Structure):
    _fields_ = [
        ("type", c_int),
        ("serial", c_ulong),
        ("send_event", c_int),
        ("display", c_void_p),
        ("window", c_ulong),
        ("message_type", c_ulong),
        ("format", c_int),
        ("data", XClientMessageData),
    ]


class XSelectionEvent(ctypes.Structure):
    _fields_ = [
        ("type", c_int),
        ("serial", c_ulong),
        ("send_event", c_int),
        ("display", c_void_p),
        ("requestor", c_ulong),
        ("selection", c_ulong),
        ("target", c_ulong),
        ("property", c_ulong),
        ("time", c_ulong),
    ]


class XEvent(ctypes.Union):
    _fields_ = [
        ("type", c_int),
        ("xclient", XClientMessageEvent),
        ("xselection", XSelectionEvent),
        ("pad", c_long * 24),
    ]


def load_xlib():
    x11 = ctypes.CDLL("libX11.so.6")
    x11.XOpenDisplay.argtypes = [c_char_p]
    x11.XOpenDisplay.restype = c_void_p
    x11.XCloseDisplay.argtypes = [c_void_p]
    x11.XCloseDisplay.restype = c_int
    x11.XDefaultScreen.argtypes = [c_void_p]
    x11.XDefaultScreen.restype = c_int
    x11.XRootWindow.argtypes = [c_void_p, c_int]
    x11.XRootWindow.restype = c_ulong
    x11.XCreateSimpleWindow.argtypes = [
        c_void_p, c_ulong, c_int, c_int, c_uint, c_uint, c_uint, c_ulong, c_ulong
    ]
    x11.XCreateSimpleWindow.restype = c_ulong
    x11.XStoreName.argtypes = [c_void_p, c_ulong, c_char_p]
    x11.XStoreName.restype = c_int
    x11.XInternAtom.argtypes = [c_void_p, c_char_p, c_int]
    x11.XInternAtom.restype = c_ulong
    x11.XChangeProperty.argtypes = [
        c_void_p, c_ulong, c_ulong, c_ulong, c_int, c_int, c_void_p, c_int
    ]
    x11.XChangeProperty.restype = c_int
    x11.XGetWindowProperty.argtypes = [
        c_void_p, c_ulong, c_ulong, c_long, c_long, c_int, c_ulong,
        ctypes.POINTER(c_ulong), ctypes.POINTER(c_int),
        ctypes.POINTER(c_ulong), ctypes.POINTER(c_ulong),
        ctypes.POINTER(c_void_p),
    ]
    x11.XGetWindowProperty.restype = c_int
    x11.XFree.argtypes = [c_void_p]
    x11.XFree.restype = c_int
    x11.XMapWindow.argtypes = [c_void_p, c_ulong]
    x11.XMapWindow.restype = c_int
    x11.XSync.argtypes = [c_void_p, c_int]
    x11.XSync.restype = c_int
    x11.XFlush.argtypes = [c_void_p]
    x11.XFlush.restype = c_int
    x11.XConnectionNumber.argtypes = [c_void_p]
    x11.XConnectionNumber.restype = c_int
    x11.XPending.argtypes = [c_void_p]
    x11.XPending.restype = c_int
    x11.XNextEvent.argtypes = [c_void_p, ctypes.POINTER(XEvent)]
    x11.XNextEvent.restype = c_int
    x11.XSendEvent.argtypes = [c_void_p, c_ulong, c_int, c_long, ctypes.POINTER(XEvent)]
    x11.XSendEvent.restype = c_int
    x11.XConvertSelection.argtypes = [c_void_p, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong]
    x11.XConvertSelection.restype = c_int
    return x11


def is_pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def pick_xvfb_display():
    forced = os.environ.get("OMNIOS_DND_DISPLAY")
    candidates = [forced] if forced else [":99", ":98", ":97"]
    for disp in candidates:
        num = disp.lstrip(":")
        lock_file = f"/tmp/.X{num}-lock"
        sock_file = f"/tmp/.X11-unix/X{num}"
        if os.path.exists(lock_file):
            try:
                pid = int(open(lock_file, "r", encoding="ascii").read().strip())
                if is_pid_alive(pid):
                    continue
            except Exception:
                continue
            try:
                os.unlink(lock_file)
            except OSError:
                continue
            try:
                if os.path.exists(sock_file):
                    os.unlink(sock_file)
            except OSError:
                pass
        return disp
    return None


def truncate_utf8_bytes(text, max_bytes):
    if max_bytes <= 0:
        return ""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def unique_dest_path(dest_dir, name, is_dir=False):
    if is_dir:
        stem, ext = name, ""
    else:
        stem, ext = os.path.splitext(name)
    ext_bytes = len(ext.encode("utf-8"))
    if ext and ext_bytes > 128:
        stem, ext, ext_bytes = name, "", 0

    if len(name.encode("utf-8")) <= 255:
        base_name = name
    elif ext:
        base_stem = truncate_utf8_bytes(stem, 255 - ext_bytes) or "file"
        base_name = f"{base_stem}{ext}"
    else:
        base_name = truncate_utf8_bytes(name, 255) or "file"

    candidate = os.path.join(dest_dir, base_name)
    if not os.path.lexists(candidate):
        return candidate

    idx = 1
    while True:
        suffix = f" ({idx})"
        suffix_bytes = len(suffix.encode("utf-8"))
        if ext and (ext_bytes + suffix_bytes) < 255:
            avail = 255 - ext_bytes - suffix_bytes
            clipped_stem = truncate_utf8_bytes(stem, avail)
            cand_name = f"{clipped_stem}{suffix}{ext}"
        else:
            avail = 255 - suffix_bytes
            clipped = truncate_utf8_bytes(name, avail)
            cand_name = f"{clipped}{suffix}"
        candidate = os.path.join(dest_dir, cand_name)
        if not os.path.lexists(candidate):
            return candidate
        idx += 1


def ignore_nested_symlinks(directory, names):
    ignored = []
    for entry in names:
        if os.path.islink(os.path.join(directory, entry)):
            ignored.append(entry)
    return ignored


def notify_kdir_added(dest_dir):
    try:
        for url in ("desktop:/", "file://" + urllib.parse.quote(dest_dir, safe="/")):
            subprocess.run(
                [
                    "dbus-send", "--session", "--type=signal", "/",
                    "org.kde.KDirNotify.FilesAdded", f"string:{url}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            )
    except Exception:
        pass


def notify_user(title, body):
    try:
        subprocess.Popen(
            ["notify-send", "-i", "folder-downloads", "-a", "OmniOS VirtualBox", title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def push_text_to_clipboard(text):
    try:
        import dbus
        bus = dbus.SessionBus()
        proxy = bus.get_object("org.kde.klipper", "/klipper")
        iface = dbus.Interface(proxy, "org.kde.klipper.klipper")
        iface.setClipboardContents(text)
        return
    except Exception:
        pass
    if os.environ.get("DISPLAY"):
        try:
            subprocess.run(
                ["xclip", "-i", "-selection", "clipboard"],
                input=text.encode("utf-8"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            )
        except Exception:
            pass


def read_window_property(x11, dpy, win, prop, req_type=AnyPropertyType, delete=0):
    actual_type = c_ulong(0)
    actual_fmt = c_int(0)
    nitems = c_ulong(0)
    bytes_after = c_ulong(0)
    prop_ptr = c_void_p(0)
    rc = x11.XGetWindowProperty(
        dpy, win, prop, 0, 1024 * 1024, delete, req_type,
        ctypes.byref(actual_type), ctypes.byref(actual_fmt),
        ctypes.byref(nitems), ctypes.byref(bytes_after),
        ctypes.byref(prop_ptr),
    )
    if rc != 0 or not prop_ptr.value:
        return 0, 0, b""
    try:
        fmt = actual_fmt.value
        count = nitems.value
        if fmt == 8:
            data = ctypes.string_at(prop_ptr.value, count)
        elif fmt == 32:
            arr = ctypes.cast(prop_ptr.value, ctypes.POINTER(c_ulong))
            data = [int(arr[i]) for i in range(count)]
        else:
            data = b""
        return int(actual_type.value), fmt, data
    finally:
        x11.XFree(prop_ptr)


def send_client_message(x11, dpy, target_win, msg_type, l0=0, l1=0, l2=0, l3=0, l4=0):
    ev = XEvent()
    ev.xclient.type = ClientMessage
    ev.xclient.window = target_win
    ev.xclient.message_type = msg_type
    ev.xclient.format = 32
    ev.xclient.data.l[0] = l0
    ev.xclient.data.l[1] = l1
    ev.xclient.data.l[2] = l2
    ev.xclient.data.l[3] = l3
    ev.xclient.data.l[4] = l4
    x11.XSendEvent(dpy, target_win, 0, NoEventMask, ctypes.byref(ev))
    x11.XFlush(dpy)


def main():
    disp = pick_xvfb_display()
    if not disp:
        sys.exit(0)

    children = []
    running = {"active": True}

    def cleanup():
        for proc in list(children):
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
        deadline = time.time() + 2.0
        for proc in list(children):
            if proc and proc.poll() is None:
                rem = max(0.05, deadline - time.time())
                try:
                    proc.wait(timeout=rem)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

    atexit.register(cleanup)

    def handle_sig(*_args):
        running["active"] = False

    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)

    xvfb_proc = subprocess.Popen(
        ["/usr/bin/Xvfb", disp, "-screen", "0", "64x64x24", "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    children.append(xvfb_proc)

    x11 = load_xlib()
    dpy = None
    for _ in range(100):
        if xvfb_proc.poll() is not None:
            sys.exit(1)
        dpy = x11.XOpenDisplay(disp.encode("ascii"))
        if dpy:
            break
        time.sleep(0.1)

    if not dpy:
        sys.exit(1)

    screen = x11.XDefaultScreen(dpy)
    root = x11.XRootWindow(dpy, screen)
    my_win = x11.XCreateSimpleWindow(dpy, root, 0, 0, 64, 64, 0, 0, 0)
    x11.XStoreName(dpy, my_win, b"OmniOS Host Drop Receiver")

    def intern(name):
        return x11.XInternAtom(dpy, name.encode("ascii"), 0)

    a_wm_state = intern("WM_STATE")
    a_xdnd_aware = intern("XdndAware")
    a_xdnd_enter = intern("XdndEnter")
    a_xdnd_position = intern("XdndPosition")
    a_xdnd_status = intern("XdndStatus")
    a_xdnd_drop = intern("XdndDrop")
    a_xdnd_leave = intern("XdndLeave")
    a_xdnd_finished = intern("XdndFinished")
    a_xdnd_selection = intern("XdndSelection")
    a_xdnd_type_list = intern("XdndTypeList")
    a_xdnd_action_copy = intern("XdndActionCopy")
    a_drop_prop = intern("OMNIOS_DND_DATA")
    a_uri_list = intern("text/uri-list")
    a_utf8_plain = intern("text/plain;charset=utf-8")
    a_utf8_str = intern("UTF8_STRING")
    a_text_plain = intern("text/plain")
    a_string = intern("STRING")

    wm_state_val = (c_long * 2)(1, 0)
    x11.XChangeProperty(dpy, my_win, a_wm_state, a_wm_state, 32, PropModeReplace, wm_state_val, 2)
    xdnd_ver = (c_long * 1)(5)
    x11.XChangeProperty(dpy, my_win, a_xdnd_aware, XA_ATOM, 32, PropModeReplace, xdnd_ver, 1)
    x11.XMapWindow(dpy, my_win)
    x11.XSync(dpy, 0)

    ready_file = os.environ.get("OMNIOS_DND_READY_FILE")
    if ready_file:
        with open(ready_file, "w", encoding="ascii") as rf:
            rf.write(f"{disp} {hex(my_win)}\n")

    vbox_proc = None
    vbox_started_at = 0.0
    backoff = 1.0
    next_spawn = 0.0

    def maybe_start_vboxclient():
        nonlocal vbox_proc, vbox_started_at, backoff, next_spawn
        children[:] = [p for p in children if p is not None and p.poll() is None]
        if NO_VBOXCLIENT or not os.path.exists("/dev/vboxguest") or not os.access("/usr/sbin/VBoxClient", os.X_OK):
            return
        now = time.monotonic()
        if vbox_proc is not None and vbox_proc.poll() is None:
            if vbox_started_at and (now - vbox_started_at) >= 60.0:
                backoff = 1.0
            return
        if vbox_proc is not None and vbox_started_at and (now - vbox_started_at) >= 60.0:
            backoff = 1.0
        if now < next_spawn:
            return
        env = os.environ.copy()
        env["DISPLAY"] = disp
        env["XDG_SESSION_TYPE"] = "x11"
        env.pop("WAYLAND_DISPLAY", None)
        vbox_proc = subprocess.Popen(
            ["/usr/sbin/VBoxClient", "--foreground", "--draganddrop"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        vbox_started_at = now
        children.append(vbox_proc)
        next_spawn = now + backoff
        backoff = min(backoff * 2.0, 10.0)

    maybe_start_vboxclient()

    target_priority = [a_uri_list, a_utf8_plain, a_utf8_str, a_text_plain, a_string]
    current_src = 0
    preferred_target = a_uri_list
    dest_dir = os.environ.get("OMNIOS_DND_DEST_DIR") or os.path.expanduser("~/Desktop")

    x_fd = x11.XConnectionNumber(dpy)
    ev = XEvent()

    while running["active"]:
        if xvfb_proc.poll() is not None:
            break
        maybe_start_vboxclient()

        while x11.XPending(dpy) == 0:
            if not running["active"] or xvfb_proc.poll() is not None:
                break
            rlist, _, _ = select.select([x_fd], [], [], 1.0)
            if not rlist:
                maybe_start_vboxclient()
        if not running["active"] or x11.XPending(dpy) == 0:
            continue

        x11.XNextEvent(dpy, ctypes.byref(ev))

        if ev.type == ClientMessage:
            mtype = ev.xclient.message_type
            if mtype == a_xdnd_enter:
                current_src = int(ev.xclient.data.l[0]) & 0xFFFFFFFFFFFFFFFF
                flags = int(ev.xclient.data.l[1])
                offered = [int(ev.xclient.data.l[i]) for i in (2, 3, 4) if ev.xclient.data.l[i]]
                if flags & 1:
                    _, fmt, extra = read_window_property(x11, dpy, current_src, a_xdnd_type_list, XA_ATOM, 0)
                    if fmt == 32 and isinstance(extra, list):
                        offered.extend(extra)
                preferred_target = a_uri_list
                for cand in target_priority:
                    if cand in offered:
                        preferred_target = cand
                        break
            elif mtype == a_xdnd_position:
                src = int(ev.xclient.data.l[0]) & 0xFFFFFFFFFFFFFFFF
                if src:
                    current_src = src
                if current_src:
                    send_client_message(x11, dpy, current_src, a_xdnd_status, my_win, 1, 0, 0, a_xdnd_action_copy)
            elif mtype == a_xdnd_drop:
                src = int(ev.xclient.data.l[0]) & 0xFFFFFFFFFFFFFFFF
                if src:
                    current_src = src
                ts = int(ev.xclient.data.l[2]) & 0xFFFFFFFFFFFFFFFF
                target = preferred_target or a_uri_list
                x11.XConvertSelection(dpy, a_xdnd_selection, target, a_drop_prop, my_win, ts or CurrentTime)
                x11.XFlush(dpy)
            elif mtype == a_xdnd_leave:
                current_src = 0
                preferred_target = a_uri_list

        elif ev.type == SelectionNotify:
            prop = int(ev.xselection.property)
            target = int(ev.xselection.target)
            if prop == 0:
                if current_src:
                    send_client_message(x11, dpy, current_src, a_xdnd_finished, my_win, 0, 0)
                current_src = 0
                continue

            _, fmt, raw = read_window_property(x11, dpy, my_win, prop, AnyPropertyType, 1)
            payload = raw.decode("utf-8", errors="replace") if (fmt == 8 and isinstance(raw, bytes)) else ""
            succeeded = False

            if target == a_uri_list:
                os.makedirs(dest_dir, exist_ok=True)
                real_dest_dir = os.path.realpath(dest_dir)
                env_allowed_root = os.environ.get("OMNIOS_DND_ALLOWED_ROOT")
                enforce_allowed_root = (not SELF_TEST) or bool(env_allowed_root)
                allowed_root = os.path.realpath(env_allowed_root or "/tmp/VirtualBox Dropped Files")
                copied = []
                for line in payload.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parsed = urllib.parse.urlparse(line)
                    if parsed.scheme != "file" or parsed.netloc.lower() not in ("", "localhost"):
                        continue
                    raw_path = urllib.parse.unquote(parsed.path)
                    if not raw_path or "\x00" in raw_path or not raw_path.startswith("/"):
                        continue
                    raw_segments = raw_path.split("/")
                    if ".." in raw_segments or "." in raw_segments:
                        continue
                    src_path = raw_path.rstrip("/")
                    if not src_path:
                        continue
                    base = os.path.basename(src_path)
                    if base in ("", ".", "..") or "/" in base or "\x00" in base:
                        continue
                    if not os.path.lexists(src_path) or os.path.islink(src_path):
                        continue
                    real_src = os.path.realpath(src_path)
                    if not os.path.exists(real_src):
                        continue
                    if enforce_allowed_root:
                        try:
                            if os.path.commonpath([real_src, allowed_root]) != allowed_root or real_src == allowed_root:
                                continue
                        except ValueError:
                            continue
                    try:
                        if os.path.isdir(real_src):
                            dst_path = unique_dest_path(dest_dir, base, is_dir=True)
                            if os.path.realpath(os.path.dirname(dst_path)) != real_dest_dir or os.path.islink(dst_path):
                                continue
                            shutil.copytree(real_src, dst_path, symlinks=True, ignore=ignore_nested_symlinks)
                        elif os.path.isfile(real_src):
                            dst_path = unique_dest_path(dest_dir, base, is_dir=False)
                            if os.path.realpath(os.path.dirname(dst_path)) != real_dest_dir or os.path.islink(dst_path):
                                continue
                            shutil.copy2(real_src, dst_path)
                        else:
                            continue
                        copied.append(os.path.basename(dst_path))
                    except Exception:
                        pass
                if copied:
                    succeeded = True
                    notify_kdir_added(dest_dir)
                    summary = ", ".join(copied[:3]) + (f" (+{len(copied) - 3} more)" if len(copied) > 3 else "")
                    notify_user("Dropped from Host", f"{summary} saved to Desktop")
            elif payload:
                push_text_to_clipboard(payload)
                succeeded = True
                notify_user("Dropped Text from Host", "Copied dropped text to clipboard")

            if current_src:
                send_client_message(
                    x11, dpy, current_src, a_xdnd_finished,
                    my_win, 1 if succeeded else 0, a_xdnd_action_copy if succeeded else 0,
                )
            current_src = 0
            preferred_target = a_uri_list

    x11.XCloseDisplay(dpy)


if __name__ == "__main__":
    main()
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-vbox-dnd-bridge"

# Unified Live Optical/USB Auto-Mount + Desktop Icon & VirtualBox Shared Folder Sync Daemon
cat > "${ROOTFS}/usr/local/bin/omnios-media-desktop-sync" <<'EOF'
#!/usr/bin/env python3
"""OmniOS v2.1 Live Optical/USB Auto-Mount & Desktop/Dolphin Shortcut Sync."""
import fcntl
import json
import os
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import time
import urllib.parse

SENTINEL = "# Managed-By: omnios-media-desktop-sync"
LIVE_LABELS = {"OMNIOS_V2_PRO", "OMNIOS_V21_PRO"}
SKIP_FSTYPES = {"", "swap", "squashfs", "crypto_LUKS", "LVM2_member"}
SKIP_PREFIXES = ("loop", "zram", "ram", "dm-")
RETRY_BACKOFFS = (2.0, 5.0, 15.0)


def unescape_mount(val):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), val)


def decode_udev_enc(val):
    out = bytearray()
    i = 0
    n = len(val)
    while i < n:
        if val[i] == "\\" and i + 3 < n and val[i + 1] == "x":
            try:
                out.append(int(val[i + 2:i + 4], 16))
                i += 4
                continue
            except ValueError:
                pass
        out.extend(val[i].encode("utf-8"))
        i += 1
    return out.decode("utf-8", errors="replace")


def read_udev_block_props(dev_path):
    props = {}
    if not dev_path or not dev_path.startswith("/dev/"):
        return props
    try:
        st = os.stat(dev_path)
        if not stat.S_ISBLK(st.st_mode):
            return props
        udev_file = f"/run/udev/data/b{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
        with open(udev_file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("E:") and "=" in line:
                    k, v = line[2:].rstrip("\r\n").split("=", 1)
                    props[k] = v
    except OSError:
        pass
    return props


def sanitize_desktop_value(val):
    if not val:
        return ""
    cleaned = re.sub(r"[\r\n\x00-\x1f\x7f]+", " ", str(val))
    cleaned = cleaned.replace("\\", "\\\\")
    return cleaned.strip()


def read_proc_mounts():
    mounts = []
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3:
                    mounts.append((unescape_mount(parts[0]), unescape_mount(parts[1]), parts[2]))
    except OSError:
        pass
    return mounts


def as_bool(val):
    return val in (True, 1, "1", "true", "True")


def get_lsblk_flat():
    try:
        res = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,PATH,TYPE,RM,HOTPLUG,TRAN,FSTYPE,LABEL,MOUNTPOINT,SIZE"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        if res.returncode != 0:
            return []
        data = json.loads(res.stdout or "{}")
    except Exception:
        return []

    flat = []

    def walk(nodes, parent_tran="", parent_rm=False, parent_hotplug=False):
        for n in nodes or []:
            tran = (n.get("tran") or "").strip().lower() or parent_tran
            rm = as_bool(n.get("rm")) or parent_rm
            hotplug = as_bool(n.get("hotplug")) or parent_hotplug
            path = (n.get("path") or "").strip()
            fstype = (n.get("fstype") or "").strip()
            label = (n.get("label") or "").strip()
            udev_ignore = False
            # Alpine lsblk is built without libudev, so non-root calls often omit FSTYPE/LABEL;
            # enrich directly from world-readable /run/udev/data/b<maj>:<min>.
            if path and (not fstype or not label or not tran):
                uprops = read_udev_block_props(path)
                if uprops:
                    if not fstype:
                        fstype = uprops.get("ID_FS_TYPE", "").strip()
                    if not label:
                        enc_lbl = uprops.get("ID_FS_LABEL_ENC", "")
                        if enc_lbl:
                            label = decode_udev_enc(enc_lbl).strip()
                        else:
                            label = uprops.get("ID_FS_LABEL", "").strip()
                    if not tran:
                        bus = uprops.get("ID_BUS", "").strip().lower()
                        if bus:
                            tran = bus
                    if uprops.get("UDISKS_IGNORE") == "1":
                        udev_ignore = True
            entry = {
                "name": (n.get("name") or "").strip(),
                "path": path,
                "type": (n.get("type") or "").strip().lower(),
                "rm": rm,
                "hotplug": hotplug,
                "tran": tran,
                "fstype": fstype,
                "label": label,
                "mountpoint": (n.get("mountpoint") or "").strip(),
                "udev_ignore": udev_ignore,
            }
            flat.append(entry)
            if n.get("children"):
                walk(n["children"], tran, rm, hotplug)

    walk(data.get("blockdevices", []))
    return flat


def ensure_vbox_places_bookmark():
    if not os.path.exists("/dev/vboxguest"):
        return
    places_dir = os.path.expanduser("~/.local/share")
    places_file = os.path.join(places_dir, "user-places.xbel")

    def build_bookmark_xml(include_icon):
        meta_fd = (
            '   <metadata owner="http://freedesktop.org">\n'
            '    <bookmark:icon name="folder-remote"/>\n'
            '   </metadata>\n'
            if include_icon
            else ""
        )
        return (
            ' <bookmark href="file:///media">\n'
            '  <title>VirtualBox Shared Folders</title>\n'
            '  <info>\n'
            + meta_fd
            + '   <metadata owner="http://www.kde.org">\n'
            '    <ID>omnios-vbox-shared-folders</ID>\n'
            '    <isSystemItem>false</isSystemItem>\n'
            '   </metadata>\n'
            '  </info>\n'
            ' </bookmark>\n'
        )

    def write_atomic(path, data):
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.replace(tmp_path, path)

    try:
        os.makedirs(places_dir, exist_ok=True)
        if not os.path.exists(places_file):
            content = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE xbel>\n'
                '<xbel xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks"'
                ' xmlns:kdepriv="http://www.kde.org/kdepriv"'
                ' xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info">\n'
                + build_bookmark_xml(True)
                + '</xbel>\n'
            )
            write_atomic(places_file, content)
            return
        with open(places_file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        if 'href="file:///media"' in text:
            return
        has_bm_ns = "xmlns:bookmark=" in text
        if not has_bm_ns:
            updated_ns, count = re.subn(
                r"<xbel(\s|>|/)",
                r'<xbel xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks"\1',
                text,
                count=1,
            )
            if count == 1:
                text = updated_ns
                has_bm_ns = True
        bookmark_xml = build_bookmark_xml(has_bm_ns)
        if "</xbel>" in text:
            updated = text.replace("</xbel>", bookmark_xml + "</xbel>", 1)
            write_atomic(places_file, updated)
        else:
            m = re.search(r"<xbel([^>]*)/\s*>", text)
            if m:
                attrs = m.group(1).rstrip()
                replacement = f"<xbel{attrs}>\n{bookmark_xml}</xbel>"
                updated = text[:m.start()] + replacement + text[m.end():]
                write_atomic(places_file, updated)
    except OSError:
        pass


def cdrom_drive_status(dev_path):
    if not dev_path.startswith("/dev/"):
        return None
    try:
        base = os.path.basename(os.path.realpath(dev_path))
    except OSError:
        base = os.path.basename(dev_path)
    if not base.startswith("sr"):
        return None
    fd = None
    try:
        fd = os.open(dev_path, os.O_RDONLY | os.O_NONBLOCK)
        return fcntl.ioctl(fd, 0x5326, 0)  # CDROM_DRIVE_STATUS
    except Exception:
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def block_device_stale(dev_path):
    if not dev_path.startswith("/dev/"):
        return False
    if not os.path.exists(dev_path):
        return True
    base = os.path.basename(os.path.realpath(dev_path))
    if base.startswith("sr"):
        # Query optical drive hardware directly (detects forced eject even while mounted)
        status = cdrom_drive_status(dev_path)
        if status in (1, 2):  # CDS_NO_DISC=1, CDS_TRAY_OPEN=2
            return True
        if status == 3:  # CDS_DRIVE_NOT_READY=3 (spinning up)
            return False
        size_path = f"/sys/class/block/{base}/size"
        try:
            with open(size_path, "r", encoding="ascii") as fh:
                if int(fh.read().strip() or "0") == 0:
                    return True
        except Exception:
            pass
    return False


def notify_kdir_changed(desktop_dir, added=False, removed_paths=None):
    try:
        if added:
            for url in ("desktop:/", "file://" + urllib.parse.quote(desktop_dir, safe="/")):
                subprocess.run(
                    ["dbus-send", "--session", "--type=signal", "/",
                     "org.kde.KDirNotify.FilesAdded", f"string:{url}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2.0,
                )
        if removed_paths:
            urls = []
            for p in removed_paths:
                urls.append("desktop:/" + urllib.parse.quote(os.path.basename(p)))
                urls.append("file://" + urllib.parse.quote(p, safe="/"))
            subprocess.run(
                ["dbus-send", "--session", "--type=signal", "/",
                 "org.kde.KDirNotify.FilesRemoved", "array:string:" + ",".join(urls)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            )
    except Exception:
        pass


def reconcile(user, desktop_dir, failed_attempts):
    ensure_vbox_places_bookmark()
    mounts = read_proc_mounts()
    media_prefix = f"/run/media/{user}/"
    retry_soon = False

    # 1. Clean up stale forced-eject/unplugged mounts under /run/media/<user>/
    stale_unmounted = False
    for dev, mp, _fstype in mounts:
        if mp.startswith(media_prefix) and block_device_stale(dev):
            try:
                subprocess.run(
                    ["udisksctl", "unmount", "-b", dev, "--force", "--no-user-interaction"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5.0,
                )
            except Exception:
                pass
            stale_unmounted = True
    if stale_unmounted:
        mounts = read_proc_mounts()

    mounted_dev_realpaths = set()
    for dev, _mp, _fstype in mounts:
        if dev.startswith("/dev/"):
            try:
                mounted_dev_realpaths.add(os.path.realpath(dev))
            except OSError:
                mounted_dev_realpaths.add(dev)

    # 2. Auto-mount eligible unmounted optical/USB/removable filesystems
    flat_devs = get_lsblk_flat()
    now = time.monotonic()
    did_mount = False
    for info in flat_devs:
        name = info["name"]
        path = info["path"]
        fstype = info["fstype"]
        label = info["label"]
        mp = info["mountpoint"]
        if not name or not path or name.startswith(SKIP_PREFIXES):
            continue
        if fstype in SKIP_FSTYPES or label in LIVE_LABELS or info.get("udev_ignore"):
            continue
        if mp or mp == "/mnt/live-media":
            continue
        try:
            if os.path.realpath(path) in mounted_dev_realpaths:
                continue
        except OSError:
            pass
        eligible = info["type"] == "rom" or name.startswith("sr") or info["rm"] or info["hotplug"] or info["tran"] == "usb"
        if not eligible or block_device_stale(path):
            continue
        if cdrom_drive_status(path) == 3:
            # CDS_DRIVE_NOT_READY: skip cleanly without recording a failure lockout
            retry_soon = True
            continue
        fail_rec = failed_attempts.get(path)
        if fail_rec is not None:
            last_fail, fail_count = fail_rec
            wait_sec = RETRY_BACKOFFS[min(fail_count - 1, len(RETRY_BACKOFFS) - 1)]
            if now - last_fail < wait_sec:
                if fail_count == 1:
                    retry_soon = True
                continue
        try:
            res = subprocess.run(
                ["udisksctl", "mount", "-b", path, "--no-user-interaction"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10.0,
            )
            if res.returncode == 0:
                failed_attempts.pop(path, None)
                did_mount = True
            else:
                prev_count = failed_attempts.get(path, (0.0, 0))[1]
                failed_attempts[path] = (now, prev_count + 1)
                if prev_count == 0:
                    retry_soon = True
        except Exception:
            prev_count = failed_attempts.get(path, (0.0, 0))[1]
            failed_attempts[path] = (now, prev_count + 1)
            if prev_count == 0:
                retry_soon = True

    if did_mount:
        mounts = read_proc_mounts()
        flat_devs = get_lsblk_flat()

    # 3. Sync managed Type=Link .desktop shortcuts in ~/Desktop/
    by_mp = {}
    by_dev = {}
    for info in flat_devs:
        if info["mountpoint"]:
            by_mp[info["mountpoint"]] = info
        if info["path"]:
            try:
                by_dev[os.path.realpath(info["path"])] = info
            except OSError:
                by_dev[info["path"]] = info

    os.makedirs(desktop_dir, exist_ok=True)
    targets = []
    seen_mps = set()

    for dev, mp, fstype in mounts:
        if mp in seen_mps or mp == "/mnt/live-media":
            continue
        if mp.startswith(media_prefix):
            if block_device_stale(dev):
                continue
            info = by_mp.get(mp)
            if not info and dev.startswith("/dev/"):
                try:
                    info = by_dev.get(os.path.realpath(dev))
                except OSError:
                    info = by_dev.get(dev)
            mp_base = os.path.basename(mp.rstrip("/"))
            if (info and info["label"] in LIVE_LABELS) or mp_base in LIVE_LABELS:
                continue
            display = (info["label"] if info and info["label"] else mp_base) or "Removable Media"
            if (info and (info["name"].startswith("sr") or info["type"] == "rom")) or os.path.basename(dev).startswith("sr") or fstype in ("iso9660", "udf"):
                icon = "media-optical"
            elif info and info["tran"] == "usb":
                icon = "drive-removable-media-usb"
            else:
                icon = "drive-harddisk"
            targets.append((mp, display, icon))
            seen_mps.add(mp)
        elif fstype == "vboxsf":
            base = os.path.basename(mp.rstrip("/")) or "Shared"
            clean = base[3:] if base.startswith("sf_") and len(base) > 3 else base
            targets.append((mp, f"Shared: {clean}", "folder-remote"))
            seen_mps.add(mp)

    desired_files = set()
    added_any = False
    for mp, display, icon in targets:
        raw_slug = os.path.basename(mp.rstrip("/")) or display
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_slug).strip("_") or "volume"
        fname = f"omnios-media-{slug}.desktop"
        suffix = 1
        while fname in desired_files:
            fname = f"omnios-media-{slug}-{suffix}.desktop"
            suffix += 1
        desired_files.add(fname)

        fpath = os.path.join(desktop_dir, fname)
        url = "file://" + urllib.parse.quote(mp, safe="/")
        safe_name = sanitize_desktop_value(display) or "Removable Media"
        safe_mp = sanitize_desktop_value(mp)
        content = (
            "[Desktop Entry]\n"
            f"{SENTINEL}\n"
            "Type=Link\n"
            f"Name={safe_name}\n"
            f"Comment=Mounted at {safe_mp}\n"
            f"URL={url}\n"
            f"Icon={icon}\n"
        )
        try:
            existing = open(fpath, "r", encoding="utf-8").read() if os.path.exists(fpath) else None
            if existing != content:
                tmp_path = fpath + ".tmp"
                with open(tmp_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
                os.chmod(tmp_path, 0o644)
                os.replace(tmp_path, fpath)
                added_any = True
        except OSError:
            pass

    # 4. Remove stale managed .desktop shortcuts (never touch user files or omnios-hub/appearance)
    removed_paths = []
    try:
        for entry in os.listdir(desktop_dir):
            if not entry.endswith(".desktop") or entry in desired_files:
                continue
            fpath = os.path.join(desktop_dir, entry)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    head = fh.read(2048)
                if SENTINEL in head:
                    os.unlink(fpath)
                    removed_paths.append(fpath)
            except OSError:
                pass
    except OSError:
        pass

    if added_any or removed_paths:
        notify_kdir_changed(desktop_dir, added=added_any, removed_paths=removed_paths)

    return retry_soon


def main():
    user = pwd.getpwuid(os.getuid()).pw_name
    desktop_dir = os.path.expanduser("~/Desktop")
    failed_attempts = {}
    running = {"active": True}

    def handle_sig(*_args):
        running["active"] = False

    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)

    def interruptible_sleep(duration):
        end = time.monotonic() + duration
        while running["active"]:
            rem = end - time.monotonic()
            if rem <= 0:
                break
            time.sleep(min(0.2, rem))

    retry_soon = reconcile(user, desktop_dir, failed_attempts)

    mon = None
    mon_started_at = 0.0
    mon_backoff = 1.0
    while running["active"]:
        if mon is None or mon.poll() is not None:
            try:
                mon_started_at = time.monotonic()
                mon = subprocess.Popen(
                    ["udisksctl", "monitor"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )
            except Exception:
                mon = None

        if mon and mon.stdout:
            poll_timeout = 2.0 if retry_soon else 4.0
            rlist, _, _ = select.select([mon.stdout], [], [], poll_timeout)
            if rlist:
                line = mon.stdout.readline()
                if not line:
                    try:
                        mon.wait(timeout=1.0)
                    except Exception:
                        pass
                    mon = None
                    if time.monotonic() - mon_started_at >= 5.0:
                        mon_backoff = 1.0
                    else:
                        interruptible_sleep(mon_backoff)
                        mon_backoff = min(mon_backoff * 2.0, 5.0)
                        if running["active"]:
                            retry_soon = reconcile(user, desktop_dir, failed_attempts)
                    continue
                if time.monotonic() - mon_started_at >= 5.0:
                    mon_backoff = 1.0
                if any(tok in line for tok in ("Added", "Removed", "PropertiesChanged", "block_devices")):
                    # Debounce burst of UDisks2 property notifications
                    deadline = time.monotonic() + 0.6
                    eof_hit = False
                    while time.monotonic() < deadline:
                        rem = max(0.05, deadline - time.monotonic())
                        rr, _, _ = select.select([mon.stdout], [], [], rem)
                        if not rr:
                            break
                        if not mon.stdout.readline():
                            eof_hit = True
                            break
                    if eof_hit:
                        try:
                            mon.wait(timeout=1.0)
                        except Exception:
                            pass
                        mon = None
                        if time.monotonic() - mon_started_at >= 5.0:
                            mon_backoff = 1.0
                        else:
                            interruptible_sleep(mon_backoff)
                            mon_backoff = min(mon_backoff * 2.0, 5.0)
                    failed_attempts.clear()
                    if running["active"]:
                        retry_soon = reconcile(user, desktop_dir, failed_attempts)
            else:
                if time.monotonic() - mon_started_at >= 5.0:
                    mon_backoff = 1.0
                retry_soon = reconcile(user, desktop_dir, failed_attempts)
        else:
            interruptible_sleep(mon_backoff)
            mon_backoff = min(mon_backoff * 2.0, 5.0)
            if running["active"]:
                retry_soon = reconcile(user, desktop_dir, failed_attempts)

    if mon and mon.poll() is None:
        try:
            mon.terminate()
            mon.wait(timeout=2.0)
        except Exception:
            pass


if __name__ == "__main__":
    main()
EOF
chmod 0755 "${ROOTFS}/usr/local/bin/omnios-media-desktop-sync"

for autostart_dir in "${HOMEDIR}/.config/autostart" "${ROOTFS}/etc/skel/.config/autostart"; do
  mkdir -p "${autostart_dir}"
  cat > "${autostart_dir}/omnios-media-sync.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=OmniOS Removable Media & Shared Folders Sync
Exec=/usr/local/bin/omnios-media-desktop-sync
OnlyShowIn=KDE;
X-KDE-autostart-phase=2
EOF
  chmod 0644 "${autostart_dir}/omnios-media-sync.desktop"
done

# Polished Zsh config with custom OmniOS prompt & fastfetch greeting
cat > "${HOMEDIR}/.zshrc" <<'EOF'
export PATH="/usr/local/bin:$PATH"
export EDITOR="nano"

autoload -Uz colors && colors
PROMPT='%F{cyan}╭─%f%B%F{white}omnios%f%b%F{242}@%f%F{39}nextgen%f %F{242}in%f %B%F{220}%~%f%b
%F{cyan}╰─❯%f '

HISTFILE=~/.zsh_history
HISTSIZE=5000
SAVEHIST=5000
setopt SHARE_HISTORY HIST_IGNORE_DUPS

alias ll='ls -lah --color=auto'
alias ls='ls --color=auto'
alias omnios='omnios-cli'
alias themes='omnios-appearance'
alias monitor='btop'

if [[ -o interactive ]] && [[ -z "$OMNIOS_BANNER_SHOWN" ]]; then
  export OMNIOS_BANNER_SHOWN=1
  fastfetch -c /etc/fastfetch/config.jsonc 2>/dev/null || true
fi
EOF

# Pre-seed Plasma 6 kdedefaults/package so startplasma-wayland resolves OmniOS layout cleanly
mkdir -p "${HOMEDIR}/.config/kdedefaults" "${ROOTFS}/etc/xdg/kdedefaults"
printf 'org.omnios.liquidglass.dark\n' > "${HOMEDIR}/.config/kdedefaults/package"
printf 'org.omnios.liquidglass.dark\n' > "${ROOTFS}/etc/xdg/kdedefaults/package"

chroot "${ROOTFS}" chown -R omnios:users /home/omnios

# Rebuild fontconfig cache AFTER all fonts & configs are installed
chroot "${ROOTFS}" /usr/bin/fc-cache -f

# Bounded udev-settle timeout so DRM/NIC coldplug completes cleanly even on slow/emulated CPUs
mkdir -p "${ROOTFS}/etc/conf.d"
cat > "${ROOTFS}/etc/conf.d/udev-settle" <<'EOF'
udev_settle_timeout="30"
EOF

# OpenRC service: /etc/init.d/omnios
cat > "${ROOTFS}/etc/init.d/omnios" <<'EOF'
#!/sbin/openrc-run

name="omnios"
description="OmniOS Multi-Platform Kernel & Adaptive Web Runtime Daemon"
command="/usr/local/bin/omnios-server"
pidfile="/run/omnios.pid"
command_background="yes"
output_log="/var/log/omnios.log"
error_log="/var/log/omnios.log"

depend() {
  after bootmisc dbus networkmanager
}
EOF
chmod 0755 "${ROOTFS}/etc/init.d/omnios"

# OpenRC service: /etc/init.d/omnios-vmtools (guards vmtoolsd via vmware-checkvm so 0 crashed on QEMU/bare metal)
cat > "${ROOTFS}/etc/init.d/omnios-vmtools" <<'EOF'
#!/sbin/openrc-run

name="omnios-vmtools"
description="VMware Guest Tools Daemon (auto-guarded via vmware-checkvm)"

depend() {
  after dbus localmount
}

start() {
  if ! [ -x /usr/bin/vmware-checkvm ] || ! /usr/bin/vmware-checkvm >/dev/null 2>&1; then
    einfo "Non-VMware environment detected; skipping vmtoolsd."
    return 0
  fi
  ebegin "Starting VMware Guest Tools (vmtoolsd)"
  start-stop-daemon --start --background --make-pidfile \
    --pidfile /run/vmtoolsd.pid \
    --env LANG=C.UTF-8 --env LC_ALL=C.UTF-8 \
    --exec /usr/bin/vmtoolsd
  eend $?
}

stop() {
  if [ ! -f /run/vmtoolsd.pid ]; then
    return 0
  fi
  ebegin "Stopping VMware Guest Tools (vmtoolsd)"
  start-stop-daemon --stop --pidfile /run/vmtoolsd.pid --exec /usr/bin/vmtoolsd
  eend $?
}
EOF
chmod 0755 "${ROOTFS}/etc/init.d/omnios-vmtools"

# OpenRC service: /etc/init.d/omnios-vbox (VirtualBox Guest Additions: VBoxService + root VBoxDRMClient, hypervisor-guarded)
cat > "${ROOTFS}/etc/init.d/omnios-vbox" <<'EOF'
#!/sbin/openrc-run

name="omnios-vbox"
description="VirtualBox Guest Additions Daemon (VBoxService + VBoxDRMClient, auto-guarded)"

depend() {
  after udev-settle dbus localmount
  before display-manager omnios-sddm
}

is_virtualbox() {
  [ -c /dev/vboxguest ] && return 0
  for dev in /sys/bus/pci/devices/*; do
    [ -r "$dev/vendor" ] && [ -r "$dev/device" ] || continue
    v="$(cat "$dev/vendor" 2>/dev/null || true)"
    d="$(cat "$dev/device" 2>/dev/null || true)"
    if [ "$v" = "0x80ee" ] && { [ "$d" = "0xcafe" ] || [ "$d" = "0xbeef" ]; }; then
      return 0
    fi
  done
  grep -qi "VirtualBox" \
    /sys/class/dmi/id/product_name \
    /sys/class/dmi/id/sys_vendor \
    /sys/class/dmi/id/board_name \
    /sys/class/dmi/id/bios_version 2>/dev/null && return 0
  return 1
}

has_vmwgfx_render() {
  for r in /dev/dri/renderD*; do
    [ -c "$r" ] || continue
    base="$(basename "$r")"
    if grep -q "DRIVER=vmwgfx" "/sys/class/drm/${base}/device/uevent" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

start() {
  if ! is_virtualbox; then
    einfo "Non-VirtualBox environment detected; skipping VirtualBox Guest Additions."
    return 0
  fi

  ebegin "Loading VirtualBox kernel modules (vboxguest, vboxsf)"
  modprobe -q vboxguest 2>/dev/null || true
  modprobe -q vboxsf 2>/dev/null || true
  _w=0
  while [ ! -c /dev/vboxguest ] && [ "$_w" -lt 20 ]; do
    sleep 0.25
    _w=$((_w + 1))
  done
  # Guarantee device permissions even if udev rule raced
  [ -c /dev/vboxguest ] && chmod 0600 /dev/vboxguest 2>/dev/null || true
  [ -c /dev/vboxuser ] && chmod 0666 /dev/vboxuser 2>/dev/null || true
  mkdir -p /media /tmp/.X11-unix
  chmod 0755 /media
  chmod 1777 /tmp/.X11-unix
  eend 0

  if [ ! -c /dev/vboxguest ]; then
    ewarn "VirtualBox detected but /dev/vboxguest unavailable; skipping VBoxService."
    return 0
  fi

  ebegin "Starting VirtualBox Guest Service (VBoxService)"
  start-stop-daemon --start --background --make-pidfile \
    --pidfile /run/vboxservice.pid \
    --stdout /var/log/vboxservice.log --stderr /var/log/vboxservice.log \
    --exec /usr/sbin/VBoxService -- --foreground
  eend $?

  if has_vmwgfx_render && [ -x /usr/sbin/VBoxDRMClient ]; then
    ebegin "Starting VirtualBox VMSVGA DRM Resize Daemon (VBoxDRMClient)"
    start-stop-daemon --start --background --make-pidfile \
      --pidfile /run/vboxdrmclient.pid \
      --stdout /var/log/VBoxDRMClient.log --stderr /var/log/VBoxDRMClient.log \
      --exec /usr/sbin/VBoxDRMClient
    eend $?
  else
    einfo "VMSVGA vmwgfx render node not active (vboxvideo handles resize in-kernel); skipping VBoxDRMClient."
  fi
}

stop() {
  if [ -f /run/vboxdrmclient.pid ]; then
    ebegin "Stopping VBoxDRMClient"
    start-stop-daemon --stop --quiet --pidfile /run/vboxdrmclient.pid || true
    rm -f /run/vboxdrmclient.pid
    eend 0
  fi
  if [ -f /run/vboxservice.pid ]; then
    ebegin "Stopping VBoxService & unmounting vboxsf shares"
    awk '$3 == "vboxsf" {print $2}' /proc/mounts | xargs -r -n1 umount 2>/dev/null || true
    start-stop-daemon --stop --quiet --pidfile /run/vboxservice.pid || true
    rm -f /run/vboxservice.pid
    eend 0
  fi
  return 0
}
EOF
chmod 0755 "${ROOTFS}/etc/init.d/omnios-vbox"

# Ensure SDDM daemon & session inherit UTF-8 locale
cat > "${ROOTFS}/etc/conf.d/omnios-sddm" <<'EOF'
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
EOF

# OmniOS Display Manager service (dynamic Wayland GreeterEnvironment + clean Headless CLI tty1 shell)
cat > "${ROOTFS}/etc/init.d/omnios-sddm" <<'EOF'
#!/sbin/openrc-run

name="omnios-sddm"
description="OmniOS Display Manager (SDDM Wayland -> Plasma 6 Wayland)"

depend() {
  provide display-manager
  need dbus elogind localmount
  after networkmanager omnios omnios-vbox polkit udisks2
}

start() {
  export LANG=C.UTF-8
  export LC_ALL=C.UTF-8
  VM_IP="$(ip -4 addr show scope global 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')"

  if grep -qw "omnios.mode=headless" /proc/cmdline 2>/dev/null; then
    einfo "Headless CLI mode active; skipping graphical desktop and starting interactive console on tty1."
    if [ -w /dev/tty1 ]; then
      {
        printf '\n============================================================\n'
        printf '  OmniOS 2.1 NextGen Pro - Server + CLI Console (Headless)\n'
        printf '============================================================\n'
        printf '  OmniOS Web Hub : http://%s:3777/\n' "${VM_IP:-127.0.0.1}"
        printf '  CLI Utility    : omnios-cli --help\n'
        printf '  Extra Shells   : Ctrl+Alt+F3 (login) | Ctrl+Alt+F4 (root)\n'
        printf '============================================================\n\n'
      } > /dev/tty1 2>/dev/null || true
    fi
    start-stop-daemon --start --background --make-pidfile \
      --pidfile /run/omnios-headless-tty1.pid \
      --exec /sbin/getty -- -n -l /bin/sh 38400 tty1 || true
    if [ -w /dev/ttyS0 ]; then
      echo "[OmniOS v2.1] HEADLESS_READY ip=${VM_IP:-local}" > /dev/ttyS0 2>/dev/null || true
    fi
    return 0
  fi

  # Wait up to 10s for any DRM card device to appear
  _w=0
  while ! { [ -e /dev/dri/card0 ] || ls /dev/dri/card* >/dev/null 2>&1; } && [ "$_w" -lt 20 ]; do
    sleep 0.5
    _w=$((_w + 1))
  done

  # Dynamically configure SDDM Wayland GreeterEnvironment for VirtualBox/QEMU/no-3D/VMware/bare-metal
  _DMI="$(cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/bios_vendor 2>/dev/null || true)"
  _HAS_RENDER=0
  for _rn in /dev/dri/renderD*; do
    [ -c "$_rn" ] && _HAS_RENDER=1 && break
  done
  _IS_VBOX_PCI=0
  for _pci in /sys/bus/pci/devices/*; do
    [ -d "$_pci" ] && [ -r "$_pci/vendor" ] && [ -r "$_pci/device" ] || continue
    _v="$(cat "$_pci/vendor" 2>/dev/null || true)"
    _d="$(cat "$_pci/device" 2>/dev/null || true)"
    if [ "$_v" = "0x80ee" ] && { [ "$_d" = "0xcafe" ] || [ "$_d" = "0xbeef" ]; }; then
      _IS_VBOX_PCI=1
      break
    fi
  done
  mkdir -p /etc/sddm.conf.d
  if grep -qwE 'omnios\.safe_gfx=1|nomodeset' /proc/cmdline 2>/dev/null \
     || [ "$_IS_VBOX_PCI" -eq 1 ] \
     || printf '%s' "$_DMI" | grep -qiE 'virtualbox|innotek|qemu|kvm|bochs' \
     || [ "$_HAS_RENDER" -eq 0 ]; then
    cat > /etc/sddm.conf.d/20-omnios-runtime.conf <<'SDDMEOF'
[General]
GreeterEnvironment=QT_WAYLAND_SHELL_INTEGRATION=layer-shell,LIBGL_ALWAYS_SOFTWARE=1,KWIN_FORCE_SW_CURSOR=1,XWAYLAND_NO_GLAMOR=1
SDDMEOF
  elif printf '%s' "$_DMI" | grep -qi 'vmware'; then
    cat > /etc/sddm.conf.d/20-omnios-runtime.conf <<'SDDMEOF'
[General]
GreeterEnvironment=QT_WAYLAND_SHELL_INTEGRATION=layer-shell,KWIN_FORCE_SW_CURSOR=1
SDDMEOF
  else
    rm -f /etc/sddm.conf.d/20-omnios-runtime.conf
  fi

  checkpath -d -o sddm:video -m 0755 /var/lib/sddm /run/sddm
  # Pre-copy-up /home/omnios/Desktop on OverlayFS so Plasma KDirWatch inotify receives live file create/delete events
  if [ -d /home/omnios/Desktop ]; then
    su -s /bin/sh omnios -c 'touch /home/omnios/Desktop/.omnios-dir-init && rm -f /home/omnios/Desktop/.omnios-dir-init' 2>/dev/null || true
  fi
  # Signal serial test console once OmniOS desktop stack is launching
  if [ -w /dev/ttyS0 ]; then
    echo "[OmniOS v2.1] LAUNCHING_SDDM ip=${VM_IP:-local}" > /dev/ttyS0 2>/dev/null || true
  fi

  ebegin "Starting OmniOS Display Manager (sddm)"
  start-stop-daemon --start --background --make-pidfile \
    --pidfile /run/sddm.pid \
    --stdout /var/log/sddm.log --stderr /var/log/sddm.log \
    --env LANG=C.UTF-8 --env LC_ALL=C.UTF-8 \
    --exec /usr/bin/sddm
  eend $?
}

stop() {
  if [ -f /run/omnios-headless-tty1.pid ]; then
    ebegin "Stopping Headless tty1 Console"
    start-stop-daemon --stop --quiet --pidfile /run/omnios-headless-tty1.pid || true
    rm -f /run/omnios-headless-tty1.pid
    eend 0
  fi
  if [ -f /run/sddm.pid ]; then
    ebegin "Stopping OmniOS Display Manager (sddm)"
    start-stop-daemon --stop --quiet --retry=TERM/5/KILL/2 --pidfile /run/sddm.pid || true
    rm -f /run/sddm.pid
    eend 0
  fi
  return 0
}
EOF
chmod 0755 "${ROOTFS}/etc/init.d/omnios-sddm"

# Configure OpenRC runlevels sequentially (do NOT enable raw unguarded virtualbox-guest-additions / virtualbox-drm-client)
chroot "${ROOTFS}" /bin/sh -c '
  rc-update add devfs sysinit
  rc-update add sysfs sysinit
  rc-update add cgroups sysinit
  rc-update add dmesg sysinit
  rc-update add udev sysinit
  rc-update add udev-trigger sysinit
  rc-update add udev-settle sysinit
  rc-update add modules boot
  rc-update add hostname boot
  rc-update add bootmisc boot
  rc-update add loopback boot
  rc-update add localmount boot
  rc-update add dbus default
  rc-update add elogind default
  rc-update add polkit default
  rc-update add udisks2 default
  rc-update add networkmanager default
  rc-update add bluetooth default
  rc-update add omnios-vmtools default
  rc-update add omnios-vbox default
  rc-update add omnios default
  rc-update add omnios-sddm default
'

cat > "${ROOTFS}/etc/inittab" <<'EOF'
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default

tty3::respawn:/sbin/getty 38400 tty3
tty4::respawn:/sbin/getty -n -l /bin/sh 38400 tty4
ttyS0::respawn:/sbin/getty -n -l /bin/sh 115200 ttyS0 vt100

::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
EOF

echo "[6/8] Building BusyBox + kmod Live Initramfs (VirtualBox/VMware/SATA/NVMe/SCSI/USB/VirtIO + OverlayFS + Copy-to-RAM)..."
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
  "${INITRD}/mnt/toram" \
  "${INITRD}/mnt/ro" \
  "${INITRD}/mnt/rw" \
  "${INITRD}/newroot" \
  "${INITRD}/lib/modules/${KVER}/kernel"

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
  echo "[OmniOS v2.1 initramfs] $*"
  [ -w /dev/ttyS0 ] && echo "[OmniOS v2.1 initramfs] $*" > /dev/ttyS0 2>/dev/null || true
}

log "Loading storage, CD-ROM, USB & filesystem drivers..."
for mod in \
  loop squashfs overlay isofs vfat nls_cp437 nls_iso8859_1 ext4 \
  cdrom sr_mod sd_mod libata ahci libahci ata_piix ata_generic \
  vmw_pvscsi mptspi mptsas mpt3sas nvme \
  virtio_pci virtio_blk virtio_scsi \
  usbcore xhci_hcd xhci_pci ehci_hcd ehci_pci uhci_hcd ohci_hcd ohci_pci usb-storage uas \
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

TORAM_ACTIVE=0
if grep -qw "omnios.toram=1" /proc/cmdline 2>/dev/null; then
  MEM_TOTAL_KB="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)"
  MEM_TOTAL_MB=$((MEM_TOTAL_KB / 1024))
  if [ "${MEM_TOTAL_MB}" -ge 3500 ]; then
    log "omnios.toram=1 active (${MEM_TOTAL_MB} MiB RAM detected). Copying SquashFS to RAM to free ${FOUND}..."
    mkdir -p /mnt/toram
    if mount -t tmpfs -o mode=0755,size=2200m tmpfs /mnt/toram \
       && cp /mnt/media/omnios/rootfs.squashfs /mnt/toram/rootfs.squashfs \
       && mount -t squashfs -o ro,loop /mnt/toram/rootfs.squashfs /mnt/ro; then
      umount /mnt/media 2>/dev/null || true
      TORAM_ACTIVE=1
      log "SquashFS copied to RAM; ${FOUND} is now unmounted and free for disc insertion."
    else
      log "WARNING: Copy to RAM failed; falling back to normal live media mount on ${FOUND}."
      umount /mnt/ro 2>/dev/null || true
      umount /mnt/toram 2>/dev/null || true
    fi
  else
    log "WARNING: omnios.toram=1 requires >= 3500 MiB RAM (detected ${MEM_TOTAL_MB} MiB); falling back to normal mount on ${FOUND}."
  fi
fi

if [ "${TORAM_ACTIVE}" -eq 0 ]; then
  log "Found live media on ${FOUND}. Mounting SquashFS + RAM OverlayFS..."
  mount -t squashfs -o ro,loop /mnt/media/omnios/rootfs.squashfs /mnt/ro
fi

mount -t tmpfs -o mode=0755,size=75% tmpfs /mnt/rw
mkdir -p /mnt/rw/upper /mnt/rw/work
mount -t overlay overlay -o lowerdir=/mnt/ro,upperdir=/mnt/rw/upper,workdir=/mnt/rw/work /newroot

mkdir -p /newroot/mnt/live-media /newroot/mnt/toram /newroot/proc /newroot/sys /newroot/dev /newroot/run
if [ "${TORAM_ACTIVE}" -eq 1 ]; then
  mount --move /mnt/toram /newroot/mnt/toram 2>/dev/null || true
else
  mount --move /mnt/media /newroot/mnt/live-media 2>/dev/null || true
fi

# On QEMU with -vga vmware (PCI 15ad:0405), vmwgfx fails probe (-38 no pitchlock) AFTER
# tearing down simpledrm. Blacklist vmwgfx ONLY on QEMU/Bochs DMI so simpledrm stays alive;
# real VMware Workstation and Oracle VirtualBox VMSVGA keep vmwgfx enabled!
if grep -qiE 'qemu|bochs' /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null; then
  mkdir -p /newroot/etc/modprobe.d
  cat > /newroot/etc/modprobe.d/99-omnios-qemu-vmwgfx.conf <<'MODEOF'
blacklist vmwgfx
install vmwgfx /bin/true
MODEOF
fi

log "Switching root to OmniOS 2.1 NextGen Pro (/sbin/init)..."
umount /proc /sys /dev 2>/dev/null || true
exec switch_root /newroot /sbin/init
EOF
chmod 0755 "${INITRD}/init"

(cd "${INITRD}" && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "${ISODIR}/boot/initramfs-omnios.gz")
ls -lh "${ISODIR}/boot/vmlinuz-lts" "${ISODIR}/boot/initramfs-omnios.gz"

# Prune redundant /boot images, caches, docs, non-English locales & unused datacenter/mobile firmware blobs
rm -rf \
  "${ROOTFS}/boot/initramfs-"* \
  "${ROOTFS}/boot/vmlinuz-"* \
  "${ROOTFS}/boot/System.map-"* \
  "${ROOTFS}/var/cache/apk/"* \
  "${ROOTFS}/usr/share/man/"* \
  "${ROOTFS}/usr/share/doc/"* \
  "${ROOTFS}/usr/share/gtk-doc/"* \
  "${ROOTFS}/usr/share/help/"* \
  "${ROOTFS}/tmp/"* \
  "${THEMES_SRC}"

if [ -d "${ROOTFS}/usr/share/locale" ]; then
  find "${ROOTFS}/usr/share/locale" -mindepth 1 -maxdepth 1 ! -name 'en*' -exec rm -rf {} + 2>/dev/null || true
fi

if [ -d "${ROOTFS}/lib/firmware" ]; then
  for fw in qcom mellanox mrvl nvidia mediatek ath11k ath12k qed netronome liquidio cxgb4 bnx2x ti-connectivity cypress cirrus qca brcm intel/ipu intel/vsc intel/catpt intel/avs intel/sof* amd-ucode xe; do
    rm -rf "${ROOTFS}/lib/firmware/"${fw} 2>/dev/null || true
  done
fi

echo "[7/8] Packing SquashFS root filesystem (${SQUASHFS_COMP}, zstd level=${SQUASHFS_ZSTD_LEVEL})..."
if [ "${SQUASHFS_COMP}" = "xz" ]; then
  mksquashfs "${ROOTFS}" "${ISODIR}/omnios/rootfs.squashfs" -comp xz -b 512K -noappend -no-progress
else
  mksquashfs "${ROOTFS}" "${ISODIR}/omnios/rootfs.squashfs" -comp zstd -Xcompression-level "${SQUASHFS_ZSTD_LEVEL:-9}" -b 512K -noappend -no-progress
fi
ls -lh "${ISODIR}/omnios/rootfs.squashfs"

# Safety check: if zstd exceeds 1900 MiB (GitHub Release 2.0 GiB asset limit), repack with xz -b 512K
SQ_MB="$(du -m "${ISODIR}/omnios/rootfs.squashfs" | awk '{print $1}')"
echo "  SquashFS size: ${SQ_MB} MiB"
if [ "${SQ_MB}" -gt 1900 ] && [ "${SQUASHFS_COMP}" != "xz" ]; then
  echo "  SquashFS > 1900 MiB; repacking with high-ratio xz -b 512K to stay under 2.0 GiB GitHub Release limit..."
  rm -f "${ISODIR}/omnios/rootfs.squashfs"
  mksquashfs "${ROOTFS}" "${ISODIR}/omnios/rootfs.squashfs" -comp xz -b 512K -noappend -no-progress
  ls -lh "${ISODIR}/omnios/rootfs.squashfs"
fi

echo "[8/8] Writing GRUB2 BIOS+UEFI boot menu and building hybrid ISO..."
cat > "${ISODIR}/boot/grub/grub.cfg" <<'EOF'
set timeout=5
set default=0

insmod all_video
insmod gfxterm
set gfxmode=1280x800x32,1024x768x32,800x600x32,auto
set gfxpayload=1280x800x32,1024x768x32,800x600x32,keep
terminal_output gfxterm

menuentry "OmniOS 2.1 NextGen Pro - Liquid Glass Desktop (Default)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 tsc=nowatchdog block.events_dfl_poll_msecs=2000 omnios.mode=full console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-omnios.gz
}

menuentry "OmniOS 2.1 NextGen Pro - Windows 12 Fluent Acrylic Mode" {
    linux /boot/vmlinuz-lts quiet loglevel=3 tsc=nowatchdog block.events_dfl_poll_msecs=2000 omnios.mode=full omnios.preset=fluent12 console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-omnios.gz
}

menuentry "OmniOS 2.1 NextGen Pro - Safe Software Graphics (nomodeset)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 tsc=nowatchdog block.events_dfl_poll_msecs=2000 omnios.mode=full omnios.safe_gfx=1 nomodeset console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-omnios.gz
}

menuentry "OmniOS 2.1 Server + CLI Console (Headless / Low RAM)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 tsc=nowatchdog block.events_dfl_poll_msecs=2000 omnios.mode=headless console=tty0 console=ttyS0,115200
    initrd /boot/initramfs-omnios.gz
}

menuentry "OmniOS 2.1 NextGen Pro - Copy to RAM (Free Optical Drive)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 tsc=nowatchdog block.events_dfl_poll_msecs=2000 omnios.mode=full omnios.toram=1 console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-omnios.gz
}
EOF

grub-mkrescue \
  -o "/out/${ISO_NAME}" \
  "${ISODIR}" \
  -- -volid "OMNIOS_V2_PRO"

echo "[OmniOS v2.1 Pro ISO] Done: /out/${ISO_NAME}"
ls -lh "/out/${ISO_NAME}"
