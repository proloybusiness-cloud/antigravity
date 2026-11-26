#!/bin/sh
# Runs inside an Alpine Linux (x86_64) container to build the flagship
# OmniOS v2.0 NextGen Pro Daily-Driver Live ISO (Hybrid BIOS + UEFI).
#
# Stack:
#   - Alpine Linux 3.24 + Linux 6.18 LTS + SquashFS/OverlayFS RAM Live Root
#   - KDE Plasma 6.6.6 Wayland + KWin Blur/Animations + SDDM + Kvantum Glass
#   - Real Open-Source Themes Customized for OmniOS v2:
#       * MacTahoe-kde -> OmniOS Liquid Glass Dark & Silk Light (macOS 29 style)
#       * Fluent-kde   -> OmniOS Fluent 12 Dark (Windows 12 style)
#       * MacTahoe-icon-theme + MacTahoe-gtk-theme + WhiteSur-cursors
#       * Bespoke OmniOS v2 Liquid Glass 16:9 Wallpapers & Orb Branding
#   - Real Open-Source Daily-Driver Apps:
#       * Firefox, LibreOffice (Writer/Calc/Impress), VLC, Elisa, GIMP, Gwenview,
#         Okular, Kate, KWrite, Dolphin, Konsole (Zsh + Fastfetch + btop),
#         Spectacle, KCalc, KClock, Ark, GParted, Plasma System Monitor,
#         Discover Software Center + Flatpak (Flathub), Wine 11, Node.js 24
#   - OmniOS Core Service (Node.js 24, http://127.0.0.1:3777) + OmniOS Hub
#   - PipeWire Audio, NetworkManager Wi-Fi/Ethernet, Bluetooth, Open-VM-Tools
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

echo "[2/8] Bootstrapping OmniOS v2.0 Pro RootFS (Plasma 6.6 + Daily-Driver Apps + PipeWire + NetworkManager + VMware Tools)..."
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
  polkit \
  polkit-elogind \
  udisks2 \
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
  mesa-dri-gallium \
  mesa-egl \
  mesa-gbm \
  mesa-gles \
  mesa-vulkan-swrast \
  xorg-server \
  xwayland \
  xcb-util-cursor \
  xf86-video-vmware \
  xf86-video-modesetting \
  xf86-video-fbdev \
  xf86-video-vesa \
  xf86-input-libinput \
  xf86-input-vmmouse \
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
VERSION_ID=2.0
PRETTY_NAME="OmniOS 2.0 NextGen Pro"
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
    "Description": "OmniOS 2.0 Flagship Liquid Glass Dark — Floating top glass bar, centered clock, translucent pill dock & Kvantum frosted windows.",
    "Id": "org.omnios.liquidglass.dark",
    "License": "GPLv3",
    "Name": "OmniOS Liquid Glass Dark",
    "Version": "2.0"
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
// OmniOS 2.0 NextGen Pro — Liquid Glass Fusion Layout (macOS 29 + Windows 12)
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
    "Version": "2.0"
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
// OmniOS 2.0 — Windows 12 Fluent Floating Taskbar Layout
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
    "Description": "OmniOS 2.0 Silk Glass Light — Bright alabaster frosted glass, floating top bar & liquid glass dock.",
    "Id": "org.omnios.liquidglass.light",
    "License": "GPLv3",
    "Name": "OmniOS Silk Glass Light",
    "Version": "2.0"
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
EOF

mkdir -p "${ROOTFS}/etc/network"
cat > "${ROOTFS}/etc/network/interfaces" <<'EOF'
auto lo
iface lo inet loopback
EOF

# Ensure /bin/zsh is in /etc/shells (required by pam_shells.so in sddm-autologin)
grep -qxF "/bin/zsh" "${ROOTFS}/etc/shells" 2>/dev/null || echo "/bin/zsh" >> "${ROOTFS}/etc/shells"
grep -qxF "/bin/bash" "${ROOTFS}/etc/shells" 2>/dev/null || echo "/bin/bash" >> "${ROOTFS}/etc/shells"

# Create desktop user 'omnios' (password: omnios) with passwordless sudo & full hardware/NM/audio groups
chroot "${ROOTFS}" /bin/sh -c '
  adduser -D -s /bin/zsh -G users omnios
  for grp in wheel video render input audio tty plugdev netdev cdrom lp; do
    addgroup "$grp" 2>/dev/null || true
    addgroup omnios "$grp" 2>/dev/null || true
  done
  echo "root:omnios" | chpasswd
  echo "omnios:omnios" | chpasswd
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

# Configure SDDM with Auto-Login into Plasma 6 Wayland & OmniOS-Glass Theme
# Remove conflicting /etc/sddm.conf installed by sddm-breeze (higher precedence than /etc/sddm.conf.d/*)
rm -f "${ROOTFS}/etc/sddm.conf"
mkdir -p "${ROOTFS}/etc/sddm.conf.d"
cat > "${ROOTFS}/etc/sddm.conf.d/10-omnios.conf" <<'EOF'
[Autologin]
User=omnios
Session=plasma
Relogin=false

[General]
DisplayServer=x11
InputMethod=

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

# Wayland/Qt/GTK environment helpers (auto-enables SW cursor under QEMU and safe GL on omnios.safe_gfx=1)
mkdir -p "${ROOTFS}/etc/profile.d"
cat > "${ROOTFS}/etc/profile.d/omnios-desktop.sh" <<'EOF'
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export QT_QPA_PLATFORMTHEME=kde
export MOZ_ENABLE_WAYLAND=1
export GTK_USE_PORTAL=1
export XDG_CURRENT_DESKTOP=KDE
if grep -qi qemu /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null; then
  export KWIN_FORCE_SW_CURSOR=1
fi
if grep -qw "omnios.safe_gfx=1" /proc/cmdline 2>/dev/null; then
  export LIBGL_ALWAYS_SOFTWARE=1
  export KWIN_DRM_NO_AMS=1
  export KWIN_FORCE_SW_CURSOR=1
fi
EOF
chmod 0644 "${ROOTFS}/etc/profile.d/omnios-desktop.sh"

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
  CHOICE="$(kdialog --title "OmniOS 2.0 Appearance Studio" \
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
cp -a "${ROOTFS}/etc/profile.d/omnios-desktop.sh" "${HOMEDIR}/.config/plasma-workspace/env/omnios-env.sh"
chmod 0755 "${HOMEDIR}/.config/plasma-workspace/env/omnios-env.sh"

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
# Start VMware guest desktop agent if running in VMware Workstation
if command -v vmware-user >/dev/null 2>&1; then
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

# Bounded udev-settle timeout so DRM/NIC coldplug completes cleanly without 120s boot stall risk
mkdir -p "${ROOTFS}/etc/conf.d"
cat > "${ROOTFS}/etc/conf.d/udev-settle" <<'EOF'
udev_settle_timeout="15"
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

# Ensure SDDM daemon & session inherit UTF-8 locale
cat > "${ROOTFS}/etc/conf.d/omnios-sddm" <<'EOF'
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
EOF

# Guard SDDM so Headless CLI GRUB entry skips graphical desktop cleanly
cat > "${ROOTFS}/etc/init.d/omnios-sddm" <<'EOF'
#!/sbin/openrc-run

name="omnios-sddm"
description="OmniOS Display Manager (SDDM -> Plasma 6 Wayland)"
command="/usr/bin/sddm"
pidfile="/run/sddm.pid"
command_background="yes"
start_stop_daemon_args="--env LANG=C.UTF-8 --env LC_ALL=C.UTF-8"
output_log="/var/log/sddm.log"
error_log="/var/log/sddm.log"

depend() {
  provide display-manager
  need dbus elogind localmount
  after networkmanager omnios
}

start_pre() {
  export LANG=C.UTF-8
  export LC_ALL=C.UTF-8
  if grep -qw "omnios.mode=headless" /proc/cmdline 2>/dev/null; then
    einfo "Headless mode active; skipping graphical desktop."
    return 1
  fi
  _w=0
  while [ ! -e /dev/dri/card0 ] && [ "$_w" -lt 10 ]; do
    sleep 0.5
    _w=$((_w + 1))
  done
  checkpath -d -o sddm:video -m 0755 /var/lib/sddm /run/sddm
  # Signal serial test console once OmniOS desktop stack is launching
  if [ -w /dev/ttyS0 ]; then
    VM_IP="$(ip -4 addr show scope global 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')"
    echo "[OmniOS v2] LAUNCHING_SDDM ip=${VM_IP:-local}" > /dev/ttyS0 2>/dev/null || true
  fi
}
EOF
chmod 0755 "${ROOTFS}/etc/init.d/omnios-sddm"

# Configure OpenRC runlevels sequentially
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
  rc-update add networkmanager default
  rc-update add bluetooth default
  rc-update add omnios-vmtools default
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

echo "[6/8] Building BusyBox + kmod Live Initramfs (VMware/SATA/NVMe/SCSI/USB/VirtIO + OverlayFS)..."
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
  echo "[OmniOS v2 initramfs] $*"
  [ -w /dev/ttyS0 ] && echo "[OmniOS v2 initramfs] $*" > /dev/ttyS0 2>/dev/null || true
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

log "Switching root to OmniOS 2.0 NextGen Pro (/sbin/init)..."
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
set gfxmode=auto
set gfxpayload=keep

menuentry "OmniOS 2.0 NextGen Pro — Liquid Glass Desktop (macOS 29 + Windows 12)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 tsc=nowatchdog omnios.mode=full console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-omnios.gz
}

menuentry "OmniOS 2.0 NextGen Pro — Windows 12 Fluent Acrylic Mode" {
    linux /boot/vmlinuz-lts quiet loglevel=3 tsc=nowatchdog omnios.mode=full omnios.preset=fluent12 console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-omnios.gz
}

menuentry "OmniOS 2.0 NextGen Pro — Safe Software Graphics (Compatibility Mode)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 tsc=nowatchdog omnios.mode=full omnios.safe_gfx=1 console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-omnios.gz
}

menuentry "OmniOS 2.0 Server + CLI Console (Headless / Low RAM)" {
    linux /boot/vmlinuz-lts quiet loglevel=3 tsc=nowatchdog omnios.mode=headless console=tty0 console=ttyS0,115200
    initrd /boot/initramfs-omnios.gz
}
EOF

grub-mkrescue \
  -o "/out/${ISO_NAME}" \
  "${ISODIR}" \
  -- -volid "OMNIOS_V2_PRO"

echo "[OmniOS v2 Pro ISO] Done: /out/${ISO_NAME}"
ls -lh "/out/${ISO_NAME}"
