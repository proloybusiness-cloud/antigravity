#!/usr/bin/env bash
# OmniOS Bootable Live ISO Builder (x86_64 Hybrid BIOS + UEFI)
# Supports both editions:
#   --edition pro   (Default) OmniOS 2.1 NextGen Pro Daily Driver
#                   KDE Plasma 6.6 + MacTahoe/Fluent 12 Liquid Glass + Firefox,
#                   LibreOffice, VLC, GIMP, Kate, Dolphin, Wine 11, Flatpak, PipeWire,
#                   VirtualBox Guest Additions, Open-VM-Tools, Optical/USB Auto-Mount & OmniOS Hub
#   --edition lite  OmniOS Potato-PC Lite Kiosk Edition (~708 MB, runs on <1GB RAM)
#
# Usage:
#   ./scripts/build-iso.sh [--edition pro|lite] [output_iso_path]
#
# Default Outputs:
#   pro  -> dist/omnios-v2-pro-x86_64.iso  (+ .sha256)
#   lite -> dist/omnios-live-x86_64.iso    (+ .sha256)

set -euo pipefail

EDITION="${OMNIOS_EDITION:-pro}"
OUT_ISO=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --edition)
      EDITION="${2:-pro}"
      shift 2
      ;;
    --edition=*)
      EDITION="${1#--edition=}"
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--edition pro|lite] [output_iso_path]"
      exit 0
      ;;
    *)
      OUT_ISO="$1"
      shift
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "${EDITION}" = "lite" ]; then
  DEFAULT_NAME="omnios-live-x86_64.iso"
  INNER_SCRIPT="/src/scripts/iso/build-in-container.sh"
else
  EDITION="pro"
  DEFAULT_NAME="omnios-v2-pro-x86_64.iso"
  INNER_SCRIPT="/src/scripts/iso/build-v2-pro-in-container.sh"
fi

OUT_ISO="${OUT_ISO:-${REPO_ROOT}/dist/${DEFAULT_NAME}}"
OUT_DIR="$(dirname "${OUT_ISO}")"
OUT_NAME="$(basename "${OUT_ISO}")"
ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:latest}"

mkdir -p "${OUT_DIR}"

if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] docker is required to build the reproducible OmniOS Live ISO." >&2
  exit 1
fi

EXTRA_DOCKER_ARGS=()
if [ "${EDITION}" = "pro" ]; then
  THEMES_CACHE="${OUT_DIR}/.themes-cache"
  mkdir -p "${THEMES_CACHE}"
  echo "[OmniOS ISO] Syncing open-source next-gen desktop themes into ${THEMES_CACHE}..."
  for repo in \
    vinceliuice/MacTahoe-kde \
    vinceliuice/Fluent-kde \
    vinceliuice/MacTahoe-icon-theme \
    vinceliuice/MacTahoe-gtk-theme \
    vinceliuice/WhiteSur-cursors; do
    name="${repo#*/}"
    if [ ! -d "${THEMES_CACHE}/${name}/.git" ]; then
      tmp_dir="${THEMES_CACHE}/.${name}.tmp.$$"
      cloned=0
      for attempt in 1 2 3; do
        rm -rf "${tmp_dir}"
        if git clone --depth=1 -q "https://github.com/${repo}.git" "${tmp_dir}"; then
          rm -rf "${THEMES_CACHE}/${name}"
          mv "${tmp_dir}" "${THEMES_CACHE}/${name}"
          cloned=1
          break
        fi
        rm -rf "${tmp_dir}"
        if [ "${attempt}" -lt 3 ]; then
          echo "[OmniOS ISO] Clone attempt ${attempt}/3 failed for ${repo}; retrying in $((attempt * 3))s..." >&2
          sleep $((attempt * 3))
        fi
      done
      if [ "${cloned}" -ne 1 ]; then
        rm -rf "${tmp_dir}" "${THEMES_CACHE}/${name}"
        echo "[ERROR] Failed to clone https://github.com/${repo}.git after 3 attempts." >&2
        exit 1
      fi
    fi
  done
  EXTRA_DOCKER_ARGS+=(-v "${THEMES_CACHE}:/themes-cache:ro")
fi

echo "[OmniOS ISO] Building edition='${EDITION}' -> ${OUT_ISO} using ${ALPINE_IMAGE}..."
docker run --rm \
  --privileged \
  -v "${REPO_ROOT}:/src:ro" \
  -v "${OUT_DIR}:/out" \
  "${EXTRA_DOCKER_ARGS[@]}" \
  -e "OMNIOS_ISO_NAME=${OUT_NAME}" \
  -e "SQUASHFS_COMP=${SQUASHFS_COMP:-zstd}" \
  -e "SQUASHFS_ZSTD_LEVEL=${SQUASHFS_ZSTD_LEVEL:-9}" \
  "${ALPINE_IMAGE}" \
  /bin/sh "${INNER_SCRIPT}"

if [ -f "${OUT_ISO}" ]; then
  SIZE_BYTES="$(stat -c%s "${OUT_ISO}")"
  echo "[OmniOS ISO] Size: ${SIZE_BYTES} bytes"
  if [ "${SIZE_BYTES}" -ge 2147483648 ]; then
    echo "[ERROR] ISO size (${SIZE_BYTES} bytes) meets or exceeds GitHub Releases 2.0 GiB asset limit (2147483648 bytes)." >&2
    exit 1
  fi
  (cd "${OUT_DIR}" && sha256sum "${OUT_NAME}" > "${OUT_NAME}.sha256")
  echo "[OmniOS ISO] Built successfully:"
  ls -lh "${OUT_ISO}" "${OUT_ISO}.sha256"
  cat "${OUT_ISO}.sha256"
else
  echo "[ERROR] Expected ISO not produced at ${OUT_ISO}" >&2
  exit 1
fi
