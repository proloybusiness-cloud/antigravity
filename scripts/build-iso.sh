#!/usr/bin/env bash
# OmniOS Bootable Live ISO Builder (x86_64 Hybrid BIOS + UEFI)
# Targets: VMware Workstation, VirtualBox, QEMU/KVM, and low-spec ("potato") PCs via USB.
#
# Usage:
#   ./scripts/build-iso.sh [output_iso_path]
#
# Output (default):
#   dist/omnios-live-x86_64.iso
#   dist/omnios-live-x86_64.iso.sha256

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ISO="${1:-${REPO_ROOT}/dist/omnios-live-x86_64.iso}"
OUT_DIR="$(dirname "${OUT_ISO}")"
OUT_NAME="$(basename "${OUT_ISO}")"
ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:latest}"

mkdir -p "${OUT_DIR}"

if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] docker is required to build the reproducible OmniOS Live ISO." >&2
  exit 1
fi

echo "[OmniOS ISO] Building ${OUT_ISO} using ${ALPINE_IMAGE}..."
docker run --rm \
  --privileged \
  -v "${REPO_ROOT}:/src:ro" \
  -v "${OUT_DIR}:/out" \
  -e "OMNIOS_ISO_NAME=${OUT_NAME}" \
  -e "SQUASHFS_COMP=${SQUASHFS_COMP:-zstd}" \
  "${ALPINE_IMAGE}" \
  /bin/sh /src/scripts/iso/build-in-container.sh

if [ -f "${OUT_ISO}" ]; then
  (cd "${OUT_DIR}" && sha256sum "${OUT_NAME}" > "${OUT_NAME}.sha256")
  echo "[OmniOS ISO] Built successfully:"
  ls -lh "${OUT_ISO}" "${OUT_ISO}.sha256"
  cat "${OUT_ISO}.sha256"
else
  echo "[ERROR] Expected ISO not produced at ${OUT_ISO}" >&2
  exit 1
fi
