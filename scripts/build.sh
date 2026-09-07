#!/usr/bin/env bash
# CYM board build dispatcher.
# Usage: scripts/build.sh <board> [fullclean]
#
# Each board builds into its own isolated directory inside the SoC source dir
# so multiple boards can coexist without clobbering each other's sdkconfig,
# build artifacts, or CMakeCache.
#
# Requires IDF to be sourced before calling:
#   . /home/dev/esp/esp-idf/export.sh

set -euo pipefail

BOARD="${1:-nm-cyd-c5}"
ACTION="${2:-build}"   # "build" or "fullclean"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Validate IDF environment ──────────────────────────────────────────────────

if [ -z "${IDF_PATH:-}" ]; then
    echo ""
    echo "ERROR: IDF_PATH is not set."
    echo "Run first:  . /home/dev/esp/esp-idf/export.sh"
    echo ""
    exit 1
fi

# ── Board → build parameters ──────────────────────────────────────────────────

case "$BOARD" in
    # ── ESP32-C5 boards ──────────────────────────────────────────────────────

    nm-cyd-c5)
        SOC_DIR="$REPO_ROOT/ESP32C5"
        TARGET="esp32c5"
        BUILD_DIR="build_nm-cyd-c5"
        SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.nm-cyd-c5"
        ;;

    ws-c5-28)
        # Waveshare ESP32-C5-Touch-LCD-2.8 (Phase 2 — board on order)
        SOC_DIR="$REPO_ROOT/ESP32C5"
        TARGET="esp32c5"
        BUILD_DIR="build_ws-c5-28"
        SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.ws-c5-28"
        ;;

    # ── ESP32 boards ─────────────────────────────────────────────────────────

    cyd2usb)
        # ESP32-2432S028R classic CYD (Phase 3)
        SOC_DIR="$REPO_ROOT/ESP32"
        TARGET="esp32"
        BUILD_DIR="build_cyd2usb"
        SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.cyd2usb"
        ;;

    # ── ESP32-S3 boards ──────────────────────────────────────────────────────

    hosyond-s3-28)
        # Hosyond ESP32-S3 2.8" 240x320 ILI9341 + FT6336 (Phase 4)
        SOC_DIR="$REPO_ROOT/ESP32S3"
        TARGET="esp32s3"
        BUILD_DIR="build_hosyond-s3-28"
        SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.hosyond-s3-28"
        ;;

    hosyond-s3-35)
        # Hosyond ESP32-S3 3.5" 240x320 ST7796 + FT6336 (Phase 4)
        SOC_DIR="$REPO_ROOT/ESP32S3"
        TARGET="esp32s3"
        BUILD_DIR="build_hosyond-s3-35"
        SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.hosyond-s3-35"
        ;;

    hosyond-s3-40)
        # Hosyond ESP32-S3 4.0" (future — not yet owned)
        SOC_DIR="$REPO_ROOT/ESP32S3"
        TARGET="esp32s3"
        BUILD_DIR="build_hosyond-s3-40"
        SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.hosyond-s3-40"
        ;;

    *)
        echo ""
        echo "ERROR: Unknown board: $BOARD"
        echo ""
        echo "Known boards:"
        echo "  ESP32-C5: nm-cyd-c5  ws-c5-28"
        echo "  ESP32:    cyd2usb"
        echo "  ESP32-S3: hosyond-s3-28  hosyond-s3-35  hosyond-s3-40"
        echo ""
        exit 1
        ;;
esac

# ── Validate source dir exists ────────────────────────────────────────────────

if [ ! -d "$SOC_DIR" ]; then
    echo ""
    echo "ERROR: SoC source directory not found: $SOC_DIR"
    echo "Board $BOARD is not yet ported (directory stub missing)."
    echo ""
    exit 1
fi

echo ""
echo "=== CYM Build: $BOARD ==="
echo "    Source dir:  $SOC_DIR"
echo "    IDF target:  $TARGET"
echo "    Build dir:   $BUILD_DIR"
echo "    Action:      $ACTION"
echo ""

cd "$SOC_DIR"

# ── Verify all sdkconfig.defaults files exist ─────────────────────────────────
# IDF will error silently or behave unexpectedly if a listed defaults file is missing.

IFS=';' read -ra DEFAULTS_FILES <<< "$SDKCONFIG_DEFAULTS"
for f in "${DEFAULTS_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: Missing sdkconfig defaults file: $SOC_DIR/$f"
        echo "Create it (even empty with a comment) before building $BOARD."
        exit 1
    fi
done

# ── Execute action ────────────────────────────────────────────────────────────

if [ "$ACTION" = "fullclean" ]; then
    echo "--- Full clean: $BUILD_DIR ---"
    idf.py -B "$BUILD_DIR" fullclean
    echo ""
    echo "=== Clean complete: $BOARD ==="
    exit 0
fi

# Build. Pass:
#   -B $BUILD_DIR             → isolated build dir, one per board
#   -DIDF_TARGET=             → sets the chip family; cmake reconfigures if it changed
#   -DSDKCONFIG=$BUILD_DIR/sdkconfig → isolate generated sdkconfig inside build dir
#   -DSDKCONFIG_DEFAULTS=     → chain of base + board-specific defaults
idf.py \
    -B "$BUILD_DIR" \
    -DIDF_TARGET="$TARGET" \
    -DSDKCONFIG="$BUILD_DIR/sdkconfig" \
    -DSDKCONFIG_DEFAULTS="$SDKCONFIG_DEFAULTS" \
    build

echo ""
echo "=== Build complete: $BOARD ==="
echo ""
