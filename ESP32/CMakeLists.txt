cmake_minimum_required(VERSION 3.16)

# ── CYM ESP32 Build (Phase 3) ─────────────────────────────────────────────────
#
# This directory will host the CYD2USB (ESP32-2432S028R) port of CYM.
# Status: PLACEHOLDER — not yet ported. Build infrastructure in place.
#
# Target chip: esp32 (dual-core Xtensa LX6 240 MHz)
# Boards planned:
#   cyd2usb  — ESP32-2432S028R (CYD2USB), 4 MB flash, no PSRAM
#              ILI9341 SPI display, XPT2046 resistive touch
#              Dual-core: can pin jammer task to Core 1
#
# To build: make cyd2usb  (from repo root, after sourcing IDF)
# ─────────────────────────────────────────────────────────────────────────────

set(PROJECT_VER "v0.0.0-esp32-placeholder")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(CYM-CYD2USB)

message(WARNING
    "CYM ESP32 port (cyd2usb) is not yet implemented.\n"
    "This is a placeholder build skeleton for Phase 3.\n"
    "See scripts/build.sh and docs/multi-board-plan.md for the roadmap."
)
