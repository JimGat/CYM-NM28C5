cmake_minimum_required(VERSION 3.16)

# ── CYM ESP32-S3 Build (Phase 4) ──────────────────────────────────────────────
#
# This directory will host the Hosyond ESP32-S3 port of CYM.
# Status: PLACEHOLDER — not yet ported. Build infrastructure in place.
#
# Target chip: esp32s3 (dual-core Xtensa LX7 240 MHz, WiFi 4, BT 5)
# Boards planned:
#   hosyond-s3-28  — Hosyond ESP32-S3 2.8" 240x320 (ASIN B0FKG7WRWV)
#                    ILI9341V SPI display, FT6336G capacitive I2C touch
#                    ESP32-S3R8: 16 MB flash, 8 MB PSRAM (OPI)
#   hosyond-s3-35  — Hosyond ESP32-S3 3.5" 240x320 (ASIN B0H28X8SQ4)
#                    ST7796 SPI display, FT6336 capacitive I2C touch
#                    ESP32-S3R8: 16 MB flash, 8 MB PSRAM
#   hosyond-s3-40  — Hosyond ESP32-S3 4.0" (future — not yet owned)
#
# Dual-core advantage: jammer task pinned to Core 1 → better nRF24 sweep timing.
#
# To build: make hosyond-s3-28  (from repo root, after sourcing IDF)
# ─────────────────────────────────────────────────────────────────────────────

set(PROJECT_VER "v0.0.0-esp32s3-placeholder")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(CYM-S3)

message(WARNING
    "CYM ESP32-S3 port (hosyond-s3-*) is not yet implemented.\n"
    "This is a placeholder build skeleton for Phase 4.\n"
    "See scripts/build.sh for the roadmap."
)
