# CYM Multi-Board Build System
# Wraps idf.py with isolated build directories and board-specific sdkconfig chains.
#
# Usage:
#   make nm-cyd-c5          Build for NM-CYD-C5 (primary, default)
#   make ws-c5-28           Build for Waveshare ESP32-C5-Touch-LCD-2.8 (on order)
#   make cyd2usb            Build for ESP32-2432S028R (CYD2USB classic)
#   make hosyond-s3-28      Build for Hosyond ESP32-S3 2.8"
#   make hosyond-s3-35      Build for Hosyond ESP32-S3 3.5"
#   make hosyond-s3-40      Build for Hosyond ESP32-S3 4.0" (future)
#
# Each board gets its own build directory: ESP32C5/build_<board>/
# All boards require IDF to be sourced first:
#   . /home/dev/esp/esp-idf/export.sh

.PHONY: all help \
        nm-cyd-c5 ws-c5-28 \
        cyd2usb \
        hosyond-s3-28 hosyond-s3-35 hosyond-s3-40 \
        clean-nm-cyd-c5 clean-ws-c5-28 \
        clean-cyd2usb \
        clean-hosyond-s3-28 clean-hosyond-s3-35 clean-hosyond-s3-40

all: nm-cyd-c5

# ── ESP32-C5 boards ──────────────────────────────────────────────────────────

nm-cyd-c5:
	@scripts/build.sh nm-cyd-c5

ws-c5-28:
	@scripts/build.sh ws-c5-28

clean-nm-cyd-c5:
	@scripts/build.sh nm-cyd-c5 fullclean

clean-ws-c5-28:
	@scripts/build.sh ws-c5-28 fullclean

# ── ESP32 boards ─────────────────────────────────────────────────────────────

cyd2usb:
	@scripts/build.sh cyd2usb

clean-cyd2usb:
	@scripts/build.sh cyd2usb fullclean

# ── ESP32-S3 boards ──────────────────────────────────────────────────────────

hosyond-s3-28:
	@scripts/build.sh hosyond-s3-28

hosyond-s3-35:
	@scripts/build.sh hosyond-s3-35

hosyond-s3-40:
	@scripts/build.sh hosyond-s3-40

clean-hosyond-s3-28:
	@scripts/build.sh hosyond-s3-28 fullclean

clean-hosyond-s3-35:
	@scripts/build.sh hosyond-s3-35 fullclean

clean-hosyond-s3-40:
	@scripts/build.sh hosyond-s3-40 fullclean

# ── Help ─────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "CYM Multi-Board Build"
	@echo ""
	@echo "  Prerequisite: . /home/dev/esp/esp-idf/export.sh"
	@echo ""
	@echo "  ESP32-C5 boards:"
	@echo "    make nm-cyd-c5         NM-CYD-C5 (primary, WiFi 6 + NM-RF-HAT)"
	@echo "    make ws-c5-28          Waveshare ESP32-C5-Touch-LCD-2.8 (on order)"
	@echo ""
	@echo "  ESP32 boards:"
	@echo "    make cyd2usb           ESP32-2432S028R (CYD2USB classic, dual-core)"
	@echo ""
	@echo "  ESP32-S3 boards:"
	@echo "    make hosyond-s3-28     Hosyond ESP32-S3 2.8\" (dual-core, ILI9341 + FT6336)"
	@echo "    make hosyond-s3-35     Hosyond ESP32-S3 3.5\" (dual-core, ST7796 + FT6336)"
	@echo "    make hosyond-s3-40     Hosyond ESP32-S3 4.0\" (future — not yet owned)"
	@echo ""
	@echo "  Clean:"
	@echo "    make clean-<board>     Full clean for a specific board's build dir"
	@echo ""
