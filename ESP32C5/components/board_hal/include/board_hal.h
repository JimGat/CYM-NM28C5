// board_hal.h — Board Hardware Abstraction Layer for CYM multi-board firmware.
//
// Selects the correct board header based on CONFIG_BOARD_* Kconfig choice,
// then re-exports all BOARD_* pin defines and capability flags.
//
// Usage in board-agnostic code:
//   #include "board_hal.h"
//   gpio_set_level(BOARD_LCD_CS, 1);
//
// During the transition period: main.c still uses its own hardcoded defines
// (LCD_CS=23, etc.). The goal is to migrate main.c to BOARD_* defines in
// Phase 2 when Waveshare support begins, using this header as the single
// source of truth for all board-variant GPIO assignments.
#pragma once

#include "sdkconfig.h"

// ── Board header dispatch ────────────────────────────────────────────────────

#if defined(CONFIG_BOARD_NM_CYD_C5)
#  include "boards/nm_cyd_c5.h"
#elif defined(CONFIG_BOARD_WS_C5_28)
#  include "boards/ws_c5_28.h"
#elif defined(CONFIG_BOARD_CYD2USB)
#  include "boards/cyd2usb.h"
#else
// Fallback: default to NM-CYD-C5 if no board is explicitly configured.
// This ensures the existing build (which predates Kconfig board selection)
// continues to compile without changes to sdkconfig.
#  include "boards/nm_cyd_c5.h"
#endif

// ── Sanity checks — catch impossible combinations at compile time ─────────────

#if defined(CONFIG_BOARD_HAS_BACKLIGHT_EXPANDER) && defined(CONFIG_BOARD_TOUCH_XPT2046)
#  error "Board config error: backlight expander boards use capacitive touch, not XPT2046"
#endif

// ── API ───────────────────────────────────────────────────────────────────────
#ifdef __cplusplus
extern "C" {
#endif

// Log board identification and capability summary to ESP_LOGI at startup.
void board_hal_log_info(void);

#ifdef __cplusplus
}
#endif
