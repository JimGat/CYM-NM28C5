// board_hal.c — Minimal implementation file for the board_hal component.
//
// All board-specific definitions live in the board headers (include/boards/*.h).
// This file exists only so CMake has a source file to compile for the component.
// It logs the active board at startup for diagnostics.
#include "board_hal.h"
#include "esp_log.h"

static const char *TAG = "board_hal";

void board_hal_log_info(void)
{
    ESP_LOGI(TAG, "Board: %s | Display: %s | Touch: %s",
             BOARD_NAME, BOARD_DISPLAY_DRIVER, BOARD_TOUCH_DRIVER);

#if CONFIG_BOARD_HAS_PSRAM
    ESP_LOGI(TAG, "  PSRAM: yes");
#else
    ESP_LOGI(TAG, "  PSRAM: no");
#endif

#if CONFIG_BOARD_HAS_5GHZ
    ESP_LOGI(TAG, "  WiFi: dual-band (2.4 + 5 GHz)");
#else
    ESP_LOGI(TAG, "  WiFi: 2.4 GHz only");
#endif

#if CONFIG_BOARD_HAS_DUAL_CORE
    ESP_LOGI(TAG, "  CPU: dual-core");
#else
    ESP_LOGI(TAG, "  CPU: single-core");
#endif

#if CONFIG_BOARD_HAS_VIBRATOR
    ESP_LOGI(TAG, "  Vibrator: GPIO%d", BOARD_VIBRATOR_GPIO);
#endif

#if CONFIG_BOARD_HAS_RGB_LED
    ESP_LOGI(TAG, "  RGB LED: GPIO%d x%d", BOARD_RGB_LED_GPIO, BOARD_RGB_LED_COUNT);
#endif
}
