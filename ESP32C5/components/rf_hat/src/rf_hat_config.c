#include "rf_hat_config.h"
#include "esp_log.h"
#include <sys/stat.h>
#include <errno.h>

static const char *TAG = "rf_hat";

// Ensure all RF HAT SD directories exist. Call once after SD mount.
void rf_hat_ensure_dirs(void)
{
    const char *dirs[] = {
        RF_HAT_IR_SAVE_DIR,
        RF_HAT_RF433_SAVE_DIR,
        RF_HAT_RADIO_SAVE_DIR,
        RF_HAT_RFID_SAVE_DIR,
    };
    for (int i = 0; i < (int)(sizeof(dirs)/sizeof(dirs[0])); i++) {
        struct stat st;
        if (stat(dirs[i], &st) != 0) {
            if (mkdir(dirs[i], 0755) == 0) {
                ESP_LOGI(TAG, "created %s", dirs[i]);
            } else {
                ESP_LOGW(TAG, "mkdir %s errno=%d", dirs[i], errno);
            }
        }
    }
}
