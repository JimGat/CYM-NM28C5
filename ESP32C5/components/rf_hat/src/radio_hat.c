#include "radio_hat.h"
#include "esp_log.h"

static const char *TAG = "radio_hat";

radio_hat_err_t radio_hat_init(radio_hat_module_t module)
{
    ESP_LOGW(TAG, "%s not yet implemented", radio_hat_module_name(module));
    return RADIO_HAT_ERR_NOT_IMPL;
}

void radio_hat_deinit(void) {}

bool radio_hat_is_impl(radio_hat_module_t module)
{
    (void)module;
    return false;
}

const char *radio_hat_module_name(radio_hat_module_t module)
{
    switch (module) {
        case RADIO_HAT_MODULE_CC1101: return "CC1101 Sub-GHz";
        case RADIO_HAT_MODULE_NRF24:  return "nRF24L01 2.4GHz";
        default:                      return "Unknown";
    }
}
