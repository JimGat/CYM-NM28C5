#include "rfid_hat.h"
#include "esp_log.h"

static const char *TAG = "rfid_hat";

rfid_hat_err_t rfid_hat_init(void)
{
    ESP_LOGW(TAG, "PN532 driver not yet implemented");
    return RFID_HAT_ERR_NOT_IMPL;
}

void rfid_hat_deinit(void) {}

bool rfid_hat_is_impl(void) { return false; }

rfid_hat_err_t rfid_hat_scan(rfid_card_t *card_out, uint32_t timeout_ms)
{
    (void)card_out; (void)timeout_ms;
    return RFID_HAT_ERR_NOT_IMPL;
}

const char *rfid_hat_err_str(rfid_hat_err_t err)
{
    switch (err) {
        case RFID_HAT_OK:           return "OK";
        case RFID_HAT_ERR_NOT_IMPL: return "Not implemented";
        case RFID_HAT_ERR_HW:       return "Hardware error";
        case RFID_HAT_ERR_NO_CARD:  return "No card detected";
        case RFID_HAT_ERR_AUTH:     return "Auth failed";
        default:                    return "Unknown error";
    }
}
