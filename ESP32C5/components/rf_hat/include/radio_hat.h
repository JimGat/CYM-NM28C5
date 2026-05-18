#pragma once
// =============================================================================
// radio_hat — CC1101 Sub-GHz (DIP 1) and nRF24L01 2.4GHz (DIP 2) scaffold
// =============================================================================
// TODO: Implement CC1101 SPI driver and nRF24L01 SPI driver.
// Both share the NM-CYD-C5 SPI bus (GPIO 2/6/7) with dedicated CS pins.
//
// CC1101 capabilities planned:
//   - Frequency: 315/433/868/915 MHz (configurable)
//   - Modulation: FSK, GFSK, OOK, ASK
//   - Scan / analyze spectrum
//   - Capture + replay OOK/ASK signals (garage doors, car fobs, etc.)
//   - Raw packet capture
//
// nRF24L01 capabilities planned:
//   - 2.4 GHz proprietary protocols
//   - MouseJack HID injection (wireless keyboard/mouse attack)
//   - Spectrum analysis (scan all 125 channels)
//   - Jammer (transmit on target channel)
// =============================================================================

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    RADIO_HAT_MODULE_CC1101 = 0,
    RADIO_HAT_MODULE_NRF24,
} radio_hat_module_t;

typedef enum {
    RADIO_HAT_OK = 0,
    RADIO_HAT_ERR_NOT_IMPL,   // not yet implemented
    RADIO_HAT_ERR_HW,
    RADIO_HAT_ERR_BUSY,
} radio_hat_err_t;

// Stub — returns RADIO_HAT_ERR_NOT_IMPL until modules are implemented.
radio_hat_err_t radio_hat_init(radio_hat_module_t module);
void            radio_hat_deinit(void);
bool            radio_hat_is_impl(radio_hat_module_t module);
const char     *radio_hat_module_name(radio_hat_module_t module);
