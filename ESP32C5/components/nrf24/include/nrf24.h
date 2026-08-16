#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"

// ── nRF24L01+ 2.4 GHz driver ─────────────────────────────────────────────────
// FOR AUTHORIZED SECURITY RESEARCH AND EDUCATION ONLY.
// NM-RF-HAT DIP-2: CE=GPIO8, CSN=GPIO9, SPI bus shared with display/SD.

// Data rates
typedef enum {
    NRF24_DR_1M   = 0,   // 1 Mbps  (default)
    NRF24_DR_2M   = 1,   // 2 Mbps
    NRF24_DR_250K = 2,   // 250 kbps (longest range)
} nrf24_dr_t;

// PA / output power levels
typedef enum {
    NRF24_PA_MIN  = 0,   // -18 dBm
    NRF24_PA_LOW  = 1,   // -12 dBm
    NRF24_PA_MED  = 2,   //  -6 dBm
    NRF24_PA_MAX  = 3,   //   0 dBm
} nrf24_pa_t;

// Single captured packet
typedef struct {
    uint8_t  channel;
    uint8_t  len;
    uint8_t  data[32];
} nrf24_packet_t;

// Futaba S-FHSS detection result
typedef struct {
    bool     found;
    uint8_t  channel;
    uint8_t  raw[10];
    uint16_t servo[8];   // 11-bit servo channel values (0 if not decoded)
} nrf24_sfhss_t;

// ── Lifecycle ─────────────────────────────────────────────────────────────────
esp_err_t nrf24_init(void);
void      nrf24_deinit(void);
bool      nrf24_is_init(void);

// ── Chip detection ────────────────────────────────────────────────────────────
// Returns STATUS register byte; 0x00 and 0xFF both indicate no chip.
uint8_t   nrf24_get_status(void);
bool      nrf24_chip_present(void);   // STATUS != 0x0E (power-down default) sanity

// Read/write any register (for diagnostics and low-level access)
uint8_t   nrf24_read_reg(uint8_t reg);
void      nrf24_write_reg(uint8_t reg, uint8_t val);

// ── Configuration ─────────────────────────────────────────────────────────────
void nrf24_set_channel(uint8_t ch);          // 0-125; freq = 2400 + ch MHz
void nrf24_set_data_rate(nrf24_dr_t dr);
void nrf24_set_pa_level(nrf24_pa_t pa);
void nrf24_set_payload_size(uint8_t size);   // 1-32 bytes
void nrf24_set_address(const uint8_t *addr, uint8_t len);  // 3-5 bytes

// ── State machine ─────────────────────────────────────────────────────────────
void nrf24_power_down(void);
void nrf24_standby(void);
void nrf24_rx_mode(void);
void nrf24_flush_rx(void);
void nrf24_flush_tx(void);

// ── RX (polling) ──────────────────────────────────────────────────────────────
bool    nrf24_data_ready(void);
uint8_t nrf24_read_payload(uint8_t *buf, uint8_t max_len);

// ── Carrier detect ────────────────────────────────────────────────────────────
// After setting channel + RX mode and waiting 130 µs, RPD bit is valid.
bool nrf24_carrier_detect(void);

// ── Channel scanner ───────────────────────────────────────────────────────────
// Sweeps channels start_ch..stop_ch, 130 µs dwell, sets carrier[] array.
// Returns ESP_OK or ESP_ERR_TIMEOUT if cancel fires.
typedef void (*nrf24_scan_cb_t)(uint8_t ch, bool carrier, void *ctx);
esp_err_t nrf24_scan_channels(uint8_t start_ch, uint8_t stop_ch,
                               nrf24_scan_cb_t cb, void *ctx,
                               volatile bool *cancel);

// ── Packet sniffer ────────────────────────────────────────────────────────────
// Promiscuous RX on a single channel; calls cb for each received packet.
// Blocks until cancel becomes true or timeout_ms elapses.
typedef void (*nrf24_rx_cb_t)(const nrf24_packet_t *pkt, void *ctx);
esp_err_t nrf24_sniff(uint8_t channel, uint8_t payload_len,
                      nrf24_rx_cb_t cb, void *ctx,
                      uint32_t timeout_ms, volatile bool *cancel);

// ── Futaba S-FHSS scanner ─────────────────────────────────────────────────────
// Scans typical S-FHSS channels for matching packets.
// Fills out; returns ESP_OK if at least one packet found.
esp_err_t nrf24_sfhss_scan(nrf24_sfhss_t *out, uint32_t timeout_ms,
                            volatile bool *cancel);

// ── Jammer (channel sweeper) ──────────────────────────────────────────────────
// Channel sets and mode names match Bruce firmware nrf_jammer.cpp exactly.
// All modes use CONT_WAVE (RF_SETUP.CONT_WAVE=1, PLL_LOCK=1) with CE HIGH,
// hopping via direct RF_CH writes at SPI speed — no power-cycle between hops.
typedef enum {
    NRF24_JAM_TEST    = 0,  // Bruce "Test"          — 40 even ch: upper(50-80) then lower(2-48)
    NRF24_JAM_BT      = 1,  // Bruce "Bluetooth"     — 79 ch sequential 2402-2480 MHz
    NRF24_JAM_BLE     = 2,  // Bruce "BLEch"         — 40 ch sequential 2402-2441 MHz
    NRF24_JAM_BLE_ADV = 3,  // Bruce "BLE Adv Pri"   — 12 ch advertising priority
    NRF24_JAM_WIFI    = 4,  // Bruce "WiFi"          — 16 ch around 2.4 GHz centers
    NRF24_JAM_ZIGBEE  = 5,  // Bruce "Zigbee"        — 48 ch, 3 per IEEE 802.15.4 ch11-26
    NRF24_JAM_USB     = 6,  // Bruce "USB"           — 20 even ch 2432-2470 MHz dongle band
    NRF24_JAM_RC      = 7,  // Bruce "RC"            — 20 odd ch 2401-2439 MHz
    NRF24_JAM_VIDEO   = 8,  // Bruce "Video Stream"  — 33 even ch 2460-2524 MHz upper band
    NRF24_JAM_FULL    = 9,  // Bruce "Full"          — 124 ch 2401-2524 MHz complete spectrum
} nrf24_jam_mode_t;

// Sweep the selected band. Blocks until *active becomes false.
void nrf24_jam_sweep(volatile bool *active, nrf24_jam_mode_t mode);

// ── Capture control (cancel from another task) ────────────────────────────────
void nrf24_capture_cancel(void);
int  nrf24_capture_count(void);

// ── .nrf24 file I/O (Flipper-compatible text format) ─────────────────────────
typedef struct {
    uint8_t        channel;
    uint8_t        addr[5];
    uint8_t        addr_len;
    uint8_t        payload_len;
    nrf24_packet_t *pkts;   // PSRAM alloc
    int            count;
} nrf24_capture_t;

esp_err_t nrf24_capture_save(const nrf24_capture_t *cap, const char *path);
esp_err_t nrf24_capture_load(const char *path, nrf24_capture_t *out);
void      nrf24_capture_free(nrf24_capture_t *cap);
