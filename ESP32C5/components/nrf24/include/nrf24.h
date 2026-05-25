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
// Rapidly sweep all 126 channels in PTX mode. Blocks until *active becomes false.
void nrf24_jam_sweep(volatile bool *active);

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
