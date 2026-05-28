#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"

// ── CC1101 Sub-GHz driver ─────────────────────────────────────────────────────
// FOR AUTHORIZED SECURITY RESEARCH AND EDUCATION ONLY.
// Supports CC1101 on NM-RF-HAT DIP-1: CS=GPIO9, GDO0=GPIO8, SPI bus shared.

// Modulation modes
typedef enum {
    CC1101_MOD_OOK   = 0,   // On-Off Keying (for simple remote codes)
    CC1101_MOD_2FSK  = 1,   // 2-FSK
    CC1101_MOD_GFSK  = 2,   // Gaussian FSK (Bluetooth-like)
    CC1101_MOD_MSK   = 3,   // Minimum Shift Keying
    CC1101_MOD_4FSK  = 4,   // 4-FSK
} cc1101_modulation_t;

// Known protocol types (for decoder)
typedef enum {
    CC1101_PROTO_UNKNOWN    = 0,
    CC1101_PROTO_PRINCETON  = 1,   // Princeton PT2262
    CC1101_PROTO_CAME       = 2,   // CAME fixed code
    CC1101_PROTO_NICE       = 3,   // Nice FLOR
    CC1101_PROTO_HCS300     = 4,   // KeeLoq rolling code
    CC1101_PROTO_DOORBELL   = 5,   // Generic doorbell OOK
} cc1101_protocol_t;

// RAW signal timing (pulse/gap alternating, microseconds, signed: >0 = pulse, <0 = gap)
typedef struct {
    int32_t  *timings;   // Allocated from PSRAM; +ve = mark, -ve = space
    int       count;     // Number of timing entries
    float     freq_mhz;  // Capture frequency
} cc1101_raw_t;

// ── Lifecycle ─────────────────────────────────────────────────────────────────

// Init: adds SPI device on SPI2_HOST, configures GPIO8/9, resets CC1101.
// Returns ESP_OK on success; ESP_ERR_NOT_FOUND if PARTNUM/VERSION mismatch.
esp_err_t cc1101_init(void);
void      cc1101_deinit(void);
bool      cc1101_is_init(void);

// ── Hardware identification ───────────────────────────────────────────────────
uint8_t   cc1101_get_partnum(void);   // should be 0x00
uint8_t   cc1101_get_version(void);   // should be 0x14

// ── Low-level SPI access ─────────────────────────────────────────────────────
uint8_t   cc1101_read_reg(uint8_t addr);
void      cc1101_write_reg(uint8_t addr, uint8_t val);
uint8_t   cc1101_strobe(uint8_t strobe);       // returns status byte
uint8_t   cc1101_read_status(uint8_t addr);    // reads status reg (burst-read)

// ── Frequency ────────────────────────────────────────────────────────────────
void      cc1101_set_freq_mhz(float mhz);
float     cc1101_get_freq_mhz(void);

// ── Modem configuration ───────────────────────────────────────────────────────
void      cc1101_set_modulation(cc1101_modulation_t mod);
void      cc1101_set_data_rate_baud(float baud);   // e.g. 4800, 9600, 38400
void      cc1101_set_rx_bw_khz(float bw_khz);      // e.g. 203, 325, 812

// ── TX power ─────────────────────────────────────────────────────────────────
void      cc1101_set_output_power_dbm(int8_t dbm);   // -30 to +10 dBm

// ── State machine ────────────────────────────────────────────────────────────
void      cc1101_idle(void);
void      cc1101_rx(void);
void      cc1101_tx(void);
void      cc1101_flush_rx(void);
void      cc1101_flush_tx(void);
uint8_t   cc1101_get_marc_state(void);

// ── RSSI ─────────────────────────────────────────────────────────────────────
int8_t    cc1101_get_rssi_dbm(void);

// ── Preset configurations ─────────────────────────────────────────────────────
// Apply a standard preset suited for common sub-GHz protocols.
typedef enum {
    CC1101_PRESET_OOK_4K8_315MHZ,   // 315 MHz OOK 4.8 kBaud (US garage)
    CC1101_PRESET_OOK_4K8_433MHZ,   // 433.92 MHz OOK 4.8 kBaud (EU remotes)
    CC1101_PRESET_OOK_4K8_868MHZ,   // 868 MHz OOK 4.8 kBaud (EU ISM)
    CC1101_PRESET_FSK_38K_433MHZ,   // 433.92 MHz 2-FSK 38.4 kBaud (POCSAG)
    CC1101_PRESET_FSK_9K6_433MHZ,   // 433.92 MHz 2-FSK 9.6 kBaud (TPMS/Weather)
    CC1101_PRESET_OOK_4K8_915MHZ,   // 915 MHz OOK 4.8 kBaud (US ISM)
    CC1101_PRESET_OOK_10K_315MHZ,   // 315 MHz OOK ~9.97 kBaud, sync D391 (US TPMS — Schrader/TRW)
    CC1101_PRESET_OOK_10K_433MHZ,   // 433.92 MHz OOK ~9.97 kBaud, sync D391 (EU TPMS OOK)
    CC1101_PRESET_FSK_10K_315MHZ,   // 315 MHz 2-FSK ~9.97 kBaud, sync D391 (Continental/Hella TPMS)
    CC1101_PRESET_FSK_10K_433MHZ,   // 433.92 MHz 2-FSK ~9.97 kBaud, sync D391 (EU TPMS FSK)
} cc1101_preset_t;
void cc1101_apply_preset(cc1101_preset_t preset);

// ── RAW capture & replay ─────────────────────────────────────────────────────

// Capture raw OOK pulses on GDO0 (GPIO8 edge-ISR timing).
// out->timings is PSRAM-allocated; call cc1101_raw_free() when done.
esp_err_t cc1101_raw_capture(cc1101_raw_t *out, uint32_t timeout_ms);

// Replay a raw signal by bit-banging GPIO8 in CC1101 async-TX mode.
esp_err_t cc1101_raw_replay(const cc1101_raw_t *sig, int repeat_count);

void      cc1101_raw_free(cc1101_raw_t *r);

// ── Flipper .sub file format ──────────────────────────────────────────────────
esp_err_t cc1101_sub_save(const cc1101_raw_t *sig, const char *path);
esp_err_t cc1101_sub_load(const char *path, cc1101_raw_t *out);

// ── Protocol decoder ─────────────────────────────────────────────────────────
// Decode a raw OOK capture. Returns detected protocol and prints code to buf.
cc1101_protocol_t cc1101_decode(const cc1101_raw_t *sig,
                                char *code_buf, size_t buf_sz);

// ── Frequency scanner ─────────────────────────────────────────────────────────
// Callback: called for each frequency step with measured RSSI.
typedef void (*cc1101_scan_cb_t)(float freq_mhz, int8_t rssi_dbm, void *ctx);
esp_err_t cc1101_scan_spectrum(float start_mhz, float stop_mhz, float step_mhz,
                               uint32_t dwell_ms,
                               cc1101_scan_cb_t cb, void *ctx,
                               volatile bool *cancel);

// ── Packet receive (TPMS / fixed-length packet mode) ─────────────────────────
// Configure CC1101 with a packet-mode preset first (e.g. CC1101_PRESET_OOK_10K_315MHZ),
// then call cc1101_rx() once, then loop calling this.
// Returns pktlen on success, -1 on timeout / cancel / FIFO overflow.
int cc1101_rx_packet(uint8_t *buf, uint8_t pktlen, int8_t *rssi_out,
                     uint32_t timeout_ms, volatile bool *cancel);

// ── Capture / replay control ──────────────────────────────────────────────────
// Safe to call from any task; causes capture loop to exit within 10 ms.
void cc1101_capture_cancel(void);
// Live edge count during an in-progress capture (volatile read).
int  cc1101_capture_count(void);
// Signal an in-progress raw_replay to stop between repetitions.
void cc1101_replay_cancel(void);
