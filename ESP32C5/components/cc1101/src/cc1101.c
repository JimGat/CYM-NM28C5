#include "cc1101.h"
#include "cc1101_regs.h"
#include "rf_hat_config.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

static const char *TAG = "cc1101";

// Shared SPI bus mutex (owned by main.c, same bus as display + SD)
extern SemaphoreHandle_t sd_spi_mutex;

// ── State ─────────────────────────────────────────────────────────────────────
static spi_device_handle_t s_spi = NULL;
static bool                s_init = false;
static float               s_freq_mhz = 433.92f;
static bool                s_isr_installed = false;  // gpio_install_isr_service called

// ── ISR raw-capture state (IRAM_ATTR) ─────────────────────────────────────────
#define CC1101_RAW_MAX_EDGES  2048

static volatile bool     s_cap_active    = false;
static volatile uint32_t s_cap_count     = 0;
static volatile int64_t  s_cap_last_us   = 0;
static int32_t          *s_cap_buf       = NULL;   // PSRAM buffer
static volatile bool     s_replay_cancel = false;

static void IRAM_ATTR s_gdo0_isr(void *arg)
{
    if (!s_cap_active || s_cap_count >= CC1101_RAW_MAX_EDGES) return;
    int64_t now = esp_timer_get_time();
    int64_t dt  = now - s_cap_last_us;
    s_cap_last_us = now;
    if (s_cap_count == 0) { s_cap_count++; return; }  // skip first (no delta)
    int level = gpio_get_level(RF_HAT_CC1101_GDO0_GPIO);
    // positive = was HIGH (mark/pulse), negative = was LOW (space/gap)
    s_cap_buf[s_cap_count - 1] = level ? (int32_t)dt : -(int32_t)dt;
    s_cap_count++;
}

// ── SPI helpers ───────────────────────────────────────────────────────────────

static uint8_t s_spi_xfer(uint8_t addr, uint8_t data)
{
    spi_transaction_t t = {
        .length    = 16,
        .tx_data   = { addr, data },
        .flags     = SPI_TRANS_USE_TXDATA | SPI_TRANS_USE_RXDATA,
    };
    if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
    spi_device_polling_transmit(s_spi, &t);
    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
    return t.rx_data[1];
}

// ── Public API ────────────────────────────────────────────────────────────────

uint8_t cc1101_strobe(uint8_t strobe)
{
    spi_transaction_t t = {
        .length   = 8,
        .tx_data  = { strobe },
        .flags    = SPI_TRANS_USE_TXDATA | SPI_TRANS_USE_RXDATA,
    };
    if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
    spi_device_polling_transmit(s_spi, &t);
    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
    return t.rx_data[0];
}

uint8_t cc1101_read_reg(uint8_t addr)
{
    return s_spi_xfer(addr | CC1101_READ, 0x00);
}

void cc1101_write_reg(uint8_t addr, uint8_t val)
{
    s_spi_xfer(addr | CC1101_WRITE, val);
}

uint8_t cc1101_read_status(uint8_t addr)
{
    // Status registers require burst-read flag + read flag
    return s_spi_xfer((addr | CC1101_READ | CC1101_BURST), 0x00);
}

uint8_t cc1101_get_partnum(void) { return cc1101_read_status(CC1101_PARTNUM); }
uint8_t cc1101_get_version(void) { return cc1101_read_status(CC1101_VERSION); }

bool cc1101_is_init(void) { return s_init; }

// ── Init / Deinit ─────────────────────────────────────────────────────────────

esp_err_t cc1101_init(void)
{
    if (s_init) return ESP_OK;

    // Add SPI device on the shared SPI2_HOST bus
    spi_device_interface_config_t devcfg = {
        .clock_speed_hz = 4 * 1000 * 1000,   // 4 MHz (safe for shared bus)
        .mode           = 0,                  // CPOL=0, CPHA=0
        .spics_io_num   = RF_HAT_CC1101_CS_GPIO,
        .queue_size     = 4,
        .flags          = 0,
    };
    esp_err_t err = spi_bus_add_device(SPI2_HOST, &devcfg, &s_spi);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "spi_bus_add_device failed: %s", esp_err_to_name(err));
        return err;
    }

    // GDO0 as input (default — raw capture uses ISR)
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << RF_HAT_CC1101_GDO0_GPIO,
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);

    // Reset CC1101
    vTaskDelay(pdMS_TO_TICKS(5));
    cc1101_strobe(CC1101_SRES);
    vTaskDelay(pdMS_TO_TICKS(10));

    // Verify chip identity
    uint8_t partnum = cc1101_get_partnum();
    uint8_t version = cc1101_get_version();
    ESP_LOGI(TAG, "PARTNUM=0x%02X VERSION=0x%02X", partnum, version);

    if (partnum != 0x00 || version != 0x14) {
        ESP_LOGE(TAG, "CC1101 not detected (expected PARTNUM=0x00 VERSION=0x14)");
        spi_bus_remove_device(s_spi);
        s_spi = NULL;
        return ESP_ERR_NOT_FOUND;
    }

    // Apply default configuration (433.92 MHz OOK)
    cc1101_apply_preset(CC1101_PRESET_OOK_4K8_433MHZ);

    s_init = true;
    ESP_LOGI(TAG, "CC1101 init OK");
    return ESP_OK;
}

void cc1101_deinit(void)
{
    if (!s_init) return;
    s_cap_active = false;
    // Only remove ISR handler if the service was ever installed (raw capture used)
    if (s_isr_installed) {
        gpio_intr_disable(RF_HAT_CC1101_GDO0_GPIO);
        gpio_isr_handler_remove(RF_HAT_CC1101_GDO0_GPIO);
        s_isr_installed = false;
    }
    cc1101_strobe(CC1101_SIDLE);
    spi_bus_remove_device(s_spi);
    s_spi = NULL;
    s_init = false;
    // Reset GDO0 (GPIO8) to safe floating input; CS (GPIO9) is released by spi_bus_remove_device
    gpio_reset_pin(RF_HAT_CC1101_GDO0_GPIO);
    ESP_LOGI(TAG, "CC1101 deinit");
}

// ── Frequency ─────────────────────────────────────────────────────────────────

void cc1101_set_freq_mhz(float mhz)
{
    uint32_t freq_word = (uint32_t)((mhz * 1e6f / CC1101_FOSC_HZ) * 65536.0f + 0.5f);
    cc1101_write_reg(CC1101_FREQ2, (freq_word >> 16) & 0xFF);
    cc1101_write_reg(CC1101_FREQ1, (freq_word >>  8) & 0xFF);
    cc1101_write_reg(CC1101_FREQ0, (freq_word >>  0) & 0xFF);
    s_freq_mhz = mhz;
}

float cc1101_get_freq_mhz(void)
{
    uint32_t f2 = cc1101_read_reg(CC1101_FREQ2);
    uint32_t f1 = cc1101_read_reg(CC1101_FREQ1);
    uint32_t f0 = cc1101_read_reg(CC1101_FREQ0);
    uint32_t fw = (f2 << 16) | (f1 << 8) | f0;
    return (float)fw * CC1101_FOSC_HZ / 65536.0f / 1e6f;
}

// ── Modem config ──────────────────────────────────────────────────────────────

void cc1101_set_modulation(cc1101_modulation_t mod)
{
    uint8_t reg = cc1101_read_reg(CC1101_MDMCFG2) & 0x8F;
    if      (mod == CC1101_MOD_OOK)  reg |= CC1101_REG_MOD_OOK;
    else if (mod == CC1101_MOD_GFSK) reg |= CC1101_REG_MOD_GFSK;
    else if (mod == CC1101_MOD_MSK)  reg |= CC1101_REG_MOD_MSK;
    else if (mod == CC1101_MOD_4FSK) reg |= CC1101_REG_MOD_4FSK;
    else                             reg |= CC1101_REG_MOD_2FSK;
    cc1101_write_reg(CC1101_MDMCFG2, reg);
}

void cc1101_set_data_rate_baud(float baud)
{
    // baud = (256 + DRATE_M) × 2^DRATE_E × Fosc / 2^28
    float a = baud * 268435456.0f / CC1101_FOSC_HZ;
    int e = (int)floorf(log2f(a / 256.0f));
    if (e < 0) e = 0;
    if (e > 15) e = 15;
    int m = (int)roundf(a / (1 << e) - 256.0f);
    if (m < 0) m = 0;
    if (m > 255) { m = 0; e++; }
    uint8_t cfg4 = (cc1101_read_reg(CC1101_MDMCFG4) & 0xF0) | (e & 0x0F);
    cc1101_write_reg(CC1101_MDMCFG4, cfg4);
    cc1101_write_reg(CC1101_MDMCFG3, (uint8_t)m);
}

void cc1101_set_rx_bw_khz(float bw_khz)
{
    // BW = Fosc / (8 × (4 + CHANBW_M) × 2^CHANBW_E)
    float target = CC1101_FOSC_HZ / 1000.0f / bw_khz;
    int best_e = 3, best_m = 3;
    float best_err = 1e9f;
    for (int e = 0; e <= 3; e++) {
        for (int m = 0; m <= 3; m++) {
            float actual = 8.0f * (4 + m) * (1 << e);
            float err = fabsf(actual - target);
            if (err < best_err) { best_err = err; best_e = e; best_m = m; }
        }
    }
    uint8_t cfg4 = (cc1101_read_reg(CC1101_MDMCFG4) & 0x0F)
                 | ((best_e & 3) << 6) | ((best_m & 3) << 4);
    cc1101_write_reg(CC1101_MDMCFG4, cfg4);
}

void cc1101_set_output_power_dbm(int8_t dbm)
{
    // Approximate PATABLE[0] values for ~433 MHz
    uint8_t pa;
    if      (dbm >= 10)  pa = 0xC0;
    else if (dbm >= 7)   pa = 0xC8;
    else if (dbm >= 5)   pa = 0x84;
    else if (dbm >= 0)   pa = 0x60;
    else if (dbm >= -6)  pa = 0x34;
    else if (dbm >= -10) pa = 0x26;
    else if (dbm >= -15) pa = 0x1D;
    else if (dbm >= -20) pa = 0x0D;
    else                 pa = 0x03;
    // Write PATABLE via burst write
    uint8_t tx_data[2] = { CC1101_PATABLE | CC1101_BURST | CC1101_WRITE, pa };
    spi_transaction_t t = {
        .length    = 16,
        .tx_buffer = tx_data,
    };
    if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
    spi_device_polling_transmit(s_spi, &t);
    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
}

// ── State machine ─────────────────────────────────────────────────────────────

void cc1101_idle(void)
{
    cc1101_strobe(CC1101_SIDLE);
    // Wait up to 50 ms for IDLE
    for (int i = 0; i < 50; i++) {
        if ((cc1101_get_marc_state() & 0x1F) == CC1101_STATE_IDLE) break;
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

void cc1101_rx(void)
{
    cc1101_idle();
    cc1101_flush_rx();
    cc1101_strobe(CC1101_SRX);
}

void cc1101_tx(void)
{
    cc1101_idle();
    cc1101_flush_tx();
    cc1101_strobe(CC1101_STX);
}

void cc1101_flush_rx(void) { cc1101_strobe(CC1101_SFRX); }
void cc1101_flush_tx(void) { cc1101_strobe(CC1101_SFTX); }

uint8_t cc1101_get_marc_state(void)
{
    return cc1101_read_status(CC1101_MARCSTATE) & 0x1F;
}

int8_t cc1101_get_rssi_dbm(void)
{
    uint8_t raw = cc1101_read_status(CC1101_RSSI);
    int16_t rssi;
    if (raw >= 128) rssi = (int16_t)raw - 256;
    else            rssi = (int16_t)raw;
    return (int8_t)(rssi / 2 - 74);
}

// ── Presets ───────────────────────────────────────────────────────────────────

void cc1101_apply_preset(cc1101_preset_t preset)
{
    cc1101_idle();

    // Common base config for all presets (from CC1101 datasheet SmartRF Studio)
    cc1101_write_reg(CC1101_IOCFG2,   0x29);   // GDO2: chip ready
    cc1101_write_reg(CC1101_IOCFG1,   0x2E);   // GDO1: tristate (SPI MISO usage)
    cc1101_write_reg(CC1101_IOCFG0,   CC1101_GDO0_RX_DATA);  // GDO0: async data
    cc1101_write_reg(CC1101_FIFOTHR,  0x47);   // RX FIFO threshold = 32 bytes
    cc1101_write_reg(CC1101_SYNC1,    0xD3);
    cc1101_write_reg(CC1101_SYNC0,    0x91);
    cc1101_write_reg(CC1101_PKTLEN,   0xFF);
    cc1101_write_reg(CC1101_PKTCTRL1, 0x04);   // No addr check, append status
    cc1101_write_reg(CC1101_PKTCTRL0, CC1101_PKT_ASYNC_SERIAL); // Async serial
    cc1101_write_reg(CC1101_CHANNR,   0x00);
    cc1101_write_reg(CC1101_FSCTRL1,  0x06);
    cc1101_write_reg(CC1101_FSCTRL0,  0x00);
    cc1101_write_reg(CC1101_MCSM2,    0x07);
    cc1101_write_reg(CC1101_MCSM1,    0x30);   // Stay in RX after RX; go to RX after TX
    cc1101_write_reg(CC1101_MCSM0,    0x18);   // Calibrate when going from IDLE to RX/TX
    cc1101_write_reg(CC1101_FOCCFG,   0x16);
    cc1101_write_reg(CC1101_BSCFG,    0x6C);
    cc1101_write_reg(CC1101_AGCCTRL2, 0x03);
    cc1101_write_reg(CC1101_AGCCTRL1, 0x40);
    cc1101_write_reg(CC1101_AGCCTRL0, 0x91);
    cc1101_write_reg(CC1101_WORCTRL,  0xFB);
    cc1101_write_reg(CC1101_FREND1,   0x56);
    cc1101_write_reg(CC1101_FREND0,   0x11);   // OOK: 2-level PATABLE
    cc1101_write_reg(CC1101_FSCAL3,   0xE9);
    cc1101_write_reg(CC1101_FSCAL2,   0x2A);
    cc1101_write_reg(CC1101_FSCAL1,   0x00);
    cc1101_write_reg(CC1101_FSCAL0,   0x1F);
    cc1101_write_reg(CC1101_TEST2,    0x81);
    cc1101_write_reg(CC1101_TEST1,    0x35);
    cc1101_write_reg(CC1101_TEST0,    0x09);

    switch (preset) {
        case CC1101_PRESET_OOK_4K8_315MHZ:
            cc1101_set_freq_mhz(315.0f);
            cc1101_write_reg(CC1101_MDMCFG4, 0xC7);  // BW=325kHz, DR_E=7
            cc1101_write_reg(CC1101_MDMCFG3, 0x4E);  // DR_M: ~4.8 kBaud
            cc1101_write_reg(CC1101_MDMCFG2, 0x33);  // OOK, no sync
            cc1101_write_reg(CC1101_DEVIATN,  0x00);
            cc1101_write_reg(CC1101_AGCCTRL2, 0x07); // Max LNA gain, 42 dB
            break;

        case CC1101_PRESET_OOK_4K8_433MHZ:
            cc1101_set_freq_mhz(433.92f);
            cc1101_write_reg(CC1101_MDMCFG4, 0xC7);
            cc1101_write_reg(CC1101_MDMCFG3, 0x4E);
            cc1101_write_reg(CC1101_MDMCFG2, 0x33);  // OOK, no sync
            cc1101_write_reg(CC1101_DEVIATN,  0x00);
            cc1101_write_reg(CC1101_AGCCTRL2, 0x07);
            break;

        case CC1101_PRESET_OOK_4K8_868MHZ:
            cc1101_set_freq_mhz(868.35f);
            cc1101_write_reg(CC1101_MDMCFG4, 0xC7);
            cc1101_write_reg(CC1101_MDMCFG3, 0x4E);
            cc1101_write_reg(CC1101_MDMCFG2, 0x33);
            cc1101_write_reg(CC1101_DEVIATN,  0x00);
            cc1101_write_reg(CC1101_AGCCTRL2, 0x07);
            break;

        case CC1101_PRESET_OOK_4K8_915MHZ:
            cc1101_set_freq_mhz(915.0f);
            cc1101_write_reg(CC1101_MDMCFG4, 0xC7);
            cc1101_write_reg(CC1101_MDMCFG3, 0x4E);
            cc1101_write_reg(CC1101_MDMCFG2, 0x33);
            cc1101_write_reg(CC1101_DEVIATN,  0x00);
            cc1101_write_reg(CC1101_AGCCTRL2, 0x07);
            break;

        case CC1101_PRESET_FSK_9K6_433MHZ:
            cc1101_set_freq_mhz(433.92f);
            cc1101_write_reg(CC1101_MDMCFG4, 0xB6);  // BW=203kHz, DR_E=6
            cc1101_write_reg(CC1101_MDMCFG3, 0x83);  // ~9.6 kBaud
            cc1101_write_reg(CC1101_MDMCFG2, 0x03);  // 2-FSK, no sync (async)
            cc1101_write_reg(CC1101_DEVIATN,  0x35);  // ±25 kHz deviation
            cc1101_write_reg(CC1101_AGCCTRL2, 0x07);
            break;

        case CC1101_PRESET_FSK_38K_433MHZ:
            cc1101_set_freq_mhz(433.92f);
            cc1101_write_reg(CC1101_MDMCFG4, 0xCA);  // BW=203kHz, DR_E=10
            cc1101_write_reg(CC1101_MDMCFG3, 0x83);  // ~38.4 kBaud
            cc1101_write_reg(CC1101_MDMCFG2, 0x03);  // 2-FSK, no sync
            cc1101_write_reg(CC1101_DEVIATN,  0x35);
            cc1101_write_reg(CC1101_AGCCTRL2, 0x43);
            break;
    }

    // Set max TX power
    cc1101_set_output_power_dbm(10);
}

// ── RAW Capture ───────────────────────────────────────────────────────────────

esp_err_t cc1101_raw_capture(cc1101_raw_t *out, uint32_t timeout_ms)
{
    if (!s_init || !out) return ESP_ERR_INVALID_ARG;

    // Allocate capture buffer in PSRAM
    if (!s_cap_buf)
        s_cap_buf = heap_caps_malloc(CC1101_RAW_MAX_EDGES * sizeof(int32_t), MALLOC_CAP_SPIRAM);
    if (!s_cap_buf) return ESP_ERR_NO_MEM;

    // Configure GDO0 as input with edge interrupt
    gpio_set_direction(RF_HAT_CC1101_GDO0_GPIO, GPIO_MODE_INPUT);
    gpio_set_intr_type(RF_HAT_CC1101_GDO0_GPIO, GPIO_INTR_ANYEDGE);
    if (!s_isr_installed) {
        gpio_install_isr_service(0);
        s_isr_installed = true;
    }
    gpio_isr_handler_add(RF_HAT_CC1101_GDO0_GPIO, s_gdo0_isr, NULL);

    // Put CC1101 in async serial RX mode
    cc1101_write_reg(CC1101_IOCFG0, CC1101_GDO0_RX_DATA);
    cc1101_write_reg(CC1101_PKTCTRL0, CC1101_PKT_ASYNC_SERIAL);

    s_cap_count  = 0;
    s_cap_last_us = esp_timer_get_time();
    s_cap_active = true;
    gpio_intr_enable(RF_HAT_CC1101_GDO0_GPIO);
    cc1101_rx();

    // Wait for capture to fill or timeout; cc1101_capture_cancel() clears s_cap_active
    uint32_t elapsed = 0;
    while (elapsed < timeout_ms && s_cap_count < CC1101_RAW_MAX_EDGES - 1 && s_cap_active) {
        vTaskDelay(pdMS_TO_TICKS(10));
        elapsed += 10;
    }

    s_cap_active = false;
    gpio_intr_disable(RF_HAT_CC1101_GDO0_GPIO);
    gpio_isr_handler_remove(RF_HAT_CC1101_GDO0_GPIO);
    cc1101_idle();

    int count = (int)s_cap_count - 1;  // -1: first edge has no valid delta
    if (count <= 0) return ESP_ERR_TIMEOUT;

    out->timings = heap_caps_malloc(count * sizeof(int32_t), MALLOC_CAP_SPIRAM);
    if (!out->timings) return ESP_ERR_NO_MEM;
    memcpy(out->timings, s_cap_buf, count * sizeof(int32_t));
    out->count    = count;
    out->freq_mhz = s_freq_mhz;
    return ESP_OK;
}

// ── RAW Replay ────────────────────────────────────────────────────────────────

esp_err_t cc1101_raw_replay(const cc1101_raw_t *sig, int repeat_count)
{
    if (!s_init || !sig || sig->count == 0) return ESP_ERR_INVALID_ARG;

    s_replay_cancel = false;

    // Async TX mode: GDO0 becomes serial data input from ESP32
    cc1101_write_reg(CC1101_PKTCTRL0, CC1101_PKT_ASYNC_SERIAL);
    cc1101_write_reg(CC1101_IOCFG0,   0x2E);  // GDO0: drive LOW (hardwired 0)

    // Configure GDO0 as ESP32 GPIO output
    gpio_set_direction(RF_HAT_CC1101_GDO0_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(RF_HAT_CC1101_GDO0_GPIO, 0);

    cc1101_tx();

    for (int rep = 0; rep < repeat_count && !s_replay_cancel; rep++) {
        for (int i = 0; i < sig->count && !s_replay_cancel; i++) {
            int32_t t = sig->timings[i];
            if (t > 0) {
                gpio_set_level(RF_HAT_CC1101_GDO0_GPIO, 1);
                esp_rom_delay_us((uint32_t)t);
            } else {
                gpio_set_level(RF_HAT_CC1101_GDO0_GPIO, 0);
                esp_rom_delay_us((uint32_t)(-t));
            }
        }
        gpio_set_level(RF_HAT_CC1101_GDO0_GPIO, 0);
        vTaskDelay(pdMS_TO_TICKS(20));  // inter-repeat gap
    }

    cc1101_idle();
    // Restore GDO0 as input
    gpio_set_direction(RF_HAT_CC1101_GDO0_GPIO, GPIO_MODE_INPUT);
    cc1101_write_reg(CC1101_IOCFG0, CC1101_GDO0_RX_DATA);
    cc1101_write_reg(CC1101_PKTCTRL0, CC1101_PKT_ASYNC_SERIAL);
    return s_replay_cancel ? ESP_ERR_TIMEOUT : ESP_OK;
}

void cc1101_capture_cancel(void) { s_cap_active = false; }
int  cc1101_capture_count(void)  { return (int)s_cap_count; }
void cc1101_replay_cancel(void)  { s_replay_cancel = true; }

void cc1101_raw_free(cc1101_raw_t *r)
{
    if (!r) return;
    free(r->timings);
    r->timings = NULL;
    r->count   = 0;
}

// ── Flipper .sub file ─────────────────────────────────────────────────────────

esp_err_t cc1101_sub_save(const cc1101_raw_t *sig, const char *path)
{
    if (!sig || !path || sig->count == 0) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen(path, "w");
    if (!f) return ESP_FAIL;

    fprintf(f, "Filetype: Flipper SubGhz Key File\n");
    fprintf(f, "Version: 1\n");
    fprintf(f, "Frequency: %u\n", (unsigned)(sig->freq_mhz * 1000000.0f));
    fprintf(f, "Preset: FuriHalSubGhzPresetOok650ASYNC\n");
    fprintf(f, "Protocol: RAW\n");
    fprintf(f, "RAW_Data:");
    for (int i = 0; i < sig->count; i++) {
        fprintf(f, " %ld", (long)sig->timings[i]);
    }
    fprintf(f, "\n");
    fclose(f);
    return ESP_OK;
}

esp_err_t cc1101_sub_load(const char *path, cc1101_raw_t *out)
{
    if (!path || !out) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen(path, "r");
    if (!f) return ESP_FAIL;

    memset(out, 0, sizeof(*out));
    out->freq_mhz = 433.92f;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Frequency:", 10) == 0) {
            unsigned hz;
            if (sscanf(line + 10, " %u", &hz) == 1)
                out->freq_mhz = hz / 1000000.0f;
        } else if (strncmp(line, "RAW_Data:", 9) == 0) {
            // Count entries first
            const char *p = line + 9;
            int count = 0;
            while (*p) {
                while (*p == ' ' || *p == '\t') p++;
                int v;
                if (sscanf(p, "%d", &v) == 1) {
                    count++;
                    while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
                } else break;
            }
            if (count == 0) break;
            out->timings = heap_caps_malloc(count * sizeof(int32_t), MALLOC_CAP_SPIRAM);
            if (!out->timings) { fclose(f); return ESP_ERR_NO_MEM; }
            p = line + 9;
            int idx = 0;
            while (idx < count) {
                while (*p == ' ' || *p == '\t') p++;
                int v;
                if (sscanf(p, "%d", &v) == 1) {
                    out->timings[idx++] = (int32_t)v;
                    while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
                } else break;
            }
            out->count = idx;
        }
    }
    fclose(f);
    return (out->count > 0) ? ESP_OK : ESP_FAIL;
}

// ── Frequency Scanner ─────────────────────────────────────────────────────────

esp_err_t cc1101_scan_spectrum(float start_mhz, float stop_mhz, float step_mhz,
                               uint32_t dwell_ms,
                               cc1101_scan_cb_t cb, void *ctx,
                               volatile bool *cancel)
{
    if (!s_init || !cb) return ESP_ERR_INVALID_ARG;
    if (step_mhz <= 0) step_mhz = 0.5f;
    for (float f = start_mhz; f <= stop_mhz; f += step_mhz) {
        if (cancel && *cancel) break;
        cc1101_idle();
        cc1101_set_freq_mhz(f);
        cc1101_rx();
        vTaskDelay(pdMS_TO_TICKS(dwell_ms));
        int8_t rssi = cc1101_get_rssi_dbm();
        cc1101_idle();
        cb(f, rssi, ctx);
    }
    cc1101_idle();
    return ESP_OK;
}

// ── Protocol Decoder ──────────────────────────────────────────────────────────

// Simple Princeton PT2262 decoder: 24-bit OOK, pulse widths ~300us/900us
static bool s_decode_princeton(const cc1101_raw_t *sig, char *buf, size_t sz)
{
    if (sig->count < 48) return false;
    // Find sync pulse (long gap ~10ms)
    int start = -1;
    for (int i = 1; i < sig->count - 1; i++) {
        if (sig->timings[i] < -8000) { start = i + 1; break; }
    }
    if (start < 0 || start + 48 > sig->count) return false;

    uint32_t code = 0;
    for (int bit = 0; bit < 24; bit++) {
        int idx = start + bit * 2;
        int32_t pulse = sig->timings[idx];
        int32_t gap   = sig->timings[idx + 1];
        if (pulse > 0 && gap < 0) {
            // '1' = long pulse short gap, '0' = short pulse long gap
            if (pulse > 600) code |= (1 << (23 - bit));
        }
    }
    snprintf(buf, sz, "Princeton: 0x%06X", (unsigned)code);
    return true;
}

cc1101_protocol_t cc1101_decode(const cc1101_raw_t *sig,
                                char *code_buf, size_t buf_sz)
{
    if (!sig || sig->count < 10) {
        snprintf(code_buf, buf_sz, "No signal");
        return CC1101_PROTO_UNKNOWN;
    }
    if (s_decode_princeton(sig, code_buf, buf_sz))
        return CC1101_PROTO_PRINCETON;

    snprintf(code_buf, buf_sz, "Unknown (%d pulses)", sig->count);
    return CC1101_PROTO_UNKNOWN;
}
