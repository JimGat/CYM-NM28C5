#include "nrf24.h"
#include "rf_hat_config.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "nrf24";

// Shared SPI bus mutex owned by main.c
extern SemaphoreHandle_t sd_spi_mutex;

// ── nRF24L01+ registers ───────────────────────────────────────────────────────
#define REG_CONFIG      0x00
#define REG_EN_AA       0x01
#define REG_EN_RXADDR   0x02
#define REG_SETUP_AW    0x03
#define REG_SETUP_RETR  0x04
#define REG_RF_CH       0x05
#define REG_RF_SETUP    0x06
#define REG_STATUS      0x07
#define REG_RPD         0x09
#define REG_RX_ADDR_P0  0x0A
#define REG_TX_ADDR     0x10
#define REG_RX_PW_P0    0x11
#define REG_FIFO_STATUS 0x17
#define REG_DYNPD       0x1C
#define REG_FEATURE     0x1D

// CONFIG bits
#define CONFIG_PRIM_RX  0x01
#define CONFIG_PWR_UP   0x02
#define CONFIG_EN_CRC   0x08
#define CONFIG_CRCO     0x04

// RF_SETUP bits
#define RF_SETUP_DR_HIGH 0x08
#define RF_SETUP_DR_LOW  0x20
#define RF_SETUP_PWR(n) ((n & 3) << 1)

// STATUS bits
#define STATUS_RX_DR    0x40
#define STATUS_TX_DS    0x20
#define STATUS_MAX_RT   0x10
#define STATUS_RX_EMPTY 0x0E

// Commands
#define CMD_R_REG       0x00
#define CMD_W_REG       0x20
#define CMD_R_PAYLOAD   0x61
#define CMD_W_PAYLOAD   0xA0
#define CMD_FLUSH_TX    0xE1
#define CMD_FLUSH_RX    0xE2
#define CMD_NOP         0xFF

// S-FHSS constants
// Futaba S-FHSS uses 1 Mbps, 2-byte CRC, 10-byte payload,
// sync address 0x550F71 (3 bytes) or 0x55 0x0F 0x71
#define SFHSS_ADDR_LEN  3
static const uint8_t SFHSS_ADDR[3] = { 0x55, 0x0F, 0x71 };
#define SFHSS_PAYLOAD   10

// S-FHSS channel list (47 channels hopping in 1-MHz steps from 2404 MHz)
static const uint8_t SFHSS_CHANNELS[] = {
     4,  8, 12, 16, 20, 24, 28, 32, 36, 40,
    44, 48, 52, 56, 60, 64, 68, 72, 76, 80,
    84, 88, 92, 96,100
};
#define SFHSS_N_CHANNELS (sizeof(SFHSS_CHANNELS) / sizeof(SFHSS_CHANNELS[0]))

// ── Driver state ─────────────────────────────────────────────────────────────
typedef struct {
    spi_device_handle_t spi;
    volatile bool       cancel;
    volatile int        cap_count;
} nrf24_drv_t;

EXT_RAM_BSS_ATTR static nrf24_drv_t *s_drv = NULL;  // pointer in PSRAM BSS; struct in PSRAM

// ── GPIO helpers ─────────────────────────────────────────────────────────────
static inline void csn_low(void)  { gpio_set_level(RF_HAT_NRF24_CS_GPIO, 0); }
static inline void csn_high(void) { gpio_set_level(RF_HAT_NRF24_CS_GPIO, 1); }
static inline void ce_low(void)   { gpio_set_level(RF_HAT_NRF24_CE_GPIO, 0); }
static inline void ce_high(void)  { gpio_set_level(RF_HAT_NRF24_CE_GPIO, 1); }

// ── SPI helpers ───────────────────────────────────────────────────────────────

static void spi_xfer_buf(const uint8_t *tx, uint8_t *rx, size_t len)
{
    spi_transaction_t t = {
        .length    = len * 8,
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
    esp_err_t err = spi_device_polling_transmit(s_drv->spi, &t);
    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
    if (err != ESP_OK) ESP_LOGE(TAG, "SPI xfer failed (%zu B): %s", len, esp_err_to_name(err));
}

uint8_t nrf24_read_reg(uint8_t reg)
{
    uint8_t tx[2] = { CMD_R_REG | (reg & 0x1F), CMD_NOP };
    uint8_t rx[2] = { 0 };
    csn_low();
    spi_xfer_buf(tx, rx, 2);
    csn_high();
    return rx[1];
}

void nrf24_write_reg(uint8_t reg, uint8_t val)
{
    uint8_t tx[2] = { CMD_W_REG | (reg & 0x1F), val };
    uint8_t rx[2];
    csn_low();
    spi_xfer_buf(tx, rx, 2);
    csn_high();
}

static void nrf24_write_reg_multi(uint8_t reg, const uint8_t *buf, uint8_t len)
{
    uint8_t tx[6];
    uint8_t rx[6];
    if (len > 5) len = 5;
    tx[0] = CMD_W_REG | (reg & 0x1F);
    memcpy(tx + 1, buf, len);
    csn_low();
    spi_xfer_buf(tx, rx, len + 1);
    csn_high();
}

static uint8_t nrf24_cmd_byte(uint8_t cmd)
{
    uint8_t tx = cmd, rx = 0;
    csn_low();
    spi_xfer_buf(&tx, &rx, 1);
    csn_high();
    return rx;
}

// ── Public API ────────────────────────────────────────────────────────────────

uint8_t nrf24_get_status(void)
{
    if (!s_drv) return 0xFF;
    return nrf24_cmd_byte(CMD_NOP);
}

bool nrf24_chip_present(void)
{
    if (!s_drv) return false;
    // Verify STATUS is 0x0E in power-down (RX_P_NO=7, TX_FULL=0)
    // or any non-0x00 and non-0xFF value
    uint8_t st = nrf24_get_status();
    return (st != 0x00 && st != 0xFF);
}

bool nrf24_is_init(void) { return s_drv != NULL; }

// ── Init / Deinit ─────────────────────────────────────────────────────────────

esp_err_t nrf24_init(void)
{
    if (s_drv) return ESP_OK;

    s_drv = heap_caps_calloc(1, sizeof(nrf24_drv_t), MALLOC_CAP_SPIRAM);
    if (!s_drv) {
        ESP_LOGE(TAG, "alloc failed");
        return ESP_ERR_NO_MEM;
    }

    // CE output, start low
    gpio_config_t ce_cfg = {
        .pin_bit_mask = 1ULL << RF_HAT_NRF24_CE_GPIO,
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&ce_cfg);
    ce_low();

    // CSN output, start high (deselected)
    gpio_config_t csn_cfg = {
        .pin_bit_mask = 1ULL << RF_HAT_NRF24_CS_GPIO,
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&csn_cfg);
    csn_high();

    // SPI device: manual CS (spics_io_num=-1) to avoid pin conflict with CC1101
    spi_device_interface_config_t devcfg = {
        .clock_speed_hz = 8 * 1000 * 1000,  // 8 MHz
        .mode           = 0,
        .spics_io_num   = -1,                // manual CS via GPIO9
        .queue_size     = 4,
        .flags          = 0,
    };
    esp_err_t err = spi_bus_add_device(SPI2_HOST, &devcfg, &s_drv->spi);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "spi_bus_add_device: %s", esp_err_to_name(err));
        heap_caps_free(s_drv);
        s_drv = NULL;
        return err;
    }

    // Power-up sequence: wait 100 ms for oscillator
    nrf24_write_reg(REG_CONFIG, CONFIG_EN_CRC | CONFIG_CRCO | CONFIG_PWR_UP);
    vTaskDelay(pdMS_TO_TICKS(100));

    // Verify the chip is responding
    uint8_t st = nrf24_get_status();
    ESP_LOGI(TAG, "STATUS=0x%02X after power-up", st);
    if (st == 0x00 || st == 0xFF) {
        ESP_LOGE(TAG, "nRF24L01 not detected (STATUS=0x%02X)", st);
        spi_bus_remove_device(s_drv->spi);
        heap_caps_free(s_drv);
        s_drv = NULL;
        return ESP_ERR_NOT_FOUND;
    }

    // Sensible defaults
    nrf24_write_reg(REG_EN_AA,      0x00);   // disable auto-ack
    nrf24_write_reg(REG_EN_RXADDR,  0x01);   // enable pipe 0
    nrf24_write_reg(REG_SETUP_AW,   0x01);   // 3-byte address
    nrf24_write_reg(REG_SETUP_RETR, 0x00);   // no retransmit
    nrf24_write_reg(REG_RF_CH,      0x4C);   // channel 76 default
    nrf24_write_reg(REG_RF_SETUP,   0x07);   // 1Mbps, 0dBm
    nrf24_write_reg(REG_RX_PW_P0,   32);     // 32-byte payload
    nrf24_write_reg(REG_DYNPD,      0x00);
    nrf24_write_reg(REG_FEATURE,    0x00);

    // Default promiscuous address
    const uint8_t bcast[3] = { 0xAA, 0xAA, 0xAA };
    nrf24_write_reg_multi(REG_RX_ADDR_P0, bcast, 3);
    nrf24_write_reg_multi(REG_TX_ADDR,    bcast, 3);

    ESP_LOGI(TAG, "nRF24L01 init OK");
    return ESP_OK;
}

void nrf24_deinit(void)
{
    if (!s_drv) return;
    s_drv->cancel = true;
    ce_low();
    nrf24_write_reg(REG_CONFIG, 0x00);   // power down
    spi_bus_remove_device(s_drv->spi);
    heap_caps_free(s_drv);
    s_drv = NULL;
    gpio_reset_pin(RF_HAT_NRF24_CE_GPIO);
    gpio_reset_pin(RF_HAT_NRF24_CS_GPIO);
    ESP_LOGI(TAG, "nRF24L01 deinit");
}

// ── Configuration ─────────────────────────────────────────────────────────────

void nrf24_set_channel(uint8_t ch)
{
    if (ch > 125) ch = 125;
    nrf24_write_reg(REG_RF_CH, ch);
}

void nrf24_set_data_rate(nrf24_dr_t dr)
{
    uint8_t rf = nrf24_read_reg(REG_RF_SETUP) & ~(RF_SETUP_DR_HIGH | RF_SETUP_DR_LOW);
    switch (dr) {
        case NRF24_DR_2M:   rf |= RF_SETUP_DR_HIGH;  break;
        case NRF24_DR_250K: rf |= RF_SETUP_DR_LOW;   break;
        default: break;  // 1 Mbps: both clear
    }
    nrf24_write_reg(REG_RF_SETUP, rf);
}

void nrf24_set_pa_level(nrf24_pa_t pa)
{
    uint8_t rf = nrf24_read_reg(REG_RF_SETUP) & ~0x06;
    rf |= RF_SETUP_PWR(pa);
    nrf24_write_reg(REG_RF_SETUP, rf);
}

void nrf24_set_payload_size(uint8_t size)
{
    if (size > 32) size = 32;
    if (size < 1)  size = 1;
    nrf24_write_reg(REG_RX_PW_P0, size);
}

void nrf24_set_address(const uint8_t *addr, uint8_t len)
{
    if (len < 3) len = 3;
    if (len > 5) len = 5;
    // Encode address width in SETUP_AW: 1=3byte, 2=4byte, 3=5byte
    nrf24_write_reg(REG_SETUP_AW, len - 2);
    nrf24_write_reg_multi(REG_RX_ADDR_P0, addr, len);
    nrf24_write_reg_multi(REG_TX_ADDR,    addr, len);
}

// ── State machine ─────────────────────────────────────────────────────────────

void nrf24_power_down(void)
{
    ce_low();
    nrf24_write_reg(REG_CONFIG, CONFIG_EN_CRC | CONFIG_CRCO);
}

void nrf24_standby(void)
{
    ce_low();
    nrf24_write_reg(REG_CONFIG, CONFIG_EN_CRC | CONFIG_CRCO | CONFIG_PWR_UP);
    vTaskDelay(pdMS_TO_TICKS(2));
}

void nrf24_rx_mode(void)
{
    ce_low();
    nrf24_write_reg(REG_CONFIG,
                    CONFIG_EN_CRC | CONFIG_CRCO | CONFIG_PWR_UP | CONFIG_PRIM_RX);
    // Clear status flags
    nrf24_write_reg(REG_STATUS, STATUS_RX_DR | STATUS_TX_DS | STATUS_MAX_RT);
    nrf24_flush_rx();
    ce_high();
    esp_rom_delay_us(130);   // Tpd2stby + Tstby2a = 130 µs
}

void nrf24_flush_rx(void) { nrf24_cmd_byte(CMD_FLUSH_RX); }
void nrf24_flush_tx(void) { nrf24_cmd_byte(CMD_FLUSH_TX); }

// ── RX ────────────────────────────────────────────────────────────────────────

bool nrf24_data_ready(void)
{
    uint8_t st = nrf24_get_status();
    return (st & STATUS_RX_DR) && ((st & STATUS_RX_EMPTY) != STATUS_RX_EMPTY);
}

uint8_t nrf24_read_payload(uint8_t *buf, uint8_t max_len)
{
    uint8_t pw = nrf24_read_reg(REG_RX_PW_P0);
    if (pw > 32) pw = 32;
    if (pw > max_len) pw = max_len;

    uint8_t tx[33] = { CMD_R_PAYLOAD };
    uint8_t rx[33] = { 0 };
    csn_low();
    spi_xfer_buf(tx, rx, pw + 1);
    csn_high();
    memcpy(buf, rx + 1, pw);
    // Clear RX_DR flag
    nrf24_write_reg(REG_STATUS, STATUS_RX_DR);
    return pw;
}

// ── Carrier detect ────────────────────────────────────────────────────────────

bool nrf24_carrier_detect(void)
{
    return (nrf24_read_reg(REG_RPD) & 0x01) != 0;
}

// ── Jammer sweep ─────────────────────────────────────────────────────────────

void nrf24_jam_sweep(volatile bool *active)
{
    if (!s_drv) return;

    // PTX mode, no CRC, no AA, 2 Mbps, max power
    nrf24_write_reg(REG_EN_AA,      0x00);
    nrf24_write_reg(REG_SETUP_RETR, 0x00);
    nrf24_write_reg(REG_RF_SETUP,   RF_SETUP_DR_HIGH | RF_SETUP_PWR(3));
    nrf24_write_reg(REG_CONFIG,     CONFIG_PWR_UP);
    vTaskDelay(pdMS_TO_TICKS(2));

    uint8_t tx_cmd[33] = { CMD_W_PAYLOAD };
    memset(tx_cmd + 1, 0xFF, 32);
    uint8_t rx_tmp[33];

    nrf24_flush_tx();

    // Burst-TX pipeline: CE stays HIGH the entire sweep.
    // The nRF24 reads RF_CH at each packet boundary, so we update RF_CH + FIFO
    // while the previous packet is still transmitting (~148 µs at 2 Mbps).
    // SPI setup per channel (~50 µs) finishes well before the packet ends,
    // so the chip never stalls — it immediately starts the next packet on the
    // new channel as soon as the current one finishes.
    // Effective rate: ~54 full-band sweeps/second vs ~5 with the CE-pulse approach.

    uint8_t ch = 0;
    nrf24_write_reg(REG_RF_CH, ch);
    csn_low(); spi_xfer_buf(tx_cmd, rx_tmp, 33); csn_high();
    ce_high();  // CE stays HIGH: burst TX, never stop transmitting

    while (active && *active) {
        ch = (ch >= 125) ? 0 : ch + 1;

        // Write next channel and payload while current packet is in-flight
        nrf24_write_reg(REG_RF_CH, ch);
        csn_low(); spi_xfer_buf(tx_cmd, rx_tmp, 33); csn_high();
        nrf24_write_reg(REG_STATUS, 0x70);

        // Yield once per full sweep: briefly lower CE so vTaskDelay can run
        // and IDLE task resets the WDT (~18 ms gap per sweep is acceptable)
        if (ch == 0) {
            ce_low();
            vTaskDelay(1);
            ce_high();
            nrf24_write_reg(REG_RF_CH, ch);
            csn_low(); spi_xfer_buf(tx_cmd, rx_tmp, 33); csn_high();
        }
    }

    ce_low();
    nrf24_standby();
}

// ── Capture control ───────────────────────────────────────────────────────────

void nrf24_capture_cancel(void)
{
    if (s_drv) s_drv->cancel = true;
}

int nrf24_capture_count(void)
{
    return s_drv ? s_drv->cap_count : 0;
}

// ── Channel scanner ───────────────────────────────────────────────────────────

esp_err_t nrf24_scan_channels(uint8_t start_ch, uint8_t stop_ch,
                               nrf24_scan_cb_t cb, void *ctx,
                               volatile bool *cancel)
{
    if (!s_drv) return ESP_ERR_INVALID_STATE;
    if (start_ch > 125) start_ch = 125;
    if (stop_ch  > 125) stop_ch  = 125;

    s_drv->cancel = false;
    // No CRC for carrier detection
    nrf24_write_reg(REG_CONFIG, CONFIG_PWR_UP | CONFIG_PRIM_RX);
    nrf24_write_reg(REG_EN_AA, 0x00);

    for (uint8_t ch = start_ch; ch <= stop_ch; ch++) {
        if ((cancel && *cancel) || s_drv->cancel) break;
        nrf24_write_reg(REG_RF_CH, ch);
        ce_high();
        esp_rom_delay_us(200);   // slightly longer than Tstby2a
        bool carrier = nrf24_carrier_detect();
        ce_low();
        if (cb) cb(ch, carrier, ctx);
    }
    return ESP_OK;
}

// ── Packet sniffer ────────────────────────────────────────────────────────────

esp_err_t nrf24_sniff(uint8_t channel, uint8_t payload_len,
                      nrf24_rx_cb_t cb, void *ctx,
                      uint32_t timeout_ms, volatile bool *cancel)
{
    if (!s_drv) return ESP_ERR_INVALID_STATE;

    s_drv->cancel  = false;
    s_drv->cap_count = 0;

    nrf24_write_reg(REG_RF_CH,    channel);
    nrf24_write_reg(REG_RX_PW_P0, payload_len > 32 ? 32 : payload_len);
    nrf24_write_reg(REG_EN_AA,    0x00);
    // No CRC to capture any packet on channel
    nrf24_write_reg(REG_CONFIG,   CONFIG_PWR_UP | CONFIG_PRIM_RX);
    nrf24_write_reg(REG_STATUS,   STATUS_RX_DR | STATUS_TX_DS | STATUS_MAX_RT);
    nrf24_flush_rx();
    ce_high();

    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;

    while (!s_drv->cancel && !(cancel && *cancel)) {
        if (timeout_ms > 0 && esp_timer_get_time() >= deadline) break;
        if (nrf24_data_ready()) {
            nrf24_packet_t pkt = { .channel = channel };
            pkt.len = nrf24_read_payload(pkt.data, 32);
            s_drv->cap_count++;
            if (cb) cb(&pkt, ctx);
        }
        vTaskDelay(pdMS_TO_TICKS(20));  // must yield ≥1 tick at 100 Hz (pdMS_TO_TICKS(1)=0)
    }
    ce_low();
    nrf24_flush_rx();
    return ESP_OK;
}

// ── Futaba S-FHSS scanner ─────────────────────────────────────────────────────

esp_err_t nrf24_sfhss_scan(nrf24_sfhss_t *out, uint32_t timeout_ms,
                            volatile bool *cancel)
{
    if (!s_drv || !out) return ESP_ERR_INVALID_ARG;

    memset(out, 0, sizeof(*out));
    s_drv->cancel  = false;
    s_drv->cap_count = 0;

    // S-FHSS config: 1 Mbps, 2-byte CRC, 10-byte payload, 3-byte sync addr
    nrf24_write_reg(REG_EN_AA,    0x00);
    nrf24_write_reg(REG_SETUP_AW, 0x01);  // 3-byte
    nrf24_write_reg(REG_RF_SETUP, 0x07);  // 1Mbps, 0 dBm
    nrf24_write_reg_multi(REG_RX_ADDR_P0, SFHSS_ADDR, SFHSS_ADDR_LEN);
    nrf24_write_reg(REG_RX_PW_P0, SFHSS_PAYLOAD);
    nrf24_write_reg(REG_CONFIG,
                    CONFIG_EN_CRC | CONFIG_CRCO | CONFIG_PWR_UP | CONFIG_PRIM_RX);

    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;

    while (!s_drv->cancel && !(cancel && *cancel)) {
        if (esp_timer_get_time() >= deadline) break;

        // Hop through S-FHSS channels
        for (int i = 0; i < (int)SFHSS_N_CHANNELS; i++) {
            if (s_drv->cancel || (cancel && *cancel)) break;
            nrf24_write_reg(REG_RF_CH, SFHSS_CHANNELS[i]);
            nrf24_write_reg(REG_STATUS, STATUS_RX_DR | STATUS_TX_DS | STATUS_MAX_RT);
            nrf24_flush_rx();
            ce_high();
            esp_rom_delay_us(400);   // longer dwell for FHSS hop detection
            bool ready = nrf24_data_ready();
            ce_low();

            if (ready) {
                uint8_t buf[32] = { 0 };
                nrf24_read_payload(buf, SFHSS_PAYLOAD);
                out->found   = true;
                out->channel = SFHSS_CHANNELS[i];
                memcpy(out->raw, buf, SFHSS_PAYLOAD);
                s_drv->cap_count++;

                // Attempt basic S-FHSS channel decode
                // S-FHSS frame: 2 flag bytes + 8 channels × 10 bits packed
                // bit-packing: ch0[9:0] = buf[2]<<2 | buf[3]>>6, etc.
                // (simplified — actual bit layout may vary by TX firmware)
                for (int c = 0; c < 8; c++) {
                    int byte_ofs = 2 + (c * 10) / 8;
                    int bit_ofs  = (c * 10) % 8;
                    if (byte_ofs + 1 < SFHSS_PAYLOAD) {
                        uint16_t raw16 = ((uint16_t)buf[byte_ofs] << 8) | buf[byte_ofs + 1];
                        out->servo[c] = (raw16 >> (6 - bit_ofs)) & 0x3FF;
                    }
                }
                return ESP_OK;
            }
            vTaskDelay(pdMS_TO_TICKS(20));  // yield to let main task reset WDT between channel hops
        }
    }
    return out->found ? ESP_OK : ESP_ERR_TIMEOUT;
}

// ── .nrf24 file format ────────────────────────────────────────────────────────
// Flipper-compatible text format:
//   Filetype: Flipper NRF24 RAW File
//   Version: 1
//   Channel: XX
//   Rate: 1M|2M|250K
//   Address: HH HH HH [HH [HH]]
//   Payload_Size: N
//   Packet_Raw: HH HH ... (one per packet)

esp_err_t nrf24_capture_save(const nrf24_capture_t *cap, const char *path)
{
    if (!cap || !path) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen(path, "w");
    if (!f) return ESP_FAIL;

    fprintf(f, "Filetype: Flipper NRF24 RAW File\r\n");
    fprintf(f, "Version: 1\r\n");
    fprintf(f, "Channel: %u\r\n", cap->channel);
    fprintf(f, "Rate: 1M\r\n");
    fprintf(f, "Address:");
    for (int i = 0; i < cap->addr_len && i < 5; i++)
        fprintf(f, " %02X", cap->addr[i]);
    fprintf(f, "\r\n");
    fprintf(f, "Payload_Size: %u\r\n", cap->payload_len);
    for (int p = 0; p < cap->count; p++) {
        fprintf(f, "Packet_Raw:");
        for (int b = 0; b < cap->pkts[p].len; b++)
            fprintf(f, " %02X", cap->pkts[p].data[b]);
        fprintf(f, "\r\n");
    }
    fclose(f);
    return ESP_OK;
}

esp_err_t nrf24_capture_load(const char *path, nrf24_capture_t *out)
{
    if (!path || !out) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen(path, "r");
    if (!f) return ESP_FAIL;

    memset(out, 0, sizeof(*out));
    out->addr_len   = 3;
    out->payload_len = 32;

    // First pass: count packets
    char line[128];
    int pkt_count = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Packet_Raw:", 11) == 0) pkt_count++;
    }
    if (pkt_count == 0) { fclose(f); return ESP_ERR_NOT_FOUND; }

    out->pkts = heap_caps_calloc(pkt_count, sizeof(nrf24_packet_t), MALLOC_CAP_SPIRAM);
    if (!out->pkts) { fclose(f); return ESP_ERR_NO_MEM; }

    // Second pass: parse
    rewind(f);
    int idx = 0;
    while (fgets(line, sizeof(line), f) && idx < pkt_count) {
        if (strncmp(line, "Channel:", 8) == 0)
            out->channel = (uint8_t)atoi(line + 8);
        else if (strncmp(line, "Payload_Size:", 13) == 0)
            out->payload_len = (uint8_t)atoi(line + 13);
        else if (strncmp(line, "Address:", 8) == 0) {
            char *p = line + 8;
            int ai = 0;
            while (*p && ai < 5) {
                while (*p == ' ') p++;
                if (*p == '\0' || *p == '\r' || *p == '\n') break;
                out->addr[ai++] = (uint8_t)strtol(p, &p, 16);
            }
            out->addr_len = ai;
        } else if (strncmp(line, "Packet_Raw:", 11) == 0) {
            char *p = line + 11;
            out->pkts[idx].channel = out->channel;
            int bi = 0;
            while (*p && bi < 32) {
                while (*p == ' ') p++;
                if (*p == '\0' || *p == '\r' || *p == '\n') break;
                out->pkts[idx].data[bi++] = (uint8_t)strtol(p, &p, 16);
            }
            out->pkts[idx].len = bi;
            idx++;
        }
    }
    fclose(f);
    out->count = idx;
    return ESP_OK;
}

void nrf24_capture_free(nrf24_capture_t *cap)
{
    if (!cap) return;
    if (cap->pkts) { heap_caps_free(cap->pkts); cap->pkts = NULL; }
    cap->count = 0;
}
