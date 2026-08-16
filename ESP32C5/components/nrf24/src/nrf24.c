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
#define RF_SETUP_DR_HIGH  0x08
#define RF_SETUP_DR_LOW   0x20
#define RF_SETUP_PWR(n)  ((n & 3) << 1)
#define RF_SETUP_PLL_LOCK 0x10   // force PLL on — required with CONT_WAVE
#define RF_SETUP_CONT_WAVE 0x80  // continuous unmodulated carrier (test mode, nRF24L01+ §6.4)

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

// ── Burst-TX jammer ──────────────────────────────────────────────────────────
// Fires 1-byte GFSK packets at 2 Mbps on each channel in rapid succession.
// Unlike CONT_WAVE, CE is pulsed per packet — TXEN follows CE naturally so
// the AT2401C works in its normal burst-amplifier role with no power-cycle
// between hops.  Channel changes happen in standby-I (~130 µs) instead of
// the full power-down/up (1 ms) CONT_WAVE requires.
//
// Per-hop timing: RF_CH write (~10 µs) + W_TX_PAYLOAD (~10 µs) +
//                 CE pulse 15 µs + packet on air ~20 µs + guard 60 µs
//                 ≈ 115 µs/hop.
// 40 BLE channels × 115 µs = 4.6 ms/sweep → ~215 sweeps/sec per channel.
// Yields 1 tick (10 ms) after each full sweep to feed LVGL and WDT.
static void s_burst_jam(volatile bool *active, const uint8_t *ch, int nch)
{
    // TX mode, no CRC, no auto-ACK, no retry, 2 Mbps, PA bits = 11 (AT2401C delivers +20 dBm)
    ce_low();
    nrf24_write_reg(REG_CONFIG,      CONFIG_PWR_UP);              // TX, no CRC
    nrf24_write_reg(REG_EN_AA,       0x00);                       // disable auto-ACK
    nrf24_write_reg(REG_SETUP_RETR,  0x00);                       // no retransmit
    nrf24_write_reg(REG_RF_SETUP,    RF_SETUP_DR_HIGH | RF_SETUP_PWR(3));  // 2 Mbps, PA=11
    static const uint8_t addr[5] = {0xAA,0xAA,0xAA,0xAA,0xAA};
    nrf24_write_reg_multi(REG_TX_ADDR, addr, 5);
    nrf24_write_reg(REG_RX_PW_P0, 1);
    nrf24_cmd_byte(CMD_FLUSH_TX);
    vTaskDelay(pdMS_TO_TICKS(2));  // Tpd2stby settle

    // nRF24L01+ TX timing from Standby-I (datasheet Table 16):
    //   Tstby2a (PLL lock):  130 µs  ← from CE HIGH
    //   1-byte packet @ 2 Mbps: ~32 µs (preamble 8µs + addr 20µs + payload 4µs)
    //   Total minimum:       ~162 µs from CE HIGH before chip is back in Standby-I
    // We use 10 µs CE pulse + 200 µs post-CE-low = 210 µs total — safe margin.
    // Bruce firmware reference: ~350 µs/hop.
    // Previous value was 75 µs (90 µs total) — too short: PLL never locked, FIFO
    // filled after 3 hops, and no signal appeared on TinySA.
    while (active && *active) {
        for (int i = 0; i < nch && *active; i++) {
            nrf24_write_reg(REG_RF_CH, ch[i]);            // set channel (chip in Standby-I)
            uint8_t tx_pkt[2] = { CMD_W_PAYLOAD, 0xAA }; // 1-byte jam payload
            csn_low(); spi_xfer_buf(tx_pkt, NULL, 2); csn_high();
            ce_high();
            esp_rom_delay_us(10);                         // ≥10 µs minimum CE pulse
            ce_low();
            esp_rom_delay_us(200);                        // 130 µs PLL + 32 µs TX + margin
            nrf24_write_reg(REG_STATUS, 0x30);            // clear TX_DS + MAX_RT
        }
        nrf24_cmd_byte(CMD_FLUSH_TX);
        vTaskDelay(pdMS_TO_TICKS(10));  // yield 1 tick between sweeps for LVGL/WDT
    }
}

// ── Jammer sweep ─────────────────────────────────────────────────────────────

void nrf24_jam_sweep(volatile bool *active, nrf24_jam_mode_t mode)
{
    if (!s_drv) return;

    // ── Continuous-carrier (CONT_WAVE) jamming — Bruce-compatible PA sequence ─
    // nRF24L01+ §6.4: RF_SETUP.CONT_WAVE=1 + RF_SETUP.PLL_LOCK=1 with CE HIGH
    // emits an unmodulated carrier at 100% duty cycle per channel dwell.
    //
    // The AT2401C PA+LNA requires a full power-down/power-up cycle between hops.
    // Cheaper approaches (CE toggle alone, RF_SETUP clear+reset alone) suppress
    // the carrier entirely — observed as zero signal on TinySA in v2.12.7/8.
    // This matches Bruce firmware's nrf_jammer_api.cpp PA-module path exactly.
    //
    // Per-hop sequence (~2 ms total):
    //   CE low + clear CONT_WAVE+PLL_LOCK  ->  power-down CONFIG  ->  500 us
    //   ->  power-up CONFIG  ->  500 us  ->  write RF_CH  ->  re-arm CONT_WAVE+PLL_LOCK
    //   ->  CE high  ->  1 ms carrier dwell
    //
    // Yield every 20 hops (40 ms max CPU hold) keeps LVGL render times normal.
    // Do NOT increase this: 82 hops * 2 ms = 164 ms starvation causes WDT warnings.

    // ── Build channel list for the requested mode ─────────────────────────────
    // BLE:    40 ch at 2 MHz spacing (2402-2480 MHz) — every BLE data+adv hop.
    // BT:     82 ch 1 MHz spacing (2-80) with BLE adv ch doubled for 2× density.
    // WiFi:   33 ch around 2.4 GHz ch 1/6/11 centers (+/-5 MHz each).
    // ALL:    126 ch (0-125 = 2400-2525 MHz, full ISM band, CONT_WAVE).
    // HID:    25 ch at 3 MHz spacing (5-77 MHz) — Logitech Unifying / MS wireless.
    // RC:     79 ch at 1 MHz (2-80) — full range FHSS RC without BLE doubling.
    // Zigbee: 16 ch at 5 MHz spacing (5-80) — IEEE 802.15.4 ch11-26.

    uint8_t channels[128];
    int nch = 0;

    switch (mode) {
        case NRF24_JAM_BLE:
            // All 40 BLE channels (advertising + data) at 2 MHz spacing 2402-2480 MHz.
            // nRF24 ch = (freq - 2400): ch 2,4,6,...,80 — covers every BLE data hop.
            for (uint8_t c = 2; c <= 80; c += 2) channels[nch++] = c;
            break;

        default:
        case NRF24_JAM_BT:
            // 79 BT Classic channels (1 MHz spacing 2402-2480 MHz, nRF24 ch 2-80).
            // BLE adv channels 2/26/80 doubled for 2× coverage — disrupts AFH below
            // the 20-clean-channel threshold that BT requires to maintain a link.
            for (uint8_t c = 2; c <= 80; c++) {
                channels[nch++] = c;
                if (c == 2 || c == 26 || c == 80)
                    channels[nch++] = c;
            }
            break;

        case NRF24_JAM_WIFI: {
            // +/-5 MHz band around WiFi ch 1 (2412), ch 6 (2437), ch 11 (2462).
            // nRF24 channel N = 2400+N MHz.
            static const uint8_t wifi_zones[3][2] = {{7,17},{32,42},{57,67}};
            for (int z = 0; z < 3; z++)
                for (uint8_t c = wifi_zones[z][0]; c <= wifi_zones[z][1]; c++)
                    channels[nch++] = c;
            break;
        }

        case NRF24_JAM_ALL:
            // Full nRF24 range: 2400-2525 MHz.
            for (uint8_t c = 0; c <= 125; c++)
                channels[nch++] = c;
            break;

        case NRF24_JAM_HID:
            // Wireless HID — Logitech Unifying / Microsoft 2.4 GHz mice and keyboards.
            // Protocols hop at ~3 MHz spacing over 2405-2477 MHz (25 channels).
            // nRF24 ch 5,8,11,...,77 (ch = freq - 2400).
            for (uint8_t c = 5; c <= 77; c += 3) channels[nch++] = c;
            break;

        case NRF24_JAM_RC:
            // RC toys and drones — full 2402-2480 MHz sweep at 1 MHz resolution.
            // FHSS RC protocols (DSMX, FlySky AFHDS2A, FrSky) hop across the entire
            // band; 1 MHz sweep without BLE channel doubling maximises hop speed.
            for (uint8_t c = 2; c <= 80; c++) channels[nch++] = c;
            break;

        case NRF24_JAM_ZIGBEE:
            // IEEE 802.15.4 channels 11-26 in the 2.4 GHz band.
            // f = 2405 + 5*(ch-11) MHz -> nRF24 ch = f - 2400: 5,10,15,...,80 (16 ch).
            for (uint8_t c = 5; c <= 80; c += 5) channels[nch++] = c;
            break;
    }

    // All modes except WiFi use burst TX — modulated GFSK, fast hop in
    // standby-I (~210 µs/ch) vs the 2 ms AT2401C power-cycle CONT_WAVE requires.
    //
    // ALL mode (126 ch × 210 µs = ~26 ms/sweep) = equivalent of Bruce firmware
    // "Test" mode: full ISM band burst TX sweep that leaves no clean FHSS channel
    // for BT AFH to escape to.  CONT_WAVE ALL was 252 ms/sweep — 10× slower.
    //
    // WiFi keeps CONT_WAVE: targeted continuous carrier around ch 1/6/11
    // drowns out WiFi OFDM more effectively than short burst packets.
    if (mode != NRF24_JAM_WIFI) {
        s_burst_jam(active, channels, nch);
        nrf24_standby();
        return;
    }

    const uint8_t RF_SETUP_JAM = RF_SETUP_CONT_WAVE | RF_SETUP_PLL_LOCK | RF_SETUP_PWR(3);
    const uint8_t RF_SETUP_CLR = RF_SETUP_PWR(3);

    // Initial power-up into TX mode (CONT_WAVE path for WiFi / ALL modes)
    ce_low();
    nrf24_write_reg(REG_EN_AA,      0x00);
    nrf24_write_reg(REG_SETUP_RETR, 0x00);
    nrf24_write_reg(REG_CONFIG,     CONFIG_PWR_UP);
    vTaskDelay(pdMS_TO_TICKS(2));

    // Each hop busy-waits ~2 ms (500+500+1000 µs).  Yielding every 20 hops
    // caps LVGL starvation at ~40 ms — well under the 10 s WDT threshold and
    // short enough that render times stay normal.  Do NOT yield less often:
    // 82 hops × 2 ms = 164 ms between yields starves priority-1 LVGL for
    // 500+ ms (observed as CRITICAL render warnings in the serial log).
    int idx = 0, hops_since_yield = 0;
    while (active && *active) {
        // Bruce PA-module hop sequence: full power cycle ensures AT2401C
        // re-locks to the new channel on every hop.
        ce_low();
        nrf24_write_reg(REG_RF_SETUP, RF_SETUP_CLR);   // clear CONT_WAVE+PLL_LOCK
        nrf24_write_reg(REG_CONFIG,   0x00);            // power down
        esp_rom_delay_us(500);

        nrf24_write_reg(REG_CONFIG,   CONFIG_PWR_UP);   // power up
        esp_rom_delay_us(500);

        nrf24_write_reg(REG_RF_CH,    channels[idx]);   // new channel
        nrf24_write_reg(REG_RF_SETUP, RF_SETUP_JAM);   // arm CONT_WAVE+PLL_LOCK
        ce_high();
        esp_rom_delay_us(1000);                         // 1 ms carrier dwell

        if (++idx >= nch) idx = 0;

        if (++hops_since_yield >= 20) {
            hops_since_yield = 0;
            vTaskDelay(pdMS_TO_TICKS(20));  // yield ~40 ms of CPU to LVGL every 20 hops
        }
    }

    // Teardown: leave chip in a clean state for scan/sniffer/HW-test.
    ce_low();
    nrf24_write_reg(REG_RF_SETUP, RF_SETUP_CLR);
    nrf24_write_reg(REG_CONFIG,   0x00);        // power down
    vTaskDelay(pdMS_TO_TICKS(2));
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
        esp_rom_delay_us(140);   // ≥130 µs for RPD latch (nRF24L01+ datasheet)
        bool carrier = nrf24_carrier_detect();
        ce_low();
        if (cb) cb(ch, carrier, ctx);
        // Yield every 8 channels — 126×200µs was starving the LVGL main loop
        if ((ch & 0x07) == 0x07) vTaskDelay(pdMS_TO_TICKS(10));
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
        // Drain the full 3-deep RX FIFO each poll cycle — a single `if` silently
        // drops up to 2 packets that arrived since the last tick.
        while (nrf24_data_ready()) {
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
    // FAT/SD SPI transactions share SPI2_HOST with the display DMA.  Without
    // sd_spi_mutex the display flush (inside lv_timer_handler) blocks on the
    // SPI host's internal lock while holding sd_spi_mutex, freezing the main
    // loop for the entire save duration (observed: 785 ms – 1530 ms stalls).
    if (sd_spi_mutex) xSemaphoreTake(sd_spi_mutex, portMAX_DELAY);
    FILE *f = fopen(path, "w");
    if (!f) {
        if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
        return ESP_FAIL;
    }

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
    if (sd_spi_mutex) xSemaphoreGive(sd_spi_mutex);
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
