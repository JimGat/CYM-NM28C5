#include "hf/pn532_driver.h"
#include "rf_hat_config.h"
#include "driver/i2c_master.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "pn532";

// ── I2C config ────────────────────────────────────────────────────────────────
#define PN532_I2C_ADDR      0x24
#define PN532_I2C_FREQ_HZ   100000
#define PN532_I2C_PORT      I2C_NUM_0
#define PN532_I2C_TIMEOUT   500    // ms per transfer (passed as-is to xfer_timeout_ms — NOT ticks)

// ── Frame bytes ───────────────────────────────────────────────────────────────
#define PN532_PREAMBLE      0x00
#define PN532_STARTCODE1    0x00
#define PN532_STARTCODE2    0xFF
#define PN532_POSTAMBLE     0x00
#define PN532_TFI_HOST      0xD4   // host → PN532
#define PN532_TFI_PN532     0xD5   // PN532 → host

// PN532 command codes
#define PN532_CMD_GET_FW_VERSION  0x02
#define PN532_CMD_SAM_CONFIGURE   0x14
#define PN532_CMD_RF_CONFIGURATION 0x32
#define PN532_CMD_IN_LIST_PASSIVE 0x4A
#define PN532_CMD_IN_DATA_EXCHANGE 0x40
#define PN532_CMD_IN_SELECT       0x54
#define PN532_CMD_IN_RELEASE      0x52

// I2C "ready" status byte
#define PN532_I2C_READY     0x01

static i2c_master_bus_handle_t s_bus  = NULL;
static i2c_master_dev_handle_t s_dev  = NULL;
static bool                    s_init = false;

// ── Internal helpers ──────────────────────────────────────────────────────────

// Poll PN532 ready byte; returns RFID_OK when ready, RFID_ERR_TIMEOUT if not.
static rfid_err_t s_wait_ready(uint32_t timeout_ms)
{
    uint8_t rdy;
    uint32_t elapsed = 0;
    while (elapsed < timeout_ms) {
        esp_err_t e = i2c_master_receive(s_dev, &rdy, 1, PN532_I2C_TIMEOUT);
        if (e == ESP_OK && rdy == PN532_I2C_READY) return RFID_OK;
        vTaskDelay(pdMS_TO_TICKS(5));
        elapsed += 5;
    }
    return RFID_ERR_TIMEOUT;
}

// Build and write a PN532 command frame over I2C.
static rfid_err_t s_write_frame(const uint8_t *cmd, uint8_t cmd_len)
{
    // Frame: PREAMBLE START1 START2 LEN LCS TFI cmd[0..cmd_len-1] DCS POSTAMBLE
    // LEN = cmd_len + 1 (TFI counts)
    uint8_t frame[PN532_MAX_FRAME_DATA + 8];
    uint8_t len = cmd_len + 1;  // TFI + command bytes
    uint8_t lcs = (uint8_t)(~len + 1);

    uint8_t dcs = PN532_TFI_HOST;
    for (int i = 0; i < cmd_len; i++) dcs += cmd[i];
    dcs = (uint8_t)(~dcs + 1);

    int idx = 0;
    frame[idx++] = PN532_PREAMBLE;
    frame[idx++] = PN532_STARTCODE1;
    frame[idx++] = PN532_STARTCODE2;
    frame[idx++] = len;
    frame[idx++] = lcs;
    frame[idx++] = PN532_TFI_HOST;
    memcpy(frame + idx, cmd, cmd_len);
    idx += cmd_len;
    frame[idx++] = dcs;
    frame[idx++] = PN532_POSTAMBLE;

    esp_err_t e = i2c_master_transmit(s_dev, frame, (size_t)idx,
                                       PN532_I2C_TIMEOUT);
    if (e != ESP_OK) {
        ESP_LOGW(TAG, "I2C write failed: %s", esp_err_to_name(e));
        return RFID_ERR_HW;
    }
    return RFID_OK;
}

// Read and validate ACK frame (6 bytes after 1 RDY byte).
static rfid_err_t s_read_ack(void)
{
    static const uint8_t ACK[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
    uint8_t buf[7];

    rfid_err_t r = s_wait_ready(100);
    if (r != RFID_OK) return r;

    esp_err_t e = i2c_master_receive(s_dev, buf, 7, PN532_I2C_TIMEOUT);
    if (e != ESP_OK) return RFID_ERR_HW;

    // buf[0] = RDY (already 0x01 from wait_ready), buf[1..6] = ACK frame
    if (memcmp(buf + 1, ACK, 6) != 0) {
        ESP_LOGW(TAG, "ACK mismatch: %02X %02X %02X %02X %02X %02X",
                 buf[1], buf[2], buf[3], buf[4], buf[5], buf[6]);
        return RFID_ERR_HW;
    }
    return RFID_OK;
}

// ── Public API ────────────────────────────────────────────────────────────────

rfid_err_t pn532_driver_init(void)
{
    if (s_init) return RFID_OK;

    // Clear any GPIO matrix routing from prior peripheral use (RMT/IR/RF433).
    // Do NOT configure direction or drive the pins here — the I2C driver owns them.
    gpio_reset_pin((gpio_num_t)RF_HAT_PN532_SCL_GPIO);
    gpio_reset_pin((gpio_num_t)RF_HAT_PN532_SDA_GPIO);

    i2c_master_bus_config_t bus_cfg = {
        .i2c_port = PN532_I2C_PORT,
        .sda_io_num = RF_HAT_PN532_SDA_GPIO,
        .scl_io_num = RF_HAT_PN532_SCL_GPIO,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    esp_err_t e = i2c_new_master_bus(&bus_cfg, &s_bus);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "i2c_new_master_bus failed: %s", esp_err_to_name(e));
        return RFID_ERR_HW;
    }

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = PN532_I2C_ADDR,
        .scl_speed_hz = PN532_I2C_FREQ_HZ,
    };
    e = i2c_master_bus_add_device(s_bus, &dev_cfg, &s_dev);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "i2c_master_bus_add_device failed: %s", esp_err_to_name(e));
        i2c_del_master_bus(s_bus);
        s_bus = NULL;
        return RFID_ERR_HW;
    }

    // Send 9 SCL clocks + STOP to release any slave holding SDA LOW, then settle.
    i2c_master_bus_reset(s_bus);
    vTaskDelay(pdMS_TO_TICKS(20));

    // PN532 I2C wakeup: after bus_reset the PN532 ignores command frames until
    // it sees a proper wakeup (START + its address byte). i2c_master_probe()
    // provides exactly that. 50 ms stabilisation is conservative (spec: <1 ms)
    // but harmless. Without this, SAM configure returns ESP_ERR_INVALID_RESPONSE
    // (device ACKs address, NACKs the first data byte of the command frame).
    i2c_master_probe(s_bus, PN532_I2C_ADDR, 50);
    vTaskDelay(pdMS_TO_TICKS(50));

    s_init = true;
    ESP_LOGI(TAG, "I2C init: SCL=GPIO%d SDA=GPIO%d addr=0x%02X",
             RF_HAT_PN532_SCL_GPIO, RF_HAT_PN532_SDA_GPIO, PN532_I2C_ADDR);
    return RFID_OK;
}

void pn532_driver_deinit(void)
{
    if (!s_init) return;
    pn532_rf_field_off();
    if (s_dev) { i2c_master_bus_rm_device(s_dev); s_dev = NULL; }
    if (s_bus) { i2c_del_master_bus(s_bus);        s_bus = NULL; }
    s_init = false;
    ESP_LOGI(TAG, "deinit");
}

bool pn532_driver_is_init(void) { return s_init; }

rfid_err_t pn532_send_command(const uint8_t *cmd, uint8_t cmd_len)
{
    if (!s_init) return RFID_ERR_NOT_INIT;
    rfid_err_t r = s_write_frame(cmd, cmd_len);
    if (r != RFID_OK) return r;
    return s_read_ack();
}

rfid_err_t pn532_read_response(uint8_t expected_cmd, uint8_t *buf, uint8_t *buf_len,
                                uint8_t buf_max, uint32_t timeout_ms)
{
    if (!s_init) return RFID_ERR_NOT_INIT;

    rfid_err_t r = s_wait_ready(timeout_ms);
    if (r != RFID_OK) return r;

    // Read maximum possible frame: 1(RDY) + 5(header) + buf_max + 2(DCS+POST)
    uint8_t raw[PN532_MAX_FRAME_DATA + 8];
    size_t read_len = (size_t)buf_max + 8;
    if (read_len > sizeof(raw)) read_len = sizeof(raw);

    esp_err_t e = i2c_master_receive(s_dev, raw, read_len,
                                      PN532_I2C_TIMEOUT);
    if (e != ESP_OK) return RFID_ERR_HW;

    // raw[0] = RDY, raw[1]=0x00, raw[2]=0x00, raw[3]=0xFF, raw[4]=LEN, raw[5]=LCS
    // raw[6] = TFI(0xD5), raw[7] = CMD+1, raw[8..] = data
    if (raw[1] != 0x00 || raw[2] != 0x00 || raw[3] != 0xFF) {
        ESP_LOGW(TAG, "Bad frame header: %02X %02X %02X", raw[1], raw[2], raw[3]);
        return RFID_ERR_HW;
    }
    uint8_t len = raw[4];
    if (raw[6] != PN532_TFI_PN532) {
        // Detect the PN532 ERROR FRAME (00 00 FF 01 FF 7F 81 00):
        // LEN=0x01, LCS=0xFF, data=0x7F, DCS=0x81 — means "syntax error /
        // command not supported." PN532 firmware v1.6 returns this for
        // RFConfiguration(0x0A) and InDataExchange with GET_VERSION (0x60).
        // Log at DEBUG (not WARNING) since it is expected and not actionable.
        if (raw[4] == 0x01 && raw[5] == 0xFF && raw[6] == 0x7F) {
            ESP_LOGD(TAG, "PN532 ERROR FRAME (cmd unsupported, fw1.6)");
        } else {
            ESP_LOGW(TAG, "TFI mismatch: got 0x%02X want 0xD5 — "
                     "raw[0..9]: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                     raw[6],
                     raw[0], raw[1], raw[2], raw[3], raw[4],
                     raw[5], raw[6], raw[7], raw[8], raw[9]);
        }
        return RFID_ERR_HW;
    }
    if (raw[7] != (uint8_t)(expected_cmd + 1)) {
        ESP_LOGW(TAG, "Cmd mismatch: got 0x%02X want 0x%02X", raw[7], expected_cmd + 1);
        return RFID_ERR_HW;
    }
    // data starts at raw[8], length = len - 2 (TFI + CMD bytes)
    uint8_t data_len = (len >= 2) ? (len - 2) : 0;
    if (data_len > buf_max) data_len = buf_max;
    if (buf)     memcpy(buf, raw + 8, data_len);
    if (buf_len) *buf_len = data_len;
    return RFID_OK;
}

rfid_err_t pn532_sam_configure(void)
{
    // Normal mode (0x01), no timeout (0x00), no IRQ (0x00)
    uint8_t cmd[] = { PN532_CMD_SAM_CONFIGURE, 0x01, 0x14, 0x01 };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;
    uint8_t resp[1];
    uint8_t rlen = 0;
    return pn532_read_response(PN532_CMD_SAM_CONFIGURE, resp, &rlen, sizeof(resp), 100);
}

rfid_err_t pn532_rf_field_on(void)
{
    // RFConfiguration: Config item 1 (RF Field), value 0x01 (on)
    uint8_t cmd[] = { PN532_CMD_RF_CONFIGURATION, 0x01, 0x01 };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;
    uint8_t resp[1]; uint8_t rlen = 0;
    return pn532_read_response(PN532_CMD_RF_CONFIGURATION, resp, &rlen, sizeof(resp), 100);
}

rfid_err_t pn532_rf_field_off(void)
{
    if (!s_init) return RFID_OK;
    uint8_t cmd[] = { PN532_CMD_RF_CONFIGURATION, 0x01, 0x00 };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;
    uint8_t resp[1]; uint8_t rlen = 0;
    return pn532_read_response(PN532_CMD_RF_CONFIGURATION, resp, &rlen, sizeof(resp), 100);
}

rfid_err_t pn532_rf_field_cycle(void)
{
    // Toggle RF off→on to reset card state — helps ISO14443A cards that are
    // slow to respond after extended no-field exposure or marginal coupling.
    rfid_err_t r = pn532_rf_field_off();
    vTaskDelay(pdMS_TO_TICKS(5));
    if (r != RFID_OK) return r;
    return pn532_rf_field_on();
}

rfid_err_t pn532_rf_configure_sensitivity(void)
{
    // RFConfiguration(0x0A) — ISO14443A 106 kbps analog settings.
    // Raises RxGain from default 38 dB → 48 dB (maximum) and lowers
    // RxThreshold MinLevel from 8 → 6 for better weak-coupling detection
    // on compact PCB antennas like the NM-RF-HAT.
    //
    // Default values (from PN532 UM10232 Table 119):
    //   CIU_RFCfg=0x59(38dB), GsNOn=0xF4, CWGsP=0x85, ModGsP=0x15,
    //   Demod=0x8A, RxThreshold=0x8A(MinLevel=8), ManualRCV=0x0B
    //
    // Modified:
    //   CIU_RFCfg: bits[6:4]=111 → 48dB max gain  (was 0x59 = 38dB)
    //   RxThreshold: MinLevel=6  → 0x6A            (was 0x8A = MinLevel=8)
    //   All other bytes unchanged from datasheet defaults.
    uint8_t cmd[] = {
        PN532_CMD_RF_CONFIGURATION, 0x0A,
        0x7F,   // CIU_RFCfg:      RxGain=111 (48 dB max) vs default 0x59 (38 dB)
        0xF4,   // CIU_GsNOn:      default
        0x85,   // CIU_CWGsP:      default
        0x15,   // CIU_ModGsP:     default
        0x8A,   // CIU_Demod:      default
        0x6A,   // CIU_RxThreshold:MinLevel=6 vs default 0x8A(MinLevel=8)
        0x0B,   // CIU_ManualRCV:  default
    };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) {
        ESP_LOGW(TAG, "rf_configure_sensitivity: send failed: %s", rfid_err_str(r));
        return r;
    }
    uint8_t resp[1]; uint8_t rlen = 0;
    r = pn532_read_response(PN532_CMD_RF_CONFIGURATION, resp, &rlen, sizeof(resp), 500);
    if (r == RFID_OK)
        ESP_LOGI(TAG, "RF sensitivity configured: RxGain=48dB RxThreshold=0x6A");
    else
        ESP_LOGW(TAG, "rf_configure_sensitivity: response failed: %s", rfid_err_str(r));
    return r;
}

rfid_err_t pn532_recover(void)
{
    // Attempt to recover from PN532 lockup (I2C NACK after extended idle scan).
    // Sequence: bus reset → probe → SAM configure → sensitivity config.
    ESP_LOGW(TAG, "[RECOVER] PN532 I2C lockup detected — attempting recovery");
    if (!s_bus) return RFID_ERR_NOT_INIT;

    i2c_master_bus_reset(s_bus);
    vTaskDelay(pdMS_TO_TICKS(20));

    esp_err_t e = i2c_master_probe(s_bus, PN532_I2C_ADDR, 50);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "[RECOVER] PN532 not responding at 0x24 after bus reset");
        return RFID_ERR_HW;
    }
    vTaskDelay(pdMS_TO_TICKS(50));

    rfid_err_t r = pn532_sam_configure();
    if (r != RFID_OK) {
        ESP_LOGE(TAG, "[RECOVER] SAM configure failed after bus reset: %s", rfid_err_str(r));
        return r;
    }
    r = pn532_rf_configure_sensitivity();
    if (r == RFID_OK)
        ESP_LOGI(TAG, "[RECOVER] Recovery successful");
    return r;
}

rfid_err_t pn532_get_firmware_version(pn532_fw_version_t *out)
{
    if (!s_init) return RFID_ERR_NOT_INIT;
    uint8_t cmd[] = { PN532_CMD_GET_FW_VERSION };
    rfid_err_t r = pn532_send_command(cmd, sizeof(cmd));
    if (r != RFID_OK) return r;

    uint8_t resp[4]; uint8_t rlen = 0;
    r = pn532_read_response(PN532_CMD_GET_FW_VERSION, resp, &rlen, sizeof(resp), 500);
    if (r != RFID_OK) return r;
    if (rlen < 4) return RFID_ERR_HW;

    if (out) {
        out->ic      = resp[0];
        out->ver     = resp[1];
        out->rev     = resp[2];
        out->support = resp[3];
    }
    ESP_LOGI(TAG, "PN532 IC=0x%02X FW=%d.%d support=0x%02X",
             resp[0], resp[1], resp[2], resp[3]);
    return RFID_OK;
}

rfid_err_t pn532_probe_device(void)
{
    if (!s_init || !s_bus) return RFID_ERR_NOT_INIT;
    // Raw address probe — does not send a command frame, just checks if the
    // device ACKs the 7-bit address. Takes at most 50 ms.
    esp_err_t e = i2c_master_probe(s_bus, PN532_I2C_ADDR, 50);
    if (e == ESP_OK) {
        ESP_LOGI(TAG, "[DIAG] I2C probe: PN532 ACK at 0x%02X", PN532_I2C_ADDR);
        return RFID_OK;
    }
    ESP_LOGW(TAG, "[DIAG] I2C probe: no ACK at 0x%02X (%s) — DIP3 OFF or wrong mode",
             PN532_I2C_ADDR, esp_err_to_name(e));
    return RFID_ERR_HW;
}

int pn532_i2c_scan(uint8_t *addrs_out, int max_addrs)
{
    if (!s_init || !s_bus) return -1;
    int found = 0;
    // Full scan 0x03-0x77 with WDT resets every 16 addresses.
    // Reset bus first — prior timeouts (wakeup, RDY polls) may leave it stuck.
    ESP_LOGI(TAG, "I2C scan: SDA=GPIO%d SCL=GPIO%d  scanning 0x03-0x77...",
             RF_HAT_PN532_SDA_GPIO, RF_HAT_PN532_SCL_GPIO);
    i2c_master_bus_reset(s_bus);
    vTaskDelay(pdMS_TO_TICKS(20));
    for (uint8_t addr = 0x03; addr <= 0x77; addr++) {
        if ((addr & 0x0F) == 0x03) esp_task_wdt_reset();
        esp_err_t e = i2c_master_probe(s_bus, addr, 10);
        if (e == ESP_OK) {
            ESP_LOGI(TAG, "  [FOUND] 0x%02X%s", addr,
                     addr == PN532_I2C_ADDR ? " — PN532!" : " — unexpected device");
            if (addrs_out && found < max_addrs)
                addrs_out[found] = addr;
            found++;
        }
    }
    if (found == 0)
        ESP_LOGW(TAG, "  No I2C devices found on GPIO%d/GPIO%d — PN532 not powered or not in I2C mode",
                 RF_HAT_PN532_SDA_GPIO, RF_HAT_PN532_SCL_GPIO);
    return found;
}
