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
#define PN532_I2C_TIMEOUT   50     // ms per transfer

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
        esp_err_t e = i2c_master_receive(s_dev, &rdy, 1, pdMS_TO_TICKS(PN532_I2C_TIMEOUT));
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
                                       pdMS_TO_TICKS(PN532_I2C_TIMEOUT));
    return (e == ESP_OK) ? RFID_OK : RFID_ERR_HW;
}

// Read and validate ACK frame (6 bytes after 1 RDY byte).
static rfid_err_t s_read_ack(void)
{
    static const uint8_t ACK[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
    uint8_t buf[7];

    rfid_err_t r = s_wait_ready(100);
    if (r != RFID_OK) return r;

    esp_err_t e = i2c_master_receive(s_dev, buf, 7, pdMS_TO_TICKS(PN532_I2C_TIMEOUT));
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

    // Release GPIO pins from any previous peripheral (RMT from IR/RF433).
    gpio_reset_pin((gpio_num_t)RF_HAT_PN532_SCL_GPIO);
    gpio_reset_pin((gpio_num_t)RF_HAT_PN532_SDA_GPIO);

    // ── GPIO level diagnostic ─────────────────────────────────────────────────
    // Read both lines as input with pull-up. Both must idle HIGH for I2C.
    {
        gpio_config_t gc = {
            .pin_bit_mask = (1ULL << RF_HAT_PN532_SCL_GPIO) |
                            (1ULL << RF_HAT_PN532_SDA_GPIO),
            .mode         = GPIO_MODE_INPUT,
            .pull_up_en   = GPIO_PULLUP_ENABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type    = GPIO_INTR_DISABLE,
        };
        gpio_config(&gc);
        vTaskDelay(pdMS_TO_TICKS(10));
        int scl_pu = gpio_get_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO);
        int sda_pu = gpio_get_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO);
        ESP_LOGI(TAG, "BUS IDLE (pull-up): SCL(GPIO%d)=%d  SDA(GPIO%d)=%d  [expect both 1]",
                 RF_HAT_PN532_SCL_GPIO, scl_pu, RF_HAT_PN532_SDA_GPIO, sda_pu);

        // Drive HIGH and read physical pad level WHILE STILL DRIVING.
        // gpio_get_level() reads GPIO_IN_REG (actual pad voltage, not output latch).
        // Open-drain slave: our 40mA output wins → reads 1 while driving.
        // Push-pull slave:  device sinks >40mA → reads 0 while driving.
        // This is the true push-pull vs open-drain discriminator.
        gpio_set_direction((gpio_num_t)RF_HAT_PN532_SCL_GPIO, GPIO_MODE_OUTPUT);
        gpio_set_direction((gpio_num_t)RF_HAT_PN532_SDA_GPIO, GPIO_MODE_OUTPUT);
        gpio_set_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO, 1);
        gpio_set_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO, 1);
        vTaskDelay(pdMS_TO_TICKS(5));
        int scl_driven = gpio_get_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO); // WHILE driving HIGH
        int sda_driven = gpio_get_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO); // WHILE driving HIGH
        // Now release and read what the device holds the line at (open-drain hold)
        gpio_set_direction((gpio_num_t)RF_HAT_PN532_SCL_GPIO, GPIO_MODE_INPUT);
        gpio_set_direction((gpio_num_t)RF_HAT_PN532_SDA_GPIO, GPIO_MODE_INPUT);
        vTaskDelay(pdMS_TO_TICKS(5));
        int scl_hi = gpio_get_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO); // after release
        int sda_hi = gpio_get_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO); // after release
        ESP_LOGI(TAG, "BUS DRIVE-HIGH (while driving): SCL=%d SDA=%d  [push-pull if 0]",
                 scl_driven, sda_driven);
        ESP_LOGI(TAG, "BUS DRIVE-HIGH (after release): SCL=%d SDA=%d  [open-drain pull if 0]",
                 scl_hi, sda_hi);

        // Drive LOW — confirms GPIO output works and lines aren't stuck HIGH.
        gpio_set_direction((gpio_num_t)RF_HAT_PN532_SCL_GPIO, GPIO_MODE_OUTPUT);
        gpio_set_direction((gpio_num_t)RF_HAT_PN532_SDA_GPIO, GPIO_MODE_OUTPUT);
        gpio_set_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO, 0);
        gpio_set_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO, 0);
        vTaskDelay(pdMS_TO_TICKS(5));
        gpio_set_direction((gpio_num_t)RF_HAT_PN532_SCL_GPIO, GPIO_MODE_INPUT);
        gpio_set_direction((gpio_num_t)RF_HAT_PN532_SDA_GPIO, GPIO_MODE_INPUT);
        vTaskDelay(pdMS_TO_TICKS(5));
        int scl_lo = gpio_get_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO);
        int sda_lo = gpio_get_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO);
        ESP_LOGI(TAG, "BUS DRIVE-LOW:      SCL(GPIO%d)=%d  SDA(GPIO%d)=%d  [expect both 0]",
                 RF_HAT_PN532_SCL_GPIO, scl_lo, RF_HAT_PN532_SDA_GPIO, sda_lo);

        // Note: gpio_get_level() while in OUTPUT mode reads GPIO_IN_REG but the GPIO
        // matrix may still route a previous peripheral signal (e.g. RMT idle-LOW) to
        // the pad, making the drive-while-output reading unreliable on ESP32-C5.
        // The idle (input) reading is the authoritative bus state.
        if (sda_driven == 0)
            ESP_LOGW(TAG, "SDA reads 0 while driven HIGH — GPIO matrix artifact (normal after RMT use); proceeding");
        if (scl_lo == 1 || sda_lo == 1)
            ESP_LOGW(TAG, "Line still HIGH after drive-LOW — may be GPIO matrix artifact; proceeding");

        // ── SDA stuck LOW (open-drain) — bus recovery ─────────────────────────
        // sda_pu==0 means PN532 is holding SDA LOW (open-drain). Two causes:
        //   (a) Power-on init: PN532 holds SDA LOW for up to ~400ms at startup.
        //   (b) Stuck mid-transaction: I2C FSM halted; 9-clock recovery needed.
        // Strategy: wait up to 500ms first (handles power-on case without recovery).
        if (sda_pu == 0) {
            ESP_LOGW(TAG, "SDA stuck LOW — waiting up to 500ms for PN532 power-on init...");
            bool released = false;
            for (int w = 0; w < 10 && !released; w++) {
                vTaskDelay(pdMS_TO_TICKS(50));
                released = gpio_get_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO);
                if (released)
                    ESP_LOGI(TAG, "  SDA released spontaneously after %dms (startup OK)", (w+1)*50);
            }

            if (!released) {
                // Still stuck after 500ms → manual bus recovery.
                // gpio_reset_pin first: clears any GPIO matrix routing left over from
                // prior RMT use that would prevent SCL from actually toggling.
                gpio_reset_pin((gpio_num_t)RF_HAT_PN532_SCL_GPIO);
                gpio_reset_pin((gpio_num_t)RF_HAT_PN532_SDA_GPIO);
                vTaskDelay(pdMS_TO_TICKS(5));

                ESP_LOGW(TAG, "SDA still LOW — bus recovery: clocking SCL up to 36x");
                gpio_set_direction((gpio_num_t)RF_HAT_PN532_SCL_GPIO, GPIO_MODE_OUTPUT);
                gpio_set_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO, 1);
                gpio_set_pull_mode((gpio_num_t)RF_HAT_PN532_SDA_GPIO, GPIO_PULLUP_ONLY);
                gpio_set_direction((gpio_num_t)RF_HAT_PN532_SDA_GPIO, GPIO_MODE_INPUT);
                vTaskDelay(pdMS_TO_TICKS(2));

                // Verify SCL drive is working after gpio_reset_pin
                int scl_chk = gpio_get_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO);
                ESP_LOGI(TAG, "  SCL drive-HIGH verify: %d (expect 1; 0 = GPIO matrix still stuck)", scl_chk);

                for (int i = 0; i < 36; i++) {  // 4 bytes worth — handles multi-byte stuck states
                    gpio_set_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO, 0);
                    vTaskDelay(pdMS_TO_TICKS(1));
                    gpio_set_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO, 1);
                    vTaskDelay(pdMS_TO_TICKS(1));
                    if (gpio_get_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO)) {
                        ESP_LOGI(TAG, "  SDA released after %d clock(s)", i + 1);
                        released = true;
                        break;
                    }
                }
                // STOP condition: SCL HIGH, SDA LOW→HIGH
                gpio_set_direction((gpio_num_t)RF_HAT_PN532_SDA_GPIO, GPIO_MODE_OUTPUT);
                gpio_set_level((gpio_num_t)RF_HAT_PN532_SCL_GPIO, 1);
                gpio_set_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO, 0);
                vTaskDelay(pdMS_TO_TICKS(1));
                gpio_set_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO, 1);
                vTaskDelay(pdMS_TO_TICKS(5));
                gpio_set_direction((gpio_num_t)RF_HAT_PN532_SDA_GPIO, GPIO_MODE_INPUT);
                gpio_set_pull_mode((gpio_num_t)RF_HAT_PN532_SDA_GPIO, GPIO_PULLUP_ONLY);
                vTaskDelay(pdMS_TO_TICKS(20));
                int sda_after = gpio_get_level((gpio_num_t)RF_HAT_PN532_SDA_GPIO);
                ESP_LOGI(TAG, "SDA after recovery: %d %s",
                         sda_after,
                         sda_after ? "(bus free)" : "(STILL STUCK)");
                if (!sda_after) {
                    ESP_LOGE(TAG, "*** SDA stuck after 36 clocks — PN532 needs power-cycle");
                    ESP_LOGE(TAG, "*** Toggle DIP switch 3 OFF, wait 2 sec, then back ON");
                    gpio_reset_pin((gpio_num_t)RF_HAT_PN532_SCL_GPIO);
                    gpio_reset_pin((gpio_num_t)RF_HAT_PN532_SDA_GPIO);
                    return RFID_ERR_HW;
                }
            }
        }

        // Reset before I2C init — clears GPIO matrix routing and driver reservation.
        gpio_reset_pin((gpio_num_t)RF_HAT_PN532_SCL_GPIO);
        gpio_reset_pin((gpio_num_t)RF_HAT_PN532_SDA_GPIO);
        vTaskDelay(pdMS_TO_TICKS(20));
    }

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

    // Allow PN532 to stabilize after power-on (DIP switch just toggled).
    // PN532 OSC startup + I2C controller init can take up to 400ms on some variants.
    vTaskDelay(pdMS_TO_TICKS(400));

    // PN532 I2C wakeup: send a WRITE of one 0x00 byte to address 0x24.
    // Per PN532 Application Note and Adafruit library: the first I2C transaction
    // after power-on must be a WRITE (not a READ) to bring the chip out of low-power
    // mode. A NACK on this write is normal — the chip may not ACK the wakeup.
    // If it times out the bus is left stuck; reset immediately.
    {
        uint8_t wake = 0x00;
        esp_err_t we = i2c_master_transmit(s_dev, &wake, 1, pdMS_TO_TICKS(PN532_I2C_TIMEOUT));
        ESP_LOGI(TAG, "I2C wakeup write: %s", (we == ESP_OK) ? "ACK" : "NACK/timeout (normal)");
        if (we != ESP_OK) {
            // Timeout leaves bus stuck (no STOP generated). Reset clears it.
            i2c_master_bus_reset(s_bus);
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
    vTaskDelay(pdMS_TO_TICKS(20));

    // Poll for RDY byte — PN532 signals 0x01 when ready to receive a command.
    // Reset the bus on each failure so timeouts don't leave it stuck for the next poll.
    {
        uint8_t rdy = 0;
        esp_err_t re = ESP_ERR_TIMEOUT;
        for (int i = 0; i < 5; i++) {
            re = i2c_master_receive(s_dev, &rdy, 1, pdMS_TO_TICKS(PN532_I2C_TIMEOUT));
            if (re == ESP_OK) {
                ESP_LOGI(TAG, "I2C ready poll [%d]: RDY=0x%02X %s",
                         i, rdy, (rdy == 0x01) ? "(READY)" : "(not ready yet)");
                if (rdy == 0x01) break;
            } else {
                ESP_LOGD(TAG, "I2C ready poll [%d]: %s", i, esp_err_to_name(re));
                i2c_master_bus_reset(s_bus);
            }
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        if (re != ESP_OK) {
            ESP_LOGW(TAG, "PN532 not responding — check: DIP 3 ON, I2C mode jumper on module");
        } else if (rdy != 0x01) {
            ESP_LOGW(TAG, "PN532 responding but RDY=0x%02X (not 0x01) — may still need time", rdy);
        }
    }

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
                                      pdMS_TO_TICKS(PN532_I2C_TIMEOUT));
    if (e != ESP_OK) return RFID_ERR_HW;

    // raw[0] = RDY, raw[1]=0x00, raw[2]=0x00, raw[3]=0xFF, raw[4]=LEN, raw[5]=LCS
    // raw[6] = TFI(0xD5), raw[7] = CMD+1, raw[8..] = data
    if (raw[1] != 0x00 || raw[2] != 0x00 || raw[3] != 0xFF) {
        ESP_LOGW(TAG, "Bad frame header: %02X %02X %02X", raw[1], raw[2], raw[3]);
        return RFID_ERR_HW;
    }
    uint8_t len = raw[4];
    if (raw[6] != PN532_TFI_PN532) {
        ESP_LOGW(TAG, "TFI mismatch: 0x%02X", raw[6]);
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
