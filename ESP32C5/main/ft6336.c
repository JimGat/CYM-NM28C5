#include "ft6336.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "FT6336";

// I2C timeout in ms
#define I2C_TIMEOUT_MS 100

/**
 * @brief Read single byte from FT6336U register using OLD I2C API
 */
static esp_err_t ft6336_read_reg(ft6336_handle_t *handle, uint8_t reg, uint8_t *data)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (FT6336_I2C_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, reg, true);
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (FT6336_I2C_ADDR << 1) | I2C_MASTER_READ, true);
    i2c_master_read_byte(cmd, data, I2C_MASTER_NACK);
    i2c_master_stop(cmd);
    esp_err_t ret = i2c_master_cmd_begin(handle->i2c_port, cmd, pdMS_TO_TICKS(I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(cmd);
    return ret;
}

/**
 * @brief Read multiple bytes from FT6336U registers using OLD I2C API
 */
static esp_err_t ft6336_read_regs(ft6336_handle_t *handle, uint8_t reg, uint8_t *data, size_t len)
{
    if (len == 0) {
        return ESP_OK;
    }
    
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (FT6336_I2C_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, reg, true);
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (FT6336_I2C_ADDR << 1) | I2C_MASTER_READ, true);
    
    if (len > 1) {
        i2c_master_read(cmd, data, len - 1, I2C_MASTER_ACK);
    }
    i2c_master_read_byte(cmd, data + len - 1, I2C_MASTER_NACK);
    i2c_master_stop(cmd);
    
    esp_err_t ret = i2c_master_cmd_begin(handle->i2c_port, cmd, pdMS_TO_TICKS(I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(cmd);
    return ret;
}

/**
 * @brief Write single byte to FT6336U register using OLD I2C API
 */
static esp_err_t ft6336_write_reg(ft6336_handle_t *handle, uint8_t reg, uint8_t data)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (FT6336_I2C_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, reg, true);
    i2c_master_write_byte(cmd, data, true);
    i2c_master_stop(cmd);
    esp_err_t ret = i2c_master_cmd_begin(handle->i2c_port, cmd, pdMS_TO_TICKS(I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(cmd);
    return ret;
}

esp_err_t ft6336_init(ft6336_handle_t *handle, i2c_port_t i2c_port,
                      int int_gpio, int rst_gpio, uint16_t width, uint16_t height)
{
    if (!handle) {
        return ESP_ERR_INVALID_ARG;
    }

    handle->i2c_port = i2c_port;
    handle->int_gpio = int_gpio;
    handle->rst_gpio = rst_gpio;
    handle->width = width;
    handle->height = height;

    // Configure Reset pin if provided
    if (rst_gpio >= 0) {
        gpio_config_t rst_conf = {
            .pin_bit_mask = (1ULL << rst_gpio),
            .mode = GPIO_MODE_OUTPUT,
            .pull_up_en = GPIO_PULLUP_DISABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_DISABLE,
        };
        esp_err_t ret = gpio_config(&rst_conf);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to configure RST GPIO: %s", esp_err_to_name(ret));
            return ret;
        }

        // Perform hardware reset
        gpio_set_level(rst_gpio, 0);  // Assert reset (active LOW)
        vTaskDelay(pdMS_TO_TICKS(10));
        gpio_set_level(rst_gpio, 1);  // Deassert reset
        vTaskDelay(pdMS_TO_TICKS(300)); // Wait for controller to boot
    }

    // Configure Interrupt pin if provided
    if (int_gpio >= 0) {
        gpio_config_t int_conf = {
            .pin_bit_mask = (1ULL << int_gpio),
            .mode = GPIO_MODE_INPUT,
            .pull_up_en = GPIO_PULLUP_ENABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_DISABLE,
        };
        esp_err_t ret = gpio_config(&int_conf);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to configure INT GPIO: %s", esp_err_to_name(ret));
            return ret;
        }
    }

    // Verify chip ID
    uint8_t chip_id = ft6336_get_chip_id(handle);
    if (chip_id == 0) {
        ESP_LOGE(TAG, "Failed to read chip ID - check I2C connection");
        return ESP_ERR_NOT_FOUND;
    }
    
    ESP_LOGI(TAG, "FT6336U detected, Chip ID: 0x%02X", chip_id);
    
    if (chip_id != FT6336_CHIP_ID) {
        ESP_LOGW(TAG, "Unexpected chip ID 0x%02X (expected 0x%02X), continuing anyway", 
                 chip_id, FT6336_CHIP_ID);
    }

    // Read firmware and vendor IDs
    uint8_t firm_id = 0, vend_id = 0;
    ft6336_read_reg(handle, FT6336_REG_FIRMID, &firm_id);
    ft6336_read_reg(handle, FT6336_REG_VENDID, &vend_id);
    ESP_LOGI(TAG, "Firmware ID: 0x%02X, Vendor ID: 0x%02X", firm_id, vend_id);

    return ESP_OK;
}

uint8_t ft6336_get_chip_id(ft6336_handle_t *handle)
{
    uint8_t chip_id = 0;
    esp_err_t ret = ft6336_read_reg(handle, FT6336_REG_CHIPID, &chip_id);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read chip ID: %s", esp_err_to_name(ret));
        return 0;
    }
    return chip_id;
}

bool ft6336_is_touched(ft6336_handle_t *handle)
{
    // Read touch status register
    uint8_t td_status = 0;
    esp_err_t ret = ft6336_read_reg(handle, FT6336_REG_TD_STATUS, &td_status);
    if (ret != ESP_OK) {
        return false;
    }
    
    // Lower 4 bits contain number of touch points
    uint8_t touch_count = td_status & 0x0F;
    return (touch_count > 0);
}

bool ft6336_read_touch(ft6336_handle_t *handle, ft6336_touch_point_t *point)
{
    if (!handle || !point) {
        return false;
    }

    // Read touch status and first touch point data (6 bytes)
    uint8_t data[6];
    esp_err_t ret = ft6336_read_regs(handle, FT6336_REG_TD_STATUS, data, 6);
    if (ret != ESP_OK) {
        return false;
    }

    // Check number of touch points
    uint8_t touch_count = data[0] & 0x0F;
    if (touch_count == 0) {
        point->touched = false;
        return false;
    }

    // Parse first touch point coordinates
    // XH: bits [3:0] are X[11:8], YH: bits [3:0] are Y[11:8]
    uint16_t raw_x = ((data[1] & 0x0F) << 8) | data[2];
    uint16_t raw_y = ((data[3] & 0x0F) << 8) | data[4];

    // FT6336U returns values already in screen resolution range, not 0-4095!
    // raw_x: ~0-320, raw_y: ~0-480
    // Apply transformation to match display orientation
    point->x = (raw_y < handle->width) ? (handle->width - raw_y) : 0;
    point->y = (raw_x < handle->height) ? raw_x : (handle->height - 1);

    // Clamp to screen bounds
    if (point->x >= handle->width) point->x = handle->width - 1;
    if (point->y >= handle->height) point->y = handle->height - 1;

    point->touched = true;
    return true;
}

int ft6336_read_multi_touch(ft6336_handle_t *handle, ft6336_touch_point_t *points, int max_points)
{
    if (!handle || !points || max_points < 1) {
        return 0;
    }

    // Read touch status and both touch points (12 bytes total)
    uint8_t data[13];
    esp_err_t ret = ft6336_read_regs(handle, FT6336_REG_TD_STATUS, data, 13);
    if (ret != ESP_OK) {
        return 0;
    }

    // Check number of touch points
    uint8_t touch_count = data[0] & 0x0F;
    if (touch_count == 0) {
        return 0;
    }

    // Limit to available points and max requested
    if (touch_count > max_points) {
        touch_count = max_points;
    }
    if (touch_count > 2) {
        touch_count = 2; // FT6336U supports max 2 points
    }

    // Parse touch point 1
    if (touch_count >= 1) {
        uint16_t raw_x = ((data[1] & 0x0F) << 8) | data[2];
        uint16_t raw_y = ((data[3] & 0x0F) << 8) | data[4];
        
        // FT6336U returns values already in screen resolution range
        points[0].x = (raw_y < handle->width) ? (handle->width - raw_y) : 0;
        points[0].y = (raw_x < handle->height) ? raw_x : (handle->height - 1);
        
        if (points[0].x >= handle->width) points[0].x = handle->width - 1;
        if (points[0].y >= handle->height) points[0].y = handle->height - 1;
        
        points[0].touched = true;
    }

    // Parse touch point 2
    if (touch_count >= 2) {
        uint16_t raw_x = ((data[7] & 0x0F) << 8) | data[8];
        uint16_t raw_y = ((data[9] & 0x0F) << 8) | data[10];
        
        // FT6336U returns values already in screen resolution range
        points[1].x = (raw_y < handle->width) ? (handle->width - raw_y) : 0;
        points[1].y = (raw_x < handle->height) ? raw_x : (handle->height - 1);
        
        if (points[1].x >= handle->width) points[1].x = handle->width - 1;
        if (points[1].y >= handle->height) points[1].y = handle->height - 1;
        
        points[1].touched = true;
    }

    return touch_count;
}
