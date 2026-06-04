#include "wifi_wardrive.h"
#include "wardrive_buffer.h"
#include "wifi_scanner.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/spi_master.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "ff.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "wifi_wardrive";

// ✅ Mutex for shared SPI bus (SD card and display)
extern SemaphoreHandle_t sd_spi_mutex;

// GPS state (extended from common gps_data_t)
typedef struct {
    bool fix_valid;
    float latitude;
    float longitude;
    float altitude;
    int satellites;
    char timestamp[32];
} gps_state_t;

static gps_state_t gps_data = {0};
static volatile bool wardrive_active = false;
static TaskHandle_t wardrive_task_handle = NULL;
static TaskHandle_t wardrive_flush_task_handle = NULL;
static esp_timer_handle_t wardrive_flush_timer = NULL;
static uint32_t wardrive_flush_interval_ms = 10000;  // 10 seconds default
static FILE *wardrive_csv_file = NULL;
static bool sd_card_mounted = false;

// SD Card state
static sdmmc_card_t *sd_card = NULL;

// ============================================================================
// GPS FUNCTIONS
// ============================================================================

static bool parse_nmea_gga(const char *sentence) {
    // Example: $GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47
    char *tokens[15];
    char buffer[256];
    strncpy(buffer, sentence, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    int token_count = 0;
    char *token = strtok(buffer, ",");
    while (token != NULL && token_count < 15) {
        tokens[token_count++] = token;
        token = strtok(NULL, ",");
    }
    
    if (token_count < 10) return false;
    if (strcmp(tokens[0], "$GPGGA") != 0 && strcmp(tokens[0], "$GNGGA") != 0) return false;
    
    // Parse fix quality
    int fix_quality = atoi(tokens[6]);
    if (fix_quality == 0) {
        gps_data.fix_valid = false;
        return false;
    }
    
    // Parse latitude
    if (strlen(tokens[2]) > 0) {
        float lat_raw = atof(tokens[2]);
        int lat_deg = (int)(lat_raw / 100);
        float lat_min = lat_raw - (lat_deg * 100);
        gps_data.latitude = lat_deg + (lat_min / 60.0);
        
        if (tokens[3][0] == 'S') {
            gps_data.latitude = -gps_data.latitude;
        }
    }
    
    // Parse longitude
    if (strlen(tokens[4]) > 0) {
        float lon_raw = atof(tokens[4]);
        int lon_deg = (int)(lon_raw / 100);
        float lon_min = lon_raw - (lon_deg * 100);
        gps_data.longitude = lon_deg + (lon_min / 60.0);
        
        if (tokens[5][0] == 'W') {
            gps_data.longitude = -gps_data.longitude;
        }
    }
    
    // Parse satellites
    if (strlen(tokens[7]) > 0) {
        gps_data.satellites = atoi(tokens[7]);
    }
    
    // Parse altitude
    if (strlen(tokens[9]) > 0) {
        gps_data.altitude = atof(tokens[9]);
    }
    
    gps_data.fix_valid = true;
    
    return true;
}

static void gps_task(void *pvParameters) {
    ESP_LOGI(TAG, "GPS task started");
    
    uint8_t *data = (uint8_t *)malloc(GPS_BUF_SIZE);
    char sentence[256];
    int sentence_idx = 0;
    
    while (wardrive_active) {
        int len = uart_read_bytes(GPS_UART_NUM, data, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(100));
        
        if (len > 0) {
            data[len] = '\0';
            
            for (int i = 0; i < len; i++) {
                char c = data[i];
                
                if (c == '$') {
                    sentence_idx = 0;
                    sentence[sentence_idx++] = c;
                } else if (c == '\n' || c == '\r') {
                    if (sentence_idx > 0) {
                        sentence[sentence_idx] = '\0';
                        
                        if (strstr(sentence, "GGA") != NULL) {
                            parse_nmea_gga(sentence);
                        }
                        
                        sentence_idx = 0;
                    }
                } else if (sentence_idx < sizeof(sentence) - 1) {
                    sentence[sentence_idx++] = c;
                }
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    free(data);
    ESP_LOGI(TAG, "GPS task stopped");
    vTaskDelete(NULL);
}

esp_err_t wifi_wardrive_init_gps(void) {
    uart_config_t uart_config = {
        .baud_rate = 9600,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    };
    
    esp_err_t ret = uart_param_config(GPS_UART_NUM, &uart_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to configure UART");
        return ret;
    }
    
    ret = uart_set_pin(GPS_UART_NUM, GPS_TX_PIN, GPS_RX_PIN, 
                       UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set UART pins");
        return ret;
    }
    
    ret = uart_driver_install(GPS_UART_NUM, GPS_BUF_SIZE * 2, 0, 0, NULL, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to install UART driver");
        return ret;
    }
    
    ESP_LOGI(TAG, "GPS UART initialized");
    return ESP_OK;
}

esp_err_t wifi_wardrive_get_gps_fix(void) {
    ESP_LOGI(TAG, "Getting GPS fix...");
    
    if (gps_data.fix_valid) {
        ESP_LOGI(TAG, "GPS Fix:");
        ESP_LOGI(TAG, "  Latitude: %.6f", gps_data.latitude);
        ESP_LOGI(TAG, "  Longitude: %.6f", gps_data.longitude);
        ESP_LOGI(TAG, "  Altitude: %.1f m", gps_data.altitude);
        ESP_LOGI(TAG, "  Satellites: %d", gps_data.satellites);
        return ESP_OK;
    } else {
        ESP_LOGW(TAG, "No GPS fix available");
        return ESP_ERR_NOT_FOUND;
    }
}

bool wifi_wardrive_has_gps_fix(void) {
    return gps_data.fix_valid;
}

float wifi_wardrive_get_latitude(void) {
    return gps_data.latitude;
}

float wifi_wardrive_get_longitude(void) {
    return gps_data.longitude;
}

// ============================================================================
// SD CARD FUNCTIONS
// ============================================================================

esp_err_t wifi_wardrive_init_sd_ex(uint32_t freq_khz, bool format_if_failed) {
    // Check if already mounted
    if (sd_card_mounted) {
        ESP_LOGI(TAG, "[SD] SD card already mounted");
        return ESP_OK;
    }

    ESP_LOGI(TAG, "[SD] Starting SD card initialization...");

    // Detailed memory diagnostics BEFORE mount
    ESP_LOGI(TAG, "[SD] Memory before mount:");
    ESP_LOGI(TAG, "[SD]   Total free: %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
    ESP_LOGI(TAG, "[SD]   Internal free: %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    ESP_LOGI(TAG, "[SD]   PSRAM free: %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    ESP_LOGI(TAG, "[SD]   DMA-capable: %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA));
    ESP_LOGI(TAG, "[SD]   Largest free block: %u bytes", (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));

    // Check if we have enough memory for mount operation
    size_t required_mem = 16384;
    size_t available = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    if (available < required_mem) {
        ESP_LOGW(TAG, "[SD] Low internal memory! Available: %u, recommended: %u",
                 (unsigned)available, (unsigned)required_mem);
    }

    ESP_LOGI(TAG, "[SD] Configuring mount parameters (fmt=%d)...", (int)format_if_failed);
    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = format_if_failed,
        .max_files = 3,
        .allocation_unit_size = 16 * 1024,  /* 16 KB clusters when formatting */
        .disk_status_check_enable = false
    };

    /* SD SPI reset preamble — 80 dummy clock cycles with CS deasserted.
     *
     * Why: During firmware flash (ESP32 in UART download mode), GPIO10 (SD_CS)
     * can float LOW, causing the SD card to start a command that never completes.
     * On the next boot the card is stuck mid-command and ignores CMD0 until it
     * sees ≥74 idle clocks with CS HIGH (SD SPI specification requirement).
     *
     * Implementation: add a temporary no-CS SPI device on the already-initialised
     * SPI2_HOST (shared with display) and send 10 bytes of 0xFF = 80 clock pulses.
     * The SPI master driver arbitrates the bus correctly with the display.
     * On failure (bus not yet init'd on very early calls) the step is skipped. */
    gpio_set_direction(SD_CS_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(SD_CS_PIN, 1);   // CS HIGH before we start clocking
    {
        spi_device_handle_t hclk;
        spi_device_interface_config_t clk_cfg = {
            .clock_speed_hz = 400000,   // 400 kHz – SD spec init rate
            .mode           = 0,
            .spics_io_num   = -1,       // no CS pin – SD_CS stays HIGH throughout
            .queue_size     = 1,
        };
        if (spi_bus_add_device(SPI2_HOST, &clk_cfg, &hclk) == ESP_OK) {
            uint8_t dummies[10];
            memset(dummies, 0xFF, sizeof(dummies));   // all-ones = idle pattern
            spi_transaction_t t = {
                .length    = sizeof(dummies) * 8,     // 80 bits = 80 clocks
                .tx_buffer = dummies,
            };
            spi_device_polling_transmit(hclk, &t);
            spi_bus_remove_device(hclk);
            ESP_LOGI(TAG, "[SD] Pre-init: sent 80 idle clocks (CS HIGH) to reset SD SPI state");
        } else {
            ESP_LOGW(TAG, "[SD] Pre-init: could not add dummy device (bus not ready?), skipping");
        }
    }
    vTaskDelay(pdMS_TO_TICKS(50));   // brief settle after idle clocks

    /* Standard settle delay: hold CS HIGH so the card exits any stuck state
       and returns to command-ready before we assert CMD0. */
    vTaskDelay(pdMS_TO_TICKS(200));

    ESP_LOGI(TAG, "[SD] Configuring SPI host at %lu kHz...", (unsigned long)freq_khz);
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SPI2_HOST;
    host.max_freq_khz = freq_khz;
    host.flags = SDMMC_HOST_FLAG_SPI | SDMMC_HOST_FLAG_DEINIT_ARG;
    host.command_timeout_ms = 2000; /* allow slow/fresh cards up to 2 s for CMD0 response */
    ESP_LOGI(TAG, "[SD]   SPI Host: %d, Frequency: %lu kHz, Flags: 0x%x", host.slot, (unsigned long)host.max_freq_khz, host.flags);

    ESP_LOGI(TAG, "[SD] Configuring slot (CS=%d)...", SD_CS_PIN);
    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = SD_CS_PIN;
    slot_config.gpio_cd = -1;
    slot_config.gpio_wp = -1;
    slot_config.host_id = (spi_host_device_t)SPI2_HOST;  // ✅ Explicit enum cast
    
    ESP_LOGI(TAG, "[SD] Attempting to mount filesystem...");
    ESP_LOGI(TAG, "[SD] This may take a few seconds...");
    
    esp_err_t ret = esp_vfs_fat_sdspi_mount("/sdcard", &host, &slot_config, &mount_config, &sd_card);
    
    // Detailed error handling
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "[SD] Mount FAILED with error: %s (0x%x)", esp_err_to_name(ret), ret);
        
        // Log memory state after failed mount
        ESP_LOGE(TAG, "[SD] Memory after failed mount:");
        ESP_LOGE(TAG, "[SD]   Total free: %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
        ESP_LOGE(TAG, "[SD]   Internal free: %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        
        // Specific error messages
        switch (ret) {
            case ESP_FAIL:
                ESP_LOGE(TAG, "[SD] Filesystem mount failed - card may not be formatted as FAT");
                break;
            case ESP_ERR_NO_MEM:
                ESP_LOGE(TAG, "[SD] Out of memory during mount operation");
                break;
            case ESP_ERR_INVALID_STATE:
                ESP_LOGE(TAG, "[SD] Invalid state - SPI bus may not be properly initialized");
                break;
            case ESP_ERR_TIMEOUT:
                ESP_LOGE(TAG, "[SD] Timeout - card not responding");
                break;
            case ESP_ERR_NOT_FOUND:
                ESP_LOGE(TAG, "[SD] Card not found - check physical connection");
                break;
            default:
                ESP_LOGE(TAG, "[SD] Unknown error during mount");
                break;
        }
        
        ESP_LOGW(TAG, "[SD] System will continue without SD card support");
        return ret;  // Return error but don't crash
    }
    
    ESP_LOGI(TAG, "[SD] Mount SUCCESS!");
    sd_card_mounted = true;
    
    // Log memory state after successful mount
    ESP_LOGI(TAG, "[SD] Memory after successful mount:");
    ESP_LOGI(TAG, "[SD]   Total free: %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
    ESP_LOGI(TAG, "[SD]   Internal free: %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    
    // Log card information
    char name_str[sizeof(sd_card->cid.name) + 1];
    memcpy(name_str, sd_card->cid.name, sizeof(sd_card->cid.name));
    name_str[sizeof(sd_card->cid.name)] = '\0';

    const uint64_t sector_count = sd_card->csd.capacity;
    const uint32_t sector_size = sd_card->csd.sector_size;
    const uint64_t capacity_bytes = sector_count * sector_size;

    ESP_LOGI(TAG, "[SD] Card info: OEM=0x%X, Name=%s", (unsigned)sd_card->cid.oem_id, name_str);
    ESP_LOGI(TAG, "[SD] Speed: %u kHz, Size: %llu bytes (%.2f MB)",
             sd_card->host.max_freq_khz, (unsigned long long)capacity_bytes,
             (float)capacity_bytes / (1024.0f * 1024.0f));

    // NOTE: Removed set_card_clk call - it was reconfiguring the shared SPI bus
    // clock after mount, which could interfere with the display on SPI2_HOST.
    // The mount function already configures the clock appropriately.

    ESP_LOGI(TAG, "[SD] Initialization completed successfully!");
    return ESP_OK;
}

esp_err_t wifi_wardrive_init_sd(void) {
    return wifi_wardrive_init_sd_ex(20000, false);
}

bool wifi_wardrive_is_sd_mounted(void) {
    return sd_card_mounted;
}

void wifi_wardrive_unmount_sd(void) {
    if (!sd_card_mounted || !sd_card) return;
    esp_vfs_fat_sdcard_unmount("/sdcard", sd_card);
    sd_card_mounted = false;
    sd_card = NULL;
    ESP_LOGI(TAG, "[SD] unmounted");
}

esp_err_t wifi_wardrive_format_sd(void) {
    if (!sd_card_mounted || !sd_card) {
        ESP_LOGW(TAG, "[SD] format: card not mounted");
        return ESP_ERR_INVALID_STATE;
    }
    ESP_LOGI(TAG, "[SD] Formatting FAT32 (16KB clusters) — this takes 30-90 s on large cards...");
    uint8_t *work = heap_caps_malloc(4096, MALLOC_CAP_INTERNAL);
    if (!work) {
        ESP_LOGE(TAG, "[SD] format: no memory for work buffer");
        return ESP_ERR_NO_MEM;
    }
    // FM_FAT32|FM_SFD forces FAT32 SFD (no MBR); 16KB clusters for fast format
    // FM_ANY=0x07 includes FM_EXFAT=0x04 which would be chosen on large cards
    // but FF_FS_EXFAT=0 in this build → corrupt filesystem. Never use FM_ANY.
    MKFS_PARM opt = { .fmt = FM_FAT32 | FM_SFD, .n_fat = 1, .align = 0, .n_root = 512, .au_size = 16 * 1024 };
    FRESULT res = f_mkfs("0:", &opt, work, 4096);
    heap_caps_free(work);

    /* Always unmount after format attempt — whether it succeeded or failed.
       Leaving the card mounted after a partial write causes the card controller
       to stay in a write-busy state that blocks ACMD41 on the next boot. */
    esp_vfs_fat_sdcard_unmount("/sdcard", sd_card);
    sd_card_mounted = false;
    sd_card = NULL;

    if (res != FR_OK) {
        ESP_LOGE(TAG, "[SD] f_mkfs failed: %d — card unmounted cleanly", (int)res);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "[SD] Format complete — card unmounted, ready for remount");
    return ESP_OK;
}

// ============================================================================
// WARDRIVE FUNCTIONS
// ============================================================================

static void wardrive_scan_task(void *pvParameters) {
    ESP_LOGI(TAG, "Wardrive task started");

    int scan_count = 0;

    while (wardrive_active && !g_operation_stop_requested) {
        // Start WiFi scan
        esp_err_t ret = wifi_scanner_start_scan();
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "Scan failed");
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        // Wait for scan to complete
        while (wifi_scanner_is_scanning()) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }

        scan_count++;

        // Get results
        wifi_ap_record_t results[MAX_SCAN_RESULTS];
        int count = wifi_scanner_get_results(results, MAX_SCAN_RESULTS);

        ESP_LOGI(TAG, "Scan #%d: Found %d networks", scan_count, count);

        // Buffer detections (non-blocking, no mutex needed)
        for (int i = 0; i < count; i++) {
            wifi_ap_record_t *ap = &results[i];

            wardrive_detection_t detection = {0};
            memcpy(detection.bssid, ap->bssid, 6);
            strncpy(detection.ssid, (const char *)ap->ssid, sizeof(detection.ssid) - 1);
            detection.channel = ap->primary;
            detection.authmode = ap->authmode;
            detection.rssi = ap->rssi;
            detection.latitude = gps_data.latitude;
            detection.longitude = gps_data.longitude;
            detection.altitude = gps_data.altitude;
            detection.satellites = gps_data.satellites;

            wardrive_buffer_add(&detection);
        }

        // Print status
        if (gps_data.fix_valid) {
            ESP_LOGI(TAG, "GPS: %.6f, %.6f (sats: %d)",
                    gps_data.latitude, gps_data.longitude, gps_data.satellites);
        } else {
            ESP_LOGW(TAG, "GPS: No fix");
        }

        vTaskDelay(pdMS_TO_TICKS(2000)); // Wait 2 seconds between scans
    }

    ESP_LOGI(TAG, "Wardrive stopped after %d scans", scan_count);
    wardrive_task_handle = NULL;
    vTaskDelete(NULL);
}

static void wardrive_flush_task(void *pvParameters) {
    (void)pvParameters;
    wardrive_detection_t batch[256];  // Batch size: 256 detections per flush

    ESP_LOGI(TAG, "Wardrive flush task started");

    while (wardrive_active && !g_operation_stop_requested) {
        // Wait for signal from timer or timeout
        uint32_t notified = ulTaskNotifyTake(pdFALSE, pdMS_TO_TICKS(wardrive_flush_interval_ms));

        if (!wardrive_active) break;

        // Get pending detections from buffer
        int count = wardrive_buffer_get_pending(batch, 256);

        if (count > 0 && wardrive_csv_file && sd_spi_mutex) {
            // Acquire mutex ONCE for entire batch write
            if (xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(2000)) == pdTRUE) {
                for (int i = 0; i < count; i++) {
                    wardrive_detection_t *det = &batch[i];

                    fprintf(wardrive_csv_file, "%02X:%02X:%02X:%02X:%02X:%02X,",
                            det->bssid[0], det->bssid[1], det->bssid[2],
                            det->bssid[3], det->bssid[4], det->bssid[5]);

                    char ssid_escaped[128];
                    escape_csv_field(det->ssid, ssid_escaped, sizeof(ssid_escaped));
                    fprintf(wardrive_csv_file, "%s,", ssid_escaped);

                    fprintf(wardrive_csv_file, "%s,%d,%d,",
                            authmode_to_string(det->authmode),
                            det->channel,
                            det->rssi);

                    fprintf(wardrive_csv_file, "%.6f,%.6f,%.1f,%d\n",
                            det->latitude, det->longitude,
                            det->altitude, det->satellites);
                }
                fflush(wardrive_csv_file);
                xSemaphoreGive(sd_spi_mutex);

                // Mark detections as flushed
                wardrive_buffer_mark_flushed(count);

                ESP_LOGI(TAG, "Flushed %d detections", count);
            } else {
                ESP_LOGW(TAG, "Failed to acquire mutex for flush, retrying later");
            }
        }

        // Check overflow condition
        int fill = wardrive_buffer_get_fill_percent();
        if (fill > 80) {
            ESP_LOGW(TAG, "Buffer %d%% full, consider increasing flush frequency", fill);
        }
    }

    // FINAL FLUSH on shutdown
    int count = wardrive_buffer_get_pending(batch, 256);
    while (count > 0) {
        if (wardrive_csv_file && sd_spi_mutex && xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(2000)) == pdTRUE) {
            for (int i = 0; i < count; i++) {
                wardrive_detection_t *det = &batch[i];
                fprintf(wardrive_csv_file, "%02X:%02X:%02X:%02X:%02X:%02X,",
                        det->bssid[0], det->bssid[1], det->bssid[2],
                        det->bssid[3], det->bssid[4], det->bssid[5]);

                char ssid_escaped[128];
                escape_csv_field(det->ssid, ssid_escaped, sizeof(ssid_escaped));
                fprintf(wardrive_csv_file, "%s,", ssid_escaped);

                fprintf(wardrive_csv_file, "%s,%d,%d,",
                        authmode_to_string(det->authmode),
                        det->channel,
                        det->rssi);

                fprintf(wardrive_csv_file, "%.6f,%.6f,%.1f,%d\n",
                        det->latitude, det->longitude,
                        det->altitude, det->satellites);
            }
            fflush(wardrive_csv_file);
            xSemaphoreGive(sd_spi_mutex);
            wardrive_buffer_mark_flushed(count);
        }
        count = wardrive_buffer_get_pending(batch, 256);
    }

    ESP_LOGI(TAG, "Flush task stopped");
    wardrive_flush_task_handle = NULL;
    vTaskDelete(NULL);
}

static void wardrive_flush_timer_callback(void *arg) {
    (void)arg;
    if (wardrive_flush_task_handle) {
        xTaskNotifyGive(wardrive_flush_task_handle);
    }
}

esp_err_t wifi_wardrive_start(void) {
    if (wardrive_active) {
        ESP_LOGW(TAG, "Wardrive already running");
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Starting wardrive...");

    // Initialize GPS if not already done
    static bool gps_initialized = false;
    if (!gps_initialized) {
        wifi_wardrive_init_gps();
        gps_initialized = true;
    }

    // Initialize SD card if not already done
    if (!sd_card_mounted) {
        esp_err_t ret = wifi_wardrive_init_sd();
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "SD card not available, logging disabled");
        }
    }

    // Open CSV file for logging
    if (sd_card_mounted && sd_spi_mutex) {
        char filename[64];
        snprintf(filename, sizeof(filename), "/sdcard/lab/wardrives/wd%lu.csv",
                 (unsigned long)(esp_timer_get_time() / 1000000));

        if (xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(5000)) == pdTRUE) {
            wardrive_csv_file = fopen(filename, "w");
            if (wardrive_csv_file) {
                fprintf(wardrive_csv_file, "BSSID,SSID,AuthMode,Channel,RSSI,Latitude,Longitude,Altitude,Satellites\n");
                fflush(wardrive_csv_file);
                ESP_LOGI(TAG, "Logging to: %s", filename);
            } else {
                ESP_LOGE(TAG, "Failed to open log file");
            }
            xSemaphoreGive(sd_spi_mutex);
        } else {
            ESP_LOGE(TAG, "Failed to acquire SD mutex for file open");
        }
    }

    wardrive_active = true;

    // Initialize detection buffer (1000 detections = ~64 KB PSRAM)
    esp_err_t ret = wardrive_buffer_init(1000);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize detection buffer");
        wardrive_active = false;
        return ret;
    }

    // Start flush task
    xTaskCreate(wardrive_flush_task, "wardrive_flush", 4096, NULL, 4, &wardrive_flush_task_handle);

    // Start flush timer (fires every wardrive_flush_interval_ms)
    esp_timer_create_args_t timer_args = {
        .callback = wardrive_flush_timer_callback,
        .arg = NULL,
        .name = "wardrive_flush",
        .dispatch_method = ESP_TIMER_TASK,
    };
    ret = esp_timer_create(&timer_args, &wardrive_flush_timer);
    if (ret == ESP_OK) {
        esp_timer_start_periodic(wardrive_flush_timer, wardrive_flush_interval_ms * 1000);
    } else {
        ESP_LOGE(TAG, "Failed to create flush timer");
    }

    // Start GPS task
    xTaskCreate(gps_task, "gps_task", 4096, NULL, 5, NULL);

    // Start wardrive scan task (priority 5 for continuous scanning)
    xTaskCreate(wardrive_scan_task, "wardrive_scan", 8192, NULL, 5, &wardrive_task_handle);

    ESP_LOGI(TAG, "Wardrive started with write-ahead buffering (flush every %u ms)", wardrive_flush_interval_ms);
    return ESP_OK;
}

esp_err_t wifi_wardrive_stop(void) {
    if (!wardrive_active) {
        ESP_LOGW(TAG, "Wardrive not running");
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Stopping wardrive...");

    wardrive_active = false;

    // Stop and delete flush timer
    if (wardrive_flush_timer) {
        esp_timer_stop(wardrive_flush_timer);
        esp_timer_delete(wardrive_flush_timer);
        wardrive_flush_timer = NULL;
    }

    // Signal flush task to do final flush and exit
    if (wardrive_flush_task_handle) {
        xTaskNotifyGive(wardrive_flush_task_handle);
    }

    // Wait for all tasks to finish
    int wait_count = 0;
    while ((wardrive_task_handle != NULL || wardrive_flush_task_handle != NULL) && wait_count < 100) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
    }

    // Close CSV file
    if (wardrive_csv_file && sd_spi_mutex) {
        if (xSemaphoreTake(sd_spi_mutex, pdMS_TO_TICKS(5000)) == pdTRUE) {
            fclose(wardrive_csv_file);
            wardrive_csv_file = NULL;
            xSemaphoreGive(sd_spi_mutex);
            ESP_LOGI(TAG, "Log file closed");
        }
    }

    // Clean up detection buffer
    wardrive_buffer_free();

    ESP_LOGI(TAG, "Wardrive stopped");
    return ESP_OK;
}

bool wifi_wardrive_is_active(void) {
    return wardrive_active;
}
