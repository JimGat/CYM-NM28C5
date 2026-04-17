// wifi_cli.c - CLI Coordinator and Command Registration
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wifi_cli.h"
#include "wifi_scanner.h"
#include "wifi_sniffer.h"
#include "wifi_attacks.h"
#include "wifi_wardrive.h"
#include "esp_log.h"
#include "esp_console.h"
#include "argtable3/argtable3.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "led_strip.h"
// Note: Legacy RMT driver removed in ESP-IDF 6.x - using led_strip component instead
#include <stdlib.h>
#include <string.h>

static const char *TAG = "wifi_cli";

// Initialization state tracking (persist across WiFi/BLE mode switches)
static bool event_loop_initialized = false;
static bool netif_initialized = false;
static esp_netif_t *sta_netif_handle = NULL;
static esp_netif_t *ap_netif_handle = NULL;
static bool wifi_event_handler_registered = false;

// LED strip (NeoPixel)
#define RMT_RES_HZ (10 * 1000 * 1000)

// WiFi event handler
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
    // TODO: Handle WiFi events (scan done, connect, etc.)
    (void)arg;
    (void)event_base;
    (void)event_id;
    (void)event_data;
}

static esp_err_t init_wifi(void) {
    // Initialize netif only once (persists across radio mode switches)
    if (!netif_initialized) {
        ESP_ERROR_CHECK(esp_netif_init());
        netif_initialized = true;
    }
    
    // Create event loop only once (shared between WiFi and BLE modes)
    if (!event_loop_initialized) {
        ESP_ERROR_CHECK(esp_event_loop_create_default());
        event_loop_initialized = true;
    }
    
    // Only create STA interface (reused on WiFi re-init)
    // AP interface is NOT created here - it will be created dynamically when needed
    // Check if STA netif already exists (from previous init)
    sta_netif_handle = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif_handle == NULL) {
        sta_netif_handle = esp_netif_create_default_wifi_sta();
    }
    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    // Register event handler only once
    if (!wifi_event_handler_registered) {
        esp_err_t reg_err = esp_event_handler_instance_register(WIFI_EVENT,
                                                            ESP_EVENT_ANY_ID,
                                                            &wifi_event_handler,
                                                            NULL,
                                                            NULL);
        if (reg_err == ESP_OK) {
            wifi_event_handler_registered = true;
        } else if (reg_err != ESP_ERR_INVALID_STATE) {
            // ESP_ERR_INVALID_STATE means already registered - that's OK
            ESP_ERROR_CHECK(reg_err);
        }
    }
    
    // Initialize in STA-only mode (uses less memory, avoids AP netif issues)
    // AP mode will be enabled dynamically when needed (Evil Twin, etc.)
    wifi_config_t wifi_config = {0};
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    vTaskDelay(pdMS_TO_TICKS(400));   // let background tasks run after start

    uint8_t mac[6];
    esp_err_t ret = esp_wifi_get_mac(WIFI_IF_STA, mac);
    if (ret == ESP_OK) {
        MY_LOG_INFO(TAG, "JanOS version: " JANOS_VERSION);
        MY_LOG_INFO(TAG, "MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    return ESP_OK;
}

static esp_err_t init_led(void) {
    led_strip_config_t strip_cfg = {
        .strip_gpio_num = NEOPIXEL_GPIO,
        .max_leds = LED_COUNT,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags.invert_out = false,
    };
    
    led_strip_rmt_config_t rmt_cfg = {
        .clk_src = LED_STRIP_RMT_CLK_SRC_DEFAULT,
        .resolution_hz = RMT_RES_HZ,
        .flags.with_dma = false,
    };
    
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &g_led_strip));
    ESP_LOGI(TAG, "LED strip initialized");
    
    return ESP_OK;
}

esp_err_t wifi_cli_init(void) {
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // Initialize LED
    init_led();
    
    // Initialize WiFi
    init_wifi();
    
    // Initialize scanner component
    wifi_scanner_init();
    
    ESP_LOGI(TAG, "WiFi CLI system initialized");
    return ESP_OK;
}

// ============================================================================
// CLI COMMANDS
// ============================================================================

static int cmd_scan(int argc, char **argv) {
    (void)argc; (void)argv;
    
    g_operation_stop_requested = false;
    esp_err_t err = wifi_scanner_start_scan();
    
    if (err == ESP_OK) {
        MY_LOG_INFO(TAG, "Scan started. Wait ~15s, then use 'show'");
    } else {
        MY_LOG_INFO(TAG, "Scan failed: %s", esp_err_to_name(err));
    }
    
    return 0;
}

static int cmd_show(int argc, char **argv) {
    (void)argc; (void)argv;
    
    if (wifi_scanner_is_scanning()) {
        MY_LOG_INFO(TAG, "Scan in progress, please wait...");
        return 0;
    }
    
    wifi_scanner_print_results();
    return 0;
}

static int cmd_select(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: select <index1> [index2] ...");
        return 1;
    }
    
    for (int i = 1; i < argc; i++) {
        int idx = atoi(argv[i]);
        wifi_scanner_select_network(idx, true);
    }
    
    MY_LOG_INFO(TAG, "Selected %d networks", wifi_scanner_get_selected_count());
    return 0;
}

static int cmd_deauth(int argc, char **argv) {
    (void)argc; (void)argv;
    wifi_attacks_start_deauth();
    return 0;
}

static int cmd_stop(int argc, char **argv) {
    (void)argc; (void)argv;
    
    g_operation_stop_requested = true;
    wifi_attacks_stop_all();
    wifi_sniffer_stop();
    wifi_wardrive_stop();
    
    MY_LOG_INFO(TAG, "All operations stopped");
    return 0;
}

static int cmd_sniffer(int argc, char **argv) {
    (void)argc; (void)argv;
    wifi_sniffer_start();
    return 0;
}

static int cmd_show_sniff(int argc, char **argv) {
    (void)argc; (void)argv;
    wifi_sniffer_show_results();
    return 0;
}

static int cmd_show_probes(int argc, char **argv) {
    (void)argc; (void)argv;
    wifi_sniffer_show_probes();
    return 0;
}

static int cmd_sniff_debug(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: sniff_debug <on|off>");
        return 1;
    }
    
    bool enable = (strcmp(argv[1], "on") == 0 || strcmp(argv[1], "1") == 0);
    wifi_sniffer_set_debug(enable);
    return 0;
}

static int cmd_snifferdog(int argc, char **argv) {
    (void)argc; (void)argv;
    wifi_sniffer_dog_start();
    return 0;
}

static int cmd_evil_twin(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: evil_twin <ssid> [password]");
        return 1;
    }
    
    const char *ssid = argv[1];
    const char *password = (argc >= 3) ? argv[2] : NULL;
    
    // Disable Karma mode for Evil Twin (enables WiFi password verification)
    wifi_attacks_set_karma_mode(false);
    wifi_attacks_start_evil_twin(ssid, password);
    return 0;
}

static int cmd_blackout(int argc, char **argv) {
    (void)argc; (void)argv;
    wifi_attacks_start_blackout();
    return 0;
}

static int cmd_sae_overflow(int argc, char **argv) {
    (void)argc; (void)argv;
    wifi_attacks_start_sae_overflow();
    return 0;
}

static int cmd_karma(int argc, char **argv) {
    (void)argc; (void)argv;
    wifi_attacks_start_karma();
    return 0;
}

static int cmd_portal(int argc, char **argv) {
    const char *ssid = (argc >= 2) ? argv[1] : "Free WiFi";
    wifi_attacks_start_portal(ssid);
    return 0;
}

static int cmd_wardrive(int argc, char **argv) {
    (void)argc; (void)argv;
    wifi_wardrive_start();
    return 0;
}

static int cmd_gps_fix(int argc, char **argv) {
    (void)argc; (void)argv;
    wifi_wardrive_get_gps_fix();
    return 0;
}

void wifi_cli_register_commands(void) {
    const esp_console_cmd_t scan_cmd = {
        .command = "scan",
        .help = "Scan WiFi networks",
        .hint = NULL,
        .func = &cmd_scan,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&scan_cmd));
    
    const esp_console_cmd_t show_cmd = {
        .command = "show",
        .help = "Show scan results",
        .hint = NULL,
        .func = &cmd_show,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_cmd));
    
    const esp_console_cmd_t select_cmd = {
        .command = "select",
        .help = "Select networks: select <idx1> [idx2] ...",
        .hint = NULL,
        .func = &cmd_select,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&select_cmd));
    
    const esp_console_cmd_t deauth_cmd = {
        .command = "deauth",
        .help = "Start deauth attack",
        .hint = NULL,
        .func = &cmd_deauth,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&deauth_cmd));
    
    const esp_console_cmd_t sniffer_cmd = {
        .command = "sniffer",
        .help = "Start sniffer",
        .hint = NULL,
        .func = &cmd_sniffer,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sniffer_cmd));
    
    const esp_console_cmd_t wardrive_cmd = {
        .command = "wardrive",
        .help = "Start wardrive",
        .hint = NULL,
        .func = &cmd_wardrive,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wardrive_cmd));
    
    const esp_console_cmd_t stop_cmd = {
        .command = "stop",
        .help = "Stop all operations",
        .hint = NULL,
        .func = &cmd_stop,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&stop_cmd));
    
    const esp_console_cmd_t show_sniff_cmd = {
        .command = "show_sniff",
        .help = "Show sniffer results",
        .hint = NULL,
        .func = &cmd_show_sniff,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_sniff_cmd));
    
    const esp_console_cmd_t show_probes_cmd = {
        .command = "show_probes",
        .help = "Show probe requests",
        .hint = NULL,
        .func = &cmd_show_probes,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_probes_cmd));
    
    const esp_console_cmd_t sniff_debug_cmd = {
        .command = "sniff_debug",
        .help = "Enable/disable sniffer debug: sniff_debug <on|off>",
        .hint = NULL,
        .func = &cmd_sniff_debug,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sniff_debug_cmd));
    
    const esp_console_cmd_t snifferdog_cmd = {
        .command = "snifferdog",
        .help = "Start SnifferDog (passive probe detection)",
        .hint = NULL,
        .func = &cmd_snifferdog,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&snifferdog_cmd));
    
    const esp_console_cmd_t evil_twin_cmd = {
        .command = "evil_twin",
        .help = "Start Evil Twin: evil_twin <ssid> [password]",
        .hint = NULL,
        .func = &cmd_evil_twin,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&evil_twin_cmd));
    
    const esp_console_cmd_t blackout_cmd = {
        .command = "blackout",
        .help = "Start blackout attack",
        .hint = NULL,
        .func = &cmd_blackout,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&blackout_cmd));
    
    const esp_console_cmd_t sae_overflow_cmd = {
        .command = "sae_overflow",
        .help = "Start SAE overflow attack",
        .hint = NULL,
        .func = &cmd_sae_overflow,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sae_overflow_cmd));
    
    const esp_console_cmd_t karma_cmd = {
        .command = "karma",
        .help = "Start Karma attack",
        .hint = NULL,
        .func = &cmd_karma,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&karma_cmd));
    
    const esp_console_cmd_t portal_cmd = {
        .command = "portal",
        .help = "Start captive portal: portal [ssid]",
        .hint = NULL,
        .func = &cmd_portal,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&portal_cmd));
    
    const esp_console_cmd_t gps_fix_cmd = {
        .command = "gps_fix",
        .help = "Get GPS fix information",
        .hint = NULL,
        .func = &cmd_gps_fix,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&gps_fix_cmd));
    
    ESP_LOGI(TAG, "CLI commands registered");
}

esp_err_t wifi_cli_start_console(void) {
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = ">";
    repl_config.max_cmdline_length = 100;
    
    esp_console_register_help_command();
    wifi_cli_register_commands();
    
    esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&hw_config, &repl_config, &repl));
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
    
    return ESP_OK;
}

