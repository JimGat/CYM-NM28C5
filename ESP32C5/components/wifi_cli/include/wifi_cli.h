#ifndef WIFI_CLI_H
#define WIFI_CLI_H

#include "wifi_common.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// CLI API
// ============================================================================

/**
 * @brief Initialize WiFi CLI system (WiFi, LED, all components)
 */
esp_err_t wifi_cli_init(void);

/**
 * @brief Register all CLI commands
 */
void wifi_cli_register_commands(void);

/**
 * @brief Start console REPL
 */
esp_err_t wifi_cli_start_console(void);

#ifdef __cplusplus
}
#endif

#endif // WIFI_CLI_H

