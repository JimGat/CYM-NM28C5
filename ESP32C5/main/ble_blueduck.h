#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "wifi_common.h"

#define BD_MAX_SCRIPTS 32

typedef const gps_data_t *(*bd_gps_fn_t)(void);

typedef struct {
    int  connects;
    int  payloads_sent;
    int  disconnects;
    int  current_persona;
    bool active;
    bool executing;
    char persona_name[32];
    char script_path[128];
    char log_path[80];
} blueduck_stats_t;

/* Call from bt_nimble_init() BEFORE nimble_port_freertos_init() */
void        blueduck_register_services(void);

/* Call once after sd_spi_mutex is created */
void        blueduck_init(SemaphoreHandle_t sd_mutex, bd_gps_fn_t gps_fn);

/* Start advertising with given persona; script_path is full SD path to .duck file */
void        blueduck_start(int persona_idx, const char *script_path);

/* Stop advertising + kill any active connection/script */
void        blueduck_stop(void);

bool        blueduck_is_active(void);
void        blueduck_get_stats(blueduck_stats_t *out);

int         blueduck_persona_count(void);
const char *blueduck_persona_name(int idx);

/* Scan /sdcard/lab/ble/blueduck/scripts/ and return number of .duck files found.
 * Each name (no path, no extension) is accessible via blueduck_script_name(i). */
int         blueduck_scan_scripts(void);
const char *blueduck_script_name(int idx);
const char *blueduck_script_path(int idx);
