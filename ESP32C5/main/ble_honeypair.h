#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "wifi_common.h"

typedef const gps_data_t *(*hp_gps_fn_t)(void);

typedef struct {
    int  connects;
    int  pairs;
    int  gatt_reads;
    int  disconnects;
    int  current_persona;
    bool active;
    char persona_name[32];
    char log_path[72];
} honeypair_stats_t;

/* Call from bt_nimble_init() BEFORE nimble_port_freertos_init() */
void        honeypair_register_services(void);

/* Call once after sd_spi_mutex is created */
void        honeypair_init(SemaphoreHandle_t sd_mutex, hp_gps_fn_t gps_fn);

/* Start connectable advertising under given persona index */
void        honeypair_start(int persona_idx);

/* Stop advertising + disconnect any active connection */
void        honeypair_stop(void);

bool        honeypair_is_active(void);
void        honeypair_get_stats(honeypair_stats_t *out);
void        honeypair_set_persona(int idx);
int         honeypair_persona_count(void);
const char *honeypair_persona_name(int idx);
