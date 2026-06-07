#ifndef SD_ERROR_HANDLER_H
#define SD_ERROR_HANDLER_H

#include <stdint.h>

typedef struct {
    uint64_t error_time_us;
    char feature[32];       // e.g. "Wardrive CSV", "PCAP capture"
    char operation[32];     // e.g. "fprintf", "fwrite", "mkdir"
    char detail[96];        // e.g. "line 11231" or "csv header"
    bool acknowledged;
} sd_error_t;

extern sd_error_t g_sd_error;
extern bool g_sd_error_pending;

void sd_error_report(const char *feature, const char *operation, const char *detail);
void sd_error_modal_show(void);
void sd_error_modal_update(void);
void sd_error_modal_dismiss(void);

#endif // SD_ERROR_HANDLER_H
