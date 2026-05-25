#pragma once
// =============================================================================
// lf_reader_iface — abstract interface for LF 125 kHz readers
// =============================================================================
// Defines the function-pointer vtable that any LF reader backend must implement.
// Current implementation: lf_stub (no hardware).
// Future: dedicated LF module (e.g. RDM6300, EM4305 writer board).
// =============================================================================

#include "rfid_types.h"

typedef struct {
    // Initialize hardware (GPIO, UART, SPI, etc.)
    rfid_err_t (*init)(void);

    // Release all hardware resources
    void (*deinit)(void);

    // Returns true if hardware is initialized
    bool (*is_init)(void);

    // Scan for one LF card, blocks up to timeout_ms.
    // Fills card->lf_raw, lf_raw_len, lf_facility_code, lf_card_number.
    rfid_err_t (*scan)(rfid_card_t *card, uint32_t timeout_ms);

    // Human-readable backend name ("LF Stub", "RDM6300", etc.)
    const char *name;
} lf_reader_iface_t;
