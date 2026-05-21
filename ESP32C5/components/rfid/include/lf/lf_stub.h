#pragma once
// =============================================================================
// lf_stub — placeholder LF 125 kHz reader backend (no hardware present)
// =============================================================================
// Satisfies lf_reader_iface_t so the menu and storage compile and function
// without a physical LF reader.  Replace with a real driver when hardware arrives.
// =============================================================================

#include "lf/lf_reader_iface.h"

// The singleton stub backend instance.
extern const lf_reader_iface_t lf_stub_reader;
