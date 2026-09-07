/*
 * obs_detectors.h — Built-in passive detector packs (Phase 4).
 *
 * Each detector is a pure obs_record_t → bool function.  Detectors may set
 * rec->confidence (0–100) and append to rec->evidence[] when they match, but
 * they never read radio hardware or allocate memory.
 *
 * Adapters in main.c pre-enrich obs_record_t from the parsed bt_device_info_t
 * booleans (is_airtag, is_tile, is_fast_pair, …) and set canonical label names
 * before calling obs_registry_run().  Detectors then confirm the classification
 * and assign confidence scores.
 *
 * This header is intentionally free of ESP-IDF types so it can be used in host
 * unit tests compiled with plain gcc (matching the obs_store.h contract).
 */

#pragma once
#include "obs_store.h"

/*
 * Pre-populate a registry with all built-in detector packs.
 *
 * Returns a pointer to static storage (valid for the lifetime of the program).
 * Thread-safety: call once from a single task (app_main) before any adapters run.
 * Subsequent calls return the same pointer without re-initialising.
 *
 * The registry is sized for exactly OBS_REGISTRY_MAX detectors (currently 8).
 * To add a detector: implement analyse(), add a static obs_detector_t, and call
 * obs_registry_register() here — or increase OBS_REGISTRY_MAX in obs_store.h.
 */
obs_registry_t *obs_detectors_default_registry(void);
