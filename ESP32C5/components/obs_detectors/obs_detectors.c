/*
 * obs_detectors.c — Built-in passive detector packs for CYM (Phase 4).
 *
 * Eight detectors filling OBS_REGISTRY_MAX slots.  Each detector's analyse()
 * function operates solely on obs_record_t fields — no radio, no I/O, no heap.
 *
 * Data flow:
 *   bt_gap_event_callback()           — parses adv data into bt_device_info_t booleans
 *     → BLE adapter (main.c)          — maps booleans to label + evidence[]
 *       → obs_registry_run()          — detector confirms classification + confidence
 *         → obs_store_add()           — persists the enriched record
 *
 * Detector registration order = priority order (first match wins).  More specific
 * detectors (AirTag, SmartTag, Tile) are registered before generic BLE catch-alls.
 */

#include "obs_detectors.h"
#include <string.h>
#include <ctype.h>

/* ── Shared helpers ─────────────────────────────────────────────────────────── */

/* Case-insensitive prefix check — portable ASCII, no locale dependency. */
static bool label_starts_ci(const char *label, const char *prefix)
{
    if (!label || !prefix) return false;
    while (*prefix) {
        if (!*label) return false;
        if (tolower((unsigned char)*label) != tolower((unsigned char)*prefix)) return false;
        label++;
        prefix++;
    }
    return true;
}

/* Append an evidence tag to rec if not already present and the array has room. */
static void ev_add(obs_record_t *rec, uint8_t ev)
{
    for (uint8_t i = 0; i < rec->evidence_count; i++) {
        if (rec->evidence[i] == ev) return;
    }
    if (rec->evidence_count < OBS_MAX_EVIDENCE)
        rec->evidence[rec->evidence_count++] = ev;
}

/* True when obs_type is any BLE variant. */
static bool is_ble_obs(const obs_record_t *rec)
{
    return rec->obs_type == (uint8_t)OBS_TYPE_BLE_ADV ||
           rec->obs_type == (uint8_t)OBS_TYPE_BLE_EXT;
}

/* ── Detector: Apple AirTag ─────────────────────────────────────────────────── */
/*
 * Matches BLE records where the adapter pre-set label "AirTag" based on
 * bt_device_info_t.is_airtag (Apple company_id 0x004C + continuity type 0x12
 * lost-mode or direct AirTag advertisement format).
 * Confidence 90: strong manufacturer-data match; MAC is randomised so OUI alone
 * would be insufficient.
 */
static bool s_analyse_airtag(obs_record_t *rec)
{
    if (!is_ble_obs(rec)) return false;
    if (!label_starts_ci(rec->label, "AirTag")) return false;
    ev_add(rec, (uint8_t)OBS_EV_MFR_DATA);
    rec->confidence = 90;
    return true;
}

static const obs_detector_t s_det_airtag = {
    .name    = "AirTag",
    .version = 1,
    .analyse = s_analyse_airtag,
};

/* ── Detector: Apple Find My (owner-proximity / paused) ─────────────────────── */
/*
 * Matches BLE records where adapter set label "FindMy" for
 * bt_device_info_t.is_possible_airtag (Apple Nearby Action type 0x05 —
 * AirTag in owner-nearby or paused mode; also used by other Apple devices).
 * Confidence 60: type 0x05 is shared across several Apple Continuity messages;
 * more context is needed to confirm this is a tracker rather than an accessory.
 */
static bool s_analyse_find_my(obs_record_t *rec)
{
    if (!is_ble_obs(rec)) return false;
    if (!label_starts_ci(rec->label, "FindMy")) return false;
    ev_add(rec, (uint8_t)OBS_EV_MFR_DATA);
    rec->confidence = 60;
    return true;
}

static const obs_detector_t s_det_find_my = {
    .name    = "FindMy",
    .version = 1,
    .analyse = s_analyse_find_my,
};

/* ── Detector: Samsung SmartTag ─────────────────────────────────────────────── */
/*
 * Matches BLE records where adapter set label "SmartTag" for
 * bt_device_info_t.is_smarttag (Samsung company_id 0x0075 manufacturer data
 * with SmartTag payload signature).
 * Confidence 85: well-established Samsung proprietary format; MAC is randomised.
 */
static bool s_analyse_smarttag(obs_record_t *rec)
{
    if (!is_ble_obs(rec)) return false;
    if (!label_starts_ci(rec->label, "SmartTag")) return false;
    ev_add(rec, (uint8_t)OBS_EV_MFR_DATA);
    rec->confidence = 85;
    return true;
}

static const obs_detector_t s_det_smarttag = {
    .name    = "SmartTag",
    .version = 1,
    .analyse = s_analyse_smarttag,
};

/* ── Detector: Tile Tracker ─────────────────────────────────────────────────── */
/*
 * Matches BLE records where adapter set label "Tile" for
 * bt_device_info_t.is_tile (SIG-assigned service UUID 0xFEED, Tile Inc.).
 * Confidence 85: UUID is unique to Tile; confirmed in Bluetooth SIG registry.
 */
static bool s_analyse_tile(obs_record_t *rec)
{
    if (!is_ble_obs(rec)) return false;
    if (!label_starts_ci(rec->label, "Tile")) return false;
    ev_add(rec, (uint8_t)OBS_EV_SVC_UUID);
    rec->confidence = 85;
    return true;
}

static const obs_detector_t s_det_tile = {
    .name    = "Tile",
    .version = 1,
    .analyse = s_analyse_tile,
};

/* ── Detector: Eddystone Beacon ─────────────────────────────────────────────── */
/*
 * Matches BLE records where adapter set label "Eddystone" for
 * bt_device_info_t.is_eddystone (SIG UUID 0xFEAA, Google Eddystone).
 * Eddystone-URL/TLM/UID subtypes are not distinguished at this layer.
 * Confidence 80: well-known open beacon format; low false-positive risk.
 */
static bool s_analyse_eddystone(obs_record_t *rec)
{
    if (!is_ble_obs(rec)) return false;
    if (!label_starts_ci(rec->label, "Eddystone")) return false;
    ev_add(rec, (uint8_t)OBS_EV_SVC_UUID);
    rec->confidence = 80;
    return true;
}

static const obs_detector_t s_det_eddystone = {
    .name    = "Eddystone",
    .version = 1,
    .analyse = s_analyse_eddystone,
};

/* ── Detector: Google Fast Pair ─────────────────────────────────────────────── */
/*
 * Matches BLE records where adapter set label "FastPair" for
 * bt_device_info_t.is_fast_pair (SIG UUID 0xFE2C, Google Fast Pair service).
 * Note: CVE-2025-36911 affects some Fast Pair implementations — passive detection
 * only; do not interact with the device.
 * Confidence 75: UUID is assigned to Google Fast Pair but also used during
 * legitimate pairing advertisements by many headphones and accessories.
 */
static bool s_analyse_fast_pair(obs_record_t *rec)
{
    if (!is_ble_obs(rec)) return false;
    if (!label_starts_ci(rec->label, "FastPair")) return false;
    ev_add(rec, (uint8_t)OBS_EV_SVC_UUID);
    rec->confidence = 75;
    return true;
}

static const obs_detector_t s_det_fast_pair = {
    .name    = "FastPair",
    .version = 1,
    .analyse = s_analyse_fast_pair,
};

/* ── Detector: Matter Commissioning Beacon ───────────────────────────────────── */
/*
 * Matches BLE records where adapter set label "Matter" for
 * bt_device_info_t.is_matter (SIG UUID 0xFFF6, Matter / Project CHIP
 * commissioning window advertisement).
 * Confidence 85: UUID is reserved for Matter commissioning; only appears when
 * a device is actively in pairing mode — transient but high-specificity.
 */
static bool s_analyse_matter(obs_record_t *rec)
{
    if (!is_ble_obs(rec)) return false;
    if (!label_starts_ci(rec->label, "Matter")) return false;
    ev_add(rec, (uint8_t)OBS_EV_SVC_UUID);
    rec->confidence = 85;
    return true;
}

static const obs_detector_t s_det_matter = {
    .name    = "Matter",
    .version = 1,
    .analyse = s_analyse_matter,
};

/* ── Detector: Pwnagotchi ────────────────────────────────────────────────────── */
/*
 * Matches WiFi AP records whose SSID (label) starts with "pwn" (case-insensitive).
 * Pwnagotchi broadcasts its unit_name as an SSID; the default prefix is "pwn"
 * (e.g., "pwnagotchi", "pwn0", "pwnagotchi-home").
 * Source: pwnagotchi.ai/configuration — unit_name field used directly as SSID.
 * Confidence 88: "pwn" prefix is distinctive; occasional legitimate hotspot
 * collisions are possible but uncommon enough not to warrant a lower score.
 */
static bool s_analyse_pwnagotchi(obs_record_t *rec)
{
    if (rec->obs_type != (uint8_t)OBS_TYPE_WIFI_AP) return false;
    if (!label_starts_ci(rec->label, "pwn")) return false;
    ev_add(rec, (uint8_t)OBS_EV_SSID_PATTERN);
    rec->confidence = 88;
    return true;
}

static const obs_detector_t s_det_pwnagotchi = {
    .name    = "Pwnagotchi",
    .version = 1,
    .analyse = s_analyse_pwnagotchi,
};

/* ── Registry ──────────────────────────────────────────────────────────────── */

obs_registry_t *obs_detectors_default_registry(void)
{
    static obs_registry_t s_reg;
    static bool           s_init = false;

    if (s_init) return &s_reg;

    obs_registry_init(&s_reg);

    /* Registration order = priority order.  First match wins (obs_registry_run
     * stops at the first detector that returns true).  Specific tracker detectors
     * are registered before generic BLE catch-alls. */
    obs_registry_register(&s_reg, &s_det_airtag);
    obs_registry_register(&s_reg, &s_det_find_my);
    obs_registry_register(&s_reg, &s_det_smarttag);
    obs_registry_register(&s_reg, &s_det_tile);
    obs_registry_register(&s_reg, &s_det_eddystone);
    obs_registry_register(&s_reg, &s_det_fast_pair);
    obs_registry_register(&s_reg, &s_det_matter);
    obs_registry_register(&s_reg, &s_det_pwnagotchi);

    s_init = true;
    return &s_reg;
}
