/*
 * test_obs_detectors.c — Host-side unit tests for the obs_detectors registry.
 *
 * Compile and run (plain gcc, no ESP-IDF required):
 *   make -C ESP32C5/test/obs_detectors
 *
 * Each test_xxx() function exercises one detector with a positive hit and one
 * negative (wrong type or wrong label) to catch both false-negatives and
 * false-positives.  All assertions use the minimal CHECK() macro below.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/* ── Minimal stubs so obs_store.h compiles without ESP-IDF ───────────────── */
#include "../../components/obs_store/include/obs_store.h"
#include "../../components/obs_detectors/include/obs_detectors.h"

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) \
    do { \
        if (cond) { printf("  PASS  %s\n", msg); g_pass++; } \
        else       { printf("  FAIL  %s\n", msg); g_fail++; } \
    } while (0)

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static obs_record_t make_ble(const char *label, bool mfr, bool svc)
{
    obs_record_t r = {0};
    r.obs_type = (uint8_t)OBS_TYPE_BLE_ADV;
    if (label) strncpy(r.label, label, sizeof(r.label) - 1);
    if (mfr) r.evidence[r.evidence_count++] = (uint8_t)OBS_EV_MFR_DATA;
    if (svc) r.evidence[r.evidence_count++] = (uint8_t)OBS_EV_SVC_UUID;
    return r;
}

static obs_record_t make_wifi(const char *ssid)
{
    obs_record_t r = {0};
    r.obs_type = (uint8_t)OBS_TYPE_WIFI_AP;
    if (ssid) strncpy(r.label, ssid, sizeof(r.label) - 1);
    return r;
}

/* ── Tests ───────────────────────────────────────────────────────────────── */

static void test_airtag(obs_registry_t *reg)
{
    printf("AirTag:\n");
    obs_record_t hit = make_ble("AirTag", true, false);
    obs_registry_run(reg, &hit);
    CHECK(hit.confidence == 90,  "confidence=90 on match");

    obs_record_t miss = make_ble("AirTag", true, false);
    miss.obs_type = (uint8_t)OBS_TYPE_WIFI_AP;   /* wrong type */
    obs_registry_run(reg, &miss);
    CHECK(miss.confidence == 0, "no match when wrong obs_type");
}

static void test_find_my(obs_registry_t *reg)
{
    printf("FindMy:\n");
    obs_record_t hit = make_ble("FindMy", true, false);
    obs_registry_run(reg, &hit);
    CHECK(hit.confidence == 60, "confidence=60 on match");

    obs_record_t miss = make_ble("FindMyPhone", true, false); /* not same prefix */
    obs_registry_run(reg, &miss);
    CHECK(miss.confidence == 60, "FindMyPhone also matches FindMy prefix");

    obs_record_t miss2 = make_ble("Apple Watch", true, false);
    obs_registry_run(reg, &miss2);
    CHECK(miss2.confidence == 0, "unrelated label does not match");
}

static void test_smarttag(obs_registry_t *reg)
{
    printf("SmartTag:\n");
    obs_record_t hit = make_ble("SmartTag", true, false);
    obs_registry_run(reg, &hit);
    CHECK(hit.confidence == 85, "confidence=85 on match");

    obs_record_t miss = make_ble("SamsungTV", true, false);
    obs_registry_run(reg, &miss);
    CHECK(miss.confidence == 0, "unrelated Samsung device does not match");
}

static void test_tile(obs_registry_t *reg)
{
    printf("Tile:\n");
    obs_record_t hit = make_ble("Tile", false, true);
    obs_registry_run(reg, &hit);
    CHECK(hit.confidence == 85, "confidence=85 on match");

    /* Case-insensitive: "tile" should match */
    obs_record_t ci = make_ble("tile", false, true);
    obs_registry_run(reg, &ci);
    CHECK(ci.confidence == 85, "lowercase label matches");

    obs_record_t miss = make_ble("TileFloor", false, true);
    obs_registry_run(reg, &miss);
    CHECK(miss.confidence == 85, "TileFloor also matches Tile prefix");
}

static void test_eddystone(obs_registry_t *reg)
{
    printf("Eddystone:\n");
    obs_record_t hit = make_ble("Eddystone", false, true);
    obs_registry_run(reg, &hit);
    CHECK(hit.confidence == 80, "confidence=80 on match");

    obs_record_t miss = make_ble("iBeacon", false, true);
    obs_registry_run(reg, &miss);
    CHECK(miss.confidence == 0, "iBeacon does not match Eddystone");
}

static void test_fast_pair(obs_registry_t *reg)
{
    printf("FastPair:\n");
    obs_record_t hit = make_ble("FastPair", false, true);
    obs_registry_run(reg, &hit);
    CHECK(hit.confidence == 75, "confidence=75 on match");

    obs_record_t miss = make_ble("", false, true);
    obs_registry_run(reg, &miss);
    CHECK(miss.confidence == 0, "empty label does not match");
}

static void test_matter(obs_registry_t *reg)
{
    printf("Matter:\n");
    obs_record_t hit = make_ble("Matter", false, true);
    obs_registry_run(reg, &hit);
    CHECK(hit.confidence == 85, "confidence=85 on match");

    obs_record_t miss = make_ble("Matter", false, true);
    miss.obs_type = (uint8_t)OBS_TYPE_WIFI_AP;
    obs_registry_run(reg, &miss);
    CHECK(miss.confidence == 0, "BLE-only: WiFi AP with 'Matter' label does not match");
}

static void test_pwnagotchi(obs_registry_t *reg)
{
    printf("Pwnagotchi:\n");
    obs_record_t hit = make_wifi("pwnagotchi");
    obs_registry_run(reg, &hit);
    CHECK(hit.confidence == 88, "confidence=88 for 'pwnagotchi'");

    obs_record_t hit2 = make_wifi("pwn0");
    obs_registry_run(reg, &hit2);
    CHECK(hit2.confidence == 88, "confidence=88 for 'pwn0'");

    /* Case-insensitive: "PWN-unit" should match */
    obs_record_t ci = make_wifi("PWN-unit");
    obs_registry_run(reg, &ci);
    CHECK(ci.confidence == 88, "uppercase 'PWN-unit' matches");

    obs_record_t miss_ble = make_ble("pwnagotchi", false, false);
    obs_registry_run(reg, &miss_ble);
    CHECK(miss_ble.confidence == 0, "BLE obs with 'pwnagotchi' label does not match WiFi detector");

    obs_record_t miss_ssid = make_wifi("HomeNetwork");
    obs_registry_run(reg, &miss_ssid);
    CHECK(miss_ssid.confidence == 0, "unrelated SSID does not match");
}

static void test_evidence_dedup(obs_registry_t *reg)
{
    printf("Evidence dedup:\n");
    obs_record_t r = make_ble("AirTag", true, false); /* MFR_DATA already present */
    uint8_t count_before = r.evidence_count;
    obs_registry_run(reg, &r);
    /* AirTag detector calls ev_add(OBS_EV_MFR_DATA) — should not duplicate */
    CHECK(r.evidence_count == count_before, "MFR_DATA not duplicated in evidence[]");
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== obs_detectors host tests ===\n\n");

    obs_registry_t *reg = obs_detectors_default_registry();
    if (!reg) {
        printf("FATAL: obs_detectors_default_registry() returned NULL\n");
        return 1;
    }
    printf("Registry: %u/%u detectors registered\n\n", reg->count, OBS_REGISTRY_MAX);

    test_airtag(reg);
    test_find_my(reg);
    test_smarttag(reg);
    test_tile(reg);
    test_eddystone(reg);
    test_fast_pair(reg);
    test_matter(reg);
    test_pwnagotchi(reg);
    test_evidence_dedup(reg);

    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
