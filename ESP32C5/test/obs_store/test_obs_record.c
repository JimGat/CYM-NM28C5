/*
 * test_obs_record.c — Host unit tests for obs_store (Phase 2)
 *
 * Compiled with plain gcc; no ESP-IDF required.
 * Run: make -C ESP32C5/test/obs_store && ESP32C5/test/obs_store/test_obs_store
 *
 * Tests cover:
 *   1. Struct sizing and field offsets
 *   2. Store init / deinit
 *   3. Add new records and count
 *   4. MAC deduplication and merge (rssi_cur, rssi_peak, rssi_trend, hit_count)
 *   5. Ring-buffer eviction and overflow counter when store is full
 *   6. obs_store_find: hit and miss
 *   7. Privacy redaction: GPS, MAC, label
 *   8. Evidence confidence bounds
 *   9. JSON serialisation smoke test (parse key/value)
 *  10. Detector registry: register, run first-match
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "obs_store.h"

/* ── Minimal test harness ────────────────────────────────────────────────── */

static int g_pass = 0, g_fail = 0;

#define CHECK(expr) do { \
    if (expr) { g_pass++; } \
    else { \
        fprintf(stderr, "FAIL  %s:%d  %s\n", __FILE__, __LINE__, #expr); \
        g_fail++; \
    } \
} while (0)

#define CHECK_EQ(a, b) CHECK((a) == (b))
#define CHECK_NE(a, b) CHECK((a) != (b))
#define CHECK_STR(s, expected) CHECK(strcmp((s), (expected)) == 0)

static void test_section(const char *name)
{
    printf("\n[%s]\n", name);
}

/* ── Helper: build a minimal record ─────────────────────────────────────── */

static obs_record_t make_record(const uint8_t mac[6], int8_t rssi,
                                uint8_t channel, obs_radio_t radio,
                                obs_type_t type, const char *label)
{
    obs_record_t r = {0};
    r.schema_version = OBS_SCHEMA_VERSION;
    r.src_radio      = (uint8_t)radio;
    r.obs_type       = (uint8_t)type;
    memcpy(r.mac, mac, 6);
    r.rssi_cur       = rssi;
    r.rssi_peak      = rssi;
    r.rssi_trend     = 0;
    r.channel        = channel;
    r.hit_count      = 1;
    r.first_seen_s   = 1000000;
    r.last_seen_s    = 1000000;
    r.latitude       = 37.7749f;
    r.longitude      = -122.4194f;
    r.altitude_m     = 10.0f;
    r.accuracy_m     = 5.0f;
    r.flags          = OBS_FLAG_GPS_VALID;
    if (label) strncpy(r.label, label, sizeof(r.label) - 1);
    return r;
}

/* ── Test 1: Struct layout ───────────────────────────────────────────────── */

static void test_struct_layout(void)
{
    test_section("1. Struct layout");

    /* Critical: must be 88 bytes on both host (LP64) and ESP32-C5 (ILP32). */
    CHECK_EQ(sizeof(obs_record_t), 88u);

    /* Spot-check key offsets to catch silent padding changes. */
    CHECK_EQ(offsetof(obs_record_t, mac),          4u);
    CHECK_EQ(offsetof(obs_record_t, rssi_cur),    16u);
    CHECK_EQ(offsetof(obs_record_t, hit_count),   28u);
    CHECK_EQ(offsetof(obs_record_t, first_seen_s),32u);
    CHECK_EQ(offsetof(obs_record_t, latitude),    40u);
    CHECK_EQ(offsetof(obs_record_t, label),       56u);

    /* hit_count and first_seen_s must be naturally aligned. */
    CHECK_EQ(offsetof(obs_record_t, hit_count)    % 2, 0u);
    CHECK_EQ(offsetof(obs_record_t, first_seen_s) % 4, 0u);
    CHECK_EQ(offsetof(obs_record_t, latitude)     % 4, 0u);
}

/* ── Test 2: Store init / deinit ─────────────────────────────────────────── */

static void test_init_deinit(void)
{
    test_section("2. Store init / deinit");

    obs_store_t s;
    CHECK(obs_store_init(&s, 4));
    CHECK_EQ(obs_store_count(&s), 0u);
    CHECK_EQ(obs_store_overflow(&s), 0u);
    CHECK_EQ(s.capacity, 4u);
    CHECK_NE(s.records, NULL);

    obs_store_deinit(&s);
    CHECK_EQ(s.records, NULL);
    CHECK_EQ(s.capacity, 0u);

    /* Default capacity */
    CHECK(obs_store_init(&s, 0));
    CHECK_EQ(s.capacity, OBS_STORE_DEFAULT_CAPACITY);
    obs_store_deinit(&s);
}

/* ── Test 3: Add new records ─────────────────────────────────────────────── */

static void test_add_new(void)
{
    test_section("3. Add new records");

    obs_store_t s;
    CHECK(obs_store_init(&s, 8));

    const uint8_t mac_a[] = {0xAA,0xBB,0xCC,0x00,0x00,0x01};
    const uint8_t mac_b[] = {0xAA,0xBB,0xCC,0x00,0x00,0x02};

    obs_record_t ra = make_record(mac_a, -60, 6, OBS_RADIO_WIFI, OBS_TYPE_WIFI_AP, "NetA");
    obs_record_t rb = make_record(mac_b, -70, 1, OBS_RADIO_BLE,  OBS_TYPE_BLE_ADV,  "DevB");

    obs_record_t *pa = obs_store_add(&s, &ra);
    CHECK_NE(pa, NULL);
    CHECK_EQ(obs_store_count(&s), 1u);

    obs_record_t *pb = obs_store_add(&s, &rb);
    CHECK_NE(pb, NULL);
    CHECK_EQ(obs_store_count(&s), 2u);
    CHECK_EQ(obs_store_overflow(&s), 0u);

    /* schema_version is stamped by the store */
    CHECK_EQ(pa->schema_version, OBS_SCHEMA_VERSION);
    CHECK_EQ(pa->hit_count, 1u);

    obs_store_deinit(&s);
}

/* ── Test 4: MAC deduplication and merge ─────────────────────────────────── */

static void test_merge(void)
{
    test_section("4. MAC dedup and merge");

    obs_store_t s;
    CHECK(obs_store_init(&s, 8));

    const uint8_t mac[] = {0x11,0x22,0x33,0x44,0x55,0x66};

    obs_record_t r1 = make_record(mac, -60, 6, OBS_RADIO_WIFI, OBS_TYPE_WIFI_AP, "Net");
    r1.first_seen_s = 1000;
    r1.last_seen_s  = 1000;
    obs_record_t *p1 = obs_store_add(&s, &r1);
    CHECK_NE(p1, NULL);
    CHECK_EQ(obs_store_count(&s), 1u);

    /* Stronger signal update */
    obs_record_t r2 = make_record(mac, -50, 6, OBS_RADIO_WIFI, OBS_TYPE_WIFI_AP, "Net");
    r2.first_seen_s = 2000;
    r2.last_seen_s  = 2000;
    obs_record_t *p2 = obs_store_add(&s, &r2);
    CHECK_EQ(p2, p1);                    /* same slot returned */
    CHECK_EQ(obs_store_count(&s), 1u);   /* still one record */
    CHECK_EQ(p1->rssi_cur,  -50);
    CHECK_EQ(p1->rssi_peak, -50);
    CHECK_EQ(p1->rssi_trend, +1);        /* stronger */
    CHECK_EQ(p1->hit_count, 2u);

    /* Weaker signal update */
    obs_record_t r3 = make_record(mac, -80, 6, OBS_RADIO_WIFI, OBS_TYPE_WIFI_AP, "Net");
    r3.last_seen_s = 3000;
    obs_store_add(&s, &r3);
    CHECK_EQ(p1->rssi_cur,   -80);
    CHECK_EQ(p1->rssi_peak,  -50);       /* peak preserved */
    CHECK_EQ(p1->rssi_trend,  -1);       /* weaker */
    CHECK_EQ(p1->hit_count,   3u);
    CHECK_EQ(p1->last_seen_s, 3000u);
    CHECK_EQ(p1->first_seen_s, 1000u);   /* first_seen unchanged */

    obs_store_deinit(&s);
}

/* ── Test 5: Ring-buffer eviction and overflow ───────────────────────────── */

static void test_eviction(void)
{
    test_section("5. Ring-buffer eviction and overflow");

    obs_store_t s;
    CHECK(obs_store_init(&s, 3));   /* tiny 3-slot store */

    const uint8_t mac1[] = {0x01,0,0,0,0,0x01};
    const uint8_t mac2[] = {0x01,0,0,0,0,0x02};
    const uint8_t mac3[] = {0x01,0,0,0,0,0x03};
    const uint8_t mac4[] = {0x01,0,0,0,0,0x04};

    obs_record_t r1 = make_record(mac1, -50, 1, OBS_RADIO_BLE, OBS_TYPE_BLE_ADV, "D1");
    obs_record_t r2 = make_record(mac2, -55, 1, OBS_RADIO_BLE, OBS_TYPE_BLE_ADV, "D2");
    obs_record_t r3 = make_record(mac3, -60, 1, OBS_RADIO_BLE, OBS_TYPE_BLE_ADV, "D3");
    obs_record_t r4 = make_record(mac4, -65, 1, OBS_RADIO_BLE, OBS_TYPE_BLE_ADV, "D4");

    obs_store_add(&s, &r1);
    obs_store_add(&s, &r2);
    obs_store_add(&s, &r3);
    CHECK_EQ(obs_store_count(&s), 3u);
    CHECK_EQ(obs_store_overflow(&s), 0u);

    /* Adding a 4th unique MAC overflows */
    obs_store_add(&s, &r4);
    CHECK_EQ(obs_store_count(&s), 3u);   /* count stays at capacity */
    CHECK_EQ(obs_store_overflow(&s), 1u);

    /* D4 should now be findable; the oldest slot (D1) was overwritten */
    CHECK_NE(obs_store_find(&s, mac4), NULL);

    /* Adding D4 again (same MAC) should merge, not overflow again */
    obs_store_add(&s, &r4);
    CHECK_EQ(obs_store_overflow(&s), 1u); /* overflow unchanged */

    obs_store_deinit(&s);
}

/* ── Test 6: Find hit and miss ───────────────────────────────────────────── */

static void test_find(void)
{
    test_section("6. obs_store_find");

    obs_store_t s;
    CHECK(obs_store_init(&s, 8));

    const uint8_t mac_in[]  = {0xDE,0xAD,0xBE,0xEF,0x00,0x01};
    const uint8_t mac_out[] = {0xCA,0xFE,0xBA,0xBE,0x00,0x01};

    obs_record_t r = make_record(mac_in, -60, 6, OBS_RADIO_WIFI, OBS_TYPE_WIFI_AP, "X");
    obs_store_add(&s, &r);

    CHECK_NE(obs_store_find(&s, mac_in),  NULL);
    CHECK_EQ(obs_store_find(&s, mac_out), NULL);

    obs_store_deinit(&s);
}

/* ── Test 7: Privacy redaction ───────────────────────────────────────────── */

static void test_redaction(void)
{
    test_section("7. Privacy redaction");

    const uint8_t mac[] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    obs_record_t r = make_record(mac, -60, 6, OBS_RADIO_WIFI, OBS_TYPE_WIFI_AP, "MySSID");
    r.flags |= OBS_FLAG_GPS_VALID;

    /* GPS redaction */
    obs_record_t g = r;
    obs_redact(&g, OBS_PRIV_REDACT_GPS);
    CHECK_EQ(g.latitude,  0.0f);
    CHECK_EQ(g.longitude, 0.0f);
    CHECK_EQ(g.altitude_m, 0.0f);
    CHECK_EQ(g.accuracy_m, 0.0f);
    CHECK(g.flags & OBS_FLAG_REDACTED);
    CHECK(!(g.flags & OBS_FLAG_GPS_VALID));
    /* MAC and label untouched */
    CHECK(memcmp(g.mac, mac, 6) == 0);
    CHECK_STR(g.label, "MySSID");

    /* MAC redaction */
    obs_record_t m = r;
    obs_redact(&m, OBS_PRIV_REDACT_MAC);
    const uint8_t zero6[6] = {0};
    CHECK(memcmp(m.mac,      zero6, 6) == 0);
    CHECK(memcmp(m.peer_mac, zero6, 6) == 0);
    CHECK(m.flags & OBS_FLAG_REDACTED);
    /* GPS untouched */
    CHECK(m.latitude  != 0.0f);

    /* Label redaction */
    obs_record_t l = r;
    obs_redact(&l, OBS_PRIV_REDACT_LABEL);
    CHECK_EQ(l.label[0], '\0');
    CHECK(l.flags & OBS_FLAG_REDACTED);

    /* Combined: all three */
    obs_record_t c = r;
    obs_redact(&c, OBS_PRIV_REDACT_GPS | OBS_PRIV_REDACT_MAC | OBS_PRIV_REDACT_LABEL);
    CHECK_EQ(c.latitude,  0.0f);
    CHECK(memcmp(c.mac, zero6, 6) == 0);
    CHECK_EQ(c.label[0], '\0');
    CHECK(c.flags & OBS_FLAG_REDACTED);
}

/* ── Test 8: Evidence and confidence bounds ──────────────────────────────── */

static void test_evidence(void)
{
    test_section("8. Evidence and confidence");

    obs_store_t s;
    CHECK(obs_store_init(&s, 4));

    const uint8_t mac[] = {0xBB,0xBB,0xBB,0xBB,0xBB,0xBB};
    obs_record_t r = make_record(mac, -60, 6, OBS_RADIO_WIFI, OBS_TYPE_WIFI_AP, "Z");
    r.evidence[0]     = OBS_EV_OUI_MATCH;
    r.evidence[1]     = OBS_EV_SSID_PATTERN;
    r.evidence_count  = 2;
    r.confidence      = 80;

    obs_record_t *p = obs_store_add(&s, &r);
    CHECK_NE(p, NULL);
    CHECK_EQ(p->confidence,     80u);
    CHECK_EQ(p->evidence_count,  2u);
    CHECK_EQ(p->evidence[0], OBS_EV_OUI_MATCH);
    CHECK_EQ(p->evidence[1], OBS_EV_SSID_PATTERN);

    /* Merge: higher confidence wins; no duplicate evidence */
    obs_record_t r2 = make_record(mac, -55, 6, OBS_RADIO_WIFI, OBS_TYPE_WIFI_AP, "Z");
    r2.evidence[0]    = OBS_EV_OUI_MATCH;   /* duplicate — should not be added */
    r2.evidence[1]    = OBS_EV_RECURRENCE;  /* new */
    r2.evidence_count = 2;
    r2.confidence     = 90;
    obs_store_add(&s, &r2);
    CHECK_EQ(p->confidence,     90u);   /* updated */
    CHECK_EQ(p->evidence_count,  3u);   /* OUI_MATCH + SSID_PATTERN + RECURRENCE */
    CHECK_EQ(p->evidence[2], OBS_EV_RECURRENCE);

    obs_store_deinit(&s);
}

/* ── Test 9: JSON serialisation ──────────────────────────────────────────── */

static void test_json(void)
{
    test_section("9. JSON serialisation");

    const uint8_t mac[] = {0x12,0x34,0x56,0x78,0x9A,0xBC};
    obs_record_t r = make_record(mac, -65, 11, OBS_RADIO_WIFI, OBS_TYPE_WIFI_AP, "TestNet");
    r.evidence[0]    = OBS_EV_OUI_MATCH;
    r.evidence_count = 1;
    r.confidence     = 50;

    char buf[512];
    int  n = obs_record_to_json(&r, buf, sizeof(buf));
    CHECK(n > 0);

    /* Basic structural checks */
    CHECK(strstr(buf, "\"v\":1")                != NULL);
    CHECK(strstr(buf, "\"radio\":0")            != NULL);
    CHECK(strstr(buf, "\"mac\":\"12:34:56:78:9A:BC\"") != NULL);
    CHECK(strstr(buf, "\"rssi\":-65")           != NULL);
    CHECK(strstr(buf, "\"ch\":11")              != NULL);
    CHECK(strstr(buf, "\"conf\":50")            != NULL);
    CHECK(strstr(buf, "\"label\":\"TestNet\"")  != NULL);
    CHECK(buf[0] == '{');
    CHECK(buf[n-1] == '}');

    /* Buffer-too-small returns -1 */
    char small[10];
    CHECK_EQ(obs_record_to_json(&r, small, sizeof(small)), -1);

    /* Label with quotes is escaped */
    obs_record_t rq = r;
    strncpy(rq.label, "Net\"Q\\X", sizeof(rq.label)-1);
    char buf2[512];
    int n2 = obs_record_to_json(&rq, buf2, sizeof(buf2));
    CHECK(n2 > 0);
    CHECK(strstr(buf2, "\\\"Q\\\\X") != NULL);

    puts(buf); /* print for visual inspection */
}

/* ── Test 10: Detector registry ──────────────────────────────────────────── */

static bool det_always_yes(obs_record_t *rec)
{
    rec->confidence = 99;
    rec->evidence[0] = OBS_EV_SSID_PATTERN;
    rec->evidence_count = 1;
    return true;
}

static bool det_always_no(obs_record_t *rec)
{
    (void)rec;
    return false;
}

static const obs_detector_t DET_YES = { .name = "always_yes", .version = 1, .analyse = det_always_yes };
static const obs_detector_t DET_NO  = { .name = "always_no",  .version = 1, .analyse = det_always_no  };

static void test_detector_registry(void)
{
    test_section("10. Detector registry");

    obs_registry_t reg;
    obs_registry_init(&reg);
    CHECK_EQ(reg.count, 0u);

    /* Register two detectors */
    CHECK(obs_registry_register(&reg, &DET_NO));
    CHECK(obs_registry_register(&reg, &DET_YES));
    CHECK_EQ(reg.count, 2u);

    /* Run: DET_NO returns false, DET_YES returns true → 1 classified */
    obs_record_t r = {0};
    int n = obs_registry_run(&reg, &r);
    CHECK_EQ(n, 1);
    CHECK_EQ(r.confidence, 99u);

    /* Registry full */
    obs_registry_t full_reg;
    obs_registry_init(&full_reg);
    for (int i = 0; i < (int)OBS_REGISTRY_MAX; i++)
        obs_registry_register(&full_reg, &DET_NO);
    CHECK(!obs_registry_register(&full_reg, &DET_YES));

    /* NULL safety */
    obs_registry_run(NULL, &r);
    obs_registry_run(&reg, NULL);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("obs_store host tests\n");
    printf("obs_record_t: sizeof=%zu, OBS_SCHEMA_VERSION=%d\n",
           sizeof(obs_record_t), OBS_SCHEMA_VERSION);

    test_struct_layout();
    test_init_deinit();
    test_add_new();
    test_merge();
    test_eviction();
    test_find();
    test_redaction();
    test_evidence();
    test_json();
    test_detector_registry();

    printf("\n%s: %d passed, %d failed\n",
           g_fail ? "FAIL" : "PASS", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
