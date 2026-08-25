/*
 * obs_store.h — Passive Observation Store (Phase 2)
 *
 * Fixed-size observation records, bounded PSRAM-backed store, privacy/redaction
 * policy, and detector registry interface for CYM passive wireless observation.
 *
 * Intentionally free of ESP-IDF types so this header can be included in host
 * unit tests compiled with plain gcc.  Adapters that bridge ESP-IDF wifi_ap_record_t
 * and bt_device_info_t into obs_record_t live in main.c and are not compiled
 * during host tests.
 *
 * Memory budget (512-record default store, PSRAM):
 *   sizeof(obs_record_t) == 88 bytes (verified by _Static_assert in obs_store.c)
 *   obs_store_t metadata: ~24 bytes (pointer + 3× uint32_t)
 *   512 records × 88 bytes = 44 032 bytes (43 KB PSRAM)
 */

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ── Schema version ─────────────────────────────────────────────────────── */
#define OBS_SCHEMA_VERSION   1

/* ── Radio source ────────────────────────────────────────────────────────── */
typedef enum {
    OBS_RADIO_WIFI = 0,
    OBS_RADIO_BLE  = 1,
} obs_radio_t;

/* ── Observation type ────────────────────────────────────────────────────── */
typedef enum {
    OBS_TYPE_WIFI_AP     = 0,   /* WiFi access point beacon / probe response */
    OBS_TYPE_WIFI_CLIENT = 1,   /* WiFi client (associated or probing) */
    OBS_TYPE_BLE_ADV     = 2,   /* BLE legacy advertising (1M PHY) */
    OBS_TYPE_BLE_EXT     = 3,   /* BLE 5.0 extended advertising */
} obs_type_t;

/* ── PHY indicator ───────────────────────────────────────────────────────── */
typedef enum {
    OBS_PHY_UNKNOWN  = 0,
    OBS_PHY_11B      = 1,   /* 802.11b DSSS */
    OBS_PHY_11G      = 2,   /* 802.11g OFDM */
    OBS_PHY_11N      = 3,   /* 802.11n HT */
    OBS_PHY_11AC     = 4,   /* 802.11ac VHT */
    OBS_PHY_11AX     = 5,   /* 802.11ax HE (WiFi 6) */
    OBS_PHY_BLE_1M   = 6,   /* BLE 1M PHY */
    OBS_PHY_BLE_2M   = 7,   /* BLE 2M PHY */
    OBS_PHY_BLE_CODED = 8,  /* BLE Coded PHY (long range) */
} obs_phy_t;

/* ── Record flags (bitmask stored in obs_record_t.flags) ────────────────── */
#define OBS_FLAG_RANDOM_ADDR  (1u << 0)  /* BLE random/resolvable address */
#define OBS_FLAG_GPS_VALID    (1u << 1)  /* live GPS fix at first_seen */
#define OBS_FLAG_GPS_STALE    (1u << 2)  /* GPS held from last known position */
#define OBS_FLAG_REDACTED     (1u << 3)  /* privacy redaction has been applied */
#define OBS_FLAG_HIDDEN_SSID  (1u << 4)  /* WiFi: SSID not broadcast */
#define OBS_FLAG_CARRIER_HIT  (1u << 5)  /* nRF24 RPD one-bit carrier flag; NOT RSSI */
#define OBS_FLAG_PMF_INFERRED (1u << 6)  /* WiFi: PMF inferred from auth mode, not RSN IE */

#define OBS_RSSI_UNKNOWN  ((int8_t)-128)
#define OBS_CHAN_UNKNOWN  ((uint8_t)0)

/* ── Evidence tags ───────────────────────────────────────────────────────── */
#define OBS_MAX_EVIDENCE  4

typedef enum {
    OBS_EV_NONE          = 0,
    OBS_EV_OUI_MATCH     = 1,   /* MAC OUI matched a known vendor prefix */
    OBS_EV_SVC_UUID      = 2,   /* BLE service UUID matched a known profile */
    OBS_EV_MFR_DATA      = 3,   /* manufacturer-specific data matched a pattern */
    OBS_EV_SSID_PATTERN  = 4,   /* WiFi SSID matched a watchlist pattern */
    OBS_EV_RATE_ANOMALY  = 5,   /* packet/advertisement rate outside baseline */
    OBS_EV_RSSI_ANOMALY  = 6,   /* RSSI deviation exceeds baseline variance */
    OBS_EV_RECURRENCE    = 7,   /* device appears in 2+ independent scan sessions */
} obs_evidence_t;

/* ── Core observation record ─────────────────────────────────────────────── */
/*
 * Fixed layout — no embedded pointers, no variable-length strings.
 * All fields must be accessed by the same CPU that wrote them; there is no
 * endian negotiation.  sizeof == 88 bytes (verified by _Static_assert).
 *
 * Field ordering is chosen to satisfy natural alignment on 32-bit RISC-V
 * without hidden compiler padding:
 *   bytes  0–15:  small integer/flag fields
 *   bytes 16–27:  mac, peer_mac
 *   bytes 28–31:  rssi, channel, phy, auth_mode
 *   bytes 32–37:  confidence, evidence_count, evidence[4]
 *   bytes 38–39:  hit_count (uint16_t, 2-byte aligned at offset 38 — ✓)
 *   pad    40–43: _align32 (2 bytes pad → moves uint32_t to offset 40 — ✓)
 *   bytes 40–43:  first_seen_s (uint32_t, 4-byte aligned — ✓)
 *   ...
 *
 * Wait — let me recalculate with the actual field order defined below.
 */
typedef struct {
    /* Provenance — 4 bytes */
    uint8_t  schema_version;        /* always OBS_SCHEMA_VERSION */
    uint8_t  src_radio;             /* obs_radio_t */
    uint8_t  obs_type;             /* obs_type_t */
    uint8_t  flags;                 /* OBS_FLAG_* bitmask */

    /* Identity — 12 bytes */
    uint8_t  mac[6];                /* BSSID (WiFi) or BLE address */
    uint8_t  peer_mac[6];          /* associated peer; zeroed if not applicable */

    /* Signal — 4 bytes */
    int8_t   rssi_cur;             /* most recent RSSI (dBm); OBS_RSSI_UNKNOWN if N/A */
    int8_t   rssi_peak;            /* highest RSSI seen across all observations */
    int8_t   rssi_trend;           /* +1 stronger, 0 stable, -1 weaker vs previous update */
    uint8_t  channel;              /* primary channel; OBS_CHAN_UNKNOWN if not applicable */

    /* PHY / auth — 2 bytes */
    uint8_t  phy;                  /* obs_phy_t */
    uint8_t  auth_mode;            /* wifi_auth_mode_t raw value; 0 for BLE */

    /* Classifier — 6 bytes */
    uint8_t  confidence;           /* 0–100: detector confidence; 0 = unclassified */
    uint8_t  evidence_count;       /* number of valid entries in evidence[] */
    uint8_t  evidence[OBS_MAX_EVIDENCE]; /* obs_evidence_t values */

    /* Timing — 2 + 2-byte pad + 8 bytes */
    uint16_t hit_count;            /* observations seen; caps at UINT16_MAX */
    uint8_t  _pad[2];              /* explicit pad — keeps first_seen_s 4-byte aligned */
    uint32_t first_seen_s;         /* UTC epoch seconds; 0 if clock not set */
    uint32_t last_seen_s;          /* UTC epoch seconds of most recent observation */

    /* GPS — 16 bytes */
    float    latitude;             /* decimal degrees; 0.0 if GPS invalid or redacted */
    float    longitude;
    float    altitude_m;
    float    accuracy_m;           /* ~150.0 when held from last known position */

    /* Label — 32 bytes */
    char     label[32];            /* SSID or BLE device name; may be redacted or empty */
} obs_record_t; /* expected sizeof == 88 */

/* ── Privacy / redaction policy ──────────────────────────────────────────── */
#define OBS_PRIV_REDACT_GPS    (1u << 0)  /* zero latitude, longitude, altitude, accuracy */
#define OBS_PRIV_REDACT_MAC    (1u << 1)  /* zero mac and peer_mac */
#define OBS_PRIV_REDACT_LABEL  (1u << 2)  /* clear label field */
typedef uint8_t obs_privacy_flags_t;

/*
 * Apply privacy redaction to a record in place.
 * Sets OBS_FLAG_REDACTED in flags regardless of which fields were zeroed.
 * Idempotent: calling twice has no additional effect.
 */
void obs_redact(obs_record_t *rec, obs_privacy_flags_t policy);

/* ── Bounded store ───────────────────────────────────────────────────────── */
/*
 * Ring-buffer backed store.  When full, the oldest slot is overwritten and
 * the overflow counter is incremented.  Linear MAC scan is O(capacity) —
 * acceptable for capacity ≤ 1024; use a hash index for larger stores.
 */
#define OBS_STORE_DEFAULT_CAPACITY  512u

typedef struct {
    obs_record_t *records;   /* flat array, PSRAM on device / heap on host */
    uint32_t      capacity;  /* max records allocated */
    uint32_t      count;     /* currently valid records (≤ capacity) */
    uint32_t      write_head;/* next slot to write (ring) */
    uint32_t      overflow;  /* dropped records due to full store */
} obs_store_t;

/*
 * Initialise a store.  capacity == 0 → OBS_STORE_DEFAULT_CAPACITY.
 * On ESP32-C5 the backing array is allocated from PSRAM.
 * Returns false if allocation fails.
 */
bool obs_store_init(obs_store_t *store, uint32_t capacity);

/* Release the backing array.  Safe to call on a partially initialised store. */
void obs_store_deinit(obs_store_t *store);

/*
 * Add or merge an observation.
 *   - If a record with the same mac already exists: update rssi_cur,
 *     compute rssi_trend, update rssi_peak, advance last_seen_s, increment
 *     hit_count (cap at UINT16_MAX).
 *   - If no matching mac: write new record at write_head.  When full,
 *     the slot is overwritten (oldest evicted) and overflow is incremented.
 * Returns a pointer to the stored (inserted or updated) record, or NULL on error.
 */
obs_record_t *obs_store_add(obs_store_t *store, const obs_record_t *rec);

/* Linear scan for MAC match.  Returns NULL if not found. */
obs_record_t *obs_store_find(obs_store_t *store, const uint8_t mac[6]);

/* Current number of valid records in the store. */
uint32_t obs_store_count(const obs_store_t *store);

/* Number of records dropped since obs_store_init (due to full store + no MAC match). */
uint32_t obs_store_overflow(const obs_store_t *store);

/* ── Serialisation ───────────────────────────────────────────────────────── */
/*
 * Serialise one record to a single-line JSON string (JSONL-compatible).
 * Always null-terminates buf.  Returns bytes written (exc. NUL) or -1 if
 * buf is too small.  Recommended minimum: 256 bytes.
 */
int obs_record_to_json(const obs_record_t *rec, char *buf, size_t buflen);

/* ── Detector registry interface ────────────────────────────────────────── */
/*
 * Detectors are registered by pointer; they are not dynamically allocated.
 * Phase 2 ships no detector packs — only the registry plumbing.
 */
typedef struct {
    const char *name;       /* static string; shown in evidence exports */
    uint8_t     version;    /* detector schema version */
    /*
     * Analyse a single record.  MAY set rec->confidence (0–100) and fill
     * rec->evidence[].  Returns true if this detector classified the record.
     * Must be reentrant (may be called from different tasks on different records).
     */
    bool (*analyse)(obs_record_t *rec);
} obs_detector_t;

#define OBS_REGISTRY_MAX  8u

typedef struct {
    const obs_detector_t *detectors[OBS_REGISTRY_MAX];
    uint8_t               count;
} obs_registry_t;

/* Zero-initialise a registry. */
void obs_registry_init(obs_registry_t *reg);

/* Register a detector.  Returns false if the registry is full. */
bool obs_registry_register(obs_registry_t *reg, const obs_detector_t *det);

/*
 * Run all registered detectors against rec in registration order.
 * The first detector that returns true wins: its confidence and evidence
 * values remain; later detectors are skipped.
 * Returns the number of detectors that returned true (0 or 1 currently).
 */
int obs_registry_run(obs_registry_t *reg, obs_record_t *rec);
