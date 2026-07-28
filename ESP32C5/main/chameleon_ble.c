/*
 * chameleon_ble.c — Chameleon Ultra / Lite BLE GATT client (Phase 1)
 *
 * Concept: @bkbroiler | Protocol ref: ChameleonUltraGUI (GameTec-live)
 *
 * Protocol: Nordic UART Service (NUS) over BLE 4.x/5.x.
 *   Service UUID: 6E400001-B5A3-F393-E0A9-E50E24DCCA9E
 *   TX char (notify, server→client): 6E400003-...
 *   RX char (write, client→server):  6E400002-...
 *
 * Frame format (9-byte header + optional payload + 1-byte LRC):
 *   [SOF:0x11] [LRC1:lrc([SOF])] [CMD_H] [CMD_L] [STATUS_H] [STATUS_L]
 *   [LEN_H] [LEN_L] [HEAD_LRC:lrc(bytes[0..7])] [DATA...] [FRAME_LRC:lrc(all)]
 *
 * Commands used in Phase 1 (device info sequence after CCCD subscribe):
 *   1000 getAppVersion      → uint16 BE version word
 *   1033 getDeviceType      → 1 byte: 0=Ultra, 1=Lite
 *   1011 getDeviceChipID    → 8 bytes chip ID
 *   1012 getDeviceBLEAddress→ 6 bytes BLE address (MSB first)
 *   1025 getBatteryCharge   → uint16 BE voltage_mV + uint8 percent
 *   1019 getSlotInfo        → 8×4 bytes slot type pairs (used only for handshake in Phase 1)
 *
 * Threading:
 *   NimBLE callbacks (NimBLE host task): fill s_rx_ring[], set s_ev_* flags.
 *   cham_poll() (main/LVGL task, ~50 ms timer): consume flags, drain ring,
 *     parse frames, dispatch command callbacks, update state.
 *   All state writes from NimBLE callbacks use volatile for ordering.
 */

#include "chameleon_ble.h"
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_uuid.h"
#include "host/ble_hs_adv.h"
#include "host/ble_store.h"
#include "services/gap/ble_svc_gap.h"
#include "os/os_mbuf.h"

static const char *TAG = "CHAM";

/* ── NUS UUID definitions (128-bit, little-endian NimBLE byte order) ─────── */
/* Service: 6E400001-B5A3-F393-E0A9-E50E24DCCA9E */
static const ble_uuid128_t s_nus_svc_uuid = BLE_UUID128_INIT(
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0,
    0x93, 0xF3, 0xA3, 0xB5, 0x01, 0x00, 0x40, 0x6E
);
/* TX (notify, server→client): 6E400003-... */
static const ble_uuid128_t s_nus_tx_uuid = BLE_UUID128_INIT(
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0,
    0x93, 0xF3, 0xA3, 0xB5, 0x03, 0x00, 0x40, 0x6E
);
/* RX (write, client→server): 6E400002-... */
static const ble_uuid128_t s_nus_rx_uuid = BLE_UUID128_INIT(
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0,
    0x93, 0xF3, 0xA3, 0xB5, 0x02, 0x00, 0x40, 0x6E
);

/* ── Frame codec constants ───────────────────────────────────────────────── */
#define CHAM_SOF         0x11U
#define CHAM_LRC1        0xEFU   /* lrc([0x11]) = (0x100 - 0x11) & 0xFF */
#define CHAM_MAX_PAYLOAD 4096
#define CHAM_MAX_FRAME   (9 + CHAM_MAX_PAYLOAD + 1)
#define CHAM_CMD_TIMEOUT_US (3000000LL)  /* 3 s per command */

/* ── RX ring buffer ──────────────────────────────────────────────────────── */
#define CHAM_RX_RING_SIZE 4200   /* > CHAM_MAX_FRAME for headroom */

static uint8_t  s_rx_ring[CHAM_RX_RING_SIZE];
static volatile int s_rx_wr = 0;  /* NimBLE task writes */
static          int s_rx_rd = 0;  /* poll (main task) reads */

/* ── Frame parse state (used only in cham_poll) ──────────────────────────── */
typedef struct {
    uint8_t  buf[CHAM_MAX_FRAME];
    int      pos;
    uint16_t dlen;
    uint16_t cmd;
    uint16_t status;
    bool     hdr_done;  /* set after pos==8 LRC check passes */
} cham_rxs_t;

static cham_rxs_t s_rxs;

/* ── Global state ────────────────────────────────────────────────────────── */
static cham_state_t s_state = CHAM_STATE_DISCONNECTED;
static char s_status_msg[64] = "Tap Scan to find Chameleon";

static cham_scan_result_t s_scan_results[CHAM_MAX_SCAN];
static int s_scan_count = 0;
static int s_connect_idx = -1;

static uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static uint16_t s_svc_start   = 0;
static uint16_t s_svc_end     = 0;
static uint16_t s_tx_val_hdl  = 0;   /* TX char value handle (notify) */
static uint16_t s_rx_val_hdl  = 0;   /* RX char value handle (write) */
static uint16_t s_cccd_hdl    = 0;   /* CCCD handle (tx_val_hdl + 1) */

/* Volatile event flags set by NimBLE callbacks, consumed in cham_poll() */
static volatile bool s_ev_connected    = false;
static volatile bool s_ev_disconnected = false;
static volatile bool s_ev_cccd_ok      = false;
static volatile bool s_ev_error        = false;
static volatile bool s_ev_passkey      = false; /* numeric comparison pending */
static volatile bool s_ev_enc_ok       = false; /* pairing completed successfully */
static volatile bool s_changed         = false; /* general "please repaint" flag */

/* Numeric comparison passkey (6-digit, set alongside s_ev_passkey) */
static uint32_t s_passkey_num = 0;

/* Pending command */
static uint16_t          s_pend_cmd  = 0xFFFF; /* 0xFFFF = none */
static cham_cmd_result_cb_t s_pend_cb   = NULL;
static int64_t           s_pend_deadline = 0; /* esp_timer_get_time() */
static volatile bool     s_pend_write_ok = false; /* write response received */

/* Device info */
static cham_device_info_t s_dev_info;

/* 250 ms defer timer before ble_gap_connect */
static esp_timer_handle_t s_defer_tmr = NULL;

/* ── LRC checksum ────────────────────────────────────────────────────────── */
static uint8_t s_lrc(const uint8_t *buf, int len)
{
    uint32_t sum = 0;
    for (int i = 0; i < len; i++) sum += buf[i];
    return (uint8_t)((0x100U - (sum & 0xFFU)) & 0xFFU);
}

/* ── Build a command frame ───────────────────────────────────────────────── */
/* Returns total byte count, or -1 if out_size insufficient. */
static int s_build_frame(uint8_t *out, int out_size, uint16_t cmd,
                          const uint8_t *data, uint16_t dlen)
{
    int total = 10 + dlen; /* 9-byte header + payload + 1-byte frame LRC */
    if (out_size < total) return -1;

    out[0] = CHAM_SOF;
    out[1] = CHAM_LRC1;                    /* lrc([SOF]) — always 0xEF */
    out[2] = (uint8_t)(cmd >> 8);
    out[3] = (uint8_t)(cmd & 0xFF);
    out[4] = 0;                             /* status_h — 0 for commands */
    out[5] = 0;                             /* status_l */
    out[6] = (uint8_t)(dlen >> 8);
    out[7] = (uint8_t)(dlen & 0xFF);
    out[8] = s_lrc(out, 8);               /* head LRC covers bytes 0..7 */
    if (data && dlen > 0) memcpy(out + 9, data, dlen);
    out[9 + dlen] = s_lrc(out, 9 + dlen); /* frame LRC covers all preceding */
    return total;
}

/* ── Feed one byte into the RX frame parser ─────────────────────────────── */
/*
 * Returns 1 when a complete valid frame has been parsed into s_rxs,
 * -1 if a framing error was detected (caller should reset s_rxs.pos),
 * 0 to keep feeding bytes.
 */
static int s_rx_feed(uint8_t byte)
{
    cham_rxs_t *rx = &s_rxs;

    if (rx->pos >= CHAM_MAX_FRAME) {
        rx->pos = 0;
        rx->hdr_done = false;
        return -1;
    }

    int p = rx->pos;
    rx->buf[p] = byte;
    rx->pos++;

    if (p == 0) {
        if (byte != CHAM_SOF) { rx->pos = 0; return -1; }
    } else if (p == 1) {
        if (byte != CHAM_LRC1) { rx->pos = 0; return -1; }
    } else if (p == 8) {
        /* Verify head LRC (sum of bytes 0..7 including SOF and LRC1 == 0 mod 256) */
        if (byte != s_lrc(rx->buf, 8)) { rx->pos = 0; return -1; }
        rx->cmd     = ((uint16_t)rx->buf[2] << 8) | rx->buf[3];
        rx->status  = ((uint16_t)rx->buf[4] << 8) | rx->buf[5];
        rx->dlen    = ((uint16_t)rx->buf[6] << 8) | rx->buf[7];
        rx->hdr_done = true;
        if (rx->dlen > CHAM_MAX_PAYLOAD) { rx->pos = 0; rx->hdr_done = false; return -1; }
    } else if (rx->hdr_done && p == (int)(9 + rx->dlen)) {
        /* Data LRC: covers all bytes 0..9+dlen-1 */
        if (byte != s_lrc(rx->buf, p)) { rx->pos = 0; rx->hdr_done = false; return -1; }
        /* Frame complete */
        rx->pos = 0;
        rx->hdr_done = false;
        return 1;
    }
    return 0;
}

/* ── Device info chain callbacks ─────────────────────────────────────────── */
/* Called from cham_poll() in response order. Each cb fires the next command. */

static void s_cb_battery(bool ok, const uint8_t *data, uint16_t dlen)
{
    if (ok && dlen >= 3) {
        s_dev_info.battery_mv  = ((uint16_t)data[0] << 8) | data[1];
        s_dev_info.battery_pct = data[2];
    }
    s_state   = CHAM_STATE_READY;
    s_changed = true;
    strlcpy(s_status_msg, "Connected", sizeof(s_status_msg));
    ESP_LOGI(TAG, "Device ready — FW:%u type:%s batt:%d%% BLE:%s ID:%s",
             s_dev_info.fw_version,
             s_dev_info.is_lite ? "Lite" : "Ultra",
             s_dev_info.battery_pct,
             s_dev_info.ble_addr,
             s_dev_info.chip_id);
}

static void s_cb_ble_addr(bool ok, const uint8_t *data, uint16_t dlen)
{
    if (ok && dlen >= 6) {
        snprintf(s_dev_info.ble_addr, sizeof(s_dev_info.ble_addr),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 data[0], data[1], data[2], data[3], data[4], data[5]);
    }
    cham_send_cmd(1025, NULL, 0, s_cb_battery);  /* getBatteryCharge */
}

static void s_cb_chip_id(bool ok, const uint8_t *data, uint16_t dlen)
{
    if (ok && dlen >= 8) {
        for (int i = 0; i < 8; i++) {
            snprintf(s_dev_info.chip_id + i * 2, 3, "%02X", data[i]);
        }
    }
    cham_send_cmd(1012, NULL, 0, s_cb_ble_addr); /* getDeviceBLEAddress */
}

static void s_cb_device_type(bool ok, const uint8_t *data, uint16_t dlen)
{
    if (ok && dlen >= 1) {
        s_dev_info.is_lite = (data[0] != 0);
    }
    cham_send_cmd(1011, NULL, 0, s_cb_chip_id);  /* getDeviceChipID */
}

static void s_cb_fw_version(bool ok, const uint8_t *data, uint16_t dlen)
{
    if (ok && dlen >= 2) {
        s_dev_info.fw_version = ((uint16_t)data[0] << 8) | data[1];
    }
    cham_send_cmd(1033, NULL, 0, s_cb_device_type); /* getDeviceType */
}

static void s_start_info_sequence(void)
{
    memset(&s_dev_info, 0, sizeof(s_dev_info));
    strlcpy(s_dev_info.ble_addr, "--:--:--:--:--:--", sizeof(s_dev_info.ble_addr));
    strlcpy(s_dev_info.chip_id,  "----------------", sizeof(s_dev_info.chip_id));
    s_state = CHAM_STATE_HANDSHAKING;
    strlcpy(s_status_msg, "Reading device info...", sizeof(s_status_msg));
    s_changed = true;
    cham_send_cmd(1000, NULL, 0, s_cb_fw_version); /* getAppVersion */
}

/* ── Write result callback (NimBLE host task) ────────────────────────────── */
static int s_write_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                      struct ble_gatt_attr *attr, void *arg)
{
    (void)conn_handle; (void)attr; (void)arg;
    if (error->status == 0) {
        s_pend_write_ok = true;
    } else {
        ESP_LOGW(TAG, "Write failed: %d", error->status);
        s_ev_error = true;
        strlcpy(s_status_msg, "BLE write error", sizeof(s_status_msg));
    }
    return 0;
}

/* ── CCCD write callback ─────────────────────────────────────────────────── */
static int s_cccd_write_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                            struct ble_gatt_attr *attr, void *arg)
{
    (void)conn_handle; (void)attr; (void)arg;
    if (error->status == 0) {
        s_ev_cccd_ok = true;
    } else {
        ESP_LOGW(TAG, "CCCD write failed: %d", error->status);
        s_ev_error = true;
        strlcpy(s_status_msg, "Notify enable failed", sizeof(s_status_msg));
    }
    return 0;
}

/* ── GATT characteristic discovery callback ──────────────────────────────── */
static int s_chr_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                          const struct ble_gatt_chr *chr, void *arg)
{
    (void)arg;
    if (error->status == BLE_HS_EDONE) {
        if (s_tx_val_hdl == 0 || s_rx_val_hdl == 0) {
            ESP_LOGE(TAG, "NUS TX or RX char not found (tx=%u rx=%u)",
                     s_tx_val_hdl, s_rx_val_hdl);
            s_ev_error = true;
            strlcpy(s_status_msg, "NUS chars not found", sizeof(s_status_msg));
            return 0;
        }
        /* Enable notifications on TX characteristic (val_handle + 1 = CCCD) */
        s_cccd_hdl = s_tx_val_hdl + 1;
        uint16_t cccd = 0x0001;
        int rc = ble_gattc_write_flat(conn_handle, s_cccd_hdl,
                                      &cccd, sizeof(cccd), s_cccd_write_cb, NULL);
        if (rc != 0) {
            ESP_LOGE(TAG, "CCCD write start failed: %d", rc);
            s_ev_error = true;
            strlcpy(s_status_msg, "CCCD start failed", sizeof(s_status_msg));
        }
        return 0;
    }
    if (error->status != 0) return 0;

    if (ble_uuid_cmp(&chr->uuid.u, &s_nus_tx_uuid.u) == 0) {
        s_tx_val_hdl = chr->val_handle;
        ESP_LOGD(TAG, "NUS TX val_hdl=%u", s_tx_val_hdl);
    } else if (ble_uuid_cmp(&chr->uuid.u, &s_nus_rx_uuid.u) == 0) {
        s_rx_val_hdl = chr->val_handle;
        ESP_LOGD(TAG, "NUS RX val_hdl=%u", s_rx_val_hdl);
    }
    return 0;
}

/* ── GATT service discovery callback ─────────────────────────────────────── */
static int s_svc_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                          const struct ble_gatt_svc *svc, void *arg)
{
    (void)arg;
    if (error->status == BLE_HS_EDONE) {
        if (s_svc_start == 0) {
            ESP_LOGE(TAG, "NUS service not found");
            s_ev_error = true;
            strlcpy(s_status_msg, "NUS service not found", sizeof(s_status_msg));
            return 0;
        }
        /* Start characteristic discovery within NUS service range */
        int rc = ble_gattc_disc_all_chrs(conn_handle, s_svc_start, s_svc_end,
                                          s_chr_disc_cb, NULL);
        if (rc != 0) {
            ESP_LOGE(TAG, "Chr disc start failed: %d", rc);
            s_ev_error = true;
            strlcpy(s_status_msg, "Chr discovery failed", sizeof(s_status_msg));
        }
        return 0;
    }
    if (error->status != 0) return 0;

    if (ble_uuid_cmp(&svc->uuid.u, &s_nus_svc_uuid.u) == 0) {
        s_svc_start = svc->start_handle;
        s_svc_end   = svc->end_handle;
        ESP_LOGD(TAG, "NUS svc found: hdl %u..%u", s_svc_start, s_svc_end);
    }
    return 0;
}

/* ── Main GAP event callback ─────────────────────────────────────────────── */
static int s_gap_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {

    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
            s_ev_connected = true;
            ESP_LOGI(TAG, "Connected: conn_handle=%u", s_conn_handle);

            /* Security MUST be established before any ATT operations — the
             * Chameleon drops ATT requests on an unencrypted link (NUS service
             * is protected).  Initiate security immediately; disc_all_svcs runs
             * from cham_poll() once ENC_CHANGE fires.
             *
             * If security_initiate fails (not applicable, already encrypted,
             * etc.) treat the link as ready and set s_ev_enc_ok so discovery
             * proceeds.  Every possible error is logged for diagnosis. */
            int sec_rc = ble_gap_security_initiate(s_conn_handle);
            ESP_LOGI(TAG, "security_initiate rc=%d (%s)",
                     sec_rc,
                     sec_rc == 0              ? "pairing started, await ENC_CHANGE" :
                     sec_rc == BLE_HS_EALREADY? "already encrypted"               :
                     sec_rc == BLE_HS_ENOTCONN? "not connected?"                  :
                     sec_rc == BLE_HS_ENOTSUP ? "not supported"                   :
                                                "unexpected error");
            if (sec_rc != 0) {
                /* Link usable without security — skip straight to discovery */
                s_ev_enc_ok = true;
            }
        } else {
            ESP_LOGW(TAG, "Connect failed: status=%d", event->connect.status);
            s_ev_error = true;
            snprintf(s_status_msg, sizeof(s_status_msg),
                     "Connect failed (%d)", event->connect.status);
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "Disconnected: reason=%d (0x%02x)",
                 event->disconnect.reason,
                 event->disconnect.reason > 0x200
                     ? event->disconnect.reason - 0x200 : event->disconnect.reason);
        s_conn_handle  = BLE_HS_CONN_HANDLE_NONE;
        s_svc_start    = 0;
        s_svc_end      = 0;
        s_tx_val_hdl   = 0;
        s_rx_val_hdl   = 0;
        s_cccd_hdl     = 0;
        s_rx_wr        = s_rx_rd; /* flush ring buffer */
        s_pend_cmd     = 0xFFFF;
        s_pend_cb      = NULL;
        s_pend_write_ok = false;
        memset(&s_rxs, 0, sizeof(s_rxs));
        s_ev_disconnected = true;
        break;

    case BLE_GAP_EVENT_NOTIFY_RX:
        /* Copy notification bytes into the ring buffer.
         * Only process notifications on the TX characteristic handle. */
        if (event->notify_rx.attr_handle == s_tx_val_hdl) {
            struct os_mbuf *om = event->notify_rx.om;
            while (om) {
                for (uint16_t i = 0; i < om->om_len; i++) {
                    int next = (s_rx_wr + 1) % CHAM_RX_RING_SIZE;
                    if (next != s_rx_rd) { /* not full */
                        s_rx_ring[s_rx_wr] = om->om_data[i];
                        s_rx_wr = next;
                    }
                }
                om = SLIST_NEXT(om, om_next);
            }
        }
        break;

    case BLE_GAP_EVENT_PASSKEY_ACTION:
        ESP_LOGI(TAG, "PASSKEY_ACTION: action=%d numcmp=%" PRIu32,
                 event->passkey.params.action,
                 event->passkey.params.numcmp);
        if (event->passkey.params.action == BLE_SM_IOACT_NUMCMP) {
            s_passkey_num = event->passkey.params.numcmp;
            s_ev_passkey  = true;
        } else {
            /* DISP or INPUT — auto-accept */
            struct ble_sm_io io = {0};
            io.action = event->passkey.params.action;
            ble_sm_inject_io(event->passkey.conn_handle, &io);
            ESP_LOGW(TAG, "Passkey action %d auto-accepted", event->passkey.params.action);
        }
        break;

    case BLE_GAP_EVENT_ENC_CHANGE:
        ESP_LOGI(TAG, "ENC_CHANGE: status=%d state=%d",
                 event->enc_change.status, (int)s_state);
        if (event->enc_change.status == 0) {
            /* Encryption up — disc_all_svcs fires from cham_poll() */
            s_ev_enc_ok = true;
        } else {
            ESP_LOGE(TAG, "ENC_CHANGE failed status=%d", event->enc_change.status);
            s_ev_error = true;
            snprintf(s_status_msg, sizeof(s_status_msg),
                     "Pairing failed (%d)", event->enc_change.status);
        }
        break;

    case BLE_GAP_EVENT_REPEAT_PAIRING: {
        /* Chameleon has a stale bond entry; we have none.  Delete theirs and
         * retry so fresh Just Works pairing proceeds without SMP failure. */
        struct ble_gap_conn_desc desc;
        ESP_LOGW(TAG, "REPEAT_PAIRING conn=%u cur_key=%u new_key=%u — deleting stale bond",
                 event->repeat_pairing.conn_handle,
                 event->repeat_pairing.cur_key_size,
                 event->repeat_pairing.new_key_size);
        if (ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc) == 0) {
            ble_store_util_delete_peer(&desc.peer_id_addr);
        }
        return BLE_GAP_REPEAT_PAIRING_RETRY;
    }

    case BLE_GAP_EVENT_PARING_COMPLETE:
        ESP_LOGI(TAG, "PAIRING_COMPLETE: status=%d conn=%u",
                 event->pairing_complete.status,
                 event->pairing_complete.conn_handle);
        break;

    default:
        ESP_LOGD(TAG, "GAP event type=%d (unhandled)", event->type);
        break;
    }
    return 0;
}

/* ── Scan GAP event callback ─────────────────────────────────────────────── */
static int s_scan_gap_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;

    /* Extract common fields from either extended or legacy disc event.
     * ble_gap_ext_disc() delivers ALL PDUs (legacy + extended) as EXT_DISC,
     * so the DISC branch is a safety fallback only. */
    const uint8_t *adv_data = NULL;
    uint8_t        adv_len  = 0;
    ble_addr_t     addr     = {0};
    int8_t         rssi     = 0;

    if (event->type == BLE_GAP_EVENT_EXT_DISC) {
        const struct ble_gap_ext_disc_desc *d = &event->ext_disc;
        adv_data = d->data;
        adv_len  = (uint8_t)(d->length_data < 255 ? d->length_data : 255);
        addr     = d->addr;
        rssi     = d->rssi;
    } else if (event->type == BLE_GAP_EVENT_DISC) {
        const struct ble_gap_disc_desc *d = &event->disc;
        adv_data = d->data;
        adv_len  = d->length_data;
        addr     = d->addr;
        rssi     = d->rssi;
    } else if (event->type == BLE_GAP_EVENT_DISC_COMPLETE) {
        /* Restart if still scanning (fires on timeout or external cancel) */
        if (s_state == CHAM_STATE_SCANNING) {
            struct ble_gap_ext_disc_params ep = {
                .itvl = 0x60, .window = 0x60, .passive = 0,
            };
            ble_gap_ext_disc(BLE_OWN_ADDR_PUBLIC, 500, 0,
                             0, BLE_HCI_SCAN_FILT_NO_WL, 0,
                             &ep, NULL, s_scan_gap_cb, NULL);
        }
        return 0;
    } else {
        return 0;
    }

    struct ble_hs_adv_fields fields;
    bool parsed = (adv_data && adv_len > 0 &&
                   ble_hs_adv_parse_fields(&fields, adv_data, adv_len) == 0);

    /* Primary filter: NUS service UUID in advertisement (128-bit list).
     * The Chameleon always advertises the NUS service UUID; this is more
     * reliable than name matching (name may be in scan response only,
     * or may be user-renamed). */
    bool has_nus = false;
    if (parsed && fields.uuids128 != NULL) {
        for (int i = 0; i < fields.num_uuids128; i++) {
            if (ble_uuid_cmp(&fields.uuids128[i].u, &s_nus_svc_uuid.u) == 0) {
                has_nus = true;
                break;
            }
        }
    }

    /* Secondary filter: device name starts with "Chameleon" (handles any
     * renamed device and catches the name whether in adv or scan response) */
    char name[32] = {0};
    bool has_cham_name = false;
    if (parsed && fields.name && fields.name_len > 0) {
        int nlen = (fields.name_len < 31) ? fields.name_len : 31;
        memcpy(name, fields.name, nlen);
        has_cham_name = (strncmp(name, "Chameleon", 9) == 0);
    }

    if (!has_nus && !has_cham_name) return 0;

    /* If found by UUID but name is unknown, use a placeholder */
    if (name[0] == '\0') {
        snprintf(name, sizeof(name), "Chameleon [%02X:%02X:%02X]",
                 addr.val[3], addr.val[4], addr.val[5]);
    }

    /* Deduplicate by address; update RSSI and name if already seen */
    for (int i = 0; i < s_scan_count; i++) {
        if (memcmp(s_scan_results[i].addr, addr.val, 6) == 0) {
            s_scan_results[i].rssi = rssi;
            if (has_cham_name && s_scan_results[i].name[0] == 'C' &&
                s_scan_results[i].name[9] == '[') {
                /* Replace placeholder with real name */
                strlcpy(s_scan_results[i].name, name, sizeof(s_scan_results[i].name));
                s_changed = true;
            }
            return 0;
        }
    }

    if (s_scan_count < CHAM_MAX_SCAN) {
        cham_scan_result_t *r = &s_scan_results[s_scan_count];
        strlcpy(r->name, name, sizeof(r->name));
        memcpy(r->addr, addr.val, 6);
        r->addr_type = addr.type;
        r->rssi      = rssi;
        r->is_lite   = (strstr(name, "Lite") != NULL);
        s_scan_count++;
        s_changed = true;
        ESP_LOGI(TAG, "Found Chameleon: \"%s\" addr=%02X:%02X:%02X:%02X:%02X:%02X RSSI=%d "
                 "(by %s)", name,
                 addr.val[0], addr.val[1], addr.val[2],
                 addr.val[3], addr.val[4], addr.val[5],
                 rssi, has_nus ? "NUS UUID" : "name");
    }
    return 0;
}

/* ── Defer-connect timer (fires 250 ms after scan cancel) ────────────────── */
static void s_defer_connect_cb(void *arg)
{
    (void)arg;
    if (s_connect_idx < 0 || s_connect_idx >= s_scan_count) {
        s_ev_error = true;
        strlcpy(s_status_msg, "No device selected", sizeof(s_status_msg));
        return;
    }

    cham_scan_result_t *r = &s_scan_results[s_connect_idx];
    ble_addr_t addr;
    memcpy(addr.val, r->addr, 6);
    addr.type = r->addr_type;

    /* Use conservative connection parameters */
    struct ble_gap_conn_params cp = {
        .scan_itvl           = 0x0010,
        .scan_window         = 0x0010,
        .itvl_min            = BLE_GAP_INITIAL_CONN_ITVL_MIN,
        .itvl_max            = BLE_GAP_INITIAL_CONN_ITVL_MAX,
        .latency             = 0,
        .supervision_timeout = 0x0200,  /* 5.12 s */
        .min_ce_len          = 0,
        .max_ce_len          = 0,
    };

    int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &addr, 10000, &cp, s_gap_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_connect rc=%d", rc);
        s_ev_error = true;
        snprintf(s_status_msg, sizeof(s_status_msg),
                 "Connect error (%d)", rc);
    }
}

/* ── Public API ──────────────────────────────────────────────────────────── */

void cham_init(void)
{
    if (s_defer_tmr) return;

    esp_timer_create_args_t args = {
        .callback = s_defer_connect_cb,
        .arg      = NULL,
        .name     = "cham_defer",
    };
    esp_timer_create(&args, &s_defer_tmr);
    memset(&s_rxs, 0, sizeof(s_rxs));
    memset(&s_dev_info, 0, sizeof(s_dev_info));
}

void cham_scan_start(void)
{
    if (s_state != CHAM_STATE_DISCONNECTED && s_state != CHAM_STATE_ERROR) return;

    /* Reset scan results */
    s_scan_count = 0;
    s_connect_idx = -1;
    memset(s_scan_results, 0, sizeof(s_scan_results));

    /* Use extended discovery — catches both BLE 5 extended PDUs and legacy PDUs.
     * ble_gap_disc() (legacy only) misses devices that advertise via extended PDUs. */
    struct ble_gap_ext_disc_params ep = {
        .itvl = 0x60, .window = 0x60, .passive = 0,
    };

    /* Cancel any ongoing scan before starting ours */
    ble_gap_disc_cancel();

    int rc = ble_gap_ext_disc(BLE_OWN_ADDR_PUBLIC, 500, 0,
                              0, BLE_HCI_SCAN_FILT_NO_WL, 0,
                              &ep, NULL, s_scan_gap_cb, NULL);
    if (rc == 0 || rc == BLE_HS_EALREADY) {
        s_state = CHAM_STATE_SCANNING;
        strlcpy(s_status_msg, "Scanning...", sizeof(s_status_msg));
        s_changed = true;
    } else {
        ESP_LOGE(TAG, "ble_gap_disc rc=%d", rc);
        s_state = CHAM_STATE_ERROR;
        strlcpy(s_status_msg, "Scan failed — is BLE on?", sizeof(s_status_msg));
    }
}

void cham_scan_stop(void)
{
    ble_gap_disc_cancel();
    if (s_state == CHAM_STATE_SCANNING) {
        s_state = CHAM_STATE_DISCONNECTED;
        strlcpy(s_status_msg, "Scan stopped", sizeof(s_status_msg));
        s_changed = true;
    }
}

bool cham_connect(int idx)
{
    if (s_state != CHAM_STATE_SCANNING && s_state != CHAM_STATE_DISCONNECTED &&
        s_state != CHAM_STATE_ERROR) {
        return false;
    }
    if (idx < 0 || idx >= s_scan_count) return false;

    s_connect_idx  = idx;
    s_svc_start    = 0;
    s_svc_end      = 0;
    s_tx_val_hdl   = 0;
    s_rx_val_hdl   = 0;
    s_cccd_hdl     = 0;
    s_rx_wr = s_rx_rd = 0;
    s_pend_cmd     = 0xFFFF;
    s_pend_cb      = NULL;
    s_ev_connected = false;
    s_ev_cccd_ok   = false;
    s_ev_error     = false;
    memset(&s_rxs, 0, sizeof(s_rxs));

    /* Cancel scan, then wait 250 ms for NimBLE to settle before connecting */
    ble_gap_disc_cancel();
    s_state = CHAM_STATE_CONNECTING;
    snprintf(s_status_msg, sizeof(s_status_msg),
             "Connecting to %s...", s_scan_results[idx].name);
    s_changed = true;

    esp_timer_stop(s_defer_tmr);
    esp_timer_start_once(s_defer_tmr, 250000); /* 250 ms */
    return true;
}

void cham_disconnect(void)
{
    esp_timer_stop(s_defer_tmr);
    ble_gap_disc_cancel();
    if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        /* s_ev_disconnected fires in s_gap_cb; poll() will update state */
    } else {
        s_state = CHAM_STATE_DISCONNECTED;
        strlcpy(s_status_msg, "Tap Scan to find Chameleon", sizeof(s_status_msg));
        s_changed = true;
    }
    s_pend_cmd = 0xFFFF;
    s_pend_cb  = NULL;
}

cham_state_t cham_get_state(void) { return s_state; }

const char *cham_get_status_msg(void) { return s_status_msg; }

uint32_t cham_get_passkey(void) { return s_passkey_num; }

void cham_passkey_accept(void)
{
    struct ble_sm_io io = {0};
    io.action = BLE_SM_IOACT_NUMCMP;
    io.numcmp_accept = 1;
    ble_sm_inject_io(s_conn_handle, &io);
    strlcpy(s_status_msg, "Pairing...", sizeof(s_status_msg));
    s_changed = true;
}

void cham_passkey_reject(void)
{
    struct ble_sm_io io = {0};
    io.action = BLE_SM_IOACT_NUMCMP;
    io.numcmp_accept = 0;
    ble_sm_inject_io(s_conn_handle, &io);
    /* Peer will disconnect; BLE_GAP_EVENT_DISCONNECT → state = ERROR */
}

const cham_device_info_t *cham_get_device_info(void)
{
    return (s_state == CHAM_STATE_READY || s_state == CHAM_STATE_HANDSHAKING)
           ? &s_dev_info : NULL;
}

int cham_scan_result_count(void) { return s_scan_count; }

const cham_scan_result_t *cham_scan_result_get(int idx)
{
    if (idx < 0 || idx >= s_scan_count) return NULL;
    return &s_scan_results[idx];
}

bool cham_send_cmd(uint16_t cmd, const uint8_t *data, uint16_t dlen,
                   cham_cmd_result_cb_t cb)
{
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE) return false;
    if (s_rx_val_hdl == 0) return false;
    if (s_pend_cmd != 0xFFFF) return false; /* command already in flight */

    uint8_t frame[CHAM_MAX_FRAME];
    int flen = s_build_frame(frame, sizeof(frame), cmd, data, dlen);
    if (flen < 0) return false;

    s_pend_cmd      = cmd;
    s_pend_cb       = cb;
    s_pend_write_ok = false;
    s_pend_deadline = esp_timer_get_time() + CHAM_CMD_TIMEOUT_US;

    int rc = ble_gattc_write_flat(s_conn_handle, s_rx_val_hdl,
                                   frame, flen, s_write_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "Write cmd 0x%04X failed: %d", cmd, rc);
        s_pend_cmd = 0xFFFF;
        s_pend_cb  = NULL;
        if (cb) cb(false, NULL, 0);
        return false;
    }
    return true;
}

bool cham_poll(void)
{
    bool changed = s_changed;
    s_changed = false;

    /* ── Handle event flags from NimBLE callbacks ── */

    if (s_ev_error) {
        s_ev_error = false;
        s_state = CHAM_STATE_ERROR;
        /* Cancel any pending command */
        if (s_pend_cmd != 0xFFFF) {
            cham_cmd_result_cb_t cb = s_pend_cb;
            s_pend_cmd = 0xFFFF;
            s_pend_cb  = NULL;
            if (cb) cb(false, NULL, 0);
        }
        changed = true;
    }

    if (s_ev_disconnected) {
        s_ev_disconnected = false;
        if (s_state != CHAM_STATE_ERROR) {
            s_state = CHAM_STATE_DISCONNECTED;
            strlcpy(s_status_msg, "Disconnected", sizeof(s_status_msg));
        }
        s_pend_cmd = 0xFFFF;
        s_pend_cb  = NULL;
        changed = true;
    }

    if (s_ev_connected) {
        s_ev_connected = false;
        s_state  = CHAM_STATE_DISCOVERING;
        strlcpy(s_status_msg, "Discovering services...", sizeof(s_status_msg));
        changed = true;
    }

    if (s_ev_passkey) {
        s_ev_passkey = false;
        s_state = CHAM_STATE_PAIRING;
        snprintf(s_status_msg, sizeof(s_status_msg),
                 "Confirm: %06" PRIu32, s_passkey_num);
        changed = true;
    }

    if (s_ev_enc_ok) {
        s_ev_enc_ok = false;
        if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE) {
            ESP_LOGW(TAG, "enc_ok but already disconnected — ignoring");
        } else {
            s_svc_start  = 0; s_svc_end  = 0;
            s_tx_val_hdl = 0; s_rx_val_hdl = 0; s_cccd_hdl = 0;
            s_state = CHAM_STATE_DISCOVERING;
            strlcpy(s_status_msg, "Discovering services...", sizeof(s_status_msg));
            int drc = ble_gattc_disc_all_svcs(s_conn_handle, s_svc_disc_cb, NULL);
            ESP_LOGI(TAG, "disc_all_svcs rc=%d", drc);
            if (drc != 0) {
                ESP_LOGE(TAG, "disc_all_svcs failed: %d", drc);
                s_ev_error = true;
                strlcpy(s_status_msg, "Svc discovery failed", sizeof(s_status_msg));
            }
            changed = true;
        }
    }

    if (s_ev_cccd_ok) {
        s_ev_cccd_ok = false;
        /* CCCD written successfully — kick the device info sequence */
        s_start_info_sequence();
        changed = true;
    }

    /* ── Drain RX ring buffer → parse frames ── */

    while (s_rx_rd != s_rx_wr) {
        uint8_t byte = s_rx_ring[s_rx_rd];
        s_rx_rd = (s_rx_rd + 1) % CHAM_RX_RING_SIZE;

        int result = s_rx_feed(byte);
        if (result == 1) {
            /* Complete frame received */
            uint16_t fcmd    = s_rxs.cmd;
            uint16_t fstatus = s_rxs.status;
            uint16_t fdlen   = s_rxs.dlen;
            const uint8_t *fdata = s_rxs.buf + 9;

            ESP_LOGD(TAG, "RX frame cmd=0x%04X status=0x%04X dlen=%u",
                     fcmd, fstatus, fdlen);

            /* Match to pending command */
            if (s_pend_cmd != 0xFFFF && fcmd == s_pend_cmd) {
                bool ok = (fstatus == 0);
                cham_cmd_result_cb_t cb = s_pend_cb;
                s_pend_cmd = 0xFFFF;
                s_pend_cb  = NULL;
                s_pend_write_ok = false;
                changed = true;
                if (cb) cb(ok, ok ? fdata : NULL, ok ? fdlen : 0);
            }
        } else if (result == -1) {
            /* Framing error — log and continue */
            ESP_LOGD(TAG, "Frame error at pos (resync)");
        }
    }

    /* ── Command timeout check ── */

    if (s_pend_cmd != 0xFFFF) {
        if (esp_timer_get_time() >= s_pend_deadline) {
            ESP_LOGW(TAG, "Command 0x%04X timed out", s_pend_cmd);
            cham_cmd_result_cb_t cb = s_pend_cb;
            s_pend_cmd = 0xFFFF;
            s_pend_cb  = NULL;
            s_pend_write_ok = false;
            changed = true;
            if (cb) cb(false, NULL, 0);
        }
    }

    return changed;
}
