#include "rfid_types.h"
#include <stdio.h>
#include <string.h>

const char *rfid_band_str(rfid_band_t band)
{
    switch (band) {
        case RFID_BAND_HF: return "HF";
        case RFID_BAND_LF: return "LF";
        default:           return "?";
    }
}

const char *rfid_technology_str(rfid_technology_t tech)
{
    switch (tech) {
        case RFID_TECH_ISO14443A: return "ISO14443A";
        case RFID_TECH_ISO14443B: return "ISO14443B";
        case RFID_TECH_FELICA:    return "FeliCa";
        case RFID_TECH_ISO15693:  return "ISO15693";
        case RFID_TECH_EM4100:    return "EM4100";
        case RFID_TECH_HID_PROX:  return "HID Prox";
        case RFID_TECH_INDALA:    return "Indala";
        default:                  return "Unknown";
    }
}

const char *rfid_protocol_str(rfid_protocol_t proto)
{
    switch (proto) {
        case RFID_PROTO_ISO14443_UID_ONLY:   return "ISO14443A";
        case RFID_PROTO_MIFARE_CLASSIC_1K:   return "MIFARE Classic 1K";
        case RFID_PROTO_MIFARE_CLASSIC_4K:   return "MIFARE Classic 4K";
        case RFID_PROTO_MIFARE_ULTRALIGHT:   return "MIFARE Ultralight";
        case RFID_PROTO_MIFARE_PLUS:         return "MIFARE Plus";
        case RFID_PROTO_NTAG213:             return "NTAG213";
        case RFID_PROTO_NTAG215:             return "NTAG215";
        case RFID_PROTO_NTAG216:             return "NTAG216";
        case RFID_PROTO_ISO14443_4:          return "ISO14443-4";
        case RFID_PROTO_DESFIRE:             return "MIFARE DESFire";
        case RFID_PROTO_EM4100:              return "EM4100";
        case RFID_PROTO_HID_26BIT:           return "HID 26-bit";
        case RFID_PROTO_HID_35BIT:           return "HID 35-bit";
        case RFID_PROTO_INDALA:              return "Indala";
        default:                             return "Unknown";
    }
}

const char *rfid_err_str(rfid_err_t err)
{
    switch (err) {
        case RFID_OK:               return "OK";
        case RFID_ERR_NOT_INIT:     return "Not initialized";
        case RFID_ERR_HW:           return "Hardware error";
        case RFID_ERR_NO_CARD:      return "No card detected";
        case RFID_ERR_COLLISION:    return "Card collision";
        case RFID_ERR_AUTH:         return "Auth failed";
        case RFID_ERR_NAK:          return "NAK from card";
        case RFID_ERR_IO:           return "SD I/O error";
        case RFID_ERR_NOT_FOUND:    return "Not found";
        case RFID_ERR_FULL:         return "Storage full";
        case RFID_ERR_NOT_SUPPORTED:return "Not supported";
        case RFID_ERR_TIMEOUT:      return "Timeout";
        default:                    return "Unknown error";
    }
}

void rfid_format_uid(const uint8_t *uid, uint8_t uid_len, char *buf, size_t buf_size)
{
    if (!uid || !buf || buf_size < 1) return;
    buf[0] = '\0';
    size_t pos = 0;
    for (int i = 0; i < uid_len && pos + 3 < buf_size; i++) {
        int n = snprintf(buf + pos, buf_size - pos, i ? " %02X" : "%02X", uid[i]);
        if (n < 0) break;
        pos += (size_t)n;
    }
}

void rfid_format_uid_compact(const uint8_t *uid, uint8_t uid_len, char *buf, size_t buf_size)
{
    if (!uid || !buf || buf_size < 1) return;
    buf[0] = '\0';
    size_t pos = 0;
    for (int i = 0; i < uid_len && pos + 2 < buf_size; i++) {
        int n = snprintf(buf + pos, buf_size - pos, "%02X", uid[i]);
        if (n < 0) break;
        pos += (size_t)n;
    }
}
