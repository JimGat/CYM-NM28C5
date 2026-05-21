#include "lf/lf_stub.h"
#include "rfid_types.h"

static rfid_err_t lf_stub_init(void)   { return RFID_ERR_NOT_SUPPORTED; }
static void       lf_stub_deinit(void) {}
static bool       lf_stub_is_init(void){ return false; }
static rfid_err_t lf_stub_scan(rfid_card_t *card, uint32_t timeout_ms)
{
    (void)card; (void)timeout_ms;
    return RFID_ERR_NOT_SUPPORTED;
}

const lf_reader_iface_t lf_stub_reader = {
    .init    = lf_stub_init,
    .deinit  = lf_stub_deinit,
    .is_init = lf_stub_is_init,
    .scan    = lf_stub_scan,
    .name    = "LF Stub (no hardware)",
};
