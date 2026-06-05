#include "sd_error_handler.h"
#include "esp_log.h"
#include "lvgl.h"
#include "esp_timer.h"

static const char *TAG = "SD_ERROR";

sd_error_t g_sd_error = {0};
bool g_sd_error_pending = false;
static lv_obj_t *s_error_modal = NULL;
static uint64_t s_modal_create_time = 0;
static const uint64_t MODAL_AUTO_DISMISS_US = 10000000; // 10 seconds

void sd_error_report(const char *feature, const char *operation, const char *detail)
{
    if (!feature || !operation) return;

    g_sd_error.error_time_us = esp_timer_get_time();
    strncpy(g_sd_error.feature, feature, sizeof(g_sd_error.feature) - 1);
    strncpy(g_sd_error.operation, operation, sizeof(g_sd_error.operation) - 1);
    strncpy(g_sd_error.detail, detail ? detail : "", sizeof(g_sd_error.detail) - 1);
    g_sd_error.acknowledged = false;

    ESP_LOGE(TAG, "SD WRITE FAIL: %s::%s (%s)", feature, operation, detail ? detail : "");
    g_sd_error_pending = true;
}

static void sd_error_modal_ok_cb(lv_event_t *e)
{
    (void)e;
    sd_error_modal_dismiss();
}

void sd_error_modal_show(void)
{
    if (s_error_modal) return; // Already showing

    lv_obj_t *parent = lv_layer_top();
    s_error_modal = lv_obj_create(parent);
    lv_obj_set_size(s_error_modal, 200, 140);
    lv_obj_center(s_error_modal);
    lv_obj_set_style_bg_color(s_error_modal, lv_color_hex(0x330000), 0); // Dark red
    lv_obj_set_style_border_color(s_error_modal, lv_color_hex(0xFF0000), 0); // Bright red
    lv_obj_set_style_border_width(s_error_modal, 2, 0);
    lv_obj_set_style_pad_all(s_error_modal, 10, 0);

    // Title
    lv_obj_t *title = lv_label_create(s_error_modal);
    lv_label_set_text(title, "SD WRITE ERROR");
    lv_obj_set_style_text_color(title, lv_color_hex(0xFF6666), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 0);

    // Message: "Feature::Operation"
    lv_obj_t *msg = lv_label_create(s_error_modal);
    char msg_text[80];
    snprintf(msg_text, sizeof(msg_text), "%s\n%s", g_sd_error.feature, g_sd_error.operation);
    lv_label_set_text(msg, msg_text);
    lv_obj_set_style_text_color(msg, lv_color_hex(0xFFFFFF), 0);
    lv_obj_set_style_text_font(msg, &lv_font_montserrat_12, 0);
    lv_obj_set_width(msg, 180);
    lv_label_set_long_mode(msg, LV_LABEL_LONG_WRAP);
    lv_obj_align(msg, LV_ALIGN_TOP_MID, 0, 24);

    // Detail text (small gray)
    if (g_sd_error.detail[0]) {
        lv_obj_t *detail = lv_label_create(s_error_modal);
        lv_label_set_text(detail, g_sd_error.detail);
        lv_obj_set_style_text_color(detail, lv_color_hex(0x999999), 0);
        lv_obj_set_style_text_font(detail, &lv_font_montserrat_12, 0);
        lv_obj_set_width(detail, 180);
        lv_label_set_long_mode(detail, LV_LABEL_LONG_WRAP);
        lv_obj_align(detail, LV_ALIGN_TOP_MID, 0, 60);
    }

    // OK button
    lv_obj_t *ok_btn = lv_btn_create(s_error_modal);
    lv_obj_set_size(ok_btn, 60, 24);
    lv_obj_align(ok_btn, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_add_event_cb(ok_btn, sd_error_modal_ok_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *ok_label = lv_label_create(ok_btn);
    lv_label_set_text(ok_label, "OK");
    lv_obj_center(ok_label);

    s_modal_create_time = esp_timer_get_time();
}

void sd_error_modal_update(void)
{
    if (!g_sd_error_pending) return;
    if (!s_error_modal && g_sd_error_pending) {
        sd_error_modal_show();
    }

    // Auto-dismiss after 10 seconds
    if (s_error_modal && (esp_timer_get_time() - s_modal_create_time > MODAL_AUTO_DISMISS_US)) {
        sd_error_modal_dismiss();
    }
}

void sd_error_modal_dismiss(void)
{
    if (s_error_modal && lv_obj_is_valid(s_error_modal)) {
        lv_obj_del(s_error_modal);
    }
    s_error_modal = NULL;
    g_sd_error_pending = false;
}
