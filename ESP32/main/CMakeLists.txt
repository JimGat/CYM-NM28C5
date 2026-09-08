# ESP32 main component — shared source files from ESP32C5/main/
# All source files are referenced by relative path from the C5 source tree.
# Board-specific behavior is controlled by board_hal Kconfig (CONFIG_BOARD_CYD2USB).
#
# ieee802154 is excluded — it only exists on C5/C6/H2 SOCs.
# All other components should be compatible with ESP32 (Xtensa LX6).

# CMAKE_CURRENT_SOURCE_DIR is ESP32/main/ — go up two levels to reach the repo root
set(C5_MAIN "${CMAKE_CURRENT_SOURCE_DIR}/../../ESP32C5/main")

idf_component_register(
    SRCS
        "${C5_MAIN}/attack_handshake.c"
        "${C5_MAIN}/xpt2046.c"
        "${C5_MAIN}/lvgl_memory.c"
        "${C5_MAIN}/main.c"
        "${C5_MAIN}/dexter_img.c"
        "${C5_MAIN}/lv_extra_symbols.c"
        "${C5_MAIN}/lab_bg.c"
        "${C5_MAIN}/deedee_img.c"
        "${C5_MAIN}/bt_lookout.c"
        "${C5_MAIN}/oui_lookup.c"
        "${C5_MAIN}/gatt_walker.c"
        "${C5_MAIN}/ble_honeypair.c"
        "${C5_MAIN}/ble_blueduck.c"
        "${C5_MAIN}/ble_whisperpair.c"
        "${C5_MAIN}/sd_error_handler.c"
        "${C5_MAIN}/chameleon_ble.c"
    INCLUDE_DIRS
        "${C5_MAIN}"
    REQUIRES
        heap driver esp_event console bt esp_adc esp-tls esp_http_server esp_wifi board_hal
        espressif__esp_lcd_ili9341
    PRIV_REQUIRES
        wifi_attacks wifi_cli wifi_scanner wifi_sniffer wifi_wardrive sniffer
        frame_analyzer hccapx_serializer pcap_serializer esp_driver_ledc
        rf_hat rfid cc1101 nrf24 obs_store obs_detectors
    EMBED_TXTFILES
        "${C5_MAIN}/gts_root_r4.pem"
)

# Disable format warning errors (size_t formatting differs between architectures)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=format)
